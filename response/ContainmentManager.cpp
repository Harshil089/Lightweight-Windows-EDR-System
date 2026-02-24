#include "response/ContainmentManager.hpp"
#include "core/Logger.hpp"
#include <filesystem>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <aclapi.h>
#include <sddl.h>

namespace cortex {

// Function pointer for NtSuspendProcess
typedef LONG (NTAPI *NtSuspendProcessFunc)(HANDLE ProcessHandle);

ContainmentManager::ContainmentManager() = default;

ContainmentManager::~ContainmentManager() {
    Stop();
}

void ContainmentManager::Initialize(bool auto_contain, bool require_confirmation,
                                   const std::string& quarantine_path) {
    auto_contain_ = auto_contain;
    require_confirmation_ = require_confirmation;
    quarantine_path_ = quarantine_path;

    // Create quarantine directory if it doesn't exist
    try {
        std::filesystem::create_directories(quarantine_path_);
        LOG_INFO("Quarantine directory: {}", quarantine_path_);
    } catch (const std::exception& ex) {
        LOG_ERROR("Failed to create quarantine directory: {}", ex.what());
    }

    // Attempt to enable required privileges
    if (!EnableSeDebugPrivilege()) {
        LOG_WARN("Failed to enable SeDebugPrivilege, process termination may be limited");
    }

    if (!EnableSeSecurityPrivilege()) {
        LOG_WARN("Failed to enable SeSecurityPrivilege, DACL modification may be limited");
    }

    LOG_INFO("ContainmentManager initialized (auto_contain={}, require_confirmation={})",
             auto_contain_, require_confirmation_);
}

void ContainmentManager::Start() {
    if (running_) {
        LOG_WARN("ContainmentManager already running");
        return;
    }

    // Subscribe to RISK_THRESHOLD_EXCEEDED events
    subscription_id_ = EventBus::Instance().Subscribe(
        EventType::RISK_THRESHOLD_EXCEEDED,
        [this](const Event& event) { OnRiskThresholdExceeded(event); }
    );

    running_ = true;
    LOG_INFO("ContainmentManager started");
}

void ContainmentManager::Stop() {
    if (!running_) {
        return;
    }

    if (subscription_id_ != 0) {
        EventBus::Instance().Unsubscribe(subscription_id_);
        subscription_id_ = 0;
    }

    running_ = false;
    LOG_INFO("ContainmentManager stopped");
}

bool ContainmentManager::EnableSeDebugPrivilege() {
    return EnablePrivilege(SE_DEBUG_NAME);
}

bool ContainmentManager::EnableSeSecurityPrivilege() {
    return EnablePrivilege(SE_SECURITY_NAME);
}

bool ContainmentManager::EnablePrivilege(const wchar_t* privilege) {
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        LOG_ERROR("Failed to open process token: {}", GetLastError());
        return false;
    }

    LUID luid;
    if (!LookupPrivilegeValueW(nullptr, privilege, &luid)) {
        LOG_ERROR("Failed to lookup privilege: {}", GetLastError());
        CloseHandle(token);
        return false;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
        LOG_ERROR("Failed to adjust token privileges: {}", GetLastError());
        CloseHandle(token);
        return false;
    }

    CloseHandle(token);
    LOG_DEBUG("Successfully enabled privilege: {}", WideToUtf8(std::wstring(privilege)));
    return true;
}

void ContainmentManager::OnRiskThresholdExceeded(const Event& event) {
    std::lock_guard<std::mutex> lock(mutex_);

    LOG_WARN("Risk threshold exceeded for PID {} ({})", event.pid, event.process_name);

    if (!auto_contain_) {
        LOG_INFO("Auto-containment disabled, manual action required for PID {}", event.pid);
        return;
    }

    if (require_confirmation_) {
        LOG_WARN("PID {} requires manual confirmation for containment", event.pid);
        return;
    }

    // Determine action based on risk level from metadata
    auto level_it = event.metadata.find("risk_level");
    if (level_it != event.metadata.end()) {
        const std::string& risk_level = level_it->second;

        if (risk_level == "CRITICAL") {
            LOG_CRITICAL("CRITICAL risk level detected for PID {}, initiating termination", event.pid);

            if (TerminateProcessInternal(event.pid)) {
                // Also attempt to quarantine the executable
                auto image_it = event.metadata.find("original_image_path");
                if (image_it != event.metadata.end()) {
                    QuarantineFileInternal(image_it->second);
                }

                // Emit containment action event
                Event containment_event(EventType::CONTAINMENT_ACTION, event.pid, "ContainmentManager");
                containment_event.metadata["action"] = "process_terminate";
                containment_event.metadata["reason"] = "critical_risk_level";
                EventBus::Instance().PublishAsync(containment_event);
            }
        } else if (risk_level == "HIGH") {
            LOG_WARN("HIGH risk level detected for PID {}, initiating suspension", event.pid);

            if (SuspendProcessInternal(event.pid)) {
                // Emit containment action event
                Event containment_event(EventType::CONTAINMENT_ACTION, event.pid, "ContainmentManager");
                containment_event.metadata["action"] = "process_suspend";
                containment_event.metadata["reason"] = "high_risk_level";
                EventBus::Instance().PublishAsync(containment_event);
            }
        }
    }
}

ContainmentResult ContainmentManager::TerminateProcess(uint32_t pid) {
    std::lock_guard<std::mutex> lock(mutex_);

    bool success = TerminateProcessInternal(pid);
    return ContainmentResult(success,
                            success ? "" : "Failed to terminate process",
                            ContainmentAction::PROCESS_TERMINATE,
                            pid);
}

bool ContainmentManager::TerminateProcessInternal(uint32_t pid) {
    HANDLE process_handle = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (process_handle == nullptr) {
        DWORD error = GetLastError();
        LOG_ERROR("Failed to open process {} for termination: {}", pid, error);
        return false;
    }

    BOOL result = ::TerminateProcess(process_handle, 1);
    DWORD error = GetLastError();
    CloseHandle(process_handle);

    if (!result) {
        LOG_ERROR("Failed to terminate process {}: {}", pid, error);
        return false;
    }

    LOG_INFO("Successfully terminated process {}", pid);
    return true;
}

ContainmentResult ContainmentManager::SuspendProcess(uint32_t pid) {
    std::lock_guard<std::mutex> lock(mutex_);

    bool success = SuspendProcessInternal(pid);
    return ContainmentResult(success,
                            success ? "" : "Failed to suspend process",
                            ContainmentAction::PROCESS_SUSPEND,
                            pid);
}

bool ContainmentManager::SuspendProcessInternal(uint32_t pid) {
    // Get ntdll.dll handle
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        LOG_ERROR("Failed to get ntdll.dll handle");
        return false;
    }

    // Get NtSuspendProcess function pointer
    auto NtSuspendProcess = (NtSuspendProcessFunc)GetProcAddress(ntdll, "NtSuspendProcess");
    if (!NtSuspendProcess) {
        LOG_ERROR("Failed to get NtSuspendProcess function address");
        return false;
    }

    // Open process handle
    HANDLE process_handle = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (!process_handle) {
        DWORD error = GetLastError();
        LOG_ERROR("Failed to open process {} for suspension: {}", pid, error);
        return false;
    }

    // Suspend process
    LONG status = NtSuspendProcess(process_handle);
    CloseHandle(process_handle);

    if (status != 0) {
        LOG_ERROR("NtSuspendProcess failed for PID {} with status: {}", pid, status);
        return false;
    }

    LOG_INFO("Successfully suspended process {}", pid);
    return true;
}

ContainmentResult ContainmentManager::BlockNetworkConnection(uint32_t pid, const std::string& remote_ip) {
    std::lock_guard<std::mutex> lock(mutex_);

    bool success = BlockIPViaFirewall(remote_ip);
    return ContainmentResult(success,
                            success ? "" : "Failed to block network connection",
                            ContainmentAction::NETWORK_BLOCK,
                            pid);
}

bool ContainmentManager::BlockIPViaFirewall(const std::string& remote_ip) {
    // Simplified implementation: Log the action
    // Full implementation would use INetFwPolicy2 COM interface
    LOG_WARN("Network blocking requested for IP {} (COM interface not fully implemented)", remote_ip);
    LOG_INFO("To implement: Use INetFwPolicy2 COM interface to add firewall rule");

    // TODO: Implement full COM-based firewall rule creation:
    // 1. CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED)
    // 2. CoCreateInstance(CLSID_NetFwPolicy2, INetFwPolicy2)
    // 3. policy->get_Rules(&rules)
    // 4. CoCreateInstance(CLSID_NetFwRule, INetFwRule)
    // 5. rule->put_Name, put_RemoteAddresses, put_Action(NET_FW_ACTION_BLOCK)
    // 6. rules->Add(rule)
    // 7. Release COM interfaces

    return false; // Not implemented
}

ContainmentResult ContainmentManager::QuarantineFile(const std::string& file_path) {
    std::lock_guard<std::mutex> lock(mutex_);

    bool success = QuarantineFileInternal(file_path);
    return ContainmentResult(success,
                            success ? "" : "Failed to quarantine file",
                            ContainmentAction::FILE_QUARANTINE,
                            0);
}

bool ContainmentManager::QuarantineFileInternal(const std::string& file_path) {
    try {
        std::wstring wide_path = Utf8ToWide(file_path);

        // Check if file exists
        if (!std::filesystem::exists(file_path)) {
            LOG_WARN("File does not exist, cannot quarantine: {}", file_path);
            return false;
        }

        // Generate quarantine filename
        std::wstring quarantine_filename = GenerateQuarantineFilename(wide_path);
        std::wstring quarantine_full_path = Utf8ToWide(quarantine_path_) + L"\\" + quarantine_filename;

        LOG_INFO("Quarantining file: {} -> {}", file_path, WideToUtf8(quarantine_full_path));

        // Move file to quarantine directory
        if (!MoveFileExW(wide_path.c_str(), quarantine_full_path.c_str(),
                        MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING)) {
            DWORD error = GetLastError();
            LOG_ERROR("Failed to move file to quarantine: {}", error);
            return false;
        }

        // Set DACL to deny all access except SYSTEM
        if (!SetFileDACLDenyAll(quarantine_full_path)) {
            LOG_WARN("File quarantined but failed to set restrictive DACL");
        }

        LOG_INFO("Successfully quarantined file: {}", file_path);
        return true;

    } catch (const std::exception& ex) {
        LOG_ERROR("Exception during file quarantine: {}", ex.what());
        return false;
    }
}

bool ContainmentManager::SetFileDACLDenyAll(const std::wstring& file_path) {
    // Create an explicit DENY ACE for Everyone (S-1-1-0)
    // Keep ALLOW ACE for SYSTEM (S-1-5-18)

    PSID everyone_sid = nullptr;
    PSID system_sid = nullptr;
    PACL acl = nullptr;
    EXPLICIT_ACCESSW ea[2] = {0};

    // Create Everyone SID
    SID_IDENTIFIER_AUTHORITY world_auth = SECURITY_WORLD_SID_AUTHORITY;
    if (!AllocateAndInitializeSid(&world_auth, 1, SECURITY_WORLD_RID,
                                  0, 0, 0, 0, 0, 0, 0, &everyone_sid)) {
        LOG_ERROR("Failed to create Everyone SID: {}", GetLastError());
        return false;
    }

    // Create SYSTEM SID
    SID_IDENTIFIER_AUTHORITY nt_auth = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(&nt_auth, 1, SECURITY_LOCAL_SYSTEM_RID,
                                  0, 0, 0, 0, 0, 0, 0, &system_sid)) {
        LOG_ERROR("Failed to create SYSTEM SID: {}", GetLastError());
        FreeSid(everyone_sid);
        return false;
    }

    // Set up DENY ACE for Everyone
    ea[0].grfAccessPermissions = GENERIC_ALL;
    ea[0].grfAccessMode = DENY_ACCESS;
    ea[0].grfInheritance = NO_INHERITANCE;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[0].Trustee.ptstrName = (LPWSTR)everyone_sid;

    // Set up ALLOW ACE for SYSTEM
    ea[1].grfAccessPermissions = GENERIC_ALL;
    ea[1].grfAccessMode = SET_ACCESS;
    ea[1].grfInheritance = NO_INHERITANCE;
    ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[1].Trustee.TrusteeType = TRUSTEE_IS_USER;
    ea[1].Trustee.ptstrName = (LPWSTR)system_sid;

    // Create ACL
    DWORD result = SetEntriesInAclW(2, ea, nullptr, &acl);
    if (result != ERROR_SUCCESS) {
        LOG_ERROR("SetEntriesInAcl failed: {}", result);
        FreeSid(everyone_sid);
        FreeSid(system_sid);
        return false;
    }

    // Apply ACL to file
    result = SetNamedSecurityInfoW((LPWSTR)file_path.c_str(), SE_FILE_OBJECT,
                                   DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                   nullptr, nullptr, acl, nullptr);

    // Cleanup
    LocalFree(acl);
    FreeSid(everyone_sid);
    FreeSid(system_sid);

    if (result != ERROR_SUCCESS) {
        LOG_ERROR("SetNamedSecurityInfo failed: {}", result);
        return false;
    }

    LOG_DEBUG("Successfully set restrictive DACL on quarantined file");
    return true;
}

std::wstring ContainmentManager::GenerateQuarantineFilename(const std::wstring& original_path) {
    // Extract filename from path
    std::filesystem::path path(original_path);
    std::wstring filename = path.filename().wstring();

    // Get current timestamp
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::system_clock::to_time_t(now);

    // Format: original_filename.quarantine.YYYYMMDD_HHMMSS
    std::wstringstream ss;
    ss << filename << L".quarantine.";

    std::tm tm_buf;
    localtime_s(&tm_buf, &timestamp);
    ss << std::put_time(&tm_buf, L"%Y%m%d_%H%M%S");

    return ss.str();
}

std::wstring ContainmentManager::Utf8ToWide(const std::string& utf8_str) {
    if (utf8_str.empty()) {
        return L"";
    }

    int size_needed = MultiByteToWideChar(CP_UTF8, 0, utf8_str.c_str(),
                                         static_cast<int>(utf8_str.size()), nullptr, 0);
    std::wstring wide_str(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, utf8_str.c_str(),
                       static_cast<int>(utf8_str.size()), &wide_str[0], size_needed);
    return wide_str;
}

std::string ContainmentManager::WideToUtf8(const std::wstring& wide_str) {
    if (wide_str.empty()) {
        return "";
    }

    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wide_str.c_str(),
                                         static_cast<int>(wide_str.size()),
                                         nullptr, 0, nullptr, nullptr);
    std::string utf8_str(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wide_str.c_str(),
                       static_cast<int>(wide_str.size()),
                       &utf8_str[0], size_needed, nullptr, nullptr);
    return utf8_str;
}

} // namespace cortex
