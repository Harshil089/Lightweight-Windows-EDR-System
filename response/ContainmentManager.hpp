#pragma once

#include "core/EventBus.hpp"
#include "core/WindowsHeaders.hpp"
#include <string>
#include <mutex>
#include <atomic>

namespace cortex {

enum class ContainmentAction {
    PROCESS_TERMINATE,
    PROCESS_SUSPEND,
    NETWORK_BLOCK,
    FILE_QUARANTINE
};

struct ContainmentResult {
    bool success;
    std::string error_message;
    ContainmentAction action;
    uint32_t pid;

    ContainmentResult(bool s = false, const std::string& err = "",
                     ContainmentAction a = ContainmentAction::PROCESS_TERMINATE, uint32_t p = 0)
        : success(s), error_message(err), action(a), pid(p) {}
};

class ContainmentManager {
public:
    ContainmentManager();
    ~ContainmentManager();

    void Initialize(bool auto_contain, bool require_confirmation, const std::string& quarantine_path);
    void Start();
    void Stop();

    // Manual containment API
    ContainmentResult TerminateProcess(uint32_t pid);
    ContainmentResult SuspendProcess(uint32_t pid);
    ContainmentResult BlockNetworkConnection(uint32_t pid, const std::string& remote_ip);
    ContainmentResult QuarantineFile(const std::string& file_path);

private:
    void OnRiskThresholdExceeded(const Event& event);
    bool EnableSeDebugPrivilege();
    bool EnableSeSecurityPrivilege();

    // Windows API wrappers
    bool TerminateProcessInternal(uint32_t pid);
    bool SuspendProcessInternal(uint32_t pid); // NtSuspendProcess via ntdll
    bool BlockIPViaFirewall(const std::string& remote_ip);
    bool QuarantineFileInternal(const std::string& file_path);
    bool SetFileDACLDenyAll(const std::wstring& file_path);

    // Helper methods
    std::wstring Utf8ToWide(const std::string& utf8_str);
    std::string WideToUtf8(const std::wstring& wide_str);
    std::wstring GenerateQuarantineFilename(const std::wstring& original_path);
    bool EnablePrivilege(const wchar_t* privilege);

    bool auto_contain_{false};
    bool require_confirmation_{false};
    std::string quarantine_path_;

    mutable std::mutex mutex_;
    std::atomic<bool> running_{false};
    SubscriptionId subscription_id_{0};
};

} // namespace cortex
