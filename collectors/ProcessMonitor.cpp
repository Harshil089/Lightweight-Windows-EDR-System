#include "collectors/ProcessMonitor.hpp"
#include <evntcons.h>
#include <sstream>
#include <iomanip>
#include <locale>
#include <codecvt>

namespace cortex {

ProcessMonitor* ProcessMonitor::instance_ = nullptr;
constexpr wchar_t ProcessMonitor::SESSION_NAME[];

ProcessMonitor::ProcessMonitor() {
    instance_ = this;
}

ProcessMonitor::~ProcessMonitor() {
    Stop();
    instance_ = nullptr;
}

bool ProcessMonitor::EnablePrivilege(const wchar_t* privilege) {
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        LOG_ERROR("Failed to open process token: {}", GetLastError());
        return false;
    }

    LUID luid;
    if (!LookupPrivilegeValueW(nullptr, privilege, &luid)) {
        LOG_ERROR("Failed to lookup privilege {}: {}", privilege, GetLastError());
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
    return true;
}

bool ProcessMonitor::Start() {
    if (running_) {
        LOG_WARN("ProcessMonitor already running");
        return true;
    }

    LOG_INFO("Starting ProcessMonitor with ETW");

    if (!EnablePrivilege(SE_DEBUG_NAME)) {
        LOG_WARN("Failed to enable SeDebugPrivilege, some monitoring may be limited");
    }

    size_t buffer_size = sizeof(EVENT_TRACE_PROPERTIES) + (wcslen(SESSION_NAME) + 1) * sizeof(wchar_t);
    trace_properties_ = static_cast<EVENT_TRACE_PROPERTIES*>(malloc(buffer_size));
    if (!trace_properties_) {
        LOG_ERROR("Failed to allocate trace properties");
        return false;
    }

    ZeroMemory(trace_properties_, buffer_size);
    trace_properties_->Wnode.BufferSize = static_cast<ULONG>(buffer_size);
    trace_properties_->Wnode.Guid = SystemTraceControlGuid;
    trace_properties_->Wnode.ClientContext = 1;
    trace_properties_->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    trace_properties_->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    trace_properties_->EnableFlags = EVENT_TRACE_FLAG_PROCESS;
    trace_properties_->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ULONG status = StartTraceW(&session_handle_, SESSION_NAME, trace_properties_);
    if (status == ERROR_ALREADY_EXISTS) {
        LOG_WARN("Trace session already exists, stopping and restarting");
        ControlTraceW(0, SESSION_NAME, trace_properties_, EVENT_TRACE_CONTROL_STOP);
        status = StartTraceW(&session_handle_, SESSION_NAME, trace_properties_);
    }

    if (status != ERROR_SUCCESS) {
        LOG_ERROR("Failed to start trace session: {}", status);
        free(trace_properties_);
        trace_properties_ = nullptr;
        return false;
    }

    running_ = true;
    stop_requested_ = false;
    monitor_thread_ = std::make_unique<std::thread>(&ProcessMonitor::MonitorThread, this);

    LOG_INFO("ProcessMonitor started successfully");
    return true;
}

void ProcessMonitor::Stop() {
    if (!running_) {
        return;
    }

    LOG_INFO("Stopping ProcessMonitor");
    stop_requested_ = true;

    if (session_handle_) {
        ControlTraceW(session_handle_, SESSION_NAME, trace_properties_, EVENT_TRACE_CONTROL_STOP);
        session_handle_ = 0;
    }

    if (monitor_thread_ && monitor_thread_->joinable()) {
        monitor_thread_->join();
    }

    if (trace_properties_) {
        free(trace_properties_);
        trace_properties_ = nullptr;
    }

    running_ = false;
    LOG_INFO("ProcessMonitor stopped");
}

ULONG WINAPI ProcessMonitor::ProcessTraceCallback(PEVENT_RECORD event_record) {
    if (instance_) {
        instance_->HandleProcessEvent(event_record);
    }
    return ERROR_SUCCESS;
}

void ProcessMonitor::MonitorThread() {
    EVENT_TRACE_LOGFILEW trace = {0};
    trace.LoggerName = const_cast<LPWSTR>(SESSION_NAME);
    trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    trace.EventRecordCallback = ProcessTraceCallback;

    trace_handle_ = OpenTraceW(&trace);
    if (trace_handle_ == INVALID_PROCESSTRACE_HANDLE) {
        LOG_ERROR("Failed to open trace: {}", GetLastError());
        running_ = false;
        return;
    }

    ULONG status = ProcessTrace(&trace_handle_, 1, nullptr, nullptr);
    if (status != ERROR_SUCCESS && status != ERROR_CANCELLED) {
        LOG_ERROR("ProcessTrace failed: {}", status);
    }

    CloseTrace(trace_handle_);
    trace_handle_ = 0;
}

void ProcessMonitor::HandleProcessEvent(PEVENT_RECORD event_record) {
    if (event_record->EventHeader.ProviderId != SystemTraceControlGuid) {
        return;
    }

    bool is_create = false;
    if (event_record->EventHeader.EventDescriptor.Opcode == EVENT_TRACE_TYPE_START ||
        event_record->EventHeader.EventDescriptor.Opcode == 1) {
        is_create = true;
    } else if (event_record->EventHeader.EventDescriptor.Opcode == EVENT_TRACE_TYPE_END ||
               event_record->EventHeader.EventDescriptor.Opcode == 2) {
        is_create = false;
    } else {
        return;
    }

    ProcessEvent proc_event;
    proc_event.is_create = is_create;
    proc_event.timestamp = event_record->EventHeader.TimeStamp.QuadPart;

    if (event_record->EventHeader.EventDescriptor.Opcode == 1 ||
        event_record->EventHeader.EventDescriptor.Opcode == 2) {

        PBYTE ptr = static_cast<PBYTE>(event_record->UserData);
        PBYTE end_ptr = ptr + event_record->UserDataLength;

        if (ptr + sizeof(ULONG) * 4 <= end_ptr) {
            proc_event.pid = *reinterpret_cast<ULONG*>(ptr);
            ptr += sizeof(ULONG);

            proc_event.parent_pid = *reinterpret_cast<ULONG*>(ptr);
            ptr += sizeof(ULONG);

            ptr += sizeof(ULONG);

            proc_event.session_id = *reinterpret_cast<ULONG*>(ptr);
            ptr += sizeof(ULONG);

            if (ptr < end_ptr) {
                proc_event.image_path = reinterpret_cast<wchar_t*>(ptr);
            }
        }
    }

    PublishProcessEvent(proc_event);
}

void ProcessMonitor::PublishProcessEvent(const ProcessEvent& proc_event) {
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    std::string image_path_str = converter.to_bytes(proc_event.image_path);

    std::string process_name = image_path_str;
    size_t last_slash = process_name.find_last_of("\\/");
    if (last_slash != std::string::npos) {
        process_name = process_name.substr(last_slash + 1);
    }

    Event event(
        proc_event.is_create ? EventType::PROCESS_CREATE : EventType::PROCESS_TERMINATE,
        proc_event.pid,
        process_name
    );

    event.metadata["image_path"] = image_path_str;
    event.metadata["parent_pid"] = std::to_string(proc_event.parent_pid);
    event.metadata["session_id"] = std::to_string(proc_event.session_id);
    event.metadata["command_line"] = converter.to_bytes(proc_event.command_line);

    EventBus::Instance().Publish(event);

    LOG_DEBUG("Process {} detected: PID={} Name={} ParentPID={}",
              proc_event.is_create ? "CREATE" : "TERMINATE",
              proc_event.pid,
              process_name,
              proc_event.parent_pid);
}

} // namespace cortex
