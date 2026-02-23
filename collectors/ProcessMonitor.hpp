#pragma once

#include "../core/WindowsHeaders.hpp"
#include "../core/EventBus.hpp"
#include "../core/Logger.hpp"
#include <evntrace.h>
#include <tdh.h>
#include <atomic>
#include <memory>
#include <string>
#include <thread>

namespace cortex {

struct ProcessEvent {
    uint32_t pid;
    uint32_t parent_pid;
    std::wstring image_path;
    std::wstring command_line;
    std::wstring user_sid;
    uint32_t session_id;
    uint64_t timestamp;
    bool is_create;
};

class ProcessMonitor {
public:
    ProcessMonitor();
    ~ProcessMonitor();

    ProcessMonitor(const ProcessMonitor&) = delete;
    ProcessMonitor& operator=(const ProcessMonitor&) = delete;

    bool Start();
    void Stop();
    bool IsRunning() const { return running_; }

private:
    static ULONG WINAPI ProcessTraceCallback(PEVENT_RECORD event_record);
    void MonitorThread();
    void HandleProcessEvent(PEVENT_RECORD event_record);

    bool EnablePrivilege(const wchar_t* privilege);
    void PublishProcessEvent(const ProcessEvent& proc_event);

    std::atomic<bool> running_{false};
    std::atomic<bool> stop_requested_{false};
    std::unique_ptr<std::thread> monitor_thread_;

    TRACEHANDLE session_handle_{0};
    TRACEHANDLE trace_handle_{0};
    EVENT_TRACE_PROPERTIES* trace_properties_{nullptr};

    static constexpr wchar_t SESSION_NAME[] = KERNEL_LOGGER_NAMEW;
    static ProcessMonitor* instance_;
};

} // namespace cortex
