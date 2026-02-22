#pragma once

#include "../core/WindowsHeaders.hpp"
#include "../core/EventBus.hpp"
#include "../core/Logger.hpp"
#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace cortex {

struct RegistryChange {
    std::wstring key_path;
    std::wstring value_name;
    uint64_t timestamp;
};

class RegistryMonitor {
public:
    RegistryMonitor();
    ~RegistryMonitor();

    RegistryMonitor(const RegistryMonitor&) = delete;
    RegistryMonitor& operator=(const RegistryMonitor&) = delete;

    bool Start();
    void Stop();
    bool IsRunning() const { return running_; }

private:
    struct WatchContext {
        HKEY root_key;
        std::wstring subkey_path;
        std::wstring full_path;
        HKEY key_handle;
        HANDLE event_handle;
        RegistryMonitor* monitor;
    };

    void MonitorRegistryKey(WatchContext* context);
    void PublishRegistryEvent(const RegistryChange& change);

    std::vector<std::unique_ptr<WatchContext>> contexts_;
    std::vector<std::unique_ptr<std::thread>> monitor_threads_;
    std::atomic<bool> running_{false};
    std::atomic<bool> stop_requested_{false};

    static constexpr const wchar_t* MONITORED_KEYS[] = {
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    };
};

} // namespace cortex
