#pragma once

#include "../core/WindowsHeaders.hpp"
#include "../core/EventBus.hpp"
#include "../core/Logger.hpp"
#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace cortex {

struct FileChange {
    std::wstring file_path;
    DWORD action;
    uint64_t timestamp;
};

class FileMonitor {
public:
    explicit FileMonitor(const std::vector<std::wstring>& watch_paths);
    ~FileMonitor();

    FileMonitor(const FileMonitor&) = delete;
    FileMonitor& operator=(const FileMonitor&) = delete;

    bool Start();
    void Stop();
    bool IsRunning() const { return running_; }

private:
    struct WatchContext {
        HANDLE dir_handle;
        std::wstring path;
        OVERLAPPED overlapped;
        BYTE buffer[64 * 1024];
        FileMonitor* monitor;
    };

    void MonitorDirectory(const std::wstring& path);
    static void CALLBACK FileChangeCallback(DWORD error_code, DWORD bytes_transferred, LPOVERLAPPED overlapped);
    void ProcessFileChange(WatchContext* context, DWORD bytes_transferred);
    void PublishFileEvent(const FileChange& change);

    std::vector<std::wstring> watch_paths_;
    std::mutex contexts_mutex_;
    std::vector<std::unique_ptr<WatchContext>> contexts_;
    std::vector<std::unique_ptr<std::thread>> monitor_threads_;
    std::atomic<bool> running_{false};
    std::atomic<bool> stop_requested_{false};
};

} // namespace cortex
