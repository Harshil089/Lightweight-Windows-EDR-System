#include "collectors/FileMonitor.hpp"

namespace {
// Helper function to convert wide string to UTF-8
std::string WideToUtf8(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), nullptr, 0, nullptr, nullptr);
    std::string result(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), &result[0], size_needed, nullptr, nullptr);
    return result;
}
} // anonymous namespace

namespace cortex {

FileMonitor::FileMonitor(const std::vector<std::wstring>& watch_paths)
    : watch_paths_(watch_paths) {
}

FileMonitor::~FileMonitor() {
    Stop();
}

bool FileMonitor::Start() {
    if (running_) {
        LOG_WARN("FileMonitor already running");
        return true;
    }

    LOG_INFO("Starting FileMonitor for {} paths", watch_paths_.size());

    running_ = true;
    stop_requested_ = false;

    for (const auto& path : watch_paths_) {
        monitor_threads_.emplace_back(
            std::make_unique<std::thread>(&FileMonitor::MonitorDirectory, this, path)
        );
    }

    LOG_INFO("FileMonitor started successfully");
    return true;
}

void FileMonitor::Stop() {
    if (!running_) {
        return;
    }

    LOG_INFO("Stopping FileMonitor");
    stop_requested_ = true;

    {
        std::lock_guard<std::mutex> lock(contexts_mutex_);
        for (auto& context : contexts_) {
            if (context->dir_handle != INVALID_HANDLE_VALUE) {
                CancelIo(context->dir_handle);
            }
        }
    }

    for (auto& thread : monitor_threads_) {
        if (thread && thread->joinable()) {
            thread->join();
        }
    }

    // Threads have exited — safe to clean up without lock
    contexts_.clear();
    monitor_threads_.clear();
    running_ = false;

    LOG_INFO("FileMonitor stopped");
}

void FileMonitor::MonitorDirectory(const std::wstring& path) {
    LOG_INFO("Monitoring directory: {}", WideToUtf8(path));

    HANDLE dir_handle = CreateFileW(
        path.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        nullptr
    );

    if (dir_handle == INVALID_HANDLE_VALUE) {
        LOG_ERROR("Failed to open directory {}: {}", WideToUtf8(path), GetLastError());
        return;
    }

    auto context = std::make_unique<WatchContext>();
    context->dir_handle = dir_handle;
    context->path = path;
    context->monitor = this;
    context->overlapped.hEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);

    if (!context->overlapped.hEvent) {
        LOG_ERROR("Failed to create event: {}", GetLastError());
        CloseHandle(dir_handle);
        return;
    }

    // Register context so Stop() can CancelIo on it
    WatchContext* ctx_ptr = context.get();
    {
        std::lock_guard<std::mutex> lock(contexts_mutex_);
        contexts_.push_back(std::move(context));
    }

    DWORD notify_filter = FILE_NOTIFY_CHANGE_FILE_NAME |
                          FILE_NOTIFY_CHANGE_LAST_WRITE |
                          FILE_NOTIFY_CHANGE_SECURITY |
                          FILE_NOTIFY_CHANGE_CREATION;

    while (!stop_requested_) {
        ZeroMemory(ctx_ptr->buffer, sizeof(ctx_ptr->buffer));
        ZeroMemory(&ctx_ptr->overlapped, sizeof(OVERLAPPED));
        ctx_ptr->overlapped.hEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);

        BOOL result = ReadDirectoryChangesW(
            ctx_ptr->dir_handle,
            ctx_ptr->buffer,
            sizeof(ctx_ptr->buffer),
            TRUE,
            notify_filter,
            nullptr,
            &ctx_ptr->overlapped,
            FileChangeCallback
        );

        if (!result) {
            DWORD error = GetLastError();
            if (error != ERROR_OPERATION_ABORTED) {
                LOG_ERROR("ReadDirectoryChangesW failed: {}", error);
            }
            break;
        }

        DWORD bytes_transferred = 0;
        if (GetOverlappedResult(ctx_ptr->dir_handle, &ctx_ptr->overlapped, &bytes_transferred, TRUE)) {
            ProcessFileChange(ctx_ptr, bytes_transferred);
        }

        CloseHandle(ctx_ptr->overlapped.hEvent);
        ctx_ptr->overlapped.hEvent = nullptr;
    }

    // Clean up handles owned by this thread
    CloseHandle(dir_handle);
    ctx_ptr->dir_handle = INVALID_HANDLE_VALUE;
}

void CALLBACK FileMonitor::FileChangeCallback(DWORD error_code, DWORD bytes_transferred, LPOVERLAPPED overlapped) {
    (void)bytes_transferred;
    (void)overlapped;
    if (error_code == ERROR_OPERATION_ABORTED) {
        return;
    }
}

void FileMonitor::ProcessFileChange(WatchContext* context, DWORD bytes_transferred) {
    if (bytes_transferred == 0) {
        return;
    }

    BYTE* ptr = context->buffer;
    while (true) {
        FILE_NOTIFY_INFORMATION* info = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(ptr);

        std::wstring filename(info->FileName, info->FileNameLength / sizeof(wchar_t));
        std::wstring full_path = context->path + L"\\" + filename;

        FileChange change;
        change.file_path = full_path;
        change.action = info->Action;
        change.timestamp = GetTickCount64();

        PublishFileEvent(change);

        if (info->NextEntryOffset == 0) {
            break;
        }
        ptr += info->NextEntryOffset;
    }
}

void FileMonitor::PublishFileEvent(const FileChange& change) {
    std::string file_path_str = WideToUtf8(change.file_path);

    EventType event_type;
    std::string action_str;

    switch (change.action) {
        case FILE_ACTION_ADDED:
            event_type = EventType::FILE_CREATE;
            action_str = "CREATE";
            break;
        case FILE_ACTION_REMOVED:
            event_type = EventType::FILE_DELETE;
            action_str = "DELETE";
            break;
        case FILE_ACTION_MODIFIED:
            event_type = EventType::FILE_MODIFY;
            action_str = "MODIFY";
            break;
        case FILE_ACTION_RENAMED_OLD_NAME:
        case FILE_ACTION_RENAMED_NEW_NAME:
            event_type = EventType::FILE_MODIFY;
            action_str = "RENAME";
            break;
        default:
            return;
    }

    Event event(event_type, 0, "FileMonitor");
    event.metadata["file_path"] = file_path_str;
    event.metadata["action"] = action_str;

    EventBus::Instance().Publish(event);

    LOG_DEBUG("File {} detected: {}", action_str, file_path_str);
}

} // namespace cortex
