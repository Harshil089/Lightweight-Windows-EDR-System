#include "collectors/RegistryMonitor.hpp"

namespace cortex {

// Helper function to convert wide string to UTF-8
static std::string WideToUtf8(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();

    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), nullptr, 0, nullptr, nullptr);
    std::string str(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), &str[0], size_needed, nullptr, nullptr);
    return str;
}

constexpr const wchar_t* RegistryMonitor::MONITORED_KEYS[];

RegistryMonitor::RegistryMonitor() {
}

RegistryMonitor::~RegistryMonitor() {
    Stop();
}

bool RegistryMonitor::Start() {
    if (running_) {
        LOG_WARN("RegistryMonitor already running");
        return true;
    }

    LOG_INFO("Starting RegistryMonitor");

    running_ = true;
    stop_requested_ = false;

    struct RootKeyPair {
        HKEY root;
        std::wstring root_name;
    };

    std::vector<RootKeyPair> roots = {
        {HKEY_LOCAL_MACHINE, L"HKLM"},
        {HKEY_CURRENT_USER, L"HKCU"}
    };

    for (const auto& root_pair : roots) {
        for (const auto& subkey : MONITORED_KEYS) {
            auto context = std::make_unique<WatchContext>();
            context->root_key = root_pair.root;
            context->subkey_path = subkey;
            context->full_path = root_pair.root_name + L"\\" + subkey;
            context->monitor = this;
            context->key_handle = nullptr;
            context->event_handle = CreateEvent(nullptr, FALSE, FALSE, nullptr);

            if (!context->event_handle) {
                LOG_ERROR("Failed to create event for registry monitoring: {}", GetLastError());
                continue;
            }

            LONG result = RegOpenKeyExW(
                context->root_key,
                context->subkey_path.c_str(),
                0,
                KEY_NOTIFY,
                &context->key_handle
            );

            if (result != ERROR_SUCCESS) {
                LOG_WARN("Failed to open registry key {}: {}",
                        WideToUtf8(context->full_path), result);
                CloseHandle(context->event_handle);
                continue;
            }

            WatchContext* ctx_ptr = context.get();
            contexts_.push_back(std::move(context));

            monitor_threads_.emplace_back(
                std::make_unique<std::thread>(&RegistryMonitor::MonitorRegistryKey, this, ctx_ptr)
            );
        }
    }

    LOG_INFO("RegistryMonitor started, monitoring {} keys", contexts_.size());
    return true;
}

void RegistryMonitor::Stop() {
    if (!running_) {
        return;
    }

    LOG_INFO("Stopping RegistryMonitor");
    stop_requested_ = true;

    for (auto& context : contexts_) {
        if (context->event_handle) {
            SetEvent(context->event_handle);
        }
    }

    for (auto& thread : monitor_threads_) {
        if (thread && thread->joinable()) {
            thread->join();
        }
    }

    for (auto& context : contexts_) {
        if (context->key_handle) {
            RegCloseKey(context->key_handle);
            context->key_handle = nullptr;
        }
        if (context->event_handle) {
            CloseHandle(context->event_handle);
            context->event_handle = nullptr;
        }
    }

    contexts_.clear();
    monitor_threads_.clear();
    running_ = false;

    LOG_INFO("RegistryMonitor stopped");
}

void RegistryMonitor::MonitorRegistryKey(WatchContext* context) {
    LOG_INFO("Monitoring registry key: {}", WideToUtf8(context->full_path));

    while (!stop_requested_) {
        LONG result = RegNotifyChangeKeyValue(
            context->key_handle,
            TRUE,
            REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_NAME,
            context->event_handle,
            TRUE
        );

        if (result != ERROR_SUCCESS) {
            LOG_ERROR("RegNotifyChangeKeyValue failed for {}: {}",
                     WideToUtf8(context->full_path), result);
            break;
        }

        DWORD wait_result = WaitForSingleObject(context->event_handle, INFINITE);

        if (wait_result == WAIT_OBJECT_0 && !stop_requested_) {
            RegistryChange change;
            change.key_path = context->full_path;
            change.value_name = L"";
            change.timestamp = GetTickCount64();

            PublishRegistryEvent(change);
        } else if (wait_result == WAIT_FAILED) {
            LOG_ERROR("WaitForSingleObject failed: {}", GetLastError());
            break;
        }
    }
}

void RegistryMonitor::PublishRegistryEvent(const RegistryChange& change) {
    std::string key_path_str = WideToUtf8(change.key_path);

    Event event(EventType::REGISTRY_WRITE, 0, "RegistryMonitor");
    event.metadata["key_path"] = key_path_str;
    event.metadata["value_name"] = WideToUtf8(change.value_name);

    EventBus::Instance().Publish(event);

    LOG_DEBUG("Registry write detected: {}", key_path_str);
}

} // namespace cortex
