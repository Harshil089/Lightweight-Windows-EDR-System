#pragma once

#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

// Forward declare ThreadPool to avoid circular includes
namespace cortex { class ThreadPool; }

namespace cortex {

enum class EventType {
    PROCESS_CREATE,
    PROCESS_TERMINATE,
    FILE_CREATE,
    FILE_MODIFY,
    FILE_DELETE,
    NETWORK_CONNECT,
    NETWORK_DISCONNECT,
    REGISTRY_WRITE,
    RISK_THRESHOLD_EXCEEDED,
    INCIDENT_STATE_CHANGE,
    CONTAINMENT_ACTION
};

struct Event {
    EventType type;
    uint64_t timestamp;
    uint32_t pid;
    std::string process_name;
    std::unordered_map<std::string, std::string> metadata;

    Event(EventType t, uint32_t p, const std::string& name)
        : type(t), timestamp(GetCurrentTimestamp()), pid(p), process_name(name) {}

private:
    static uint64_t GetCurrentTimestamp();
};

using EventHandler = std::function<void(const Event&)>;
using SubscriptionId = uint64_t;

class EventBus {
public:
    static EventBus& Instance();

    EventBus(const EventBus&) = delete;
    EventBus& operator=(const EventBus&) = delete;

    SubscriptionId Subscribe(EventType type, EventHandler handler);
    void Unsubscribe(SubscriptionId id);
    void Publish(const Event& event);
    void PublishAsync(Event event);

    // Initialize the internal thread pool for async publishing.
    // Must be called once before any PublishAsync() calls.
    void InitAsyncPool(size_t num_threads = 2);

    // Drain all pending async tasks and shut down the pool.
    // Call during application shutdown before EventBus destruction.
    void ShutdownAsyncPool();

    size_t GetSubscriberCount(EventType type) const;
    void Clear();

private:
    EventBus() = default;

    mutable std::mutex mutex_;
    std::unordered_map<EventType, std::vector<std::pair<SubscriptionId, EventHandler>>> subscribers_;
    SubscriptionId next_id_ = 1;

    std::unique_ptr<ThreadPool> async_pool_;
};

inline std::string EventTypeToString(EventType type) {
    switch (type) {
        case EventType::PROCESS_CREATE:          return "PROCESS_CREATE";
        case EventType::PROCESS_TERMINATE:       return "PROCESS_TERMINATE";
        case EventType::FILE_CREATE:             return "FILE_CREATE";
        case EventType::FILE_MODIFY:             return "FILE_MODIFY";
        case EventType::FILE_DELETE:             return "FILE_DELETE";
        case EventType::NETWORK_CONNECT:         return "NETWORK_CONNECT";
        case EventType::NETWORK_DISCONNECT:      return "NETWORK_DISCONNECT";
        case EventType::REGISTRY_WRITE:          return "REGISTRY_WRITE";
        case EventType::RISK_THRESHOLD_EXCEEDED: return "RISK_THRESHOLD_EXCEEDED";
        case EventType::INCIDENT_STATE_CHANGE:   return "INCIDENT_STATE_CHANGE";
        case EventType::CONTAINMENT_ACTION:      return "CONTAINMENT_ACTION";
        default:                                 return "UNKNOWN";
    }
}

} // namespace cortex
