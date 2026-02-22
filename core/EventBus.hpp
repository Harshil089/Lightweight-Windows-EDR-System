#pragma once

#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

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

    size_t GetSubscriberCount(EventType type) const;
    void Clear();

private:
    EventBus() = default;

    mutable std::mutex mutex_;
    std::unordered_map<EventType, std::vector<std::pair<SubscriptionId, EventHandler>>> subscribers_;
    SubscriptionId next_id_ = 1;
};

} // namespace cortex
