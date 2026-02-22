#include "core/EventBus.hpp"
#include <chrono>
#include <algorithm>

namespace cortex {

uint64_t Event::GetCurrentTimestamp() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

EventBus& EventBus::Instance() {
    static EventBus instance;
    return instance;
}

SubscriptionId EventBus::Subscribe(EventType type, EventHandler handler) {
    std::lock_guard<std::mutex> lock(mutex_);
    SubscriptionId id = next_id_++;
    subscribers_[type].emplace_back(id, std::move(handler));
    return id;
}

void EventBus::Unsubscribe(SubscriptionId id) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [type, handlers] : subscribers_) {
        handlers.erase(
            std::remove_if(handlers.begin(), handlers.end(),
                [id](const auto& pair) { return pair.first == id; }),
            handlers.end()
        );
    }
}

void EventBus::Publish(const Event& event) {
    std::vector<EventHandler> handlers_copy;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = subscribers_.find(event.type);
        if (it != subscribers_.end()) {
            handlers_copy.reserve(it->second.size());
            for (const auto& [id, handler] : it->second) {
                handlers_copy.push_back(handler);
            }
        }
    }

    for (const auto& handler : handlers_copy) {
        handler(event);
    }
}

void EventBus::PublishAsync(Event event) {
    std::thread([event = std::move(event)]() {
        EventBus::Instance().Publish(event);
    }).detach();
}

size_t EventBus::GetSubscriberCount(EventType type) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = subscribers_.find(type);
    return it != subscribers_.end() ? it->second.size() : 0;
}

void EventBus::Clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    subscribers_.clear();
}

} // namespace cortex
