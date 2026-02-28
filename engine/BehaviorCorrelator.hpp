#pragma once

#include "core/EventBus.hpp"
#include "engine/RiskScorer.hpp"
#include <string>
#include <vector>
#include <deque>
#include <unordered_map>
#include <shared_mutex>
#include <atomic>

namespace cortex {

struct BehaviorPattern {
    std::string name;
    std::vector<EventType> sequence; // Ordered event types
    uint32_t time_window_seconds;
    uint32_t bonus_score;

    BehaviorPattern(const std::string& n, const std::vector<EventType>& seq,
                   uint32_t window, uint32_t score)
        : name(n), sequence(seq), time_window_seconds(window), bonus_score(score) {}
};

struct ProcessTimeline {
    uint32_t pid;
    std::deque<Event> events; // Ring buffer (60s window)
    uint64_t last_cleanup_time;

    ProcessTimeline() : pid(0), last_cleanup_time(0) {}
    ProcessTimeline(uint32_t p) : pid(p), last_cleanup_time(0) {}
};

class BehaviorCorrelator {
public:
    BehaviorCorrelator();
    ~BehaviorCorrelator();

    void Initialize(RiskScorer* risk_scorer);
    void Start();
    void Stop();

    size_t GetTimelineCount() const;
    size_t GetPatternCount() const;

private:
    void OnEvent(const Event& event);
    void AddEventToTimeline(uint32_t pid, const Event& event);
    void CleanupOldEvents(ProcessTimeline& timeline, uint64_t current_time);
    void CleanupTerminatedProcesses();

    // Pattern detection methods
    bool DetectPattern(const BehaviorPattern& pattern, const ProcessTimeline& timeline);
    bool DetectDropperPattern(const ProcessTimeline& timeline);
    bool DetectPersistencePattern(const ProcessTimeline& timeline);
    bool DetectLateralMovementPattern(const ProcessTimeline& timeline);

    // Helper methods
    uint64_t GetCurrentTimestamp() const;
    void EmitPatternDetection(uint32_t pid, const std::string& pattern_name,
                             const std::string& description, uint32_t bonus_score);

    std::unordered_map<uint32_t, ProcessTimeline> process_timelines_;
    std::vector<BehaviorPattern> patterns_;
    RiskScorer* risk_scorer_{nullptr};

    mutable std::shared_mutex mutex_;
    std::atomic<bool> running_{false};
    std::vector<SubscriptionId> subscription_ids_;

    static constexpr uint32_t TIMELINE_WINDOW_SECONDS = 60;
    static constexpr uint32_t DROPPER_WINDOW_SECONDS = 30;
    static constexpr uint32_t PERSISTENCE_WINDOW_SECONDS = 60;
    static constexpr uint32_t LATERAL_WINDOW_SECONDS = 10;
};

} // namespace cortex
