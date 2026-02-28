#pragma once

#include "core/EventBus.hpp"
#include "engine/RiskScorer.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <mutex>
#include <atomic>

namespace cortex {

enum class IncidentState {
    NEW,
    INVESTIGATING,
    ACTIVE,
    CONTAINED,
    CLOSED,
    ESCALATED
};

inline std::string IncidentStateToString(IncidentState state) {
    switch (state) {
        case IncidentState::NEW:           return "NEW";
        case IncidentState::INVESTIGATING: return "INVESTIGATING";
        case IncidentState::ACTIVE:        return "ACTIVE";
        case IncidentState::CONTAINED:     return "CONTAINED";
        case IncidentState::CLOSED:        return "CLOSED";
        case IncidentState::ESCALATED:     return "ESCALATED";
        default:                           return "UNKNOWN";
    }
}

struct StateTransition {
    IncidentState from_state;
    IncidentState to_state;
    uint64_t timestamp;
    std::string reason;
};

struct ContainmentRecord {
    std::string action;
    bool success;
    uint64_t timestamp;
    std::string details;
};

struct RiskScoreSnapshot {
    uint32_t score;
    RiskLevel level;
    uint64_t timestamp;
};

struct Incident {
    std::string uuid;
    uint32_t pid;
    std::string process_name;
    IncidentState state;
    std::vector<Event> associated_events;
    std::vector<RiskScoreSnapshot> risk_timeline;
    std::vector<ContainmentRecord> containment_actions;
    std::vector<StateTransition> state_history;
    uint64_t created_at;
    uint64_t updated_at;

    Incident()
        : pid(0), state(IncidentState::NEW), created_at(0), updated_at(0) {}
};

class IncidentManager {
public:
    IncidentManager();
    ~IncidentManager();

    void Initialize(RiskScorer* risk_scorer, const std::string& incidents_dir = "incidents");
    void Start();
    void Stop();

    // Query API
    std::vector<Incident> ListIncidents() const;
    std::optional<Incident> GetIncident(const std::string& uuid) const;
    size_t GetActiveIncidentCount() const;
    size_t GetTotalIncidentCount() const;

    // Mutation API (for CLI commands)
    bool ContainIncident(const std::string& uuid);
    bool CloseIncident(const std::string& uuid);
    bool EscalateIncident(const std::string& uuid);
    bool RevertIncident(const std::string& uuid);

private:
    // EventBus handlers
    void OnRiskThresholdExceeded(const Event& event);
    void OnContainmentAction(const Event& event);

    // State machine
    bool TransitionState(Incident& incident, IncidentState new_state, const std::string& reason);
    bool IsValidTransition(IncidentState from, IncidentState to) const;

    // Incident lookup/creation
    Incident& FindOrCreateIncident(uint32_t pid, const std::string& process_name);
    std::string FindIncidentByPid(uint32_t pid) const;

    // Persistence
    void SerializeIncident(const Incident& incident);
    std::string GetIncidentFilePath(const Incident& incident) const;

    // Helpers
    static std::string GenerateUUID();
    static uint64_t GetCurrentTimestamp();
    static std::string TimestampToISO8601(uint64_t ms_epoch);
    static std::string TimestampToDateString(uint64_t ms_epoch);

    // State
    std::unordered_map<std::string, Incident> incidents_;
    std::unordered_map<uint32_t, std::string> pid_to_incident_;
    RiskScorer* risk_scorer_{nullptr};
    std::string incidents_dir_;

    mutable std::mutex mutex_;
    std::atomic<bool> running_{false};
    SubscriptionId risk_sub_id_{0};
    SubscriptionId containment_sub_id_{0};
};

} // namespace cortex
