#include "response/IncidentManager.hpp"
#include "core/Logger.hpp"
#include <nlohmann/json.hpp>
#include <openssl/rand.h>
#include <filesystem>
#include <fstream>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <cstdio>

namespace cortex {

IncidentManager::IncidentManager() = default;

IncidentManager::~IncidentManager() {
    Stop();
}

void IncidentManager::Initialize(RiskScorer* risk_scorer, const std::string& incidents_dir) {
    risk_scorer_ = risk_scorer;
    incidents_dir_ = incidents_dir;

    try {
        std::filesystem::create_directories(incidents_dir_);
        LOG_INFO("IncidentManager initialized (incidents_dir={})", incidents_dir_);
    } catch (const std::exception& ex) {
        LOG_ERROR("Failed to create incidents directory: {}", ex.what());
    }
}

void IncidentManager::Start() {
    if (running_) {
        LOG_WARN("IncidentManager already running");
        return;
    }

    risk_sub_id_ = EventBus::Instance().Subscribe(
        EventType::RISK_THRESHOLD_EXCEEDED,
        [this](const Event& event) { OnRiskThresholdExceeded(event); }
    );

    containment_sub_id_ = EventBus::Instance().Subscribe(
        EventType::CONTAINMENT_ACTION,
        [this](const Event& event) { OnContainmentAction(event); }
    );

    running_ = true;
    LOG_INFO("IncidentManager started");
}

void IncidentManager::Stop() {
    if (!running_) {
        return;
    }

    if (risk_sub_id_ != 0) {
        EventBus::Instance().Unsubscribe(risk_sub_id_);
        risk_sub_id_ = 0;
    }

    if (containment_sub_id_ != 0) {
        EventBus::Instance().Unsubscribe(containment_sub_id_);
        containment_sub_id_ = 0;
    }

    running_ = false;
    LOG_INFO("IncidentManager stopped");
}

// --- Query API ---

std::vector<Incident> IncidentManager::ListIncidents() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Incident> result;
    result.reserve(incidents_.size());
    for (const auto& [uuid, incident] : incidents_) {
        result.push_back(incident);
    }
    return result;
}

std::optional<Incident> IncidentManager::GetIncident(const std::string& uuid) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = incidents_.find(uuid);
    if (it != incidents_.end()) {
        return it->second;
    }
    return std::nullopt;
}

size_t IncidentManager::GetActiveIncidentCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t count = 0;
    for (const auto& [uuid, incident] : incidents_) {
        if (incident.state != IncidentState::CLOSED) {
            ++count;
        }
    }
    return count;
}

size_t IncidentManager::GetTotalIncidentCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return incidents_.size();
}

// --- Mutation API ---

bool IncidentManager::ContainIncident(const std::string& uuid) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = incidents_.find(uuid);
    if (it == incidents_.end()) {
        LOG_WARN("ContainIncident: incident {} not found", uuid);
        return false;
    }
    return TransitionState(it->second, IncidentState::CONTAINED, "Manual containment via CLI");
}

bool IncidentManager::CloseIncident(const std::string& uuid) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = incidents_.find(uuid);
    if (it == incidents_.end()) {
        LOG_WARN("CloseIncident: incident {} not found", uuid);
        return false;
    }
    return TransitionState(it->second, IncidentState::CLOSED, "Manual close via CLI");
}

bool IncidentManager::EscalateIncident(const std::string& uuid) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = incidents_.find(uuid);
    if (it == incidents_.end()) {
        LOG_WARN("EscalateIncident: incident {} not found", uuid);
        return false;
    }
    return TransitionState(it->second, IncidentState::ESCALATED, "Manual escalation via CLI");
}

bool IncidentManager::RevertIncident(const std::string& uuid) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = incidents_.find(uuid);
    if (it == incidents_.end()) {
        LOG_WARN("RevertIncident: incident {} not found", uuid);
        return false;
    }

    LOG_WARN("RevertIncident: revert actions not yet implemented for incident {}", uuid);
    // Future: undo containment actions (unblock IPs, restore quarantined files, resume processes)
    return false;
}

// --- EventBus Handlers ---

void IncidentManager::OnRiskThresholdExceeded(const Event& event) {
    std::lock_guard<std::mutex> lock(mutex_);

    Incident& incident = FindOrCreateIncident(event.pid, event.process_name);

    // Append the event
    incident.associated_events.push_back(event);
    incident.updated_at = GetCurrentTimestamp();

    // Snapshot the current risk score
    if (risk_scorer_ && event.pid > 0) {
        auto risk = risk_scorer_->GetProcessRiskScore(event.pid);
        RiskScoreSnapshot snapshot;
        snapshot.score = risk.score;
        snapshot.level = risk.level;
        snapshot.timestamp = GetCurrentTimestamp();
        incident.risk_timeline.push_back(snapshot);
    }

    // Determine state transition based on risk level
    auto level_it = event.metadata.find("risk_level");
    if (level_it != event.metadata.end()) {
        const std::string& risk_level = level_it->second;

        if (risk_level == "CRITICAL") {
            if (incident.state == IncidentState::ACTIVE) {
                TransitionState(incident, IncidentState::ESCALATED, "Risk level reached CRITICAL");
            } else if (incident.state == IncidentState::NEW || incident.state == IncidentState::INVESTIGATING) {
                // Fast-track: NEW/INVESTIGATING -> ACTIVE -> ESCALATED
                if (incident.state == IncidentState::NEW) {
                    TransitionState(incident, IncidentState::INVESTIGATING, "Initial risk threshold crossing");
                }
                TransitionState(incident, IncidentState::ACTIVE, "Risk level reached HIGH+");
                TransitionState(incident, IncidentState::ESCALATED, "Risk level reached CRITICAL");
            }
        } else if (risk_level == "HIGH") {
            if (incident.state == IncidentState::NEW) {
                TransitionState(incident, IncidentState::INVESTIGATING, "Initial risk threshold crossing");
                TransitionState(incident, IncidentState::ACTIVE, "Risk level reached HIGH");
            } else if (incident.state == IncidentState::INVESTIGATING) {
                TransitionState(incident, IncidentState::ACTIVE, "Risk level reached HIGH");
            }
        } else if (risk_level == "MEDIUM") {
            if (incident.state == IncidentState::NEW) {
                TransitionState(incident, IncidentState::INVESTIGATING, "Risk level reached MEDIUM");
            }
        }
    }

    SerializeIncident(incident);
}

void IncidentManager::OnContainmentAction(const Event& event) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string uuid = FindIncidentByPid(event.pid);
    if (uuid.empty()) {
        LOG_DEBUG("ContainmentAction for PID {} has no associated incident", event.pid);
        return;
    }

    auto it = incidents_.find(uuid);
    if (it == incidents_.end()) {
        return;
    }

    Incident& incident = it->second;

    // Record the containment action
    ContainmentRecord record;
    auto action_it = event.metadata.find("action");
    record.action = (action_it != event.metadata.end()) ? action_it->second : "unknown";

    auto reason_it = event.metadata.find("reason");
    record.details = (reason_it != event.metadata.end()) ? reason_it->second : "";

    record.success = true;
    record.timestamp = GetCurrentTimestamp();
    incident.containment_actions.push_back(record);
    incident.updated_at = GetCurrentTimestamp();

    // Transition to CONTAINED if currently ACTIVE or ESCALATED
    if (incident.state == IncidentState::ACTIVE || incident.state == IncidentState::ESCALATED) {
        TransitionState(incident, IncidentState::CONTAINED, "Containment action: " + record.action);
    }

    SerializeIncident(incident);
}

// --- State Machine ---

bool IncidentManager::TransitionState(Incident& incident, IncidentState new_state, const std::string& reason) {
    if (!IsValidTransition(incident.state, new_state)) {
        LOG_WARN("Invalid state transition for incident {}: {} -> {}",
                 incident.uuid,
                 IncidentStateToString(incident.state),
                 IncidentStateToString(new_state));
        return false;
    }

    StateTransition transition;
    transition.from_state = incident.state;
    transition.to_state = new_state;
    transition.timestamp = GetCurrentTimestamp();
    transition.reason = reason;

    incident.state_history.push_back(transition);
    incident.state = new_state;
    incident.updated_at = transition.timestamp;

    LOG_INFO("Incident {} state: {} -> {} (reason: {})",
             incident.uuid,
             IncidentStateToString(transition.from_state),
             IncidentStateToString(new_state),
             reason);

    // Emit state change event
    Event state_event(EventType::INCIDENT_STATE_CHANGE, incident.pid, "IncidentManager");
    state_event.metadata["incident_uuid"] = incident.uuid;
    state_event.metadata["from_state"] = IncidentStateToString(transition.from_state);
    state_event.metadata["to_state"] = IncidentStateToString(new_state);
    state_event.metadata["reason"] = reason;
    EventBus::Instance().PublishAsync(state_event);

    return true;
}

bool IncidentManager::IsValidTransition(IncidentState from, IncidentState to) const {
    switch (from) {
        case IncidentState::NEW:
            return to == IncidentState::INVESTIGATING;
        case IncidentState::INVESTIGATING:
            return to == IncidentState::ACTIVE || to == IncidentState::CLOSED;
        case IncidentState::ACTIVE:
            return to == IncidentState::CONTAINED ||
                   to == IncidentState::ESCALATED ||
                   to == IncidentState::CLOSED;
        case IncidentState::ESCALATED:
            return to == IncidentState::CONTAINED || to == IncidentState::CLOSED;
        case IncidentState::CONTAINED:
            return to == IncidentState::CLOSED;
        case IncidentState::CLOSED:
            return false;
        default:
            return false;
    }
}

// --- Incident Lookup/Creation ---

Incident& IncidentManager::FindOrCreateIncident(uint32_t pid, const std::string& process_name) {
    // Check if an active incident already exists for this PID
    auto pid_it = pid_to_incident_.find(pid);
    if (pid_it != pid_to_incident_.end()) {
        auto inc_it = incidents_.find(pid_it->second);
        if (inc_it != incidents_.end() && inc_it->second.state != IncidentState::CLOSED) {
            return inc_it->second;
        }
    }

    // Create new incident
    Incident incident;
    incident.uuid = GenerateUUID();
    incident.pid = pid;
    incident.process_name = process_name;
    incident.state = IncidentState::NEW;
    incident.created_at = GetCurrentTimestamp();
    incident.updated_at = incident.created_at;

    std::string uuid = incident.uuid;
    incidents_[uuid] = std::move(incident);
    pid_to_incident_[pid] = uuid;

    LOG_INFO("Created new incident {} for PID {} ({})", uuid, pid, process_name);

    return incidents_[uuid];
}

std::string IncidentManager::FindIncidentByPid(uint32_t pid) const {
    auto it = pid_to_incident_.find(pid);
    if (it != pid_to_incident_.end()) {
        return it->second;
    }
    return "";
}

// --- Persistence ---

void IncidentManager::SerializeIncident(const Incident& incident) {
    try {
        std::filesystem::create_directories(incidents_dir_);

        std::string filepath = GetIncidentFilePath(incident);

        nlohmann::json j;
        j["uuid"] = incident.uuid;
        j["pid"] = incident.pid;
        j["process_name"] = incident.process_name;
        j["state"] = IncidentStateToString(incident.state);
        j["created_at"] = TimestampToISO8601(incident.created_at);
        j["updated_at"] = TimestampToISO8601(incident.updated_at);

        // Associated events
        nlohmann::json events_json = nlohmann::json::array();
        for (const auto& evt : incident.associated_events) {
            nlohmann::json ej;
            ej["event_type"] = EventTypeToString(evt.type);
            ej["timestamp"] = TimestampToISO8601(evt.timestamp);
            ej["pid"] = evt.pid;
            ej["process_name"] = evt.process_name;

            nlohmann::json meta;
            for (const auto& [key, value] : evt.metadata) {
                meta[key] = value;
            }
            ej["metadata"] = meta;
            events_json.push_back(ej);
        }
        j["associated_events"] = events_json;

        // Risk timeline
        nlohmann::json risk_json = nlohmann::json::array();
        for (const auto& snap : incident.risk_timeline) {
            nlohmann::json rj;
            rj["score"] = snap.score;
            rj["level"] = (snap.level == RiskLevel::LOW) ? "LOW" :
                          (snap.level == RiskLevel::MEDIUM) ? "MEDIUM" :
                          (snap.level == RiskLevel::HIGH) ? "HIGH" : "CRITICAL";
            rj["timestamp"] = TimestampToISO8601(snap.timestamp);
            risk_json.push_back(rj);
        }
        j["risk_timeline"] = risk_json;

        // Containment actions
        nlohmann::json actions_json = nlohmann::json::array();
        for (const auto& rec : incident.containment_actions) {
            nlohmann::json aj;
            aj["action"] = rec.action;
            aj["success"] = rec.success;
            aj["timestamp"] = TimestampToISO8601(rec.timestamp);
            aj["details"] = rec.details;
            actions_json.push_back(aj);
        }
        j["containment_actions"] = actions_json;

        // State history
        nlohmann::json history_json = nlohmann::json::array();
        for (const auto& trans : incident.state_history) {
            nlohmann::json hj;
            hj["from"] = IncidentStateToString(trans.from_state);
            hj["to"] = IncidentStateToString(trans.to_state);
            hj["timestamp"] = TimestampToISO8601(trans.timestamp);
            hj["reason"] = trans.reason;
            history_json.push_back(hj);
        }
        j["state_history"] = history_json;

        std::ofstream ofs(filepath);
        if (ofs.is_open()) {
            ofs << j.dump(2);
            LOG_DEBUG("Serialized incident {} to {}", incident.uuid, filepath);
        } else {
            LOG_ERROR("Failed to open {} for writing", filepath);
        }
    } catch (const std::exception& ex) {
        LOG_ERROR("Failed to serialize incident {}: {}", incident.uuid, ex.what());
    }
}

std::string IncidentManager::GetIncidentFilePath(const Incident& incident) const {
    std::string date_str = TimestampToDateString(incident.created_at);
    return incidents_dir_ + "/" + date_str + "_" + incident.uuid + ".json";
}

// --- Helpers ---

std::string IncidentManager::GenerateUUID() {
    unsigned char bytes[16];
    RAND_bytes(bytes, 16);

    // Set version 4 bits
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    // Set variant bits
    bytes[8] = (bytes[8] & 0x3F) | 0x80;

    char uuid_str[37];
    std::snprintf(uuid_str, sizeof(uuid_str),
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);

    return std::string(uuid_str);
}

uint64_t IncidentManager::GetCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    return static_cast<uint64_t>(ms.count());
}

std::string IncidentManager::TimestampToISO8601(uint64_t ms_epoch) {
    auto seconds = static_cast<time_t>(ms_epoch / 1000);
    auto millis = ms_epoch % 1000;

    std::tm tm_buf;
    gmtime_s(&tm_buf, &seconds);

    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
        tm_buf.tm_year + 1900, tm_buf.tm_mon + 1, tm_buf.tm_mday,
        tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec,
        static_cast<int>(millis));

    return std::string(buf);
}

std::string IncidentManager::TimestampToDateString(uint64_t ms_epoch) {
    auto seconds = static_cast<time_t>(ms_epoch / 1000);

    std::tm tm_buf;
    gmtime_s(&tm_buf, &seconds);

    char buf[12];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d",
        tm_buf.tm_year + 1900, tm_buf.tm_mon + 1, tm_buf.tm_mday);

    return std::string(buf);
}

} // namespace cortex
