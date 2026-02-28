#include "persistence/DatabaseManager.hpp"
#include "core/Logger.hpp"
#include <nlohmann/json.hpp>
#include <filesystem>
#include <chrono>
#include <cstdio>

namespace cortex {

DatabaseManager::DatabaseManager() = default;

DatabaseManager::~DatabaseManager() {
    Shutdown();
}

bool DatabaseManager::Initialize(const std::string& db_path) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Create parent directory if needed (skip for :memory:)
    if (db_path != ":memory:") {
        try {
            std::filesystem::path p(db_path);
            if (p.has_parent_path() && !p.parent_path().empty()) {
                std::filesystem::create_directories(p.parent_path());
            }
        } catch (const std::exception& ex) {
            LOG_ERROR("DatabaseManager: Failed to create directory for {}: {}", db_path, ex.what());
            return false;
        }
    }

    int rc = sqlite3_open(db_path.c_str(), &db_);
    if (rc != SQLITE_OK) {
        LOG_ERROR("DatabaseManager: Failed to open database {}: {}", db_path, sqlite3_errmsg(db_));
        db_ = nullptr;
        return false;
    }

    // Enable WAL mode for better concurrent performance
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA synchronous=NORMAL;", nullptr, nullptr, nullptr);

    CreateSchema();
    PrepareStatements();

    LOG_INFO("DatabaseManager initialized (db_path={})", db_path);
    return true;
}

void DatabaseManager::Shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    FinalizeStatements();

    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
        LOG_INFO("DatabaseManager shutdown");
    }
}

void DatabaseManager::CreateSchema() {
    const char* schema = R"SQL(
        CREATE TABLE IF NOT EXISTS events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            event_type  TEXT    NOT NULL,
            pid         INTEGER NOT NULL,
            process_name TEXT   NOT NULL,
            risk_score  INTEGER DEFAULT 0,
            details     TEXT,
            created_at  TEXT    DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
        CREATE INDEX IF NOT EXISTS idx_events_pid ON events(pid);
        CREATE INDEX IF NOT EXISTS idx_events_risk ON events(risk_score);

        CREATE TABLE IF NOT EXISTS incidents (
            uuid            TEXT PRIMARY KEY,
            pid             INTEGER NOT NULL,
            process_name    TEXT    NOT NULL,
            state           TEXT    NOT NULL,
            created_at      TEXT    NOT NULL,
            updated_at      TEXT    NOT NULL,
            associated_events TEXT,
            risk_timeline     TEXT,
            containment_actions TEXT,
            state_history     TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_incidents_state ON incidents(state);
        CREATE INDEX IF NOT EXISTS idx_incidents_pid ON incidents(pid);

        CREATE TABLE IF NOT EXISTS audit_log (
            sequence_id     INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT    NOT NULL,
            action          TEXT    NOT NULL,
            actor           TEXT    NOT NULL,
            target          TEXT    NOT NULL,
            details         TEXT,
            prev_hash       TEXT    NOT NULL,
            entry_hash      TEXT    NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
        CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
    )SQL";

    char* err_msg = nullptr;
    int rc = sqlite3_exec(db_, schema, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        LOG_ERROR("DatabaseManager: Failed to create schema: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
    }
}

void DatabaseManager::PrepareStatements() {
    sqlite3_prepare_v2(db_,
        "INSERT INTO events (timestamp, event_type, pid, process_name, risk_score, details) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        -1, &stmt_insert_event_, nullptr);

    sqlite3_prepare_v2(db_,
        "INSERT OR REPLACE INTO incidents "
        "(uuid, pid, process_name, state, created_at, updated_at, "
        "associated_events, risk_timeline, containment_actions, state_history) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        -1, &stmt_upsert_incident_, nullptr);

    sqlite3_prepare_v2(db_,
        "SELECT uuid, pid, process_name, state, created_at, updated_at, "
        "associated_events, risk_timeline, containment_actions, state_history "
        "FROM incidents WHERE uuid = ?",
        -1, &stmt_load_incident_, nullptr);

    sqlite3_prepare_v2(db_,
        "SELECT uuid, pid, process_name, state, created_at, updated_at, "
        "associated_events, risk_timeline, containment_actions, state_history "
        "FROM incidents",
        -1, &stmt_load_all_incidents_, nullptr);

    sqlite3_prepare_v2(db_,
        "SELECT COUNT(*) FROM events",
        -1, &stmt_event_count_, nullptr);

    sqlite3_prepare_v2(db_,
        "SELECT COALESCE(MAX(risk_score), 0) FROM events",
        -1, &stmt_highest_risk_, nullptr);

    sqlite3_prepare_v2(db_,
        "SELECT COUNT(*) FROM incidents WHERE state != 'CLOSED'",
        -1, &stmt_active_incident_count_, nullptr);

    // Audit log statements
    sqlite3_prepare_v2(db_,
        "INSERT INTO audit_log (timestamp, action, actor, target, details, prev_hash, entry_hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        -1, &stmt_insert_audit_, nullptr);

    sqlite3_prepare_v2(db_,
        "SELECT COUNT(*) FROM audit_log",
        -1, &stmt_audit_count_, nullptr);
}

void DatabaseManager::FinalizeStatements() {
    auto finalize = [](sqlite3_stmt*& stmt) {
        if (stmt) { sqlite3_finalize(stmt); stmt = nullptr; }
    };
    finalize(stmt_insert_event_);
    finalize(stmt_upsert_incident_);
    finalize(stmt_load_incident_);
    finalize(stmt_load_all_incidents_);
    finalize(stmt_event_count_);
    finalize(stmt_highest_risk_);
    finalize(stmt_active_incident_count_);
    finalize(stmt_insert_audit_);
    finalize(stmt_audit_count_);
}

// --- Events ---

void DatabaseManager::InsertEvent(const Event& event, uint32_t risk_score) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!db_ || !stmt_insert_event_) return;

    std::string ts = TimestampToISO8601(event.timestamp);
    std::string type = EventTypeToStr(event.type);

    nlohmann::json details;
    for (const auto& [key, value] : event.metadata) {
        details[key] = value;
    }
    std::string details_str = details.dump();

    sqlite3_reset(stmt_insert_event_);
    sqlite3_bind_text(stmt_insert_event_, 1, ts.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt_insert_event_, 2, type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt_insert_event_, 3, static_cast<int>(event.pid));
    sqlite3_bind_text(stmt_insert_event_, 4, event.process_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt_insert_event_, 5, static_cast<int>(risk_score));
    sqlite3_bind_text(stmt_insert_event_, 6, details_str.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt_insert_event_);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("DatabaseManager: Failed to insert event: {}", sqlite3_errmsg(db_));
    }
}

std::vector<std::string> DatabaseManager::QueryEventsJson(const std::string& where_clause,
                                                           int limit, int offset) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> results;
    if (!db_) return results;

    std::string sql = "SELECT timestamp, event_type, pid, process_name, risk_score, details FROM events";
    if (!where_clause.empty()) {
        sql += " WHERE " + where_clause;
    }
    sql += " ORDER BY id DESC LIMIT " + std::to_string(limit) + " OFFSET " + std::to_string(offset);

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        LOG_ERROR("DatabaseManager: Query prepare failed: {}", sqlite3_errmsg(db_));
        return results;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        nlohmann::json j;
        j["timestamp"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        j["event_type"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        j["pid"] = sqlite3_column_int(stmt, 2);
        j["process_name"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        j["risk_score"] = sqlite3_column_int(stmt, 4);

        const char* details = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        if (details) {
            try {
                j["details"] = nlohmann::json::parse(details);
            } catch (...) {
                j["details"] = details;
            }
        }
        results.push_back(j.dump());
    }

    sqlite3_finalize(stmt);
    return results;
}

size_t DatabaseManager::GetEventCount() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!db_ || !stmt_event_count_) return 0;

    sqlite3_reset(stmt_event_count_);
    if (sqlite3_step(stmt_event_count_) == SQLITE_ROW) {
        return static_cast<size_t>(sqlite3_column_int64(stmt_event_count_, 0));
    }
    return 0;
}

// --- Incidents ---

void DatabaseManager::UpsertIncident(const Incident& incident) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!db_ || !stmt_upsert_incident_) return;

    // Serialize sub-arrays as JSON
    nlohmann::json events_json = nlohmann::json::array();
    for (const auto& evt : incident.associated_events) {
        nlohmann::json ej;
        ej["event_type"] = EventTypeToStr(evt.type);
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

    nlohmann::json actions_json = nlohmann::json::array();
    for (const auto& rec : incident.containment_actions) {
        nlohmann::json aj;
        aj["action"] = rec.action;
        aj["success"] = rec.success;
        aj["timestamp"] = TimestampToISO8601(rec.timestamp);
        aj["details"] = rec.details;
        actions_json.push_back(aj);
    }

    nlohmann::json history_json = nlohmann::json::array();
    for (const auto& trans : incident.state_history) {
        nlohmann::json hj;
        hj["from"] = IncidentStateToString(trans.from_state);
        hj["to"] = IncidentStateToString(trans.to_state);
        hj["timestamp"] = TimestampToISO8601(trans.timestamp);
        hj["reason"] = trans.reason;
        history_json.push_back(hj);
    }

    std::string state_str = IncidentStateToString(incident.state);
    std::string created_str = TimestampToISO8601(incident.created_at);
    std::string updated_str = TimestampToISO8601(incident.updated_at);
    std::string events_str = events_json.dump();
    std::string risk_str = risk_json.dump();
    std::string actions_str = actions_json.dump();
    std::string history_str = history_json.dump();

    sqlite3_reset(stmt_upsert_incident_);
    sqlite3_bind_text(stmt_upsert_incident_, 1, incident.uuid.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt_upsert_incident_, 2, static_cast<int>(incident.pid));
    sqlite3_bind_text(stmt_upsert_incident_, 3, incident.process_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt_upsert_incident_, 4, state_str.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt_upsert_incident_, 5, created_str.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt_upsert_incident_, 6, updated_str.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt_upsert_incident_, 7, events_str.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt_upsert_incident_, 8, risk_str.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt_upsert_incident_, 9, actions_str.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt_upsert_incident_, 10, history_str.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt_upsert_incident_);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("DatabaseManager: Failed to upsert incident {}: {}", incident.uuid, sqlite3_errmsg(db_));
    }
}

static IncidentState StringToIncidentState(const std::string& s) {
    if (s == "NEW") return IncidentState::NEW;
    if (s == "INVESTIGATING") return IncidentState::INVESTIGATING;
    if (s == "ACTIVE") return IncidentState::ACTIVE;
    if (s == "CONTAINED") return IncidentState::CONTAINED;
    if (s == "CLOSED") return IncidentState::CLOSED;
    if (s == "ESCALATED") return IncidentState::ESCALATED;
    return IncidentState::NEW;
}

static RiskLevel StringToRiskLevel(const std::string& s) {
    if (s == "MEDIUM") return RiskLevel::MEDIUM;
    if (s == "HIGH") return RiskLevel::HIGH;
    if (s == "CRITICAL") return RiskLevel::CRITICAL;
    return RiskLevel::LOW;
}

static EventType StringToEventType(const std::string& s) {
    if (s == "PROCESS_CREATE") return EventType::PROCESS_CREATE;
    if (s == "PROCESS_TERMINATE") return EventType::PROCESS_TERMINATE;
    if (s == "FILE_CREATE") return EventType::FILE_CREATE;
    if (s == "FILE_MODIFY") return EventType::FILE_MODIFY;
    if (s == "FILE_DELETE") return EventType::FILE_DELETE;
    if (s == "NETWORK_CONNECT") return EventType::NETWORK_CONNECT;
    if (s == "NETWORK_DISCONNECT") return EventType::NETWORK_DISCONNECT;
    if (s == "REGISTRY_WRITE") return EventType::REGISTRY_WRITE;
    if (s == "RISK_THRESHOLD_EXCEEDED") return EventType::RISK_THRESHOLD_EXCEEDED;
    if (s == "INCIDENT_STATE_CHANGE") return EventType::INCIDENT_STATE_CHANGE;
    if (s == "CONTAINMENT_ACTION") return EventType::CONTAINMENT_ACTION;
    return EventType::PROCESS_CREATE;
}

static Incident DeserializeIncidentFromRow(sqlite3_stmt* stmt) {
    Incident incident;
    incident.uuid = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
    incident.pid = static_cast<uint32_t>(sqlite3_column_int(stmt, 1));
    incident.process_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
    incident.state = StringToIncidentState(
        reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3)));

    // Parse timestamps back to epoch ms (simplified — store as raw ms in the future)
    // For now, created_at and updated_at are stored as ISO8601 and we need epoch ms
    // We'll store them in a round-trip friendly way
    incident.created_at = 0;
    incident.updated_at = 0;

    // Parse associated_events
    const char* events_str = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
    if (events_str) {
        try {
            auto events_json = nlohmann::json::parse(events_str);
            for (const auto& ej : events_json) {
                Event evt(StringToEventType(ej.value("event_type", "PROCESS_CREATE")),
                          ej.value("pid", 0u),
                          ej.value("process_name", ""));
                if (ej.contains("metadata")) {
                    for (auto& [k, v] : ej["metadata"].items()) {
                        evt.metadata[k] = v.get<std::string>();
                    }
                }
                incident.associated_events.push_back(std::move(evt));
            }
        } catch (...) {}
    }

    // Parse risk_timeline
    const char* risk_str = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
    if (risk_str) {
        try {
            auto risk_json = nlohmann::json::parse(risk_str);
            for (const auto& rj : risk_json) {
                RiskScoreSnapshot snap;
                snap.score = rj.value("score", 0u);
                snap.level = StringToRiskLevel(rj.value("level", "LOW"));
                snap.timestamp = 0;
                incident.risk_timeline.push_back(snap);
            }
        } catch (...) {}
    }

    // Parse containment_actions
    const char* actions_str = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 8));
    if (actions_str) {
        try {
            auto actions_json = nlohmann::json::parse(actions_str);
            for (const auto& aj : actions_json) {
                ContainmentRecord rec;
                rec.action = aj.value("action", "");
                rec.success = aj.value("success", false);
                rec.timestamp = 0;
                rec.details = aj.value("details", "");
                incident.containment_actions.push_back(rec);
            }
        } catch (...) {}
    }

    // Parse state_history
    const char* history_str = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 9));
    if (history_str) {
        try {
            auto history_json = nlohmann::json::parse(history_str);
            for (const auto& hj : history_json) {
                StateTransition trans;
                trans.from_state = StringToIncidentState(hj.value("from", "NEW"));
                trans.to_state = StringToIncidentState(hj.value("to", "NEW"));
                trans.timestamp = 0;
                trans.reason = hj.value("reason", "");
                incident.state_history.push_back(trans);
            }
        } catch (...) {}
    }

    return incident;
}

std::vector<Incident> DatabaseManager::LoadAllIncidents() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Incident> results;
    if (!db_ || !stmt_load_all_incidents_) return results;

    sqlite3_reset(stmt_load_all_incidents_);
    while (sqlite3_step(stmt_load_all_incidents_) == SQLITE_ROW) {
        results.push_back(DeserializeIncidentFromRow(stmt_load_all_incidents_));
    }

    return results;
}

std::optional<Incident> DatabaseManager::LoadIncident(const std::string& uuid) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!db_ || !stmt_load_incident_) return std::nullopt;

    sqlite3_reset(stmt_load_incident_);
    sqlite3_bind_text(stmt_load_incident_, 1, uuid.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt_load_incident_) == SQLITE_ROW) {
        return DeserializeIncidentFromRow(stmt_load_incident_);
    }
    return std::nullopt;
}

DatabaseManager::StatusSnapshot DatabaseManager::GetStatusSnapshot() {
    std::lock_guard<std::mutex> lock(mutex_);
    StatusSnapshot snap{};
    if (!db_) return snap;

    // Event count
    sqlite3_reset(stmt_event_count_);
    if (sqlite3_step(stmt_event_count_) == SQLITE_ROW) {
        snap.total_event_count = static_cast<size_t>(sqlite3_column_int64(stmt_event_count_, 0));
    }

    // Highest risk score
    sqlite3_reset(stmt_highest_risk_);
    if (sqlite3_step(stmt_highest_risk_) == SQLITE_ROW) {
        snap.highest_risk_score = static_cast<uint32_t>(sqlite3_column_int(stmt_highest_risk_, 0));
    }

    // Active incident count
    sqlite3_reset(stmt_active_incident_count_);
    if (sqlite3_step(stmt_active_incident_count_) == SQLITE_ROW) {
        snap.active_incident_count = static_cast<size_t>(sqlite3_column_int64(stmt_active_incident_count_, 0));
    }

    return snap;
}

// --- Audit Log ---

void DatabaseManager::InsertAuditEntry(uint64_t timestamp,
                                         const std::string& action,
                                         const std::string& actor,
                                         const std::string& target,
                                         const std::string& details,
                                         const std::string& prev_hash,
                                         const std::string& entry_hash) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!db_ || !stmt_insert_audit_) return;

    std::string ts = TimestampToISO8601(timestamp);

    sqlite3_reset(stmt_insert_audit_);
    sqlite3_bind_text(stmt_insert_audit_, 1, ts.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt_insert_audit_, 2, action.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt_insert_audit_, 3, actor.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt_insert_audit_, 4, target.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt_insert_audit_, 5, details.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt_insert_audit_, 6, prev_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt_insert_audit_, 7, entry_hash.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt_insert_audit_);
    if (rc != SQLITE_DONE) {
        LOG_ERROR("DatabaseManager: Failed to insert audit entry: {}", sqlite3_errmsg(db_));
    }
}

std::vector<DatabaseManager::AuditEntryRow> DatabaseManager::QueryAuditEntriesRaw(
    const std::string& where_clause, int limit, int offset, bool desc) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<AuditEntryRow> results;
    if (!db_) return results;

    std::string sql = "SELECT sequence_id, timestamp, action, actor, target, details, prev_hash, entry_hash FROM audit_log";
    if (!where_clause.empty()) {
        sql += " WHERE " + where_clause;
    }
    sql += desc ? " ORDER BY sequence_id DESC" : " ORDER BY sequence_id ASC";
    if (limit > 0) {
        sql += " LIMIT " + std::to_string(limit) + " OFFSET " + std::to_string(offset);
    }

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        LOG_ERROR("DatabaseManager: Audit query prepare failed: {}", sqlite3_errmsg(db_));
        return results;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        AuditEntryRow row;
        row.sequence_id = static_cast<uint64_t>(sqlite3_column_int64(stmt, 0));
        row.timestamp = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        row.action = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        row.actor = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
        row.target = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        const char* det = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 5));
        row.details = det ? det : "";
        row.prev_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6));
        row.entry_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7));
        results.push_back(row);
    }

    sqlite3_finalize(stmt);
    return results;
}

size_t DatabaseManager::GetAuditEntryCount() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!db_ || !stmt_audit_count_) return 0;

    sqlite3_reset(stmt_audit_count_);
    if (sqlite3_step(stmt_audit_count_) == SQLITE_ROW) {
        return static_cast<size_t>(sqlite3_column_int64(stmt_audit_count_, 0));
    }
    return 0;
}

// --- Helpers ---

std::string DatabaseManager::TimestampToISO8601(uint64_t ms_epoch) {
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

std::string DatabaseManager::EventTypeToStr(EventType type) {
    return EventTypeToString(type);
}

} // namespace cortex
