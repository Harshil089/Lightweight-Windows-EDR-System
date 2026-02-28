#pragma once

#include "core/EventBus.hpp"
#include "response/IncidentManager.hpp"
#include <sqlite3.h>
#include <string>
#include <vector>
#include <optional>
#include <mutex>
#include <cstdint>

namespace cortex {

class DatabaseManager {
public:
    DatabaseManager();
    ~DatabaseManager();

    bool Initialize(const std::string& db_path = "data/cortex.db");
    void Shutdown();

    // Events
    void InsertEvent(const Event& event, uint32_t risk_score);
    std::vector<std::string> QueryEventsJson(const std::string& where_clause = "",
                                              int limit = 100, int offset = 0);
    size_t GetEventCount();

    // Incidents
    void UpsertIncident(const Incident& incident);
    std::vector<Incident> LoadAllIncidents();
    std::optional<Incident> LoadIncident(const std::string& uuid);

    // Status
    struct StatusSnapshot {
        size_t active_incident_count;
        size_t total_event_count;
        uint32_t highest_risk_score;
    };
    StatusSnapshot GetStatusSnapshot();

    // Audit Log
    struct AuditEntryRow {
        uint64_t sequence_id;
        std::string timestamp;
        std::string action;
        std::string actor;
        std::string target;
        std::string details;
        std::string prev_hash;
        std::string entry_hash;
    };

    void InsertAuditEntry(uint64_t timestamp,
                          const std::string& action,
                          const std::string& actor,
                          const std::string& target,
                          const std::string& details,
                          const std::string& prev_hash,
                          const std::string& entry_hash);
    std::vector<AuditEntryRow> QueryAuditEntriesRaw(const std::string& where_clause = "",
                                                      int limit = 0, int offset = 0,
                                                      bool desc = false);
    size_t GetAuditEntryCount();

private:
    void CreateSchema();
    void PrepareStatements();
    void FinalizeStatements();

    static std::string TimestampToISO8601(uint64_t ms_epoch);
    static std::string EventTypeToStr(EventType type);

    sqlite3* db_{nullptr};
    std::mutex mutex_;

    // Prepared statements
    sqlite3_stmt* stmt_insert_event_{nullptr};
    sqlite3_stmt* stmt_upsert_incident_{nullptr};
    sqlite3_stmt* stmt_load_incident_{nullptr};
    sqlite3_stmt* stmt_load_all_incidents_{nullptr};
    sqlite3_stmt* stmt_event_count_{nullptr};
    sqlite3_stmt* stmt_highest_risk_{nullptr};
    sqlite3_stmt* stmt_active_incident_count_{nullptr};

    // Audit log statements
    sqlite3_stmt* stmt_insert_audit_{nullptr};
    sqlite3_stmt* stmt_audit_count_{nullptr};
};

} // namespace cortex
