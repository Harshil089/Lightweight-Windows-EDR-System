#pragma once

#include "core/EventBus.hpp"
#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <cstdint>

namespace cortex {

class DatabaseManager;

struct AuditEntry {
    uint64_t sequence_id;
    uint64_t timestamp;
    std::string action;
    std::string actor;
    std::string target;
    std::string details;
    std::string prev_hash;
    std::string entry_hash;

    AuditEntry()
        : sequence_id(0), timestamp(0) {}
};

class AuditLogger {
public:
    AuditLogger();
    ~AuditLogger();

    void Initialize(DatabaseManager* db, const std::string& hmac_key);
    void Start();
    void Stop();

    // Log an auditable action
    void LogAction(const std::string& action,
                   const std::string& actor,
                   const std::string& target,
                   const std::string& details = "");

    // Verify the integrity of the entire audit chain
    bool VerifyIntegrity();

    // Export audit log entries within a time range
    bool ExportAuditLog(uint64_t start_time, uint64_t end_time,
                        const std::string& output_path);

    // Query
    std::vector<AuditEntry> QueryEntries(uint64_t start_time = 0,
                                          uint64_t end_time = 0,
                                          int limit = 1000);
    size_t GetEntryCount() const;

private:
    // EventBus handlers
    void OnRiskThresholdExceeded(const Event& event);
    void OnIncidentStateChange(const Event& event);
    void OnContainmentAction(const Event& event);

    // HMAC computation
    std::string ComputeHMAC(const std::string& data) const;
    std::string ComputeEntryHash(const AuditEntry& entry) const;
    std::string ComputeEntryHashFromStrings(
        const std::string& timestamp_iso, const std::string& action,
        const std::string& actor, const std::string& target,
        const std::string& details, const std::string& prev_hash) const;

    // Helpers
    static uint64_t GetCurrentTimestamp();
    static std::string TimestampToISO8601(uint64_t ms_epoch);

    DatabaseManager* database_{nullptr};
    std::string hmac_key_;
    std::string last_hash_;

    mutable std::mutex mutex_;
    std::atomic<bool> running_{false};
    std::vector<SubscriptionId> subscription_ids_;
    std::atomic<size_t> entry_count_{0};
};

} // namespace cortex
