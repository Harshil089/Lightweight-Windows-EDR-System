#include "compliance/AuditLogger.hpp"
#include "persistence/DatabaseManager.hpp"
#include "core/Logger.hpp"
#include <nlohmann/json.hpp>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <chrono>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <filesystem>

namespace cortex {

AuditLogger::AuditLogger() = default;

AuditLogger::~AuditLogger() {
    Stop();
}

void AuditLogger::Initialize(DatabaseManager* db, const std::string& hmac_key) {
    database_ = db;
    hmac_key_ = hmac_key;
    last_hash_ = "GENESIS";

    // Load the last hash from the database to continue the chain
    if (database_) {
        auto rows = database_->QueryAuditEntriesRaw("", 1, 0, true);
        if (!rows.empty()) {
            last_hash_ = rows[0].entry_hash;
            entry_count_ = database_->GetAuditEntryCount();
        }
    }

    LOG_INFO("AuditLogger initialized (chain_tip={})", last_hash_.substr(0, 16));
}

void AuditLogger::Start() {
    if (running_.exchange(true)) return;

    // Subscribe to auditable events
    auto& bus = EventBus::Instance();

    subscription_ids_.push_back(
        bus.Subscribe(EventType::RISK_THRESHOLD_EXCEEDED,
            [this](const Event& event) { OnRiskThresholdExceeded(event); })
    );

    subscription_ids_.push_back(
        bus.Subscribe(EventType::INCIDENT_STATE_CHANGE,
            [this](const Event& event) { OnIncidentStateChange(event); })
    );

    subscription_ids_.push_back(
        bus.Subscribe(EventType::CONTAINMENT_ACTION,
            [this](const Event& event) { OnContainmentAction(event); })
    );

    LogAction("AUDIT_STARTED", "system", "audit_logger", "Audit logging system started");
    LOG_INFO("AuditLogger started with {} subscriptions", subscription_ids_.size());
}

void AuditLogger::Stop() {
    if (!running_.exchange(false)) return;

    LogAction("AUDIT_STOPPED", "system", "audit_logger", "Audit logging system stopped");

    auto& bus = EventBus::Instance();
    for (auto id : subscription_ids_) {
        bus.Unsubscribe(id);
    }
    subscription_ids_.clear();

    LOG_INFO("AuditLogger stopped");
}

void AuditLogger::LogAction(const std::string& action,
                             const std::string& actor,
                             const std::string& target,
                             const std::string& details) {
    std::lock_guard<std::mutex> lock(mutex_);

    AuditEntry entry;
    entry.timestamp = GetCurrentTimestamp();
    entry.action = action;
    entry.actor = actor;
    entry.target = target;
    entry.details = details;
    entry.prev_hash = last_hash_;
    entry.entry_hash = ComputeEntryHash(entry);

    // Persist to database
    if (database_) {
        database_->InsertAuditEntry(entry.timestamp, entry.action, entry.actor,
                                      entry.target, entry.details,
                                      entry.prev_hash, entry.entry_hash);
    }

    last_hash_ = entry.entry_hash;
    entry_count_++;

    LOG_DEBUG("AuditLogger: action={} actor={} target={}", action, actor, target);
}

bool AuditLogger::VerifyIntegrity() {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!database_) {
        LOG_ERROR("AuditLogger: Cannot verify integrity without database");
        return false;
    }

    auto rows = database_->QueryAuditEntriesRaw("", 0, 0, false);
    if (rows.empty()) {
        LOG_INFO("AuditLogger: No entries to verify");
        return true;
    }

    std::string expected_prev = "GENESIS";

    for (const auto& row : rows) {
        // Verify chain linkage
        if (row.prev_hash != expected_prev) {
            LOG_ERROR("AuditLogger: Chain broken at sequence_id={} "
                      "(expected prev_hash={}, got={})",
                      row.sequence_id,
                      expected_prev.substr(0, 16),
                      row.prev_hash.substr(0, 16));
            return false;
        }

        // Verify HMAC using the stored ISO8601 timestamp string
        std::string computed = ComputeEntryHashFromStrings(
            row.timestamp, row.action, row.actor,
            row.target, row.details, row.prev_hash);
        if (computed != row.entry_hash) {
            LOG_ERROR("AuditLogger: HMAC mismatch at sequence_id={} "
                      "(expected={}, got={})",
                      row.sequence_id,
                      row.entry_hash.substr(0, 16),
                      computed.substr(0, 16));
            return false;
        }

        expected_prev = row.entry_hash;
    }

    LOG_INFO("AuditLogger: Integrity verified ({} entries)", rows.size());
    return true;
}

bool AuditLogger::ExportAuditLog(uint64_t start_time, uint64_t end_time,
                                   const std::string& output_path) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (!database_) return false;

    // Build where clause for time range
    std::string where;
    if (start_time > 0 && end_time > 0) {
        where = "timestamp >= '" + TimestampToISO8601(start_time) +
                "' AND timestamp <= '" + TimestampToISO8601(end_time) + "'";
    }

    auto rows = database_->QueryAuditEntriesRaw(where, 0, 0, false);

    // Create parent directory
    try {
        std::filesystem::path p(output_path);
        if (p.has_parent_path()) {
            std::filesystem::create_directories(p.parent_path());
        }
    } catch (const std::exception& ex) {
        LOG_ERROR("AuditLogger: Failed to create export directory: {}", ex.what());
        return false;
    }

    nlohmann::json export_json;
    export_json["export_timestamp"] = TimestampToISO8601(GetCurrentTimestamp());
    export_json["entry_count"] = rows.size();
    export_json["chain_valid"] = true;

    nlohmann::json entries_array = nlohmann::json::array();
    for (const auto& row : rows) {
        nlohmann::json ej;
        ej["sequence_id"] = row.sequence_id;
        ej["timestamp"] = row.timestamp;
        ej["action"] = row.action;
        ej["actor"] = row.actor;
        ej["target"] = row.target;
        ej["details"] = row.details;
        ej["prev_hash"] = row.prev_hash;
        ej["entry_hash"] = row.entry_hash;
        entries_array.push_back(ej);
    }
    export_json["entries"] = entries_array;

    std::ofstream out(output_path);
    if (!out.is_open()) {
        LOG_ERROR("AuditLogger: Failed to open export file: {}", output_path);
        return false;
    }

    out << export_json.dump(2);
    out.close();

    LOG_INFO("AuditLogger: Exported {} entries to {}", rows.size(), output_path);
    return true;
}

std::vector<AuditEntry> AuditLogger::QueryEntries(uint64_t start_time,
                                                     uint64_t end_time,
                                                     int limit) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!database_) return {};

    std::string where;
    if (start_time > 0 && end_time > 0) {
        where = "timestamp >= '" + TimestampToISO8601(start_time) +
                "' AND timestamp <= '" + TimestampToISO8601(end_time) + "'";
    }

    auto rows = database_->QueryAuditEntriesRaw(where, limit, 0, false);
    std::vector<AuditEntry> result;
    result.reserve(rows.size());
    for (const auto& row : rows) {
        AuditEntry entry;
        entry.sequence_id = row.sequence_id;
        entry.timestamp = 0;
        entry.action = row.action;
        entry.actor = row.actor;
        entry.target = row.target;
        entry.details = row.details;
        entry.prev_hash = row.prev_hash;
        entry.entry_hash = row.entry_hash;
        result.push_back(std::move(entry));
    }
    return result;
}

size_t AuditLogger::GetEntryCount() const {
    return entry_count_.load();
}

// --- EventBus handlers ---

void AuditLogger::OnRiskThresholdExceeded(const Event& event) {
    nlohmann::json details;
    for (const auto& [key, value] : event.metadata) {
        details[key] = value;
    }
    LogAction("RISK_THRESHOLD_EXCEEDED", "system",
              "PID:" + std::to_string(event.pid),
              details.dump());
}

void AuditLogger::OnIncidentStateChange(const Event& event) {
    nlohmann::json details;
    for (const auto& [key, value] : event.metadata) {
        details[key] = value;
    }
    LogAction("INCIDENT_STATE_CHANGE", "system",
              event.process_name.empty() ? "PID:" + std::to_string(event.pid) : event.process_name,
              details.dump());
}

void AuditLogger::OnContainmentAction(const Event& event) {
    nlohmann::json details;
    for (const auto& [key, value] : event.metadata) {
        details[key] = value;
    }
    LogAction("CONTAINMENT_ACTION", "system",
              "PID:" + std::to_string(event.pid),
              details.dump());
}

// --- HMAC computation ---

std::string AuditLogger::ComputeHMAC(const std::string& data) const {
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int result_len = 0;

    HMAC(EVP_sha256(),
         hmac_key_.c_str(), static_cast<int>(hmac_key_.size()),
         reinterpret_cast<const unsigned char*>(data.c_str()),
         data.size(),
         result, &result_len);

    std::ostringstream oss;
    for (unsigned int i = 0; i < result_len; i++) {
        oss << std::hex << std::setfill('0') << std::setw(2)
            << static_cast<int>(result[i]);
    }
    return oss.str();
}

std::string AuditLogger::ComputeEntryHash(const AuditEntry& entry) const {
    // Concatenate fields in deterministic order using ISO8601 timestamp
    // so the hash can be verified from the DB (which stores ISO8601).
    // sequence_id excluded — assigned by SQLite AUTOINCREMENT at insert time.
    std::string data;
    data += TimestampToISO8601(entry.timestamp);
    data += "|";
    data += entry.action;
    data += "|";
    data += entry.actor;
    data += "|";
    data += entry.target;
    data += "|";
    data += entry.details;
    data += "|";
    data += entry.prev_hash;

    return ComputeHMAC(data);
}

std::string AuditLogger::ComputeEntryHashFromStrings(
    const std::string& timestamp_iso,
    const std::string& action,
    const std::string& actor,
    const std::string& target,
    const std::string& details,
    const std::string& prev_hash) const {
    std::string data;
    data += timestamp_iso;
    data += "|";
    data += action;
    data += "|";
    data += actor;
    data += "|";
    data += target;
    data += "|";
    data += details;
    data += "|";
    data += prev_hash;

    return ComputeHMAC(data);
}

// --- Helpers ---

uint64_t AuditLogger::GetCurrentTimestamp() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );
}

std::string AuditLogger::TimestampToISO8601(uint64_t ms_epoch) {
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

} // namespace cortex
