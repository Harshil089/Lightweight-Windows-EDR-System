#include "compliance/ForensicsExporter.hpp"
#include "compliance/AuditLogger.hpp"
#include "persistence/DatabaseManager.hpp"
#include "core/Logger.hpp"
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <fstream>
#include <filesystem>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <random>

namespace cortex {

ForensicsExporter::ForensicsExporter() = default;

void ForensicsExporter::Initialize(DatabaseManager* db, MitreMapper* mapper, AuditLogger* auditor) {
    database_ = db;
    mitre_mapper_ = mapper;
    audit_logger_ = auditor;
    LOG_INFO("ForensicsExporter initialized");
}

bool ForensicsExporter::ExportTimeline(uint64_t start_time, uint64_t end_time,
                                         const std::string& output_path) {
    try {
        std::filesystem::path p(output_path);
        if (p.has_parent_path()) {
            std::filesystem::create_directories(p.parent_path());
        }
    } catch (const std::exception& ex) {
        LOG_ERROR("ForensicsExporter: Failed to create directory: {}", ex.what());
        return false;
    }

    auto timeline = BuildTimeline(start_time, end_time);

    nlohmann::json j;
    j["export_type"] = "timeline";
    j["generated_at"] = TimestampToISO8601(GetCurrentTimestamp());
    j["time_range"]["start"] = TimestampToISO8601(start_time);
    j["time_range"]["end"] = TimestampToISO8601(end_time);
    j["entry_count"] = timeline.size();

    nlohmann::json entries = nlohmann::json::array();
    for (const auto& entry : timeline) {
        nlohmann::json ej;
        ej["timestamp"] = TimestampToISO8601(entry.timestamp);
        ej["event_type"] = entry.event_type;
        ej["pid"] = entry.pid;
        ej["process_name"] = entry.process_name;
        ej["risk_score"] = entry.risk_score;
        ej["mitre_techniques"] = entry.mitre_techniques;

        if (!entry.details.empty()) {
            try {
                ej["details"] = nlohmann::json::parse(entry.details);
            } catch (...) {
                ej["details"] = entry.details;
            }
        }

        entries.push_back(ej);
    }
    j["timeline"] = entries;

    std::ofstream out(output_path);
    if (!out.is_open()) {
        LOG_ERROR("ForensicsExporter: Failed to open output file: {}", output_path);
        return false;
    }

    out << j.dump(2);
    out.close();

    LOG_INFO("ForensicsExporter: Timeline exported ({} entries) to {}", timeline.size(), output_path);
    return true;
}

bool ForensicsExporter::ExportForensicsPackage(const std::string& case_id,
                                                  uint64_t start_time, uint64_t end_time,
                                                  const std::string& output_dir) {
    std::string pkg_dir = output_dir + "/" + case_id;

    try {
        std::filesystem::create_directories(pkg_dir);
        std::filesystem::create_directories(pkg_dir + "/artifacts");
    } catch (const std::exception& ex) {
        LOG_ERROR("ForensicsExporter: Failed to create package directory: {}", ex.what());
        return false;
    }

    LOG_INFO("ForensicsExporter: Creating forensics package {} in {}", case_id, pkg_dir);

    // 1. Export timeline
    auto timeline = BuildTimeline(start_time, end_time);
    {
        nlohmann::json tj;
        tj["case_id"] = case_id;
        tj["generated_at"] = TimestampToISO8601(GetCurrentTimestamp());
        tj["time_range"]["start"] = TimestampToISO8601(start_time);
        tj["time_range"]["end"] = TimestampToISO8601(end_time);
        tj["entry_count"] = timeline.size();

        nlohmann::json entries = nlohmann::json::array();
        for (const auto& entry : timeline) {
            nlohmann::json ej;
            ej["timestamp"] = TimestampToISO8601(entry.timestamp);
            ej["event_type"] = entry.event_type;
            ej["pid"] = entry.pid;
            ej["process_name"] = entry.process_name;
            ej["risk_score"] = entry.risk_score;
            ej["mitre_techniques"] = entry.mitre_techniques;
            if (!entry.details.empty()) {
                try { ej["details"] = nlohmann::json::parse(entry.details); }
                catch (...) { ej["details"] = entry.details; }
            }
            entries.push_back(ej);
        }
        tj["timeline"] = entries;

        std::ofstream out(pkg_dir + "/timeline.json");
        if (out.is_open()) { out << tj.dump(2); out.close(); }
    }

    // 2. Export incidents
    {
        auto incidents = database_ ? database_->LoadAllIncidents() : std::vector<Incident>{};

        nlohmann::json ij;
        ij["case_id"] = case_id;
        ij["incident_count"] = incidents.size();

        nlohmann::json incidents_array = nlohmann::json::array();
        for (const auto& inc : incidents) {
            nlohmann::json incj;
            incj["uuid"] = inc.uuid;
            incj["pid"] = inc.pid;
            incj["process_name"] = inc.process_name;
            incj["state"] = IncidentStateToString(inc.state);
            incj["event_count"] = inc.associated_events.size();
            incj["containment_actions"] = inc.containment_actions.size();
            incj["state_transitions"] = inc.state_history.size();
            incidents_array.push_back(incj);
        }
        ij["incidents"] = incidents_array;

        std::ofstream out(pkg_dir + "/incidents.json");
        if (out.is_open()) { out << ij.dump(2); out.close(); }
    }

    // 3. Export audit trail
    if (audit_logger_) {
        audit_logger_->ExportAuditLog(start_time, end_time, pkg_dir + "/audit_trail.json");
    }

    // 4. Collect quarantine artifacts
    auto artifacts = CollectQuarantineArtifacts(pkg_dir + "/artifacts");

    // 5. Collect observed MITRE techniques
    std::unordered_map<std::string, MitreTechnique> observed_map;
    if (mitre_mapper_) {
        for (const auto& entry : timeline) {
            for (const auto& tech_id : entry.mitre_techniques) {
                auto tech = mitre_mapper_->GetTechniqueById(tech_id);
                if (tech.has_value()) {
                    observed_map[tech_id] = tech.value();
                }
            }
        }
    }

    // 6. Generate manifest
    GenerateManifest(pkg_dir, case_id);

    LOG_INFO("ForensicsExporter: Package {} complete ({} timeline entries, {} artifacts)",
             case_id, timeline.size(), artifacts.size());
    return true;
}

std::vector<ArtifactRecord> ForensicsExporter::CollectQuarantineArtifacts(const std::string& output_dir) {
    std::vector<ArtifactRecord> artifacts;
    std::string quarantine_path = "C:\\ProgramData\\CortexEDR\\quarantine";

    try {
        if (!std::filesystem::exists(quarantine_path)) {
            LOG_INFO("ForensicsExporter: No quarantine directory found");
            return artifacts;
        }

        std::filesystem::create_directories(output_dir);

        for (const auto& entry : std::filesystem::directory_iterator(quarantine_path)) {
            if (!entry.is_regular_file()) continue;

            ArtifactRecord rec;
            rec.artifact_type = "quarantined_file";
            rec.original_path = entry.path().string();
            rec.file_size = entry.file_size();
            rec.collected_at = GetCurrentTimestamp();

            std::string dest = output_dir + "/" + entry.path().filename().string();
            try {
                std::filesystem::copy_file(entry.path(), dest,
                    std::filesystem::copy_options::overwrite_existing);
                rec.collected_path = dest;
                rec.sha256_hash = ComputeFileSHA256(dest);
            } catch (const std::exception& ex) {
                LOG_WARN("ForensicsExporter: Failed to copy artifact {}: {}",
                         entry.path().string(), ex.what());
                continue;
            }

            artifacts.push_back(rec);
        }
    } catch (const std::exception& ex) {
        LOG_WARN("ForensicsExporter: Error collecting quarantine artifacts: {}", ex.what());
    }

    LOG_INFO("ForensicsExporter: Collected {} quarantine artifacts", artifacts.size());
    return artifacts;
}

bool ForensicsExporter::GenerateManifest(const std::string& package_dir, const std::string& case_id) {
    nlohmann::json manifest;
    manifest["case_id"] = case_id;
    manifest["generated_at"] = TimestampToISO8601(GetCurrentTimestamp());
    manifest["generator"] = "CortexEDR ForensicsExporter v1.0";

    nlohmann::json files_array = nlohmann::json::array();

    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(package_dir)) {
            if (!entry.is_regular_file()) continue;

            std::string rel_path = std::filesystem::relative(entry.path(), package_dir).string();
            if (rel_path == "manifest.json") continue; // Don't include self

            nlohmann::json fj;
            fj["path"] = rel_path;
            fj["size_bytes"] = entry.file_size();
            fj["sha256"] = ComputeFileSHA256(entry.path().string());
            files_array.push_back(fj);
        }
    } catch (const std::exception& ex) {
        LOG_WARN("ForensicsExporter: Error generating manifest: {}", ex.what());
    }

    manifest["files"] = files_array;
    manifest["file_count"] = files_array.size();

    std::ofstream out(package_dir + "/manifest.json");
    if (!out.is_open()) {
        LOG_ERROR("ForensicsExporter: Failed to write manifest");
        return false;
    }

    out << manifest.dump(2);
    out.close();

    LOG_INFO("ForensicsExporter: Manifest generated ({} files)", files_array.size());
    return true;
}

// --- Private helpers ---

std::vector<TimelineEntry> ForensicsExporter::BuildTimeline(uint64_t start_time, uint64_t end_time) {
    std::vector<TimelineEntry> timeline;

    if (!database_) return timeline;

    std::string where;
    if (start_time > 0 && end_time > 0) {
        where = "timestamp >= '" + TimestampToISO8601(start_time) +
                "' AND timestamp <= '" + TimestampToISO8601(end_time) + "'";
    }

    auto events_json = database_->QueryEventsJson(where, 10000, 0);

    for (const auto& event_str : events_json) {
        try {
            auto j = nlohmann::json::parse(event_str);

            TimelineEntry entry;
            entry.event_type = j.value("event_type", "");
            entry.pid = j.value("pid", 0u);
            entry.process_name = j.value("process_name", "");
            entry.risk_score = j.value("risk_score", 0u);

            if (j.contains("details")) {
                entry.details = j["details"].is_string() ?
                    j["details"].get<std::string>() : j["details"].dump();
            }

            // Map to MITRE techniques
            if (mitre_mapper_) {
                // Create a temporary Event for mapping
                Event evt(EventType::PROCESS_CREATE, entry.pid, entry.process_name);

                // Try to parse the matched_rule from details
                if (j.contains("details") && j["details"].is_object()) {
                    if (j["details"].contains("matched_rule")) {
                        evt.metadata["matched_rule"] = j["details"]["matched_rule"].get<std::string>();
                    }
                }

                auto techniques = mitre_mapper_->MapEvent(evt);
                for (const auto& t : techniques) {
                    entry.mitre_techniques.push_back(t.technique_id);
                }
            }

            timeline.push_back(entry);
        } catch (const std::exception& ex) {
            LOG_WARN("ForensicsExporter: Failed to parse event: {}", ex.what());
        }
    }

    // Timeline is already ordered by QueryEventsJson (ORDER BY id DESC)
    // Reverse to get chronological order
    std::reverse(timeline.begin(), timeline.end());

    return timeline;
}

std::string ForensicsExporter::ComputeFileSHA256(const std::string& file_path) {
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) return "";

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return "";

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }

    char buffer[8192];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
        EVP_DigestUpdate(ctx, buffer, static_cast<size_t>(file.gcount()));
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    EVP_MD_CTX_free(ctx);

    std::ostringstream oss;
    for (unsigned int i = 0; i < hash_len; i++) {
        oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(hash[i]);
    }
    return oss.str();
}

uint64_t ForensicsExporter::GetCurrentTimestamp() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );
}

std::string ForensicsExporter::TimestampToISO8601(uint64_t ms_epoch) {
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

std::string ForensicsExporter::GenerateCaseId() {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

    std::mt19937 rng(static_cast<unsigned int>(ms));
    std::uniform_int_distribution<int> dist(0, 15);

    std::ostringstream oss;
    oss << "CASE-";

    auto t = std::chrono::system_clock::to_time_t(now);
    std::tm tm_buf;
    gmtime_s(&tm_buf, &t);
    oss << std::setfill('0') << std::setw(4) << (tm_buf.tm_year + 1900)
        << std::setw(2) << (tm_buf.tm_mon + 1)
        << std::setw(2) << tm_buf.tm_mday << "-";

    const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 8; i++) {
        oss << hex[dist(rng)];
    }

    return oss.str();
}

} // namespace cortex
