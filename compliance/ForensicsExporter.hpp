#pragma once

#include "compliance/MitreMapper.hpp"
#include "response/IncidentManager.hpp"
#include <string>
#include <vector>
#include <cstdint>

namespace cortex {

class DatabaseManager;
class AuditLogger;

struct TimelineEntry {
    uint64_t timestamp;
    std::string event_type;
    uint32_t pid;
    std::string process_name;
    uint32_t risk_score;
    std::string details;
    std::vector<std::string> mitre_techniques;

    TimelineEntry()
        : timestamp(0), pid(0), risk_score(0) {}
};

struct ArtifactRecord {
    std::string artifact_type;
    std::string original_path;
    std::string collected_path;
    std::string sha256_hash;
    uint64_t file_size;
    uint64_t collected_at;

    ArtifactRecord()
        : file_size(0), collected_at(0) {}
};

struct ForensicsPackage {
    std::string case_id;
    std::string generated_at;
    std::string time_range_start;
    std::string time_range_end;
    std::vector<TimelineEntry> timeline;
    std::vector<Incident> incidents;
    std::vector<MitreTechnique> observed_techniques;
    std::vector<ArtifactRecord> artifacts;
};

class ForensicsExporter {
public:
    ForensicsExporter();
    ~ForensicsExporter() = default;

    void Initialize(DatabaseManager* db, MitreMapper* mapper, AuditLogger* auditor);

    // Export event timeline as JSON
    bool ExportTimeline(uint64_t start_time, uint64_t end_time,
                        const std::string& output_path);

    // Export full forensics package
    bool ExportForensicsPackage(const std::string& case_id,
                                 uint64_t start_time, uint64_t end_time,
                                 const std::string& output_dir);

    // Collect quarantined file artifacts
    std::vector<ArtifactRecord> CollectQuarantineArtifacts(const std::string& output_dir);

    // Generate integrity manifest for an export directory
    bool GenerateManifest(const std::string& package_dir, const std::string& case_id);

private:
    // Build timeline from database events
    std::vector<TimelineEntry> BuildTimeline(uint64_t start_time, uint64_t end_time);

    // File hashing
    static std::string ComputeFileSHA256(const std::string& file_path);

    // Helpers
    static std::string TimestampToISO8601(uint64_t ms_epoch);
    static uint64_t GetCurrentTimestamp();
    static std::string GenerateCaseId();

    DatabaseManager* database_{nullptr};
    MitreMapper* mitre_mapper_{nullptr};
    AuditLogger* audit_logger_{nullptr};
};

} // namespace cortex
