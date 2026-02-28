#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace cortex {

class DatabaseManager;
class AuditLogger;

enum class ComplianceFramework {
    PCI_DSS,
    HIPAA,
    SOC2
};

struct ComplianceControl {
    std::string control_id;
    std::string description;
    std::string status;       // "COMPLIANT", "NON_COMPLIANT", "PARTIAL", "NOT_APPLICABLE"
    std::string evidence;
    std::vector<std::string> findings;
};

struct ComplianceReport {
    ComplianceFramework framework;
    std::string generated_at;
    std::string reporting_period_start;
    std::string reporting_period_end;
    std::string system_name;
    std::vector<ComplianceControl> controls;
    uint32_t compliant_count;
    uint32_t non_compliant_count;
    uint32_t partial_count;

    ComplianceReport()
        : framework(ComplianceFramework::PCI_DSS),
          compliant_count(0), non_compliant_count(0), partial_count(0) {}
};

class ComplianceReporter {
public:
    ComplianceReporter();
    ~ComplianceReporter() = default;

    void Initialize(DatabaseManager* db, AuditLogger* audit_logger);

    // Generate a compliance report for a specific framework
    ComplianceReport GenerateReport(ComplianceFramework framework,
                                     uint64_t start_time, uint64_t end_time);

    // Export report
    bool ExportReportJson(const ComplianceReport& report, const std::string& output_path);
    bool ExportReportHtml(const ComplianceReport& report, const std::string& output_path);

    // Utility
    static std::string GetFrameworkName(ComplianceFramework framework);

private:
    // Framework-specific report generators
    ComplianceReport GeneratePCIDSSReport(uint64_t start_time, uint64_t end_time);
    ComplianceReport GenerateHIPAAReport(uint64_t start_time, uint64_t end_time);
    ComplianceReport GenerateSOC2Report(uint64_t start_time, uint64_t end_time);

    // Evidence gathering helpers
    std::string GetEventCountEvidence(uint64_t start_time, uint64_t end_time);
    std::string GetIncidentCountEvidence();
    std::string GetAuditIntegrityEvidence();
    std::string GetMonitoringStatusEvidence();

    // Helpers
    static std::string TimestampToISO8601(uint64_t ms_epoch);
    static uint64_t GetCurrentTimestamp();

    DatabaseManager* database_{nullptr};
    AuditLogger* audit_logger_{nullptr};
};

} // namespace cortex
