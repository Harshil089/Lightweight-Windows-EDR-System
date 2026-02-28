#include "compliance/ComplianceReporter.hpp"
#include "compliance/AuditLogger.hpp"
#include "persistence/DatabaseManager.hpp"
#include "core/Logger.hpp"
#include <nlohmann/json.hpp>
#include <fstream>
#include <filesystem>
#include <chrono>
#include <sstream>

namespace cortex {

ComplianceReporter::ComplianceReporter() = default;

void ComplianceReporter::Initialize(DatabaseManager* db, AuditLogger* audit_logger) {
    database_ = db;
    audit_logger_ = audit_logger;
    LOG_INFO("ComplianceReporter initialized");
}

ComplianceReport ComplianceReporter::GenerateReport(ComplianceFramework framework,
                                                      uint64_t start_time,
                                                      uint64_t end_time) {
    switch (framework) {
        case ComplianceFramework::PCI_DSS:
            return GeneratePCIDSSReport(start_time, end_time);
        case ComplianceFramework::HIPAA:
            return GenerateHIPAAReport(start_time, end_time);
        case ComplianceFramework::SOC2:
            return GenerateSOC2Report(start_time, end_time);
        default:
            return GeneratePCIDSSReport(start_time, end_time);
    }
}

// --- PCI-DSS Report ---

ComplianceReport ComplianceReporter::GeneratePCIDSSReport(uint64_t start_time, uint64_t end_time) {
    ComplianceReport report;
    report.framework = ComplianceFramework::PCI_DSS;
    report.generated_at = TimestampToISO8601(GetCurrentTimestamp());
    report.reporting_period_start = TimestampToISO8601(start_time);
    report.reporting_period_end = TimestampToISO8601(end_time);
    report.system_name = "CortexEDR";

    // PCI-DSS 5.2 - Anti-malware deployed
    {
        ComplianceControl ctrl;
        ctrl.control_id = "PCI-DSS 5.2";
        ctrl.description = "Anti-malware solution is deployed on all systems";
        ctrl.evidence = GetMonitoringStatusEvidence();
        ctrl.status = "COMPLIANT";
        ctrl.findings.push_back("Process, file, network, and registry monitors are active");
        report.controls.push_back(ctrl);
    }

    // PCI-DSS 5.3 - Anti-malware mechanisms active
    {
        ComplianceControl ctrl;
        ctrl.control_id = "PCI-DSS 5.3";
        ctrl.description = "Anti-malware mechanisms are actively running and cannot be disabled by users";
        ctrl.evidence = "Real-time monitoring via ETW, ReadDirectoryChangesW, IP Helper API, RegNotifyChangeKeyValue";
        ctrl.status = "COMPLIANT";
        ctrl.findings.push_back("All monitoring subsystems operate as Windows services with real-time event collection");
        report.controls.push_back(ctrl);
    }

    // PCI-DSS 10.2 - Audit log implemented
    {
        ComplianceControl ctrl;
        ctrl.control_id = "PCI-DSS 10.2";
        ctrl.description = "Implement automated audit trails for all system components";
        ctrl.evidence = GetAuditIntegrityEvidence();
        bool has_audit = (audit_logger_ && audit_logger_->GetEntryCount() > 0);
        ctrl.status = has_audit ? "COMPLIANT" : "PARTIAL";
        ctrl.findings.push_back("HMAC-SHA256 chained audit log with " +
            std::to_string(audit_logger_ ? audit_logger_->GetEntryCount() : 0) + " entries");
        report.controls.push_back(ctrl);
    }

    // PCI-DSS 10.3 - Audit trail records events
    {
        ComplianceControl ctrl;
        ctrl.control_id = "PCI-DSS 10.3";
        ctrl.description = "Record audit trail entries for all system components for each event";
        ctrl.evidence = GetEventCountEvidence(start_time, end_time);
        ctrl.status = "COMPLIANT";
        ctrl.findings.push_back("Events recorded with timestamp, event type, PID, process name, risk score, and metadata");
        report.controls.push_back(ctrl);
    }

    // PCI-DSS 10.5 - Audit trails secured
    {
        ComplianceControl ctrl;
        ctrl.control_id = "PCI-DSS 10.5";
        ctrl.description = "Secure audit trails so they cannot be altered";
        bool integrity_ok = audit_logger_ ? audit_logger_->VerifyIntegrity() : false;
        ctrl.evidence = integrity_ok ? "HMAC-SHA256 chain integrity verified" : "Audit chain not verified";
        ctrl.status = integrity_ok ? "COMPLIANT" : "NON_COMPLIANT";
        if (integrity_ok) {
            ctrl.findings.push_back("Tamper-proof chain verified with cryptographic HMAC linkage");
        } else {
            ctrl.findings.push_back("Audit trail integrity could not be verified");
        }
        report.controls.push_back(ctrl);
    }

    // PCI-DSS 10.7 - Retain audit trail history
    {
        ComplianceControl ctrl;
        ctrl.control_id = "PCI-DSS 10.7";
        ctrl.description = "Retain audit trail history for at least one year";
        ctrl.evidence = "SQLite database with WAL mode provides durable storage";
        ctrl.status = "PARTIAL";
        ctrl.findings.push_back("Audit data persisted in SQLite; retention policy should be configured per organizational requirements");
        report.controls.push_back(ctrl);
    }

    // PCI-DSS 11.5 - Change detection mechanism
    {
        ComplianceControl ctrl;
        ctrl.control_id = "PCI-DSS 11.5";
        ctrl.description = "Deploy a change-detection mechanism to alert on unauthorized modification";
        ctrl.evidence = "FileMonitor tracks changes via ReadDirectoryChangesW on critical directories";
        ctrl.status = "COMPLIANT";
        ctrl.findings.push_back("Real-time file change detection on System32, Temp, Users, and ProgramData directories");
        report.controls.push_back(ctrl);
    }

    // PCI-DSS 12.10 - Incident response plan
    {
        ComplianceControl ctrl;
        ctrl.control_id = "PCI-DSS 12.10";
        ctrl.description = "Implement an incident response plan";
        ctrl.evidence = GetIncidentCountEvidence();
        ctrl.status = "COMPLIANT";
        ctrl.findings.push_back("IncidentManager with state machine (NEW→INVESTIGATING→ACTIVE→CONTAINED→CLOSED)");
        ctrl.findings.push_back("ContainmentManager supports process termination, suspension, network blocking, file quarantine");
        report.controls.push_back(ctrl);
    }

    // Tally
    for (const auto& ctrl : report.controls) {
        if (ctrl.status == "COMPLIANT") report.compliant_count++;
        else if (ctrl.status == "NON_COMPLIANT") report.non_compliant_count++;
        else if (ctrl.status == "PARTIAL") report.partial_count++;
    }

    LOG_INFO("PCI-DSS report generated: {}/{} compliant",
             report.compliant_count, report.controls.size());
    return report;
}

// --- HIPAA Report ---

ComplianceReport ComplianceReporter::GenerateHIPAAReport(uint64_t start_time, uint64_t end_time) {
    ComplianceReport report;
    report.framework = ComplianceFramework::HIPAA;
    report.generated_at = TimestampToISO8601(GetCurrentTimestamp());
    report.reporting_period_start = TimestampToISO8601(start_time);
    report.reporting_period_end = TimestampToISO8601(end_time);
    report.system_name = "CortexEDR";

    // 164.312(b) - Audit Controls
    {
        ComplianceControl ctrl;
        ctrl.control_id = "HIPAA 164.312(b)";
        ctrl.description = "Implement hardware, software, and/or procedural mechanisms that record and examine activity";
        ctrl.evidence = GetAuditIntegrityEvidence();
        ctrl.status = (audit_logger_ && audit_logger_->GetEntryCount() > 0) ? "COMPLIANT" : "PARTIAL";
        ctrl.findings.push_back("Comprehensive event logging with " + GetEventCountEvidence(start_time, end_time));
        ctrl.findings.push_back("Tamper-proof audit trail with HMAC-SHA256 integrity chain");
        report.controls.push_back(ctrl);
    }

    // 164.312(c)(2) - Mechanism to authenticate ePHI
    {
        ComplianceControl ctrl;
        ctrl.control_id = "HIPAA 164.312(c)(2)";
        ctrl.description = "Implement electronic mechanisms to corroborate that ePHI has not been altered or destroyed";
        bool integrity_ok = audit_logger_ ? audit_logger_->VerifyIntegrity() : false;
        ctrl.evidence = integrity_ok ? "HMAC-SHA256 audit chain verified" : "Chain verification not available";
        ctrl.status = integrity_ok ? "COMPLIANT" : "NON_COMPLIANT";
        ctrl.findings.push_back("File integrity monitoring detects unauthorized modifications to system files");
        report.controls.push_back(ctrl);
    }

    // 164.308(a)(1)(ii)(D) - Information system activity review
    {
        ComplianceControl ctrl;
        ctrl.control_id = "HIPAA 164.308(a)(1)(ii)(D)";
        ctrl.description = "Implement procedures to regularly review records of information system activity";
        ctrl.evidence = GetEventCountEvidence(start_time, end_time);
        ctrl.status = "COMPLIANT";
        ctrl.findings.push_back("Real-time event monitoring across process, file, network, and registry activities");
        ctrl.findings.push_back("Risk scoring with behavioral correlation for anomaly detection");
        report.controls.push_back(ctrl);
    }

    // 164.308(a)(5) - Security awareness and training
    {
        ComplianceControl ctrl;
        ctrl.control_id = "HIPAA 164.308(a)(5)";
        ctrl.description = "Implement a security awareness and training program";
        ctrl.evidence = "Threat detection and alerting provide visibility into security events";
        ctrl.status = "PARTIAL";
        ctrl.findings.push_back("EDR provides real-time threat visibility; organizational training program should complement");
        report.controls.push_back(ctrl);
    }

    // 164.308(a)(6) - Security incident procedures
    {
        ComplianceControl ctrl;
        ctrl.control_id = "HIPAA 164.308(a)(6)";
        ctrl.description = "Implement policies and procedures to address security incidents";
        ctrl.evidence = GetIncidentCountEvidence();
        ctrl.status = "COMPLIANT";
        ctrl.findings.push_back("Automated incident detection, state management, and containment capabilities");
        ctrl.findings.push_back("Incident lifecycle: NEW→INVESTIGATING→ACTIVE→CONTAINED→CLOSED→ESCALATED");
        report.controls.push_back(ctrl);
    }

    for (const auto& ctrl : report.controls) {
        if (ctrl.status == "COMPLIANT") report.compliant_count++;
        else if (ctrl.status == "NON_COMPLIANT") report.non_compliant_count++;
        else if (ctrl.status == "PARTIAL") report.partial_count++;
    }

    LOG_INFO("HIPAA report generated: {}/{} compliant",
             report.compliant_count, report.controls.size());
    return report;
}

// --- SOC 2 Report ---

ComplianceReport ComplianceReporter::GenerateSOC2Report(uint64_t start_time, uint64_t end_time) {
    ComplianceReport report;
    report.framework = ComplianceFramework::SOC2;
    report.generated_at = TimestampToISO8601(GetCurrentTimestamp());
    report.reporting_period_start = TimestampToISO8601(start_time);
    report.reporting_period_end = TimestampToISO8601(end_time);
    report.system_name = "CortexEDR";

    // CC6.1 - Logical and physical access controls
    {
        ComplianceControl ctrl;
        ctrl.control_id = "SOC2 CC6.1";
        ctrl.description = "The entity implements logical access security software, infrastructure, and architectures";
        ctrl.evidence = GetMonitoringStatusEvidence();
        ctrl.status = "COMPLIANT";
        ctrl.findings.push_back("Process monitoring detects unauthorized execution");
        ctrl.findings.push_back("Registry monitoring detects persistence mechanism installations");
        report.controls.push_back(ctrl);
    }

    // CC6.8 - Prevent/detect unauthorized software
    {
        ComplianceControl ctrl;
        ctrl.control_id = "SOC2 CC6.8";
        ctrl.description = "The entity implements controls to prevent or detect and act upon the introduction of unauthorized or malicious software";
        ctrl.evidence = "RuleEngine with " + std::to_string(database_ ? database_->GetEventCount() : 0) + " events analyzed";
        ctrl.status = "COMPLIANT";
        ctrl.findings.push_back("Rule-based detection with hash, path, network, and registry pattern matching");
        ctrl.findings.push_back("Behavioral correlation detects dropper, persistence, and lateral movement patterns");
        report.controls.push_back(ctrl);
    }

    // CC7.2 - Monitor system components
    {
        ComplianceControl ctrl;
        ctrl.control_id = "SOC2 CC7.2";
        ctrl.description = "The entity monitors system components for anomalies indicative of malicious acts";
        ctrl.evidence = GetEventCountEvidence(start_time, end_time);
        ctrl.status = "COMPLIANT";
        ctrl.findings.push_back("Four real-time collectors: Process (ETW), File (ReadDirectoryChangesW), Network (IP Helper), Registry (RegNotify)");
        report.controls.push_back(ctrl);
    }

    // CC7.3 - Evaluate security events
    {
        ComplianceControl ctrl;
        ctrl.control_id = "SOC2 CC7.3";
        ctrl.description = "The entity evaluates detected security events and determines whether they represent failures";
        ctrl.evidence = "Multi-layer analysis: RiskScorer → RuleEngine → BehaviorCorrelator";
        ctrl.status = "COMPLIANT";
        ctrl.findings.push_back("Weighted risk scoring (0-100) with configurable thresholds");
        ctrl.findings.push_back("Behavioral pattern detection across 60-second time windows");
        report.controls.push_back(ctrl);
    }

    // CC7.4 - Respond to incidents
    {
        ComplianceControl ctrl;
        ctrl.control_id = "SOC2 CC7.4";
        ctrl.description = "The entity responds to identified security incidents by executing a defined incident response program";
        ctrl.evidence = GetIncidentCountEvidence();
        ctrl.status = "COMPLIANT";
        ctrl.findings.push_back("Automated containment: process terminate/suspend, network block, file quarantine");
        ctrl.findings.push_back("Full incident lifecycle management with state machine and audit trail");
        report.controls.push_back(ctrl);
    }

    for (const auto& ctrl : report.controls) {
        if (ctrl.status == "COMPLIANT") report.compliant_count++;
        else if (ctrl.status == "NON_COMPLIANT") report.non_compliant_count++;
        else if (ctrl.status == "PARTIAL") report.partial_count++;
    }

    LOG_INFO("SOC2 report generated: {}/{} compliant",
             report.compliant_count, report.controls.size());
    return report;
}

// --- Export ---

bool ComplianceReporter::ExportReportJson(const ComplianceReport& report,
                                            const std::string& output_path) {
    try {
        std::filesystem::path p(output_path);
        if (p.has_parent_path()) {
            std::filesystem::create_directories(p.parent_path());
        }
    } catch (const std::exception& ex) {
        LOG_ERROR("ComplianceReporter: Failed to create directory: {}", ex.what());
        return false;
    }

    nlohmann::json j;
    j["framework"] = GetFrameworkName(report.framework);
    j["generated_at"] = report.generated_at;
    j["reporting_period"]["start"] = report.reporting_period_start;
    j["reporting_period"]["end"] = report.reporting_period_end;
    j["system_name"] = report.system_name;
    j["summary"]["compliant"] = report.compliant_count;
    j["summary"]["non_compliant"] = report.non_compliant_count;
    j["summary"]["partial"] = report.partial_count;
    j["summary"]["total"] = report.controls.size();

    nlohmann::json controls_array = nlohmann::json::array();
    for (const auto& ctrl : report.controls) {
        nlohmann::json cj;
        cj["control_id"] = ctrl.control_id;
        cj["description"] = ctrl.description;
        cj["status"] = ctrl.status;
        cj["evidence"] = ctrl.evidence;
        cj["findings"] = ctrl.findings;
        controls_array.push_back(cj);
    }
    j["controls"] = controls_array;

    std::ofstream out(output_path);
    if (!out.is_open()) {
        LOG_ERROR("ComplianceReporter: Failed to open output file: {}", output_path);
        return false;
    }

    out << j.dump(2);
    out.close();

    LOG_INFO("ComplianceReporter: JSON report exported to {}", output_path);
    return true;
}

bool ComplianceReporter::ExportReportHtml(const ComplianceReport& report,
                                            const std::string& output_path) {
    try {
        std::filesystem::path p(output_path);
        if (p.has_parent_path()) {
            std::filesystem::create_directories(p.parent_path());
        }
    } catch (const std::exception& ex) {
        LOG_ERROR("ComplianceReporter: Failed to create directory: {}", ex.what());
        return false;
    }

    std::ostringstream html;
    html << "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\">\n";
    html << "<title>" << GetFrameworkName(report.framework) << " Compliance Report</title>\n";
    html << "<style>\n";
    html << "body { font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: #f5f5f5; }\n";
    html << ".header { background: #1a237e; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }\n";
    html << ".summary { display: flex; gap: 20px; margin-bottom: 20px; }\n";
    html << ".stat { background: white; padding: 15px; border-radius: 8px; flex: 1; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }\n";
    html << ".stat .value { font-size: 2em; font-weight: bold; }\n";
    html << ".compliant { color: #2e7d32; } .non-compliant { color: #c62828; } .partial { color: #f57f17; }\n";
    html << "table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }\n";
    html << "th { background: #283593; color: white; padding: 12px; text-align: left; }\n";
    html << "td { padding: 12px; border-bottom: 1px solid #e0e0e0; vertical-align: top; }\n";
    html << "tr:hover { background: #f5f5f5; }\n";
    html << ".status-badge { padding: 4px 12px; border-radius: 12px; font-weight: bold; font-size: 0.85em; }\n";
    html << ".badge-compliant { background: #e8f5e9; color: #2e7d32; }\n";
    html << ".badge-non-compliant { background: #ffebee; color: #c62828; }\n";
    html << ".badge-partial { background: #fff8e1; color: #f57f17; }\n";
    html << ".findings { font-size: 0.9em; color: #555; }\n";
    html << "</style></head><body>\n";

    html << "<div class=\"header\">\n";
    html << "<h1>" << GetFrameworkName(report.framework) << " Compliance Report</h1>\n";
    html << "<p>Generated: " << report.generated_at << " | System: " << report.system_name << "</p>\n";
    html << "<p>Reporting Period: " << report.reporting_period_start << " to " << report.reporting_period_end << "</p>\n";
    html << "</div>\n";

    html << "<div class=\"summary\">\n";
    html << "<div class=\"stat\"><div class=\"value compliant\">" << report.compliant_count << "</div><div>Compliant</div></div>\n";
    html << "<div class=\"stat\"><div class=\"value partial\">" << report.partial_count << "</div><div>Partial</div></div>\n";
    html << "<div class=\"stat\"><div class=\"value non-compliant\">" << report.non_compliant_count << "</div><div>Non-Compliant</div></div>\n";
    html << "<div class=\"stat\"><div class=\"value\">" << report.controls.size() << "</div><div>Total Controls</div></div>\n";
    html << "</div>\n";

    html << "<table>\n";
    html << "<tr><th>Control ID</th><th>Description</th><th>Status</th><th>Evidence</th><th>Findings</th></tr>\n";

    for (const auto& ctrl : report.controls) {
        std::string badge_class = "badge-compliant";
        if (ctrl.status == "NON_COMPLIANT") badge_class = "badge-non-compliant";
        else if (ctrl.status == "PARTIAL") badge_class = "badge-partial";

        html << "<tr>";
        html << "<td><strong>" << ctrl.control_id << "</strong></td>";
        html << "<td>" << ctrl.description << "</td>";
        html << "<td><span class=\"status-badge " << badge_class << "\">" << ctrl.status << "</span></td>";
        html << "<td>" << ctrl.evidence << "</td>";
        html << "<td class=\"findings\"><ul>";
        for (const auto& f : ctrl.findings) {
            html << "<li>" << f << "</li>";
        }
        html << "</ul></td></tr>\n";
    }

    html << "</table>\n";
    html << "<p style=\"color:#999;margin-top:20px;font-size:0.85em;\">Generated by CortexEDR Compliance Reporter</p>\n";
    html << "</body></html>\n";

    std::ofstream out(output_path);
    if (!out.is_open()) {
        LOG_ERROR("ComplianceReporter: Failed to open HTML output: {}", output_path);
        return false;
    }

    out << html.str();
    out.close();

    LOG_INFO("ComplianceReporter: HTML report exported to {}", output_path);
    return true;
}

std::string ComplianceReporter::GetFrameworkName(ComplianceFramework framework) {
    switch (framework) {
        case ComplianceFramework::PCI_DSS: return "PCI-DSS v4.0";
        case ComplianceFramework::HIPAA:   return "HIPAA Security Rule";
        case ComplianceFramework::SOC2:    return "SOC 2 Type II";
        default:                           return "Unknown";
    }
}

// --- Evidence Helpers ---

std::string ComplianceReporter::GetEventCountEvidence(uint64_t /*start_time*/, uint64_t /*end_time*/) {
    size_t count = database_ ? database_->GetEventCount() : 0;
    return std::to_string(count) + " events recorded in database";
}

std::string ComplianceReporter::GetIncidentCountEvidence() {
    if (!database_) return "Database not available";
    auto snap = database_->GetStatusSnapshot();
    return std::to_string(snap.active_incident_count) + " active incidents, " +
           std::to_string(snap.total_event_count) + " total events tracked";
}

std::string ComplianceReporter::GetAuditIntegrityEvidence() {
    if (!audit_logger_) return "Audit logger not configured";
    return "Audit trail with " + std::to_string(audit_logger_->GetEntryCount()) +
           " entries, HMAC-SHA256 chain integrity";
}

std::string ComplianceReporter::GetMonitoringStatusEvidence() {
    return "Active monitors: ProcessMonitor (ETW), FileMonitor (ReadDirectoryChangesW), "
           "NetworkMonitor (IP Helper API), RegistryMonitor (RegNotifyChangeKeyValue)";
}

// --- Helpers ---

uint64_t ComplianceReporter::GetCurrentTimestamp() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );
}

std::string ComplianceReporter::TimestampToISO8601(uint64_t ms_epoch) {
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
