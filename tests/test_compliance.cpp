#include <gtest/gtest.h>
#include "compliance/AuditLogger.hpp"
#include "compliance/MitreMapper.hpp"
#include "compliance/ComplianceReporter.hpp"
#include "compliance/ForensicsExporter.hpp"
#include "persistence/DatabaseManager.hpp"
#include "core/EventBus.hpp"
#include <filesystem>
#include <fstream>
#include <string>

using namespace cortex;

// ═══════════════════════════════════════════════════════════════
// AuditLogger Tests
// ═══════════════════════════════════════════════════════════════

class AuditLoggerTest : public ::testing::Test {
protected:
    void SetUp() override {
        db_ = std::make_unique<DatabaseManager>();
        ASSERT_TRUE(db_->Initialize(":memory:"));

        logger_ = std::make_unique<AuditLogger>();
        logger_->Initialize(db_.get(), "test-hmac-key-12345");
    }

    void TearDown() override {
        logger_.reset();
        db_->Shutdown();
        db_.reset();
    }

    std::unique_ptr<DatabaseManager> db_;
    std::unique_ptr<AuditLogger> logger_;
};

TEST_F(AuditLoggerTest, LogActionInsertsEntry) {
    logger_->LogAction("TEST_ACTION", "test_actor", "test_target", "test details");
    EXPECT_EQ(logger_->GetEntryCount(), 1);
}

TEST_F(AuditLoggerTest, MultipleEntriesTracked) {
    logger_->LogAction("ACTION_1", "actor", "target1", "");
    logger_->LogAction("ACTION_2", "actor", "target2", "");
    logger_->LogAction("ACTION_3", "actor", "target3", "");
    EXPECT_EQ(logger_->GetEntryCount(), 3);
}

TEST_F(AuditLoggerTest, IntegrityVerificationPasses) {
    logger_->LogAction("ACTION_1", "system", "target1", "details1");
    logger_->LogAction("ACTION_2", "system", "target2", "details2");
    logger_->LogAction("ACTION_3", "system", "target3", "details3");
    EXPECT_TRUE(logger_->VerifyIntegrity());
}

TEST_F(AuditLoggerTest, EmptyChainVerifies) {
    EXPECT_TRUE(logger_->VerifyIntegrity());
}

TEST_F(AuditLoggerTest, QueryEntriesReturnsAll) {
    logger_->LogAction("A1", "actor", "t1", "");
    logger_->LogAction("A2", "actor", "t2", "");
    auto entries = logger_->QueryEntries(0, 0, 100);
    EXPECT_EQ(entries.size(), 2);
    EXPECT_EQ(entries[0].action, "A1");
    EXPECT_EQ(entries[1].action, "A2");
}

TEST_F(AuditLoggerTest, ExportAuditLogCreatesFile) {
    logger_->LogAction("EXPORT_TEST", "system", "target", "export details");

    std::string export_path = "test_audit_export.json";
    EXPECT_TRUE(logger_->ExportAuditLog(0, 0, export_path));
    EXPECT_TRUE(std::filesystem::exists(export_path));

    // Cleanup
    std::filesystem::remove(export_path);
}

// ═══════════════════════════════════════════════════════════════
// MitreMapper Tests
// ═══════════════════════════════════════════════════════════════

class MitreMapperTest : public ::testing::Test {
protected:
    void SetUp() override {
        mapper_ = std::make_unique<MitreMapper>();
        mapper_->Initialize();
    }

    std::unique_ptr<MitreMapper> mapper_;
};

TEST_F(MitreMapperTest, InitializesWithMappings) {
    EXPECT_GT(mapper_->GetMappingCount(), 0);
}

TEST_F(MitreMapperTest, MapsTempExecutionRule) {
    auto techniques = mapper_->MapRule("Suspicious Temp Execution");
    ASSERT_FALSE(techniques.empty());
    EXPECT_EQ(techniques[0].technique_id, "T1204.002");
    EXPECT_EQ(techniques[0].tactic, "Execution");
}

TEST_F(MitreMapperTest, MapsPersistenceRegistryRule) {
    auto techniques = mapper_->MapRule("Persistence Registry Key Modification");
    ASSERT_FALSE(techniques.empty());
    EXPECT_EQ(techniques[0].technique_id, "T1547.001");
    EXPECT_EQ(techniques[0].tactic, "Persistence");
}

TEST_F(MitreMapperTest, MapsWinlogonRule) {
    auto techniques = mapper_->MapRule("Winlogon Persistence");
    ASSERT_FALSE(techniques.empty());
    EXPECT_EQ(techniques[0].technique_id, "T1547.004");
}

TEST_F(MitreMapperTest, MapsServiceInstallation) {
    auto techniques = mapper_->MapRule("Service Installation");
    ASSERT_FALSE(techniques.empty());
    EXPECT_EQ(techniques[0].technique_id, "T1543.003");
}

TEST_F(MitreMapperTest, MapsNetworkRules) {
    auto c2 = mapper_->MapRule("C2 Network Indicator - Tor Exit Nodes");
    ASSERT_FALSE(c2.empty());
    EXPECT_EQ(c2[0].technique_id, "T1071.001");

    auto ports = mapper_->MapRule("Suspicious High-Risk Ports");
    ASSERT_FALSE(ports.empty());
    EXPECT_EQ(ports[0].technique_id, "T1571");
}

TEST_F(MitreMapperTest, MapsBehaviorPatterns) {
    auto dropper = mapper_->MapRule("Dropper Pattern");
    ASSERT_FALSE(dropper.empty());
    EXPECT_EQ(dropper[0].technique_id, "T1105");

    auto lateral = mapper_->MapRule("Lateral Movement Pattern");
    ASSERT_FALSE(lateral.empty());
    EXPECT_EQ(lateral[0].technique_id, "T1021");
}

TEST_F(MitreMapperTest, UnknownRuleReturnsEmpty) {
    auto techniques = mapper_->MapRule("Nonexistent Rule");
    EXPECT_TRUE(techniques.empty());
}

TEST_F(MitreMapperTest, GetTechniqueByIdWorks) {
    auto tech = mapper_->GetTechniqueById("T1059");
    ASSERT_TRUE(tech.has_value());
    EXPECT_EQ(tech->technique_name, "Command and Scripting Interpreter");
}

TEST_F(MitreMapperTest, GetTechniqueByIdReturnsNulloptForInvalid) {
    auto tech = mapper_->GetTechniqueById("T9999");
    EXPECT_FALSE(tech.has_value());
}

TEST_F(MitreMapperTest, CoverageStatsValid) {
    auto stats = mapper_->GetCoverageStats();
    EXPECT_GT(stats.total_techniques, 0);
    EXPECT_GT(stats.total_tactics, 0);
    EXPECT_FALSE(stats.techniques_per_tactic.empty());
}

TEST_F(MitreMapperTest, GetAllMappingsReturnsAll) {
    auto mappings = mapper_->GetAllMappings();
    EXPECT_EQ(mappings.size(), mapper_->GetMappingCount());
    for (const auto& m : mappings) {
        EXPECT_FALSE(m.rule_name.empty());
        EXPECT_FALSE(m.techniques.empty());
    }
}

TEST_F(MitreMapperTest, MapEventByType) {
    Event evt(EventType::REGISTRY_WRITE, 1234, "test.exe");
    auto techniques = mapper_->MapEvent(evt);
    EXPECT_FALSE(techniques.empty());
}

TEST_F(MitreMapperTest, MapEventWithMatchedRule) {
    Event evt(EventType::PROCESS_CREATE, 1234, "test.exe");
    evt.metadata["matched_rule"] = "Suspicious Temp Execution";
    auto techniques = mapper_->MapEvent(evt);

    bool found_t1204 = false;
    for (const auto& t : techniques) {
        if (t.technique_id == "T1204.002") found_t1204 = true;
    }
    EXPECT_TRUE(found_t1204);
}

// ═══════════════════════════════════════════════════════════════
// ComplianceReporter Tests
// ═══════════════════════════════════════════════════════════════

class ComplianceReporterTest : public ::testing::Test {
protected:
    void SetUp() override {
        db_ = std::make_unique<DatabaseManager>();
        ASSERT_TRUE(db_->Initialize(":memory:"));

        audit_logger_ = std::make_unique<AuditLogger>();
        audit_logger_->Initialize(db_.get(), "test-key");
        audit_logger_->LogAction("SYSTEM_START", "system", "edr", "Test startup");

        reporter_ = std::make_unique<ComplianceReporter>();
        reporter_->Initialize(db_.get(), audit_logger_.get());
    }

    void TearDown() override {
        audit_logger_.reset();
        reporter_.reset();
        db_->Shutdown();
        db_.reset();
    }

    std::unique_ptr<DatabaseManager> db_;
    std::unique_ptr<AuditLogger> audit_logger_;
    std::unique_ptr<ComplianceReporter> reporter_;
};

TEST_F(ComplianceReporterTest, GeneratePCIDSSReport) {
    auto report = reporter_->GenerateReport(ComplianceFramework::PCI_DSS, 0, 0);
    EXPECT_EQ(report.framework, ComplianceFramework::PCI_DSS);
    EXPECT_FALSE(report.controls.empty());
    EXPECT_EQ(report.system_name, "CortexEDR");
    EXPECT_EQ(report.compliant_count + report.non_compliant_count + report.partial_count,
              static_cast<uint32_t>(report.controls.size()));
}

TEST_F(ComplianceReporterTest, GenerateHIPAAReport) {
    auto report = reporter_->GenerateReport(ComplianceFramework::HIPAA, 0, 0);
    EXPECT_EQ(report.framework, ComplianceFramework::HIPAA);
    EXPECT_FALSE(report.controls.empty());
}

TEST_F(ComplianceReporterTest, GenerateSOC2Report) {
    auto report = reporter_->GenerateReport(ComplianceFramework::SOC2, 0, 0);
    EXPECT_EQ(report.framework, ComplianceFramework::SOC2);
    EXPECT_FALSE(report.controls.empty());
}

TEST_F(ComplianceReporterTest, FrameworkNames) {
    EXPECT_EQ(ComplianceReporter::GetFrameworkName(ComplianceFramework::PCI_DSS), "PCI-DSS v4.0");
    EXPECT_EQ(ComplianceReporter::GetFrameworkName(ComplianceFramework::HIPAA), "HIPAA Security Rule");
    EXPECT_EQ(ComplianceReporter::GetFrameworkName(ComplianceFramework::SOC2), "SOC 2 Type II");
}

TEST_F(ComplianceReporterTest, ExportJsonReport) {
    auto report = reporter_->GenerateReport(ComplianceFramework::PCI_DSS, 0, 0);
    std::string path = "test_compliance_report.json";
    EXPECT_TRUE(reporter_->ExportReportJson(report, path));
    EXPECT_TRUE(std::filesystem::exists(path));
    std::filesystem::remove(path);
}

TEST_F(ComplianceReporterTest, ExportHtmlReport) {
    auto report = reporter_->GenerateReport(ComplianceFramework::SOC2, 0, 0);
    std::string path = "test_compliance_report.html";
    EXPECT_TRUE(reporter_->ExportReportHtml(report, path));
    EXPECT_TRUE(std::filesystem::exists(path));
    std::filesystem::remove(path);
}

TEST_F(ComplianceReporterTest, AllControlsHaveRequiredFields) {
    auto report = reporter_->GenerateReport(ComplianceFramework::PCI_DSS, 0, 0);
    for (const auto& ctrl : report.controls) {
        EXPECT_FALSE(ctrl.control_id.empty());
        EXPECT_FALSE(ctrl.description.empty());
        EXPECT_FALSE(ctrl.status.empty());
        EXPECT_TRUE(ctrl.status == "COMPLIANT" || ctrl.status == "NON_COMPLIANT" ||
                     ctrl.status == "PARTIAL" || ctrl.status == "NOT_APPLICABLE");
    }
}

// ═══════════════════════════════════════════════════════════════
// ForensicsExporter Tests
// ═══════════════════════════════════════════════════════════════

class ForensicsExporterTest : public ::testing::Test {
protected:
    void SetUp() override {
        db_ = std::make_unique<DatabaseManager>();
        ASSERT_TRUE(db_->Initialize(":memory:"));

        mapper_ = std::make_unique<MitreMapper>();
        mapper_->Initialize();

        audit_logger_ = std::make_unique<AuditLogger>();
        audit_logger_->Initialize(db_.get(), "test-key");

        exporter_ = std::make_unique<ForensicsExporter>();
        exporter_->Initialize(db_.get(), mapper_.get(), audit_logger_.get());

        // Insert some test events
        Event e1(EventType::PROCESS_CREATE, 1234, "malware.exe");
        e1.metadata["path"] = "C:\\Temp\\malware.exe";
        db_->InsertEvent(e1, 75);

        Event e2(EventType::NETWORK_CONNECT, 1234, "malware.exe");
        e2.metadata["remote_ip"] = "185.220.101.1";
        db_->InsertEvent(e2, 85);

        Event e3(EventType::REGISTRY_WRITE, 1234, "malware.exe");
        e3.metadata["key"] = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
        db_->InsertEvent(e3, 90);
    }

    void TearDown() override {
        exporter_.reset();
        audit_logger_.reset();
        mapper_.reset();
        db_->Shutdown();
        db_.reset();

        // Cleanup test outputs
        try {
            std::filesystem::remove_all("test_forensics_output");
            std::filesystem::remove("test_timeline.json");
        } catch (...) {}
    }

    std::unique_ptr<DatabaseManager> db_;
    std::unique_ptr<MitreMapper> mapper_;
    std::unique_ptr<AuditLogger> audit_logger_;
    std::unique_ptr<ForensicsExporter> exporter_;
};

TEST_F(ForensicsExporterTest, ExportTimeline) {
    std::string path = "test_timeline.json";
    EXPECT_TRUE(exporter_->ExportTimeline(0, 0, path));
    EXPECT_TRUE(std::filesystem::exists(path));
}

TEST_F(ForensicsExporterTest, ExportForensicsPackage) {
    std::string output_dir = "test_forensics_output";
    EXPECT_TRUE(exporter_->ExportForensicsPackage("TEST-CASE-001", 0, 0, output_dir));

    std::string pkg_dir = output_dir + "/TEST-CASE-001";
    EXPECT_TRUE(std::filesystem::exists(pkg_dir + "/timeline.json"));
    EXPECT_TRUE(std::filesystem::exists(pkg_dir + "/incidents.json"));
    EXPECT_TRUE(std::filesystem::exists(pkg_dir + "/manifest.json"));
}

TEST_F(ForensicsExporterTest, ManifestContainsFiles) {
    std::string output_dir = "test_forensics_output";
    exporter_->ExportForensicsPackage("TEST-CASE-002", 0, 0, output_dir);

    std::string manifest_path = output_dir + "/TEST-CASE-002/manifest.json";
    ASSERT_TRUE(std::filesystem::exists(manifest_path));

    std::ifstream f(manifest_path);
    std::string content((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());
    EXPECT_FALSE(content.empty());
    EXPECT_NE(content.find("TEST-CASE-002"), std::string::npos);
    EXPECT_NE(content.find("sha256"), std::string::npos);
}
