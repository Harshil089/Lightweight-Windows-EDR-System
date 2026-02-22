#include <gtest/gtest.h>
#include "engine/RiskScorer.hpp"

using namespace cortex;

class RiskScorerTest : public ::testing::Test {
protected:
    RiskScorer scorer;
};

TEST_F(RiskScorerTest, InitialScoreIsZero) {
    auto risk = scorer.GetProcessRiskScore(1234);
    EXPECT_EQ(risk.score, 0);
    EXPECT_EQ(risk.level, RiskLevel::LOW);
}

TEST_F(RiskScorerTest, ProcessFromTempDirectory) {
    Event event(EventType::PROCESS_CREATE, 1234, "malware.exe");
    event.metadata["image_path"] = "C:\\Users\\User\\AppData\\Local\\Temp\\malware.exe";

    scorer.ProcessEvent(event);

    auto risk = scorer.GetProcessRiskScore(1234);
    EXPECT_GE(risk.score, 15);
}

TEST_F(RiskScorerTest, WriteToSystemDirectory) {
    Event event(EventType::FILE_MODIFY, 1234, "process.exe");
    event.metadata["file_path"] = "C:\\Windows\\System32\\malicious.dll";

    scorer.ProcessEvent(event);

    auto risk = scorer.GetProcessRiskScore(1234);
    EXPECT_GE(risk.score, 15);
}

TEST_F(RiskScorerTest, RegistryPersistence) {
    Event event(EventType::REGISTRY_WRITE, 1234, "process.exe");
    event.metadata["key_path"] = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";

    scorer.ProcessEvent(event);

    auto risk = scorer.GetProcessRiskScore(1234);
    EXPECT_GE(risk.score, 20);
}

TEST_F(RiskScorerTest, ExternalNetworkConnection) {
    Event event(EventType::NETWORK_CONNECT, 1234, "process.exe");
    event.metadata["remote_address"] = "185.220.101.5";
    event.metadata["remote_port"] = "443";

    scorer.ProcessEvent(event);

    auto risk = scorer.GetProcessRiskScore(1234);
    EXPECT_GE(risk.score, 10);
}

TEST_F(RiskScorerTest, SuspiciousPort) {
    Event event(EventType::NETWORK_CONNECT, 1234, "process.exe");
    event.metadata["remote_address"] = "1.2.3.4";
    event.metadata["remote_port"] = "4444";

    scorer.ProcessEvent(event);

    auto risk = scorer.GetProcessRiskScore(1234);
    EXPECT_GE(risk.score, 25);
}

TEST_F(RiskScorerTest, AccumulatedRiskScore) {
    Event event1(EventType::PROCESS_CREATE, 1234, "malware.exe");
    event1.metadata["image_path"] = "C:\\Temp\\malware.exe";
    scorer.ProcessEvent(event1);

    Event event2(EventType::REGISTRY_WRITE, 1234, "malware.exe");
    event2.metadata["key_path"] = "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
    scorer.ProcessEvent(event2);

    Event event3(EventType::NETWORK_CONNECT, 1234, "malware.exe");
    event3.metadata["remote_address"] = "185.220.101.5";
    event3.metadata["remote_port"] = "4444";
    scorer.ProcessEvent(event3);

    auto risk = scorer.GetProcessRiskScore(1234);
    EXPECT_GE(risk.score, 50);
}

TEST_F(RiskScorerTest, ClearProcessScore) {
    Event event(EventType::PROCESS_CREATE, 1234, "test.exe");
    event.metadata["image_path"] = "C:\\Temp\\test.exe";

    scorer.ProcessEvent(event);
    auto risk = scorer.GetProcessRiskScore(1234);
    EXPECT_GT(risk.score, 0);

    scorer.ClearProcessScore(1234);
    risk = scorer.GetProcessRiskScore(1234);
    EXPECT_EQ(risk.score, 0);
}

TEST_F(RiskScorerTest, CustomThresholds) {
    scorer.SetThresholds(20, 40, 60, 80);

    Event event(EventType::REGISTRY_WRITE, 1234, "process.exe");
    event.metadata["key_path"] = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
    scorer.ProcessEvent(event);

    auto risk = scorer.GetProcessRiskScore(1234);
    EXPECT_EQ(risk.level, RiskLevel::MEDIUM);
}
