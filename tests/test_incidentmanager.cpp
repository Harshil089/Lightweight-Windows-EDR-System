#include <gtest/gtest.h>
#include "response/IncidentManager.hpp"
#include "engine/RiskScorer.hpp"
#include <filesystem>
#include <thread>
#include <chrono>

using namespace cortex;

class IncidentManagerTest : public ::testing::Test {
protected:
    RiskScorer scorer;
    IncidentManager manager;

    void SetUp() override {
        EventBus::Instance().Clear();
        manager.Initialize(&scorer, "test_incidents");
        manager.Start();
    }

    void TearDown() override {
        manager.Stop();
        EventBus::Instance().Clear();
        std::filesystem::remove_all("test_incidents");
    }

    // Helper: publish a RISK_THRESHOLD_EXCEEDED event
    void PublishRiskEvent(uint32_t pid, const std::string& process_name,
                         const std::string& risk_level) {
        Event event(EventType::RISK_THRESHOLD_EXCEEDED, pid, process_name);
        event.metadata["risk_level"] = risk_level;
        EventBus::Instance().Publish(event);
    }

    // Helper: publish a CONTAINMENT_ACTION event
    void PublishContainmentEvent(uint32_t pid, const std::string& action,
                                const std::string& reason) {
        Event event(EventType::CONTAINMENT_ACTION, pid, "ContainmentManager");
        event.metadata["action"] = action;
        event.metadata["reason"] = reason;
        EventBus::Instance().Publish(event);
    }
};

TEST_F(IncidentManagerTest, IncidentCreatedOnRiskThreshold) {
    PublishRiskEvent(1234, "malware.exe", "MEDIUM");

    auto incidents = manager.ListIncidents();
    ASSERT_EQ(incidents.size(), 1);
    EXPECT_EQ(incidents[0].pid, 1234);
    EXPECT_EQ(incidents[0].process_name, "malware.exe");
    EXPECT_EQ(incidents[0].state, IncidentState::INVESTIGATING);
}

TEST_F(IncidentManagerTest, TransitionsToActiveOnHighRisk) {
    PublishRiskEvent(1234, "malware.exe", "HIGH");

    auto incidents = manager.ListIncidents();
    ASSERT_EQ(incidents.size(), 1);
    EXPECT_EQ(incidents[0].state, IncidentState::ACTIVE);
}

TEST_F(IncidentManagerTest, TransitionsToEscalatedOnCritical) {
    // First create an ACTIVE incident
    PublishRiskEvent(1234, "malware.exe", "HIGH");
    // Then escalate with CRITICAL
    PublishRiskEvent(1234, "malware.exe", "CRITICAL");

    auto incident = manager.GetIncident(manager.ListIncidents()[0].uuid);
    ASSERT_TRUE(incident.has_value());
    EXPECT_EQ(incident->state, IncidentState::ESCALATED);
}

TEST_F(IncidentManagerTest, TransitionsToContainedOnAction) {
    // Create an ACTIVE incident
    PublishRiskEvent(1234, "malware.exe", "HIGH");

    // Publish containment action
    PublishContainmentEvent(1234, "process_suspend", "high_risk_level");

    auto incidents = manager.ListIncidents();
    ASSERT_EQ(incidents.size(), 1);
    EXPECT_EQ(incidents[0].state, IncidentState::CONTAINED);
    EXPECT_EQ(incidents[0].containment_actions.size(), 1);
    EXPECT_EQ(incidents[0].containment_actions[0].action, "process_suspend");
}

TEST_F(IncidentManagerTest, CloseFromContained) {
    PublishRiskEvent(1234, "malware.exe", "HIGH");
    PublishContainmentEvent(1234, "process_terminate", "critical_risk_level");

    auto incidents = manager.ListIncidents();
    ASSERT_EQ(incidents.size(), 1);
    std::string uuid = incidents[0].uuid;

    EXPECT_TRUE(manager.CloseIncident(uuid));

    auto incident = manager.GetIncident(uuid);
    ASSERT_TRUE(incident.has_value());
    EXPECT_EQ(incident->state, IncidentState::CLOSED);
}

TEST_F(IncidentManagerTest, InvalidTransitionRejected) {
    PublishRiskEvent(1234, "malware.exe", "MEDIUM");

    auto incidents = manager.ListIncidents();
    std::string uuid = incidents[0].uuid;

    // Can't contain an INVESTIGATING incident directly
    EXPECT_FALSE(manager.ContainIncident(uuid));

    // Can't escalate an INVESTIGATING incident
    EXPECT_FALSE(manager.EscalateIncident(uuid));

    // State should still be INVESTIGATING
    auto incident = manager.GetIncident(uuid);
    ASSERT_TRUE(incident.has_value());
    EXPECT_EQ(incident->state, IncidentState::INVESTIGATING);
}

TEST_F(IncidentManagerTest, DuplicateEventsAppendToSameIncident) {
    PublishRiskEvent(1234, "malware.exe", "MEDIUM");
    PublishRiskEvent(1234, "malware.exe", "HIGH");

    auto incidents = manager.ListIncidents();
    ASSERT_EQ(incidents.size(), 1);
    EXPECT_EQ(incidents[0].associated_events.size(), 2);
    EXPECT_EQ(incidents[0].state, IncidentState::ACTIVE);
}

TEST_F(IncidentManagerTest, EscalateFromActive) {
    PublishRiskEvent(1234, "malware.exe", "HIGH");

    auto incidents = manager.ListIncidents();
    std::string uuid = incidents[0].uuid;

    EXPECT_TRUE(manager.EscalateIncident(uuid));

    auto incident = manager.GetIncident(uuid);
    ASSERT_TRUE(incident.has_value());
    EXPECT_EQ(incident->state, IncidentState::ESCALATED);
}

TEST_F(IncidentManagerTest, IncidentSerializedToFile) {
    PublishRiskEvent(1234, "malware.exe", "HIGH");

    // Check that a JSON file was created in the incidents directory
    bool found_file = false;
    for (const auto& entry : std::filesystem::directory_iterator("test_incidents")) {
        if (entry.path().extension() == ".json") {
            found_file = true;
            break;
        }
    }
    EXPECT_TRUE(found_file);
}

TEST_F(IncidentManagerTest, RiskTimelineTracked) {
    PublishRiskEvent(1234, "malware.exe", "MEDIUM");
    PublishRiskEvent(1234, "malware.exe", "HIGH");

    auto incidents = manager.ListIncidents();
    ASSERT_EQ(incidents.size(), 1);
    EXPECT_GE(incidents[0].risk_timeline.size(), 2);
}

TEST_F(IncidentManagerTest, ListAndGetIncidents) {
    PublishRiskEvent(1234, "malware1.exe", "MEDIUM");
    PublishRiskEvent(5678, "malware2.exe", "HIGH");

    auto incidents = manager.ListIncidents();
    ASSERT_EQ(incidents.size(), 2);

    EXPECT_EQ(manager.GetTotalIncidentCount(), 2);
    EXPECT_EQ(manager.GetActiveIncidentCount(), 2);

    // Verify GetIncident works
    auto incident = manager.GetIncident(incidents[0].uuid);
    ASSERT_TRUE(incident.has_value());
    EXPECT_EQ(incident->uuid, incidents[0].uuid);

    // Non-existent UUID returns nullopt
    auto missing = manager.GetIncident("non-existent-uuid");
    EXPECT_FALSE(missing.has_value());
}

TEST_F(IncidentManagerTest, StateHistoryRecorded) {
    PublishRiskEvent(1234, "malware.exe", "HIGH");
    PublishContainmentEvent(1234, "process_terminate", "high_risk");

    auto incidents = manager.ListIncidents();
    ASSERT_EQ(incidents.size(), 1);

    // NEW -> INVESTIGATING -> ACTIVE -> CONTAINED = 3 transitions
    EXPECT_EQ(incidents[0].state_history.size(), 3);
    EXPECT_EQ(incidents[0].state_history[0].from_state, IncidentState::NEW);
    EXPECT_EQ(incidents[0].state_history[0].to_state, IncidentState::INVESTIGATING);
    EXPECT_EQ(incidents[0].state_history[1].to_state, IncidentState::ACTIVE);
    EXPECT_EQ(incidents[0].state_history[2].to_state, IncidentState::CONTAINED);
}
