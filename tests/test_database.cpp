#include <gtest/gtest.h>
#include "persistence/DatabaseManager.hpp"
#include "core/EventBus.hpp"
#include <filesystem>

using namespace cortex;

class DatabaseManagerTest : public ::testing::Test {
protected:
    DatabaseManager db;

    void SetUp() override {
        ASSERT_TRUE(db.Initialize(":memory:"));
    }

    void TearDown() override {
        db.Shutdown();
    }
};

TEST_F(DatabaseManagerTest, InsertAndQueryEvent) {
    Event event(EventType::PROCESS_CREATE, 1234, "test.exe");
    event.metadata["image_path"] = "C:\\Temp\\test.exe";
    db.InsertEvent(event, 45);

    EXPECT_EQ(db.GetEventCount(), 1);

    auto results = db.QueryEventsJson("", 10, 0);
    ASSERT_EQ(results.size(), 1);
    EXPECT_TRUE(results[0].find("test.exe") != std::string::npos);
    EXPECT_TRUE(results[0].find("PROCESS_CREATE") != std::string::npos);
}

TEST_F(DatabaseManagerTest, InsertMultipleEvents) {
    for (int i = 0; i < 50; i++) {
        Event event(EventType::FILE_MODIFY, static_cast<uint32_t>(i), "proc_" + std::to_string(i));
        db.InsertEvent(event, i);
    }

    EXPECT_EQ(db.GetEventCount(), 50);

    // Test limit
    auto page1 = db.QueryEventsJson("", 10, 0);
    EXPECT_EQ(page1.size(), 10);

    // Test offset
    auto page2 = db.QueryEventsJson("", 10, 10);
    EXPECT_EQ(page2.size(), 10);
}

TEST_F(DatabaseManagerTest, QueryEventsByType) {
    Event e1(EventType::PROCESS_CREATE, 100, "proc1.exe");
    Event e2(EventType::FILE_MODIFY, 200, "proc2.exe");
    Event e3(EventType::PROCESS_CREATE, 300, "proc3.exe");
    db.InsertEvent(e1, 10);
    db.InsertEvent(e2, 20);
    db.InsertEvent(e3, 30);

    auto results = db.QueryEventsJson("event_type = 'PROCESS_CREATE'", 100, 0);
    EXPECT_EQ(results.size(), 2);
}

TEST_F(DatabaseManagerTest, UpsertAndLoadIncident) {
    Incident incident;
    incident.uuid = "test-uuid-1234";
    incident.pid = 5678;
    incident.process_name = "malware.exe";
    incident.state = IncidentState::ACTIVE;
    incident.created_at = 1000000;
    incident.updated_at = 2000000;

    StateTransition trans;
    trans.from_state = IncidentState::NEW;
    trans.to_state = IncidentState::ACTIVE;
    trans.timestamp = 1500000;
    trans.reason = "Risk escalation";
    incident.state_history.push_back(trans);

    db.UpsertIncident(incident);

    auto loaded = db.LoadIncident("test-uuid-1234");
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(loaded->uuid, "test-uuid-1234");
    EXPECT_EQ(loaded->pid, 5678);
    EXPECT_EQ(loaded->process_name, "malware.exe");
    EXPECT_EQ(loaded->state, IncidentState::ACTIVE);
    EXPECT_EQ(loaded->state_history.size(), 1);
    EXPECT_EQ(loaded->state_history[0].reason, "Risk escalation");
}

TEST_F(DatabaseManagerTest, UpsertIncidentUpdate) {
    Incident incident;
    incident.uuid = "update-test";
    incident.pid = 100;
    incident.process_name = "proc.exe";
    incident.state = IncidentState::NEW;
    incident.created_at = 1000;
    incident.updated_at = 1000;

    db.UpsertIncident(incident);

    // Update state
    incident.state = IncidentState::CONTAINED;
    incident.updated_at = 2000;
    db.UpsertIncident(incident);

    auto loaded = db.LoadIncident("update-test");
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(loaded->state, IncidentState::CONTAINED);
}

TEST_F(DatabaseManagerTest, LoadAllIncidents) {
    for (int i = 0; i < 5; i++) {
        Incident incident;
        incident.uuid = "uuid-" + std::to_string(i);
        incident.pid = static_cast<uint32_t>(i);
        incident.process_name = "proc_" + std::to_string(i);
        incident.state = IncidentState::INVESTIGATING;
        incident.created_at = 1000;
        incident.updated_at = 2000;
        db.UpsertIncident(incident);
    }

    auto all = db.LoadAllIncidents();
    EXPECT_EQ(all.size(), 5);
}

TEST_F(DatabaseManagerTest, EventCountAccuracy) {
    EXPECT_EQ(db.GetEventCount(), 0);

    for (int i = 0; i < 25; i++) {
        Event event(EventType::NETWORK_CONNECT, static_cast<uint32_t>(i), "net.exe");
        db.InsertEvent(event, 5);
    }

    EXPECT_EQ(db.GetEventCount(), 25);
}

TEST_F(DatabaseManagerTest, StatusSnapshot) {
    // Insert some events
    for (int i = 0; i < 10; i++) {
        Event event(EventType::PROCESS_CREATE, static_cast<uint32_t>(i), "proc.exe");
        db.InsertEvent(event, i * 10);
    }

    // Insert incidents
    Incident active;
    active.uuid = "active-1";
    active.pid = 1;
    active.process_name = "proc.exe";
    active.state = IncidentState::ACTIVE;
    active.created_at = 1000;
    active.updated_at = 2000;
    db.UpsertIncident(active);

    Incident closed;
    closed.uuid = "closed-1";
    closed.pid = 2;
    closed.process_name = "proc2.exe";
    closed.state = IncidentState::CLOSED;
    closed.created_at = 1000;
    closed.updated_at = 2000;
    db.UpsertIncident(closed);

    auto snap = db.GetStatusSnapshot();
    EXPECT_EQ(snap.total_event_count, 10);
    EXPECT_EQ(snap.active_incident_count, 1);  // Only non-CLOSED
    EXPECT_EQ(snap.highest_risk_score, 90);     // 9 * 10
}

TEST_F(DatabaseManagerTest, EmptyDatabaseReturnsEmptyResults) {
    auto events = db.QueryEventsJson("", 100, 0);
    EXPECT_TRUE(events.empty());

    auto incidents = db.LoadAllIncidents();
    EXPECT_TRUE(incidents.empty());

    auto missing = db.LoadIncident("nonexistent");
    EXPECT_FALSE(missing.has_value());

    EXPECT_EQ(db.GetEventCount(), 0);
}

// Test that data survives shutdown/reinitialize using a temp file
TEST_F(DatabaseManagerTest, IncidentSurvivesReopen) {
    // Use a file-based database for this test
    DatabaseManager fileDb;
    std::string path = "test_persist.db";
    ASSERT_TRUE(fileDb.Initialize(path));

    Incident incident;
    incident.uuid = "persist-test";
    incident.pid = 999;
    incident.process_name = "persist.exe";
    incident.state = IncidentState::ESCALATED;
    incident.created_at = 5000;
    incident.updated_at = 6000;
    fileDb.UpsertIncident(incident);

    fileDb.Shutdown();

    // Reopen
    DatabaseManager fileDb2;
    ASSERT_TRUE(fileDb2.Initialize(path));

    auto loaded = fileDb2.LoadIncident("persist-test");
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(loaded->process_name, "persist.exe");
    EXPECT_EQ(loaded->state, IncidentState::ESCALATED);

    fileDb2.Shutdown();
    std::filesystem::remove(path);
}
