#include "core/WindowsHeaders.hpp"
#include <gtest/gtest.h>
#include "core/EventBus.hpp"
#include "engine/RiskScorer.hpp"
#include "response/IncidentManager.hpp"
#include "telemetry/TelemetryExporter.hpp"
#include "persistence/DatabaseManager.hpp"
#include "ipc/PipeClient.hpp"
#include "ipc/SharedMemoryServer.hpp"
#include "ipc/SharedMemoryClient.hpp"
#include <thread>
#include <chrono>
#include <mutex>
#include <condition_variable>
#include <filesystem>

using namespace cortex;

class E2EBridgeTest : public ::testing::Test {
protected:
    RiskScorer scorer;
    IncidentManager incident_manager;
    TelemetryExporter telemetry_exporter;
    DatabaseManager database;

    void SetUp() override {
        EventBus::Instance().Clear();
        EventBus::Instance().InitAsyncPool(2);

        // Initialize database in memory
        ASSERT_TRUE(database.Initialize(":memory:"));

        // Initialize incident manager
        incident_manager.Initialize(&scorer, "test_e2e_incidents");
        incident_manager.SetDatabaseManager(&database);
        incident_manager.Start();

        // Initialize telemetry with named pipe enabled
        telemetry_exporter.Initialize(&scorer, true,
            "test_e2e_telemetry/events.ndjson", true,
            "\\\\.\\pipe\\CortexEDR_E2E_Test");
        telemetry_exporter.SetDatabaseManager(&database);
        telemetry_exporter.Start();
    }

    void TearDown() override {
        telemetry_exporter.Stop();
        incident_manager.Stop();
        EventBus::Instance().ShutdownAsyncPool();
        EventBus::Instance().Clear();
        database.Shutdown();
        std::filesystem::remove_all("test_e2e_incidents");
        std::filesystem::remove_all("test_e2e_telemetry");
    }
};

TEST_F(E2EBridgeTest, SyntheticEventReachesPipeClient) {
    std::mutex mtx;
    std::condition_variable cv;
    std::string received;
    bool got_message = false;

    PipeClient client;
    client.Start("\\\\.\\pipe\\CortexEDR_E2E_Test", [&](const std::string& line) {
        std::lock_guard<std::mutex> lock(mtx);
        if (!got_message) {  // Only capture first message
            received = line;
            got_message = true;
            cv.notify_one();
        }
    });

    // Give client time to connect
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // Publish event through EventBus
    Event event(EventType::PROCESS_CREATE, 9999, "e2e_test.exe");
    event.metadata["image_path"] = "C:\\Temp\\e2e_test.exe";
    EventBus::Instance().Publish(event);

    // Wait for message
    {
        std::unique_lock<std::mutex> lock(mtx);
        cv.wait_for(lock, std::chrono::seconds(5), [&] { return got_message; });
    }

    client.Stop();

    EXPECT_TRUE(got_message);
    EXPECT_TRUE(received.find("e2e_test.exe") != std::string::npos);
    EXPECT_TRUE(received.find("PROCESS_CREATE") != std::string::npos);
}

TEST_F(E2EBridgeTest, EventPersistedToSQLite) {
    // Publish events through EventBus
    for (int i = 0; i < 5; i++) {
        Event event(EventType::FILE_MODIFY, static_cast<uint32_t>(i + 100), "file_test.exe");
        EventBus::Instance().Publish(event);
    }

    // Brief wait for event processing
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    size_t count = database.GetEventCount();
    EXPECT_GE(count, 5);
}

TEST_F(E2EBridgeTest, IncidentCreatedAndPersistedToSQLite) {
    // Publish a risk threshold exceeded event
    Event event(EventType::RISK_THRESHOLD_EXCEEDED, 7777, "risky.exe");
    event.metadata["risk_level"] = "HIGH";
    EventBus::Instance().Publish(event);

    // Wait for processing
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // Verify in-memory incident
    EXPECT_GE(incident_manager.GetTotalIncidentCount(), 1);

    // Verify in SQLite
    auto incidents = database.LoadAllIncidents();
    EXPECT_GE(incidents.size(), 1);

    bool found = false;
    for (const auto& inc : incidents) {
        if (inc.process_name == "risky.exe") {
            found = true;
            EXPECT_EQ(inc.pid, 7777);
            break;
        }
    }
    EXPECT_TRUE(found);
}

TEST_F(E2EBridgeTest, SharedMemoryReflectsState) {
    SharedMemoryServer server;
    SharedMemoryClient client;

    std::string shm_name = "Local\\CortexEDR_E2E_SHM";
    ASSERT_TRUE(server.Create(shm_name));
    ASSERT_TRUE(client.Connect(shm_name));

    // Simulate what main.cpp Run() loop does
    SharedStatus status{};
    status.magic = SHARED_STATUS_MAGIC;
    status.version = SHARED_STATUS_VERSION;
    status.protection_active = 1;
    status.active_incident_count = static_cast<uint32_t>(incident_manager.GetActiveIncidentCount());
    status.total_event_count = static_cast<uint32_t>(telemetry_exporter.GetExportedEventCount());
    status.process_monitor_active = 1;
    status.file_monitor_active = 1;
    status.network_monitor_active = 1;
    status.registry_monitor_active = 1;

    server.Update(status);

    auto read = client.Read();
    ASSERT_TRUE(read.has_value());
    EXPECT_EQ(read->protection_active, 1);
    EXPECT_EQ(read->process_monitor_active, 1);

    client.Disconnect();
    server.Destroy();
}
