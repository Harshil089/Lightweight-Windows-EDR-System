#include <gtest/gtest.h>
#include "ipc/SharedMemoryServer.hpp"
#include "ipc/SharedMemoryClient.hpp"
#include <cstring>

using namespace cortex;

class SharedMemoryTest : public ::testing::Test {
protected:
    SharedMemoryServer server;
    SharedMemoryClient client;
    std::string test_name = "Local\\CortexEDR_Test_SHM";

    void TearDown() override {
        client.Disconnect();
        server.Destroy();
    }
};

TEST_F(SharedMemoryTest, ClientReadsServerWrites) {
    ASSERT_TRUE(server.Create(test_name));
    ASSERT_TRUE(client.Connect(test_name));

    SharedStatus status{};
    status.magic = SHARED_STATUS_MAGIC;
    status.version = SHARED_STATUS_VERSION;
    status.protection_active = 1;
    status.active_incident_count = 3;
    status.total_incident_count = 10;
    status.total_event_count = 500;
    status.highest_risk_score = 85;
    status.engine_uptime_ms = 60000;
    status.last_updated_ms = 1234567890;
    status.process_monitor_active = 1;
    status.file_monitor_active = 1;
    status.network_monitor_active = 0;
    status.registry_monitor_active = 1;
    strncpy_s(status.engine_version, sizeof(status.engine_version), "1.0.0", _TRUNCATE);

    server.Update(status);

    auto read = client.Read();
    ASSERT_TRUE(read.has_value());
    EXPECT_EQ(read->magic, SHARED_STATUS_MAGIC);
    EXPECT_EQ(read->version, SHARED_STATUS_VERSION);
    EXPECT_EQ(read->protection_active, 1);
    EXPECT_EQ(read->active_incident_count, 3);
    EXPECT_EQ(read->total_incident_count, 10);
    EXPECT_EQ(read->total_event_count, 500);
    EXPECT_EQ(read->highest_risk_score, 85);
    EXPECT_EQ(read->engine_uptime_ms, 60000);
    EXPECT_EQ(read->process_monitor_active, 1);
    EXPECT_EQ(read->network_monitor_active, 0);
    EXPECT_STREQ(read->engine_version, "1.0.0");
}

TEST_F(SharedMemoryTest, ClientDetectsUpdate) {
    ASSERT_TRUE(server.Create(test_name));
    ASSERT_TRUE(client.Connect(test_name));

    // Write status A
    SharedStatus statusA{};
    statusA.magic = SHARED_STATUS_MAGIC;
    statusA.version = SHARED_STATUS_VERSION;
    statusA.active_incident_count = 1;
    server.Update(statusA);

    auto readA = client.Read();
    ASSERT_TRUE(readA.has_value());
    EXPECT_EQ(readA->active_incident_count, 1);

    // Write status B
    SharedStatus statusB{};
    statusB.magic = SHARED_STATUS_MAGIC;
    statusB.version = SHARED_STATUS_VERSION;
    statusB.active_incident_count = 5;
    server.Update(statusB);

    auto readB = client.Read();
    ASSERT_TRUE(readB.has_value());
    EXPECT_EQ(readB->active_incident_count, 5);
}

TEST_F(SharedMemoryTest, ClientWithoutServerFails) {
    // Don't create server
    bool connected = client.Connect("Local\\NonExistent_Test_SHM");
    EXPECT_FALSE(connected);
    EXPECT_FALSE(client.IsConnected());
}

TEST_F(SharedMemoryTest, ReadWithoutConnectionReturnsNullopt) {
    auto read = client.Read();
    EXPECT_FALSE(read.has_value());
}
