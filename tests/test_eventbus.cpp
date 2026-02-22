#include <gtest/gtest.h>
#include "core/EventBus.hpp"
#include <atomic>

using namespace cortex;

class EventBusTest : public ::testing::Test {
protected:
    void SetUp() override {
        EventBus::Instance().Clear();
    }

    void TearDown() override {
        EventBus::Instance().Clear();
    }
};

TEST_F(EventBusTest, SubscribeAndPublish) {
    std::atomic<int> call_count{0};

    auto id = EventBus::Instance().Subscribe(
        EventType::PROCESS_CREATE,
        [&call_count](const Event& e) { call_count++; }
    );

    Event event(EventType::PROCESS_CREATE, 1234, "test.exe");
    EventBus::Instance().Publish(event);

    EXPECT_EQ(call_count, 1);
    EventBus::Instance().Unsubscribe(id);
}

TEST_F(EventBusTest, MultipleSubscribers) {
    std::atomic<int> count1{0};
    std::atomic<int> count2{0};

    auto id1 = EventBus::Instance().Subscribe(
        EventType::PROCESS_CREATE,
        [&count1](const Event& e) { count1++; }
    );

    auto id2 = EventBus::Instance().Subscribe(
        EventType::PROCESS_CREATE,
        [&count2](const Event& e) { count2++; }
    );

    Event event(EventType::PROCESS_CREATE, 1234, "test.exe");
    EventBus::Instance().Publish(event);

    EXPECT_EQ(count1, 1);
    EXPECT_EQ(count2, 1);

    EventBus::Instance().Unsubscribe(id1);
    EventBus::Instance().Unsubscribe(id2);
}

TEST_F(EventBusTest, Unsubscribe) {
    std::atomic<int> call_count{0};

    auto id = EventBus::Instance().Subscribe(
        EventType::PROCESS_CREATE,
        [&call_count](const Event& e) { call_count++; }
    );

    Event event(EventType::PROCESS_CREATE, 1234, "test.exe");
    EventBus::Instance().Publish(event);
    EXPECT_EQ(call_count, 1);

    EventBus::Instance().Unsubscribe(id);
    EventBus::Instance().Publish(event);
    EXPECT_EQ(call_count, 1);
}

TEST_F(EventBusTest, DifferentEventTypes) {
    std::atomic<int> process_count{0};
    std::atomic<int> file_count{0};

    auto id1 = EventBus::Instance().Subscribe(
        EventType::PROCESS_CREATE,
        [&process_count](const Event& e) { process_count++; }
    );

    auto id2 = EventBus::Instance().Subscribe(
        EventType::FILE_CREATE,
        [&file_count](const Event& e) { file_count++; }
    );

    Event process_event(EventType::PROCESS_CREATE, 1234, "test.exe");
    Event file_event(EventType::FILE_CREATE, 5678, "file.txt");

    EventBus::Instance().Publish(process_event);
    EventBus::Instance().Publish(file_event);

    EXPECT_EQ(process_count, 1);
    EXPECT_EQ(file_count, 1);

    EventBus::Instance().Unsubscribe(id1);
    EventBus::Instance().Unsubscribe(id2);
}
