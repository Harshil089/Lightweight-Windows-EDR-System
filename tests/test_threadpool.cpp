#include <gtest/gtest.h>
#include "core/ThreadPool.hpp"
#include <atomic>
#include <chrono>

using namespace cortex;

TEST(ThreadPoolTest, BasicExecution) {
    ThreadPool pool(2);
    std::atomic<int> counter{0};

    auto future = pool.Enqueue([&counter]() {
        counter++;
        return 42;
    });

    EXPECT_EQ(future.get(), 42);
    EXPECT_EQ(counter, 1);
}

TEST(ThreadPoolTest, MultipleTasksSequential) {
    ThreadPool pool(2);
    std::atomic<int> counter{0};

    std::vector<std::future<void>> futures;
    for (int i = 0; i < 10; ++i) {
        futures.push_back(pool.Enqueue([&counter]() {
            counter++;
        }));
    }

    for (auto& future : futures) {
        future.get();
    }

    EXPECT_EQ(counter, 10);
}

TEST(ThreadPoolTest, ReturnValues) {
    ThreadPool pool(2);

    auto future1 = pool.Enqueue([]() { return 1 + 1; });
    auto future2 = pool.Enqueue([]() { return 2 * 2; });
    auto future3 = pool.Enqueue([]() { return 3 + 3; });

    EXPECT_EQ(future1.get(), 2);
    EXPECT_EQ(future2.get(), 4);
    EXPECT_EQ(future3.get(), 6);
}

TEST(ThreadPoolTest, ShutdownWaitsForTasks) {
    auto pool = std::make_unique<ThreadPool>(2);
    std::atomic<bool> task_completed{false};

    pool->Enqueue([&task_completed]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        task_completed = true;
    });

    pool->Shutdown();
    EXPECT_TRUE(task_completed);
}
