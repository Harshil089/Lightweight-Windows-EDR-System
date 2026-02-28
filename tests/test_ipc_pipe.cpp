#include "core/WindowsHeaders.hpp"
#include <gtest/gtest.h>
#include "ipc/PipeClient.hpp"
#include <thread>
#include <chrono>
#include <atomic>
#include <mutex>
#include <vector>
#include <string>
#include <condition_variable>

using namespace cortex;

class PipeIPCTest : public ::testing::Test {
protected:
    HANDLE server_pipe_{INVALID_HANDLE_VALUE};
    std::string pipe_name_ = "\\\\.\\pipe\\CortexEDR_Test_Pipe";

    void SetUp() override {
        CreateServerPipe();
    }

    void TearDown() override {
        DestroyServerPipe();
    }

    void CreateServerPipe() {
        std::wstring wide_name(pipe_name_.begin(), pipe_name_.end());
        server_pipe_ = CreateNamedPipeW(
            wide_name.c_str(),
            PIPE_ACCESS_OUTBOUND,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1, 65536, 0, 5000, nullptr
        );
        ASSERT_NE(server_pipe_, INVALID_HANDLE_VALUE);
    }

    void DestroyServerPipe() {
        if (server_pipe_ != INVALID_HANDLE_VALUE) {
            DisconnectNamedPipe(server_pipe_);
            CloseHandle(server_pipe_);
            server_pipe_ = INVALID_HANDLE_VALUE;
        }
    }

    void WriteToPipe(const std::string& message) {
        std::string line = message + "\n";
        DWORD bytes_written = 0;
        WriteFile(server_pipe_, line.c_str(),
                  static_cast<DWORD>(line.size()), &bytes_written, nullptr);
    }
};

TEST_F(PipeIPCTest, ClientConnectsAndReceivesMessage) {
    std::mutex mtx;
    std::condition_variable cv;
    std::string received;
    bool got_message = false;

    PipeClient client;
    client.Start(pipe_name_, [&](const std::string& line) {
        std::lock_guard<std::mutex> lock(mtx);
        received = line;
        got_message = true;
        cv.notify_one();
    });

    // Wait for client to connect
    ConnectNamedPipe(server_pipe_, nullptr);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Write a message
    WriteToPipe("{\"event_type\":\"PROCESS_CREATE\",\"pid\":1234}");

    // Wait for message receipt
    {
        std::unique_lock<std::mutex> lock(mtx);
        cv.wait_for(lock, std::chrono::seconds(5), [&] { return got_message; });
    }

    client.Stop();

    EXPECT_TRUE(got_message);
    EXPECT_TRUE(received.find("PROCESS_CREATE") != std::string::npos);
    EXPECT_TRUE(received.find("1234") != std::string::npos);
}

TEST_F(PipeIPCTest, ClientReceivesMultipleMessages) {
    std::mutex mtx;
    std::condition_variable cv;
    std::vector<std::string> messages;

    PipeClient client;
    client.Start(pipe_name_, [&](const std::string& line) {
        std::lock_guard<std::mutex> lock(mtx);
        messages.push_back(line);
        cv.notify_one();
    });

    ConnectNamedPipe(server_pipe_, nullptr);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Write 5 messages
    for (int i = 0; i < 5; i++) {
        WriteToPipe("{\"id\":" + std::to_string(i) + "}");
    }

    // Wait for all messages
    {
        std::unique_lock<std::mutex> lock(mtx);
        cv.wait_for(lock, std::chrono::seconds(5), [&] { return messages.size() >= 5; });
    }

    client.Stop();

    EXPECT_GE(messages.size(), 5);
}

TEST_F(PipeIPCTest, ClientReportsConnectedState) {
    PipeClient client;

    EXPECT_FALSE(client.IsConnected());

    client.Start(pipe_name_, [](const std::string&) {});

    // Wait for client to connect
    ConnectNamedPipe(server_pipe_, nullptr);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    EXPECT_TRUE(client.IsConnected());

    client.Stop();
    EXPECT_FALSE(client.IsConnected());
}
