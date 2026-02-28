#pragma once

#include <string>
#include <functional>
#include <atomic>
#include <thread>

namespace cortex {

class PipeClient {
public:
    using MessageCallback = std::function<void(const std::string& json_line)>;

    PipeClient();
    ~PipeClient();

    void Start(const std::string& pipe_name, MessageCallback callback);
    void Stop();
    bool IsConnected() const { return connected_; }

private:
    void ReaderLoop();

    std::string pipe_name_;
    MessageCallback callback_;
    std::atomic<bool> running_{false};
    std::atomic<bool> connected_{false};
    std::atomic<void*> pipe_handle_{(void*)(~(uintptr_t)0)};  // INVALID_HANDLE_VALUE
    std::thread reader_thread_;
};

} // namespace cortex
