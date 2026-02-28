#include "core/WindowsHeaders.hpp"
#include "ipc/PipeClient.hpp"
#include <chrono>
#include <string>

namespace cortex {

PipeClient::PipeClient() = default;

PipeClient::~PipeClient() {
    Stop();
}

void PipeClient::Start(const std::string& pipe_name, MessageCallback callback) {
    if (running_) return;

    pipe_name_ = pipe_name;
    callback_ = std::move(callback);
    running_ = true;

    reader_thread_ = std::thread(&PipeClient::ReaderLoop, this);
}

void PipeClient::Stop() {
    running_ = false;

    // Cancel any blocking I/O on the pipe handle
    HANDLE h = pipe_handle_.load();
    if (h != INVALID_HANDLE_VALUE) {
        CancelIoEx(h, nullptr);
    }

    if (reader_thread_.joinable()) {
        reader_thread_.join();
    }
    connected_ = false;
}

void PipeClient::ReaderLoop() {
    constexpr DWORD BUFFER_SIZE = 65536;
    char buffer[BUFFER_SIZE];
    std::string partial_line;

    while (running_) {
        // Convert pipe name to wide string
        int size_needed = MultiByteToWideChar(CP_UTF8, 0, pipe_name_.c_str(),
                                              static_cast<int>(pipe_name_.size()), nullptr, 0);
        std::wstring wide_name(size_needed, 0);
        MultiByteToWideChar(CP_UTF8, 0, pipe_name_.c_str(),
                           static_cast<int>(pipe_name_.size()), &wide_name[0], size_needed);

        // Try to connect to the pipe
        HANDLE pipe = CreateFileW(
            wide_name.c_str(),
            GENERIC_READ,
            0,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED,
            nullptr
        );

        if (pipe == INVALID_HANDLE_VALUE) {
            connected_ = false;
            // Retry after 2 seconds
            for (int i = 0; i < 20 && running_; ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            continue;
        }

        // Set pipe to message read mode
        DWORD mode = PIPE_READMODE_MESSAGE;
        SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr);

        pipe_handle_ = pipe;
        connected_ = true;
        partial_line.clear();

        // Create event for overlapped I/O
        HANDLE read_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);

        // Read loop
        while (running_) {
            OVERLAPPED overlapped{};
            overlapped.hEvent = read_event;

            DWORD bytes_read = 0;
            BOOL success = ReadFile(pipe, buffer, BUFFER_SIZE - 1, &bytes_read, &overlapped);

            if (!success) {
                DWORD error = GetLastError();
                if (error == ERROR_IO_PENDING) {
                    // Wait for completion or cancellation
                    DWORD wait_result = WaitForSingleObject(read_event, 500);
                    if (wait_result == WAIT_TIMEOUT) {
                        if (!running_) {
                            CancelIoEx(pipe, &overlapped);
                            GetOverlappedResult(pipe, &overlapped, &bytes_read, TRUE);
                            break;
                        }
                        CancelIoEx(pipe, &overlapped);
                        GetOverlappedResult(pipe, &overlapped, &bytes_read, TRUE);
                        continue;
                    }
                    if (!GetOverlappedResult(pipe, &overlapped, &bytes_read, FALSE)) {
                        DWORD ov_error = GetLastError();
                        if (ov_error == ERROR_BROKEN_PIPE || ov_error == ERROR_PIPE_NOT_CONNECTED ||
                            ov_error == ERROR_OPERATION_ABORTED) {
                            break;
                        }
                        if (ov_error == ERROR_MORE_DATA) {
                            buffer[bytes_read] = '\0';
                            partial_line += buffer;
                            continue;
                        }
                        break;
                    }
                } else if (error == ERROR_BROKEN_PIPE || error == ERROR_PIPE_NOT_CONNECTED) {
                    break;
                } else if (error == ERROR_MORE_DATA) {
                    buffer[bytes_read] = '\0';
                    partial_line += buffer;
                    continue;
                } else {
                    break;
                }
            }

            if (bytes_read == 0) continue;

            buffer[bytes_read] = '\0';
            partial_line += buffer;

            // Split by newlines and dispatch complete lines
            size_t pos = 0;
            size_t newline_pos;
            while ((newline_pos = partial_line.find('\n', pos)) != std::string::npos) {
                std::string line = partial_line.substr(pos, newline_pos - pos);
                if (!line.empty() && line.back() == '\r') {
                    line.pop_back();
                }
                if (!line.empty() && callback_) {
                    callback_(line);
                }
                pos = newline_pos + 1;
            }
            partial_line = partial_line.substr(pos);
        }

        CloseHandle(read_event);
        pipe_handle_ = INVALID_HANDLE_VALUE;
        CloseHandle(pipe);
        connected_ = false;

        // Brief pause before reconnecting
        if (running_) {
            for (int i = 0; i < 20 && running_; ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
    }
}

} // namespace cortex
