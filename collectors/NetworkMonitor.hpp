#pragma once

#include "core/EventBus.hpp"
#include "core/Logger.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <unordered_set>
#include <chrono>

namespace cortex {

struct ConnectionInfo {
    DWORD pid;
    std::string local_address;
    USHORT local_port;
    std::string remote_address;
    USHORT remote_port;
    std::string protocol;
    DWORD state;

    std::string GetKey() const {
        return protocol + ":" + std::to_string(pid) + ":" +
               local_address + ":" + std::to_string(local_port) + ":" +
               remote_address + ":" + std::to_string(remote_port);
    }
};

class NetworkMonitor {
public:
    explicit NetworkMonitor(std::chrono::seconds poll_interval = std::chrono::seconds(2));
    ~NetworkMonitor();

    NetworkMonitor(const NetworkMonitor&) = delete;
    NetworkMonitor& operator=(const NetworkMonitor&) = delete;

    bool Start();
    void Stop();
    bool IsRunning() const { return running_; }

private:
    void MonitorThread();
    void PollConnections();
    void PollTcpConnections();
    void PollUdpConnections();

    std::string IpToString(DWORD ip);
    void PublishConnectionEvent(const ConnectionInfo& conn, bool is_new);

    std::chrono::seconds poll_interval_;
    std::atomic<bool> running_{false};
    std::atomic<bool> stop_requested_{false};
    std::unique_ptr<std::thread> monitor_thread_;
    std::unordered_set<std::string> known_connections_;
    mutable std::mutex connections_mutex_;
};

} // namespace cortex
