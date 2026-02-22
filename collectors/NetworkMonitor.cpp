#include "collectors/NetworkMonitor.hpp"
#include <sstream>
#include <iomanip>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace cortex {

NetworkMonitor::NetworkMonitor(std::chrono::seconds poll_interval)
    : poll_interval_(poll_interval) {
}

NetworkMonitor::~NetworkMonitor() {
    Stop();
}

bool NetworkMonitor::Start() {
    if (running_) {
        LOG_WARN("NetworkMonitor already running");
        return true;
    }

    LOG_INFO("Starting NetworkMonitor with {}s poll interval", poll_interval_.count());

    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        LOG_ERROR("WSAStartup failed: {}", WSAGetLastError());
        return false;
    }

    running_ = true;
    stop_requested_ = false;
    monitor_thread_ = std::make_unique<std::thread>(&NetworkMonitor::MonitorThread, this);

    LOG_INFO("NetworkMonitor started successfully");
    return true;
}

void NetworkMonitor::Stop() {
    if (!running_) {
        return;
    }

    LOG_INFO("Stopping NetworkMonitor");
    stop_requested_ = true;

    if (monitor_thread_ && monitor_thread_->joinable()) {
        monitor_thread_->join();
    }

    WSACleanup();
    running_ = false;

    LOG_INFO("NetworkMonitor stopped");
}

void NetworkMonitor::MonitorThread() {
    while (!stop_requested_) {
        PollConnections();

        for (int i = 0; i < poll_interval_.count() * 10 && !stop_requested_; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}

void NetworkMonitor::PollConnections() {
    PollTcpConnections();
    PollUdpConnections();
}

void NetworkMonitor::PollTcpConnections() {
    PMIB_TCPTABLE_OWNER_PID tcp_table = nullptr;
    DWORD size = 0;
    DWORD result;

    result = GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (result != ERROR_INSUFFICIENT_BUFFER) {
        return;
    }

    tcp_table = static_cast<PMIB_TCPTABLE_OWNER_PID>(malloc(size));
    if (!tcp_table) {
        return;
    }

    result = GetExtendedTcpTable(tcp_table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (result != NO_ERROR) {
        free(tcp_table);
        return;
    }

    for (DWORD i = 0; i < tcp_table->dwNumEntries; ++i) {
        MIB_TCPROW_OWNER_PID& row = tcp_table->table[i];

        ConnectionInfo conn;
        conn.pid = row.dwOwningPid;
        conn.local_address = IpToString(row.dwLocalAddr);
        conn.local_port = ntohs(static_cast<USHORT>(row.dwLocalPort));
        conn.remote_address = IpToString(row.dwRemoteAddr);
        conn.remote_port = ntohs(static_cast<USHORT>(row.dwRemotePort));
        conn.protocol = "TCP";
        conn.state = row.dwState;

        std::string key = conn.GetKey();
        bool is_new = false;

        {
            std::lock_guard<std::mutex> lock(connections_mutex_);
            if (known_connections_.find(key) == known_connections_.end()) {
                known_connections_.insert(key);
                is_new = true;
            }
        }

        if (is_new && conn.state == MIB_TCP_STATE_ESTAB) {
            PublishConnectionEvent(conn, true);
        }
    }

    free(tcp_table);
}

void NetworkMonitor::PollUdpConnections() {
    PMIB_UDPTABLE_OWNER_PID udp_table = nullptr;
    DWORD size = 0;
    DWORD result;

    result = GetExtendedUdpTable(nullptr, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (result != ERROR_INSUFFICIENT_BUFFER) {
        return;
    }

    udp_table = static_cast<PMIB_UDPTABLE_OWNER_PID>(malloc(size));
    if (!udp_table) {
        return;
    }

    result = GetExtendedUdpTable(udp_table, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (result != NO_ERROR) {
        free(udp_table);
        return;
    }

    for (DWORD i = 0; i < udp_table->dwNumEntries; ++i) {
        MIB_UDPROW_OWNER_PID& row = udp_table->table[i];

        ConnectionInfo conn;
        conn.pid = row.dwOwningPid;
        conn.local_address = IpToString(row.dwLocalAddr);
        conn.local_port = ntohs(static_cast<USHORT>(row.dwLocalPort));
        conn.remote_address = "0.0.0.0";
        conn.remote_port = 0;
        conn.protocol = "UDP";
        conn.state = 0;

        std::string key = conn.GetKey();
        bool is_new = false;

        {
            std::lock_guard<std::mutex> lock(connections_mutex_);
            if (known_connections_.find(key) == known_connections_.end()) {
                known_connections_.insert(key);
                is_new = true;
            }
        }

        if (is_new) {
            PublishConnectionEvent(conn, true);
        }
    }

    free(udp_table);
}

std::string NetworkMonitor::IpToString(DWORD ip) {
    in_addr addr;
    addr.S_un.S_addr = ip;
    char buffer[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, buffer, INET_ADDRSTRLEN);
    return std::string(buffer);
}

void NetworkMonitor::PublishConnectionEvent(const ConnectionInfo& conn, bool is_new) {
    Event event(EventType::NETWORK_CONNECT, conn.pid, "NetworkMonitor");

    event.metadata["local_address"] = conn.local_address;
    event.metadata["local_port"] = std::to_string(conn.local_port);
    event.metadata["remote_address"] = conn.remote_address;
    event.metadata["remote_port"] = std::to_string(conn.remote_port);
    event.metadata["protocol"] = conn.protocol;
    event.metadata["state"] = std::to_string(conn.state);
    event.metadata["is_new"] = is_new ? "true" : "false";

    EventBus::Instance().Publish(event);

    LOG_DEBUG("Network connection detected: PID={} {}://{}:{} -> {}:{}",
              conn.pid,
              conn.protocol,
              conn.local_address,
              conn.local_port,
              conn.remote_address,
              conn.remote_port);
}

} // namespace cortex
