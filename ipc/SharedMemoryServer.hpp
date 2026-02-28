#pragma once

#include <string>
#include <cstdint>

// Forward declare HANDLE to avoid pulling in Windows headers
using HANDLE = void*;

namespace cortex {

#pragma pack(push, 1)
struct SharedStatus {
    uint32_t magic;                  // 0x43455452 ('CEDR') for validation
    uint32_t version;                // Protocol version = 1
    uint8_t  protection_active;      // 0 or 1
    uint32_t active_incident_count;
    uint32_t total_incident_count;
    uint32_t total_event_count;
    uint32_t highest_risk_score;
    uint64_t engine_uptime_ms;
    uint64_t last_updated_ms;        // epoch ms
    uint8_t  process_monitor_active;
    uint8_t  file_monitor_active;
    uint8_t  network_monitor_active;
    uint8_t  registry_monitor_active;
    char     engine_version[32];     // null-terminated
};
#pragma pack(pop)

constexpr uint32_t SHARED_STATUS_MAGIC = 0x43455452;  // 'CEDR'
constexpr uint32_t SHARED_STATUS_VERSION = 1;

class SharedMemoryServer {
public:
    SharedMemoryServer();
    ~SharedMemoryServer();

    bool Create(const std::string& name = "Local\\CortexEDR_SharedStatus");
    void Update(const SharedStatus& status);
    void Destroy();

private:
    HANDLE map_handle_{nullptr};
    SharedStatus* mapped_ptr_{nullptr};
    std::string name_;
};

} // namespace cortex
