#pragma once

#include "ipc/SharedMemoryServer.hpp"  // for SharedStatus struct
#include <string>
#include <optional>

namespace cortex {

class SharedMemoryClient {
public:
    SharedMemoryClient();
    ~SharedMemoryClient();

    bool Connect(const std::string& name = "Local\\CortexEDR_SharedStatus");
    void Disconnect();
    bool IsConnected() const;

    std::optional<SharedStatus> Read() const;

private:
    HANDLE map_handle_{nullptr};
    const SharedStatus* mapped_ptr_{nullptr};
};

} // namespace cortex
