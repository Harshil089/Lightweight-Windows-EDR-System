#include "core/WindowsHeaders.hpp"
#include "ipc/SharedMemoryClient.hpp"
#include <cstring>

namespace cortex {

SharedMemoryClient::SharedMemoryClient() = default;

SharedMemoryClient::~SharedMemoryClient() {
    Disconnect();
}

bool SharedMemoryClient::Connect(const std::string& name) {
    // Convert name to wide string
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, name.c_str(),
                                          static_cast<int>(name.size()), nullptr, 0);
    std::wstring wide_name(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, name.c_str(),
                       static_cast<int>(name.size()), &wide_name[0], size_needed);

    map_handle_ = OpenFileMappingW(
        FILE_MAP_READ,
        FALSE,
        wide_name.c_str()
    );

    if (!map_handle_) {
        return false;
    }

    mapped_ptr_ = static_cast<const SharedStatus*>(
        MapViewOfFile(map_handle_, FILE_MAP_READ, 0, 0, sizeof(SharedStatus))
    );

    if (!mapped_ptr_) {
        CloseHandle(map_handle_);
        map_handle_ = nullptr;
        return false;
    }

    return true;
}

void SharedMemoryClient::Disconnect() {
    if (mapped_ptr_) {
        UnmapViewOfFile(mapped_ptr_);
        mapped_ptr_ = nullptr;
    }
    if (map_handle_) {
        CloseHandle(map_handle_);
        map_handle_ = nullptr;
    }
}

bool SharedMemoryClient::IsConnected() const {
    return mapped_ptr_ != nullptr;
}

std::optional<SharedStatus> SharedMemoryClient::Read() const {
    if (!mapped_ptr_) return std::nullopt;

    SharedStatus status;
    std::memcpy(&status, mapped_ptr_, sizeof(SharedStatus));

    // Validate magic number
    if (status.magic != SHARED_STATUS_MAGIC) {
        return std::nullopt;
    }

    return status;
}

} // namespace cortex
