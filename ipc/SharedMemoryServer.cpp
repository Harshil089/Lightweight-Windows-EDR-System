#include "core/WindowsHeaders.hpp"
#include "ipc/SharedMemoryServer.hpp"
#include "core/Logger.hpp"
#include <cstring>

namespace cortex {

SharedMemoryServer::SharedMemoryServer() = default;

SharedMemoryServer::~SharedMemoryServer() {
    Destroy();
}

bool SharedMemoryServer::Create(const std::string& name) {
    name_ = name;

    // Convert name to wide string
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, name_.c_str(),
                                          static_cast<int>(name_.size()), nullptr, 0);
    std::wstring wide_name(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, name_.c_str(),
                       static_cast<int>(name_.size()), &wide_name[0], size_needed);

    map_handle_ = CreateFileMappingW(
        INVALID_HANDLE_VALUE,
        nullptr,
        PAGE_READWRITE,
        0,
        sizeof(SharedStatus),
        wide_name.c_str()
    );

    if (!map_handle_) {
        LOG_ERROR("SharedMemoryServer: Failed to create file mapping {}: {}", name_, GetLastError());
        return false;
    }

    mapped_ptr_ = static_cast<SharedStatus*>(
        MapViewOfFile(map_handle_, FILE_MAP_WRITE, 0, 0, sizeof(SharedStatus))
    );

    if (!mapped_ptr_) {
        LOG_ERROR("SharedMemoryServer: Failed to map view: {}", GetLastError());
        CloseHandle(map_handle_);
        map_handle_ = nullptr;
        return false;
    }

    // Initialize with default values
    std::memset(mapped_ptr_, 0, sizeof(SharedStatus));
    mapped_ptr_->magic = SHARED_STATUS_MAGIC;
    mapped_ptr_->version = SHARED_STATUS_VERSION;
    strncpy_s(mapped_ptr_->engine_version, sizeof(mapped_ptr_->engine_version), "1.0.0", _TRUNCATE);

    LOG_INFO("SharedMemoryServer created: {}", name_);
    return true;
}

void SharedMemoryServer::Update(const SharedStatus& status) {
    if (!mapped_ptr_) return;

    // Copy the entire struct atomically (small enough for a single memcpy)
    std::memcpy(mapped_ptr_, &status, sizeof(SharedStatus));
    // Ensure magic and version are always correct
    mapped_ptr_->magic = SHARED_STATUS_MAGIC;
    mapped_ptr_->version = SHARED_STATUS_VERSION;
}

void SharedMemoryServer::Destroy() {
    if (mapped_ptr_) {
        UnmapViewOfFile(mapped_ptr_);
        mapped_ptr_ = nullptr;
    }
    if (map_handle_) {
        CloseHandle(map_handle_);
        map_handle_ = nullptr;
        LOG_INFO("SharedMemoryServer destroyed");
    }
}

} // namespace cortex
