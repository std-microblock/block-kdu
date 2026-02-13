/* Driver loading/unloading utilities implementation */

#include "driver_exploit.h"
#include <windows.h>
#include <print>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>

namespace kdu::core {

namespace fs = std::filesystem;

std::expected<HANDLE, std::string> IDriverProvider::load_driver_from_memory(
    const uint8_t* driver_data,
    size_t driver_size,
    const std::wstring& service_name,
    const std::wstring& device_name) noexcept {
    if (!driver_data || driver_size == 0) {
        return std::unexpected("Invalid driver data");
    }

    auto driver_path =
        std::filesystem::current_path() / (service_name + L".sys");

    std::println("Driver path: {}, svc name: {}", driver_path.string(),
                 std::filesystem::path(service_name).string());

    std::ignore = unload_driver(service_name);
    // Write driver to file
    try {
        std::ofstream file(driver_path, std::ios::binary);
        if (!file) {
            return std::unexpected("Failed to open driver file for writing");
        }
        file.write(reinterpret_cast<const char*>(driver_data), driver_size);
        file.close();

        // Verify file was written
        if (!fs::exists(driver_path)) {
            return std::unexpected("Driver file not found after writing");
        }
        std::println("Driver file written successfully: {}",
                     driver_path.string());
    } catch (const std::exception& e) {
        return std::unexpected(std::string("Failed to write driver: ") +
                               e.what());
    } catch (...) {
        return std::unexpected("Failed to write driver to file");
    }

    // Open SC Manager
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        DeleteFileW(driver_path.c_str());
        return std::unexpected("Failed to open SC Manager");
    }

    // Create service
    SC_HANDLE service = CreateServiceW(
        scm, service_name.c_str(), service_name.c_str(),
        SERVICE_START | SERVICE_STOP | DELETE, SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, driver_path.c_str(),
        nullptr, nullptr, nullptr, nullptr, nullptr);

    if (!service) {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_EXISTS ||
            error == ERROR_DUPLICATE_SERVICE_NAME) {
            // Service already exists, clean it up first
            CloseServiceHandle(scm);

            // Reopen SC Manager and try again
            scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
            if (!scm) {
                DeleteFileW(driver_path.c_str());
                return std::unexpected("Failed to reopen SC Manager");
            }

            service = CreateServiceW(
                scm, service_name.c_str(), service_name.c_str(),
                SERVICE_START | SERVICE_STOP | DELETE, SERVICE_KERNEL_DRIVER,
                SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, driver_path.c_str(),
                nullptr, nullptr, nullptr, nullptr, nullptr);
        }

        if (!service) {
            CloseServiceHandle(scm);
            DeleteFileW(driver_path.c_str());
            return std::unexpected("Failed to create service: " +
                                   std::to_string(GetLastError()));
        }
    }

    // Start service
    if (!StartServiceW(service, 0, nullptr)) {
        DWORD error = GetLastError();
        if (error != ERROR_SERVICE_ALREADY_RUNNING) {
            CloseServiceHandle(service);
            CloseServiceHandle(scm);
            return std::unexpected("Failed to start service: " +
                                   std::to_string(error));
        }
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);

    // Open device
    HANDLE device =
        CreateFileW(device_name.c_str(), GENERIC_READ | GENERIC_WRITE, 0,
                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (device == INVALID_HANDLE_VALUE) {
        std::ignore = unload_driver(service_name);
        return std::unexpected("Failed to open device");
    }

    return device;
}

std::expected<void, std::string> IDriverProvider::unload_driver(
    const std::wstring& service_name) noexcept {
    std::println("Unloading driver service: {}",
                 std::filesystem::path(service_name).string());
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) {
        return std::unexpected("Failed to open SC Manager");
    }

    SC_HANDLE service =
        OpenServiceW(scm, service_name.c_str(),
                     SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (!service) {
        CloseServiceHandle(scm);
        return {};
    }

    // Stop service
    SERVICE_STATUS status{};
    ControlService(service, SERVICE_CONTROL_STOP, &status);

    // Wait for service to stop
    for (int i = 0; i < 10; ++i) {
        if (QueryServiceStatus(service, &status)) {
            if (status.dwCurrentState == SERVICE_STOPPED) {
                break;
            }
        }
        Sleep(100);
    }

    // Delete service
    DeleteService(service);

    CloseServiceHandle(service);
    CloseServiceHandle(scm);

    return {};
}

std::expected<void, std::string> DriverExploit::try_unload() noexcept {
    if (service_name_.empty()) {
        return std::unexpected("Service name not provided, cannot unload");
    }
    return IDriverProvider::unload_driver(service_name_);
}

}  // namespace kdu::core
