/* Process operations interface. */

#pragma once

#include <windows.h>
#include <cstdint>
#include <expected>
#include <string>

namespace kdu::core {

/**
 * @brief Interface for opening process handles from kernel mode.
 */
class IOpenProcess {
   public:
    virtual ~IOpenProcess() = default;

    /**
     * @brief Attempts to open a process handle with specified access rights.
     * @param process_id The process ID to open.
     * @param desired_access The desired access mask.
     * @return Expected containing the process handle on success, or error
     * message on failure.
     */
    [[nodiscard]] virtual std::expected<HANDLE, std::string> try_open_process(
        uint32_t process_id, uint32_t desired_access) noexcept = 0;

    /**
     * @brief Opens a process handle with specified access rights (throws on
     * failure).
     * @param process_id The process ID to open.
     * @param desired_access The desired access mask.
     * @return The process handle.
     */
    [[nodiscard]] HANDLE open_process(uint32_t process_id,
                                       uint32_t desired_access) {
        return try_open_process(process_id, desired_access).value();
    }
};

}  // namespace kdu::core
