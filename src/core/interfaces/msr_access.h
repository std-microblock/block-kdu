/* MSR (Model Specific Register) access interface. */

#pragma once

#include <cstdint>
#include <expected>
#include <string>

namespace kdu::core {

/**
 * @brief Interface for reading MSR registers.
 */
class IMsrRead {
   public:
    virtual ~IMsrRead() = default;

    /**
     * @brief Attempts to read a Model-Specific Register.
     * @param msr_index The MSR index to read.
     * @return Expected containing the 64-bit MSR value on success, or error
     * message on failure.
     */
    [[nodiscard]] virtual std::expected<uint64_t, std::string> try_read_msr(
        uint32_t msr_index) const noexcept = 0;

    /**
     * @brief Reads a Model-Specific Register (throws on failure).
     * @param msr_index The MSR index to read.
     * @return The 64-bit MSR value.
     */
    [[nodiscard]] uint64_t read_msr(uint32_t msr_index) const {
        return try_read_msr(msr_index).value();
    }
};

/**
 * @brief Interface for writing to MSR registers.
 */
class IMsrWrite {
   public:
    virtual ~IMsrWrite() = default;

    /**
     * @brief Attempts to write to a Model-Specific Register.
     * @param msr_index The MSR index to write to.
     * @param value The 64-bit value to write.
     * @return Expected containing success or error message.
     */
    [[nodiscard]] virtual std::expected<void, std::string> try_write_msr(
        uint32_t msr_index, uint64_t value) noexcept = 0;

    /**
     * @brief Writes to a Model-Specific Register (throws on failure).
     * @param msr_index The MSR index to write to.
     * @param value The 64-bit value to write.
     */
    void write_msr(uint32_t msr_index, uint64_t value) {
        try_write_msr(msr_index, value).value();
    }
};

}  // namespace kdu::core
