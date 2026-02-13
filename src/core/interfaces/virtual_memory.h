/* Virtual (kernel) memory access interface. */

#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <vector>

namespace kdu::core {

/**
 * @brief Interface for reading kernel virtual memory.
 */
class IVirtualMemoryRead {
   public:
    virtual ~IVirtualMemoryRead() = default;

    /**
     * @brief Attempts to read from kernel virtual memory.
     * @param virtual_address The virtual address to read from.
     * @param size Number of bytes to read.
     * @return Expected containing read data on success, or error message on
     * failure.
     */
    [[nodiscard]] virtual std::expected<std::vector<uint8_t>, std::string>
    try_read_virtual_memory(uintptr_t virtual_address,
                            size_t size) const noexcept = 0;

    /**
     * @brief Reads from kernel virtual memory (throws on failure).
     * @param virtual_address The virtual address to read from.
     * @param size Number of bytes to read.
     * @return Vector containing the read data.
     */
    [[nodiscard]] std::vector<uint8_t> read_virtual_memory(
        uintptr_t virtual_address, size_t size) const {
        return try_read_virtual_memory(virtual_address, size).value();
    }

    /**
     * @brief Reads a typed value from kernel virtual memory.
     * @tparam T The type to read.
     * @param virtual_address The virtual address to read from.
     * @return Expected containing the value on success, or error on failure.
     */
    template <typename T>
    [[nodiscard]] std::expected<T, std::string> try_read_virtual(
        uintptr_t virtual_address) const noexcept {
        auto result = try_read_virtual_memory(virtual_address, sizeof(T));
        if (!result) {
            return std::unexpected(result.error());
        }
        T value;
        std::memcpy(&value, result->data(), sizeof(T));
        return value;
    }

    /**
     * @brief Reads a typed value from kernel virtual memory (throws on
     * failure).
     * @tparam T The type to read.
     * @param virtual_address The virtual address to read from.
     * @return The read value.
     */
    template <typename T>
    [[nodiscard]] T read_virtual(uintptr_t virtual_address) const {
        return try_read_virtual<T>(virtual_address).value();
    }
};

/**
 * @brief Interface for writing to kernel virtual memory.
 */
class IVirtualMemoryWrite {
   public:
    virtual ~IVirtualMemoryWrite() = default;

    /**
     * @brief Attempts to write to kernel virtual memory.
     * @param virtual_address The virtual address to write to.
     * @param data Pointer to data to write.
     * @param size Number of bytes to write.
     * @return Expected containing success or error message.
     */
    [[nodiscard]] virtual std::expected<void, std::string>
    try_write_virtual_memory(uintptr_t virtual_address,
                             const void* data,
                             size_t size) noexcept = 0;

    /**
     * @brief Writes to kernel virtual memory (throws on failure).
     * @param virtual_address The virtual address to write to.
     * @param data Pointer to data to write.
     * @param size Number of bytes to write.
     */
    void write_virtual_memory(uintptr_t virtual_address,
                              const void* data,
                              size_t size) {
        try_write_virtual_memory(virtual_address, data, size).value();
    }

    /**
     * @brief Writes a typed value to kernel virtual memory.
     * @tparam T The type to write.
     * @param virtual_address The virtual address to write to.
     * @param value The value to write.
     * @return Expected containing success or error message.
     */
    template <typename T>
    [[nodiscard]] std::expected<void, std::string> try_write_virtual(
        uintptr_t virtual_address, const T& value) noexcept {
        return try_write_virtual_memory(virtual_address, &value, sizeof(T));
    }

    /**
     * @brief Writes a typed value to kernel virtual memory (throws on
     * failure).
     * @tparam T The type to write.
     * @param virtual_address The virtual address to write to.
     * @param value The value to write.
     */
    template <typename T>
    void write_virtual(uintptr_t virtual_address, const T& value) {
        try_write_virtual(virtual_address, value).value();
    }
};

}  // namespace kdu::core
