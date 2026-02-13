/* Physical memory access interface. */

#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <vector>

namespace kdu::core {

/**
 * @brief Interface for reading physical memory.
 */
class IPhysicalMemoryRead {
   public:
    virtual ~IPhysicalMemoryRead() = default;

    /**
     * @brief Attempts to read from physical memory.
     * @param physical_address The physical address to read from.
     * @param size Number of bytes to read.
     * @return Expected containing read data on success, or error message on
     * failure.
     */
    [[nodiscard]] virtual std::expected<std::vector<uint8_t>, std::string>
    try_read_physical_memory(uintptr_t physical_address,
                             size_t size) const noexcept = 0;

    /**
     * @brief Reads from physical memory (throws on failure).
     * @param physical_address The physical address to read from.
     * @param size Number of bytes to read.
     * @return Vector containing the read data.
     * @throws std::runtime_error if the read fails.
     */
    [[nodiscard]] std::vector<uint8_t> read_physical_memory(
        uintptr_t physical_address, size_t size) const {
        return try_read_physical_memory(physical_address, size).value();
    }

    /**
     * @brief Reads a typed value from physical memory.
     * @tparam T The type to read.
     * @param physical_address The physical address to read from.
     * @return Expected containing the value on success, or error on failure.
     */
    template <typename T>
    [[nodiscard]] std::expected<T, std::string> try_read_physical(
        uintptr_t physical_address) const noexcept {
        auto result = try_read_physical_memory(physical_address, sizeof(T));
        if (!result) {
            return std::unexpected(result.error());
        }
        T value;
        std::memcpy(&value, result->data(), sizeof(T));
        return value;
    }

    /**
     * @brief Reads a typed value from physical memory (throws on failure).
     * @tparam T The type to read.
     * @param physical_address The physical address to read from.
     * @return The read value.
     */
    template <typename T>
    [[nodiscard]] T read_physical(uintptr_t physical_address) const {
        return try_read_physical<T>(physical_address).value();
    }
};

/**
 * @brief Interface for writing to physical memory.
 */
class IPhysicalMemoryWrite {
   public:
    virtual ~IPhysicalMemoryWrite() = default;

    /**
     * @brief Attempts to write to physical memory.
     * @param physical_address The physical address to write to.
     * @param data Pointer to data to write.
     * @param size Number of bytes to write.
     * @return Expected containing success or error message.
     */
    [[nodiscard]] virtual std::expected<void, std::string>
    try_write_physical_memory(uintptr_t physical_address,
                              const void* data,
                              size_t size) noexcept = 0;

    /**
     * @brief Writes to physical memory (throws on failure).
     * @param physical_address The physical address to write to.
     * @param data Pointer to data to write.
     * @param size Number of bytes to write.
     * @throws std::runtime_error if the write fails.
     */
    void write_physical_memory(uintptr_t physical_address,
                               const void* data,
                               size_t size) {
        try_write_physical_memory(physical_address, data, size).value();
    }

    /**
     * @brief Writes a typed value to physical memory.
     * @tparam T The type to write.
     * @param physical_address The physical address to write to.
     * @param value The value to write.
     * @return Expected containing success or error message.
     */
    template <typename T>
    [[nodiscard]] std::expected<void, std::string> try_write_physical(
        uintptr_t physical_address, const T& value) noexcept {
        return try_write_physical_memory(physical_address, &value, sizeof(T));
    }

    /**
     * @brief Writes a typed value to physical memory (throws on failure).
     * @tparam T The type to write.
     * @param physical_address The physical address to write to.
     * @param value The value to write.
     */
    template <typename T>
    void write_physical(uintptr_t physical_address, const T& value) {
        try_write_physical(physical_address, value).value();
    }
};

}  // namespace kdu::core
