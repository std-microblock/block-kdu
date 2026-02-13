/* Adapter to automatically provide virtual memory access from physical memory + PML4. */

#pragma once

#include <memory>
#include <expected>
#include <string>
#include <vector>

#include "physical_memory.h"
#include "virtual_memory.h"

namespace kdu::core {

/**
 * @brief Mixin class that adds virtual memory support to drivers with physical
 * memory + PML4 capabilities.
 *
 * Use this when you have:
 * - IPhysicalMemoryRead and IPhysicalMemoryWrite
 * - IQueryPML4
 *
 * And want to automatically get:
 * - IVirtualMemoryRead and IVirtualMemoryWrite
 *
 * Example usage:
 *   class MyExploit : public DriverExploit,
 *                     public IPhysicalMemoryRead,
 *                     public IPhysicalMemoryWrite,
 *                     public IQueryPML4,
 *                     public VirtualFromPhysicalMixin<MyExploit> {
 *       // ... implement physical memory and PML4 methods
 *   };
 */
template <typename Derived>
class VirtualFromPhysicalMixin : public IVirtualMemoryRead,
                                 public IVirtualMemoryWrite {
public:
    [[nodiscard]] std::expected<std::vector<uint8_t>, std::string>
    try_read_virtual_memory(uintptr_t virtual_address,
                           size_t size) const noexcept override {
        const auto* self = static_cast<const Derived*>(this);
        std::vector<uint8_t> total_buffer;
        total_buffer.reserve(size);

        size_t processed_size = 0;
        while (processed_size < size) {
            uintptr_t current_va = virtual_address + processed_size;
            
            auto pa_res = self->try_virtual_to_physical(current_va);
            if (!pa_res) return std::unexpected("Translation failed at VA 0x" + std::to_string(current_va) + ": " + pa_res.error());

            size_t page_offset = current_va & 0xFFF;
            size_t remaining_in_page = 0x1000 - page_offset;
            size_t to_read = std::min(size - processed_size, remaining_in_page);

            const auto* phys_reader = self->template as<IPhysicalMemoryRead>();
            auto read_res = phys_reader->try_read_physical_memory(*pa_res, to_read);
            if (!read_res) return std::unexpected("Physical read failed: " + read_res.error());

            total_buffer.insert(total_buffer.end(), read_res->begin(), read_res->end());
            processed_size += to_read;
        }

        return total_buffer;
    }

    [[nodiscard]] std::expected<void, std::string>
    try_write_virtual_memory(uintptr_t virtual_address, const void* data,
                            size_t size) noexcept override {
        auto* self = static_cast<Derived*>(this);
        const uint8_t* byte_data = static_cast<const uint8_t*>(data);

        size_t processed_size = 0;
        while (processed_size < size) {
            uintptr_t current_va = virtual_address + processed_size;

            auto pa_res = self->try_virtual_to_physical(current_va);
            if (!pa_res) return std::unexpected("Translation failed at VA 0x" + std::to_string(current_va));

            size_t page_offset = current_va & 0xFFF;
            size_t remaining_in_page = 0x1000 - page_offset;
            size_t to_write = std::min(size - processed_size, remaining_in_page);

            auto* phys_writer = self->template as<IPhysicalMemoryWrite>();
            auto write_res = phys_writer->try_write_physical_memory(*pa_res, byte_data + processed_size, to_write);
            if (!write_res) return std::unexpected("Physical write failed: " + write_res.error());

            processed_size += to_write;
        }

        return {};
    }
};

}  // namespace kdu::core
