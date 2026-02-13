/* Mixin to automatically provide virtual-to-physical translation from PML4. */

#pragma once

#include <memory>
#include <expected>
#include <string>
#include <vector>

#include "physical_memory.h"
#include "address_translation.h"
#include "../driver_exploit.h"

namespace kdu::core {

/**
 * @brief Mixin class that adds PML4 query support to drivers with physical
 * memory read capability.
 *
 * Use this when you have:
 * - IPhysicalMemoryRead
 *
 * And want to automatically get:
 * - IQueryPML4
 *
 * Example usage:
 *   class MyExploit : public DriverExploit,
 *                     public IPhysicalMemoryRead,
 *                     public QueryPML4FromPhysicalMixin<MyExploit> {
 *       // ... implement physical memory read
 *   };
 */
template <typename Derived>
class QueryPML4FromPhysicalMixin : public IQueryPML4 {
   public:
    /**
     * @brief Query PML4 (CR3) value from physical memory.
     * @return Expected containing PML4 value on success, error message on
     * failure.
     *
     * Scans the first 1MB of physical memory for PROCESSOR_START_BLOCK
     * signature to find the PML4 value.
     */
    [[nodiscard]] std::expected<uintptr_t, std::string> try_query_pml4()
        const noexcept override {
        const auto* self = static_cast<const Derived*>(this);
        const auto* phys_reader = self->template as<IPhysicalMemoryRead>();
        if (!phys_reader)
            return std::unexpected("Physical reader unavailable");

        const uint32_t lm_target_offset = 0x70;
        const uint32_t cr3_offset = 0xA0;

        for (uintptr_t offset = 0x1000; offset < 0x100000; offset += 0x1000) {
            auto res = phys_reader->try_read_physical_memory(offset, 0x1000);
            if (!res)
                continue;
            const uint8_t* block = res->data();

            uint64_t jmp_val = *reinterpret_cast<const uint64_t*>(block);
            if ((jmp_val & 0xffffffffffff00ff) != 0x00000001000600E9)
                continue;

            uint64_t lm_target =
                *reinterpret_cast<const uint64_t*>(block + lm_target_offset);
            if ((lm_target & 0xfffff80000000003) != 0xfffff80000000000)
                continue;

            uint64_t cr3 =
                *reinterpret_cast<const uint64_t*>(block + cr3_offset);

            if (cr3 & 0xffffff0000000fff)
                continue;

            if (cr3 != 0) {
                return static_cast<uintptr_t>(cr3);
            }
        }

        return std::unexpected("Could not find PML4 via LowStub scanning");
    }
};

/**
 * @brief Mixin class that adds virtual-to-physical translation support to
 * drivers with physical memory read + PML4 query capabilities.
 *
 * Use this when you have:
 * - IPhysicalMemoryRead
 * - IQueryPML4
 *
 * And want to automatically get:
 * - IVirtualToPhysical
 *
 * Example usage:
 *   class MyExploit : public DriverExploit,
 *                     public IPhysicalMemoryRead,
 *                     public IQueryPML4,
 *                     public V2PFromPhysicalMixin<MyExploit> {
 *       // ... implement physical memory and PML4 methods
 *   };
 */
template <typename Derived>
class V2PFromPhysicalMixin : public IVirtualToPhysical {
   public:
    /**
     * @brief Translate virtual address to physical address using page table
     * walking.
     */
    [[nodiscard]] std::expected<uintptr_t, std::string> try_virtual_to_physical(
        uintptr_t virtual_address) const noexcept override {
        const auto* self = static_cast<const Derived*>(this);

        const auto* phys_reader = self->template as<IPhysicalMemoryRead>();
        const auto* pml4_query = self->template as<IQueryPML4>();
        if (!phys_reader || !pml4_query) {
            return std::unexpected(
                "Required interfaces (Reader/Query) not available");
        }

        auto pml4_res = pml4_query->try_query_pml4();
        if (!pml4_res)
            return std::unexpected("PML4 Query failed: " + pml4_res.error());

        const uint64_t ADDRESS_MASK = 0x000FFFFFFFFFF000ull;
        uintptr_t current_table_phys = *pml4_res & ADDRESS_MASK;

        const uint64_t indices[] = {
            (virtual_address >> 39) & 0x1FF,  // PML4 Index
            (virtual_address >> 30) & 0x1FF,  // PDPT Index
            (virtual_address >> 21) & 0x1FF,  // PD Index
            (virtual_address >> 12) & 0x1FF   // PT Index
        };

        for (int level = 0; level < 4; ++level) {
            uintptr_t entry_addr =
                current_table_phys + (indices[level] * sizeof(uint64_t));

            auto read_res = phys_reader->try_read_physical_memory(
                entry_addr, sizeof(uint64_t));
            if (!read_res) {
                return std::unexpected("Failed to read table at level " +
                                       std::to_string(level));
            }

            uint64_t entry =
                *reinterpret_cast<const uint64_t*>(read_res->data());

            if (!(entry & 0x1)) {
                return std::unexpected(
                    "Page table entry not present at level " +
                    std::to_string(level));
            }

            if ((level == 1 || level == 2) && (entry & 0x80)) {
                uint64_t page_size_mask = (level == 1) ? 0x3FFFFFFF : 0x1FFFFF;
                return (entry & ~page_size_mask & ADDRESS_MASK) +
                       (virtual_address & page_size_mask);
            }

            current_table_phys = entry & ADDRESS_MASK;
        }

        return current_table_phys + (virtual_address & 0xFFF);
    }
};

}  // namespace kdu::core
