/* Address translation interface. */

#pragma once

#include <cstdint>
#include <expected>
#include <string>

namespace kdu::core {

/**
 * @brief Interface for virtual to physical address translation.
 */
class IVirtualToPhysical {
   public:
    virtual ~IVirtualToPhysical() = default;

    /**
     * @brief Attempts to translate a virtual address to a physical address.
     * @param virtual_address The virtual address to translate.
     * @return Expected containing the physical address on success, or error
     * message on failure.
     */
    [[nodiscard]] virtual std::expected<uintptr_t, std::string>
    try_virtual_to_physical(uintptr_t virtual_address) const noexcept = 0;

    /**
     * @brief Translates a virtual address to a physical address (throws on
     * failure).
     * @param virtual_address The virtual address to translate.
     * @return The physical address.
     */
    [[nodiscard]] uintptr_t virtual_to_physical(
        uintptr_t virtual_address) const {
        return try_virtual_to_physical(virtual_address).value();
    }
};

/**
 * @brief Interface for querying the PML4 base address.
 */
class IQueryPML4 {
   public:
    virtual ~IQueryPML4() = default;

    /**
     * @brief Attempts to query the CR3 (PML4 base) value.
     * @return Expected containing the PML4 value on success, or error message
     * on failure.
     */
    [[nodiscard]] virtual std::expected<uintptr_t, std::string>
    try_query_pml4() const noexcept = 0;

    /**
     * @brief Queries the CR3 (PML4 base) value (throws on failure).
     * @return The PML4 value.
     */
    [[nodiscard]] uintptr_t query_pml4() const {
        return try_query_pml4().value();
    }
};

}  // namespace kdu::core
