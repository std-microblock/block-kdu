/* Core capability flags for driver exploits. */

#pragma once

#include <cstdint>

namespace kdu::core {

/**
 * @brief Capability flags representing driver primitive operations.
 * 
 * Each flag represents a specific low-level capability that a vulnerable
 * driver may expose. Multiple capabilities can be combined using bitwise OR.
 */
enum class AbilityFlags : uint64_t {
    None = 0,

    // Physical memory operations
    PhysicalMemoryRead = 1ULL << 0,
    PhysicalMemoryWrite = 1ULL << 1,

    // Virtual (kernel) memory operations
    VirtualMemoryRead = 1ULL << 2,
    VirtualMemoryWrite = 1ULL << 3,

    // Address translation
    VirtualToPhysical = 1ULL << 4,
    QueryPML4 = 1ULL << 5,

    // CPU register access
    ReadMSR = 1ULL << 6,
    WriteMSR = 1ULL << 7,
    ReadCR = 1ULL << 8,
    WriteCR = 1ULL << 9,

    // I/O port operations
    ReadPort = 1ULL << 10,
    WritePort = 1ULL << 11,

    // Memory mapping
    MapPhysicalMemory = 1ULL << 12,
    UnmapPhysicalMemory = 1ULL << 13,

    // Pool memory allocation
    AllocatePool = 1ULL << 14,
    FreePool = 1ULL << 15,

    // Process operations
    OpenProcess = 1ULL << 16,

    // Code execution
    ExecuteKernelCode = 1ULL << 17,

    // IDT/GDT manipulation
    ReadIDT = 1ULL << 18,
    WriteIDT = 1ULL << 19,
    ReadGDT = 1ULL << 20,
    WriteGDT = 1ULL << 21,
};

// Bitwise operators for AbilityFlags
constexpr AbilityFlags operator|(AbilityFlags a, AbilityFlags b) noexcept {
    return static_cast<AbilityFlags>(static_cast<uint64_t>(a) |
                                     static_cast<uint64_t>(b));
}

constexpr AbilityFlags operator&(AbilityFlags a, AbilityFlags b) noexcept {
    return static_cast<AbilityFlags>(static_cast<uint64_t>(a) &
                                     static_cast<uint64_t>(b));
}

constexpr AbilityFlags operator^(AbilityFlags a, AbilityFlags b) noexcept {
    return static_cast<AbilityFlags>(static_cast<uint64_t>(a) ^
                                     static_cast<uint64_t>(b));
}

constexpr AbilityFlags operator~(AbilityFlags a) noexcept {
    return static_cast<AbilityFlags>(~static_cast<uint64_t>(a));
}

inline AbilityFlags& operator|=(AbilityFlags& a, AbilityFlags b) noexcept {
    return a = a | b;
}

inline AbilityFlags& operator&=(AbilityFlags& a, AbilityFlags b) noexcept {
    return a = a & b;
}

inline AbilityFlags& operator^=(AbilityFlags& a, AbilityFlags b) noexcept {
    return a = a ^ b;
}

constexpr bool has_ability(AbilityFlags flags, AbilityFlags ability) noexcept {
    return (flags & ability) == ability;
}

}  // namespace kdu::core
