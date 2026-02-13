/* KDU Core - Modern CLI with cxxopts */

#include <windows.h>
#include <iostream>
#include <format>
#include <iomanip>
#include <string>
#include <vector>

#include "cxxopts.hpp"
#include "core/kdu_core.h"
#include "drivers/gdrv-exploit/gdrv_exploit.cpp"

using namespace kdu;

void print_hex_dump(const std::vector<uint8_t>& data, uintptr_t base_address) {
    std::cout << std::format("\nHex dump at 0x{:016X}:\n", base_address);
    
    for (size_t i = 0; i < data.size(); i += 16) {
        std::cout << std::format("{:016X}  ", base_address + i);
        
        // Hex bytes
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < data.size()) {
                std::cout << std::format("{:02X} ", data[i + j]);
            } else {
                std::cout << "   ";
            }
            if (j == 7) std::cout << " ";
        }
        
        std::cout << " |";
        
        // ASCII representation
        for (size_t j = 0; j < 16 && i + j < data.size(); ++j) {
            uint8_t byte = data[i + j];
            std::cout << (byte >= 32 && byte < 127 ? static_cast<char>(byte) : '.');
        }
        
        std::cout << "|\n";
    }
}

int cmd_list_drivers(const cxxopts::ParseResult& args) {
    auto& manager = core::DriverManager::instance();
    auto providers = manager.get_all_providers();
    
    std::cout << std::format("\n=== Registered Driver Providers ({}) ===\n\n", providers.size());
    
    for (const auto& provider : providers) {
        const auto& meta = provider->metadata();
        std::cout << std::format("Driver: {}\n", meta.driver_name);
        std::cout << std::format("  Device:      {}\n", meta.device_name);
        std::cout << std::format("  Description: {}\n", meta.description);
        std::cout << std::format("  CVE:         {}\n", meta.cve_id);
        
        std::cout << "  Capabilities:\n";
        auto caps = meta.capabilities;
        if (core::has_ability(caps, core::AbilityFlags::PhysicalMemoryRead))
            std::cout << "    - Physical Memory Read\n";
        if (core::has_ability(caps, core::AbilityFlags::PhysicalMemoryWrite))
            std::cout << "    - Physical Memory Write\n";
        if (core::has_ability(caps, core::AbilityFlags::VirtualMemoryRead))
            std::cout << "    - Virtual Memory Read\n";
        if (core::has_ability(caps, core::AbilityFlags::VirtualMemoryWrite))
            std::cout << "    - Virtual Memory Write\n";
        if (core::has_ability(caps, core::AbilityFlags::VirtualToPhysical))
            std::cout << "    - Virtual to Physical Translation\n";
        if (core::has_ability(caps, core::AbilityFlags::QueryPML4))
            std::cout << "    - PML4 Query\n";
        
        std::cout << "\n";
    }
    
    return 0;
}

int cmd_read_physical(const cxxopts::ParseResult& args) {
    uintptr_t address = args["address"].as<uint64_t>();
    size_t size = args["size"].as<size_t>();
    std::string driver_name = args["driver"].as<std::string>();
    
    std::cout << std::format("Reading {} bytes from physical address 0x{:X}\n", size, address);
    std::cout << std::format("Using driver: {}\n", driver_name);
    
    // Find driver
    auto& manager = core::DriverManager::instance();
    auto provider = manager.find_provider_by_name(driver_name);
    
    if (!provider) {
        std::cerr << std::format("Error: Driver '{}' not found\n", driver_name);
        return 1;
    }
    
    // Create instance
    auto instance_result = provider->create_instance();
    if (!instance_result) {
        std::cerr << std::format("Error: Failed to create driver instance: {}\n",
                                instance_result.error());
        return 1;
    }
    
    auto& instance = *instance_result;
    
    // Query interface
    auto* phys_read = instance->as<core::IPhysicalMemoryRead>();
    if (!phys_read) {
        std::cerr << "Error: Driver does not support physical memory read\n";
        return 1;
    }
    
    // Read memory
    auto result = phys_read->try_read_physical_memory(address, size);
    if (!result) {
        std::cerr << std::format("Error: Read failed: {}\n", result.error());
        return 1;
    }
    
    std::cout << "Read succeeded!\n";
    print_hex_dump(*result, address);
    
    return 0;
}

int cmd_write_physical(const cxxopts::ParseResult& args) {
    uintptr_t address = args["address"].as<uint64_t>();
    std::string data_str = args["data"].as<std::string>();
    std::string driver_name = args["driver"].as<std::string>();
    
    // Parse hex data
    std::vector<uint8_t> data;
    for (size_t i = 0; i < data_str.length(); i += 2) {
        if (i + 1 < data_str.length()) {
            std::string byte_str = data_str.substr(i, 2);
            data.push_back(static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16)));
        }
    }
    
    std::cout << std::format("Writing {} bytes to physical address 0x{:X}\n", data.size(), address);
    std::cout << std::format("Data: {}\n", data_str);
    std::cout << std::format("Using driver: {}\n", driver_name);
    
    // Find driver
    auto& manager = core::DriverManager::instance();
    auto provider = manager.find_provider_by_name(driver_name);
    
    if (!provider) {
        std::cerr << std::format("Error: Driver '{}' not found\n", driver_name);
        return 1;
    }
    
    // Create instance
    auto instance_result = provider->create_instance();
    if (!instance_result) {
        std::cerr << std::format("Error: Failed to create driver instance: {}\n",
                                instance_result.error());
        return 1;
    }
    
    auto& instance = *instance_result;
    
    // Query interface
    auto* phys_write = instance->as<core::IPhysicalMemoryWrite>();
    if (!phys_write) {
        std::cerr << "Error: Driver does not support physical memory write\n";
        return 1;
    }
    
    // Write memory
    auto result = phys_write->try_write_physical_memory(address, data.data(), data.size());
    if (!result) {
        std::cerr << std::format("Error: Write failed: {}\n", result.error());
        return 1;
    }
    
    std::cout << "Write succeeded!\n";
    
    return 0;
}

int cmd_query_pml4(const cxxopts::ParseResult& args) {
    std::string driver_name = args["driver"].as<std::string>();
    
    std::cout << std::format("Querying PML4 using driver: {}\n", driver_name);
    
    // Find driver
    auto& manager = core::DriverManager::instance();
    auto provider = manager.find_provider_by_name(driver_name);
    
    if (!provider) {
        std::cerr << std::format("Error: Driver '{}' not found\n", driver_name);
        return 1;
    }
    
    // Create instance
    auto instance_result = provider->create_instance();
    if (!instance_result) {
        std::cerr << std::format("Error: Failed to create driver instance: {}\n",
                                instance_result.error());
        return 1;
    }
    
    auto& instance = *instance_result;
    
    // Query interface
    auto* pml4_query = instance->as<core::IQueryPML4>();
    if (!pml4_query) {
        std::cerr << "Error: Driver does not support PML4 query\n";
        return 1;
    }
    
    // Query PML4
    auto result = pml4_query->try_query_pml4();
    if (!result) {
        std::cerr << std::format("Error: Query failed: {}\n", result.error());
        return 1;
    }
    
    std::cout << std::format("PML4 (CR3) = 0x{:016X}\n", *result);
    
    return 0;
}

int cmd_test_memory(const cxxopts::ParseResult& args) {
    std::string driver_name = args["driver"].as<std::string>();
    
    std::cout << std::format("\n=== Memory R/W Test using {} ===\n\n", driver_name);
    
    // Find driver
    auto& manager = core::DriverManager::instance();
    auto provider = manager.find_provider_by_name(driver_name);
    
    if (!provider) {
        std::cerr << std::format("Error: Driver '{}' not found\n", driver_name);
        return 1;
    }
    
    // Create instance
    auto instance_result = provider->create_instance();
    if (!instance_result) {
        std::cerr << std::format("Error: Failed to create driver instance: {}\n",
                                instance_result.error());
        return 1;
    }
    
    auto& instance = *instance_result;
    
    // Test 1: Read from known safe physical address (low memory)
    std::cout << "Test 1: Reading from physical address 0x1000 (4KB page)\n";
    if (auto* reader = instance->as<core::IPhysicalMemoryRead>()) {
        auto result = reader->try_read_physical_memory(0x1000, 64);
        if (result) {
            std::cout << "  ✓ Read succeeded\n";
            print_hex_dump(*result, 0x1000);
        } else {
            std::cout << std::format("  ✗ Read failed: {}\n", result.error());
        }
    } else {
        std::cout << "  - Driver does not support physical memory read\n";
    }
    
    // Test 2: Query PML4
    std::cout << "\nTest 2: Querying PML4 (CR3 register)\n";
    if (auto* pml4 = instance->as<core::IQueryPML4>()) {
        auto result = pml4->try_query_pml4();
        if (result) {
            std::cout << std::format("  ✓ PML4 = 0x{:016X}\n", *result);
        } else {
            std::cout << std::format("  ✗ Query failed: {}\n", result.error());
        }
    } else {
        std::cout << "  - Driver does not support PML4 query\n";
    }
    
    // Test 3: Read/Write cycle test (use temporary buffer in physical memory)
    std::cout << "\nTest 3: Read-Modify-Write cycle test\n";
    if (auto* reader = instance->as<core::IPhysicalMemoryRead>()) {
        if (auto* writer = instance->as<core::IPhysicalMemoryWrite>()) {
            constexpr uintptr_t TEST_ADDR = 0x10000; // 64KB mark
            
            // Read original
            auto original = reader->try_read_physical_memory(TEST_ADDR, 16);
            if (!original) {
                std::cout << std::format("  ✗ Read failed: {}\n", original.error());
            } else {
                std::cout << "  ✓ Original data read\n";
                
                // Create test pattern
                std::vector<uint8_t> test_pattern = {
                    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
                    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0
                };
                
                // Write test pattern
                auto write_result = writer->try_write_physical_memory(
                    TEST_ADDR, test_pattern.data(), test_pattern.size());
                
                if (!write_result) {
                    std::cout << std::format("  ✗ Write failed: {}\n", write_result.error());
                } else {
                    std::cout << "  ✓ Test pattern written\n";
                    
                    // Read back
                    auto readback = reader->try_read_physical_memory(TEST_ADDR, 16);
                    if (!readback) {
                        std::cout << std::format("  ✗ Read-back failed: {}\n", readback.error());
                    } else {
                        // Verify
                        bool match = (*readback == test_pattern);
                        if (match) {
                            std::cout << "  ✓ Verification succeeded - Data matches!\n";
                        } else {
                            std::cout << "  ✗ Verification failed - Data mismatch\n";
                            std::cout << "    Expected: ";
                            for (auto b : test_pattern) std::cout << std::format("{:02X} ", b);
                            std::cout << "\n    Got:      ";
                            for (auto b : *readback) std::cout << std::format("{:02X} ", b);
                            std::cout << "\n";
                        }
                        
                        // Restore original
                        writer->try_write_physical_memory(TEST_ADDR, original->data(), original->size());
                        std::cout << "  ✓ Original data restored\n";
                    }
                }
            }
        } else {
            std::cout << "  - Driver does not support physical memory write\n";
        }
    } else {
        std::cout << "  - Driver does not support physical memory read\n";
    }
    
    std::cout << "\n=== Test Complete ===\n";
    
    return 0;
}

int main(int argc, char** argv) {
    std::cout << "KDU Core - Modern Driver Utility\n";
    std::cout << "================================\n\n";
    
    try {
        cxxopts::Options options("kdu-core", "Kernel Driver Utility - New Architecture");
        
        options.add_options()
            ("h,help", "Print help")
            ("v,version", "Print version");
        
        options.add_options("Commands")
            ("list", "List all registered drivers")
            ("read-phys", "Read physical memory")
            ("write-phys", "Write physical memory")
            ("query-pml4", "Query PML4 (CR3) value")
            ("test", "Run memory R/W tests");
        
        options.add_options("Options")
            ("a,address", "Memory address (hex)", cxxopts::value<uint64_t>())
            ("s,size", "Size in bytes", cxxopts::value<size_t>()->default_value("64"))
            ("d,driver", "Driver name", cxxopts::value<std::string>()->default_value("gdrv"))
            ("data", "Data to write (hex string)", cxxopts::value<std::string>());
        
        auto result = options.parse(argc, argv);
        
        if (result.count("help")) {
            std::cout << options.help() << std::endl;
            std::cout << "\nExamples:\n";
            std::cout << "  kdu-core --list\n";
            std::cout << "  kdu-core --read-phys -a 0x1000 -s 128 -d gdrv\n";
            std::cout << "  kdu-core --write-phys -a 0x2000 --data DEADBEEF -d gdrv\n";
            std::cout << "  kdu-core --query-pml4 -d gdrv\n";
            std::cout << "  kdu-core --test -d gdrv\n";
            return 0;
        }
        
        if (result.count("version")) {
            std::cout << "KDU Core v2.0 - Plugin Architecture\n";
            return 0;
        }
        
        if (result.count("list")) {
            return cmd_list_drivers(result);
        }
        
        if (result.count("read-phys")) {
            if (!result.count("address")) {
                std::cerr << "Error: --address required for read-phys\n";
                return 1;
            }
            return cmd_read_physical(result);
        }
        
        if (result.count("write-phys")) {
            if (!result.count("address") || !result.count("data")) {
                std::cerr << "Error: --address and --data required for write-phys\n";
                return 1;
            }
            return cmd_write_physical(result);
        }
        
        if (result.count("query-pml4")) {
            return cmd_query_pml4(result);
        }
        
        if (result.count("test")) {
            return cmd_test_memory(result);
        }
        
        std::cout << "No command specified. Use --help for usage.\n";
        return 1;
        
    } catch (const cxxopts::exceptions::exception& e) {
        std::cerr << "Error parsing options: " << e.what() << "\n";
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}
