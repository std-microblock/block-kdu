/* Main header for the KDU core library. */

#pragma once

// Core types and capabilities
#include "ability_flags.h"
#include "driver_exploit.h"
#include "driver_manager.h"

// Capability interfaces
#include "interfaces/address_translation.h"
#include "interfaces/msr_access.h"
#include "interfaces/physical_memory.h"
#include "interfaces/process_operations.h"
#include "interfaces/virtual_memory.h"
