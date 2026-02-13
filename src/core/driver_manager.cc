#include "driver_manager.h"

kdu::core::DriverManager& kdu::core::DriverManager::instance() {
    static DriverManager instance;
    return instance;
}
