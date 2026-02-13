/* Driver manager for registering and discovering driver providers. */

#pragma once

#include <expected>
#include <memory>
#include <mutex>
#include <print>
#include <string>
#include <vector>

#include "ability_flags.h"
#include "driver_exploit.h"

namespace kdu::core {

/**
 * @brief Singleton manager for driver exploit providers.
 *
 * This class maintains a global registry of all available driver providers
 * and provides methods for querying and instantiating them.
 */
class DriverManager {
   public:
    /**
     * @brief Gets the singleton instance.
     */
    static DriverManager& instance();

    // Non-copyable, non-movable
    DriverManager(const DriverManager&) = delete;
    DriverManager& operator=(const DriverManager&) = delete;
    DriverManager(DriverManager&&) = delete;
    DriverManager& operator=(DriverManager&&) = delete;

    /**
     * @brief Registers a driver provider.
     * @param provider The provider to register.
     */
    void register_provider(std::shared_ptr<IDriverProvider> provider) {
        std::lock_guard<std::mutex> lock(mutex_);
        providers_.push_back(std::move(provider));
    }

    /**
     * @brief Gets all registered providers.
     */
    [[nodiscard]] std::vector<std::shared_ptr<IDriverProvider>>
    get_all_providers() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return providers_;
    }

    /**
     * @brief Finds a provider by driver name.
     * @param driver_name The name of the driver (e.g., "gdrv").
     * @return The provider if found, nullptr otherwise.
     */
    [[nodiscard]] std::shared_ptr<IDriverProvider> find_provider_by_name(
        std::string_view driver_name) const {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& provider : providers_) {
            if (provider->metadata().driver_name == driver_name) {
                return provider;
            }
        }
        return nullptr;
    }

    /**
     * @brief Finds all providers that support a specific capability.
     * @param required_capabilities The required capabilities.
     * @return Vector of providers that support the required capabilities.
     */
    [[nodiscard]] std::vector<std::shared_ptr<IDriverProvider>>
    find_providers_with_capabilities(AbilityFlags required_capabilities) const {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<std::shared_ptr<IDriverProvider>> result;

        for (const auto& provider : providers_) {
            const auto& caps = provider->metadata().capabilities;
            if ((caps & required_capabilities) == required_capabilities) {
                result.push_back(provider);
            }
        }

        return result;
    }

    /**
     * @brief Attempts to create a driver exploit with the required
     * capabilities.
     * @param required_capabilities The required capabilities.
     * @return Expected containing the exploit instance on success, or error
     * message on failure.
     */
    [[nodiscard]] std::expected<std::unique_ptr<DriverExploit>, std::string>
    create_best_match(AbilityFlags required_capabilities) const {
        auto providers =
            find_providers_with_capabilities(required_capabilities);

        if (providers.empty()) {
            return std::unexpected(
                "No driver found with required capabilities");
        }

        // Try each provider until one succeeds
        for (const auto& provider : providers) {
            auto available_check = provider->check_available();
            if (!available_check) {
                continue;  // This provider is not available, try next
            }

            auto instance = provider->create_instance();
            if (instance) {
                return instance;
            }
        }

        return std::unexpected("All matching drivers failed to initialize");
    }

   private:
    DriverManager() = default;

    mutable std::mutex mutex_;
    std::vector<std::shared_ptr<IDriverProvider>> providers_;
};

/**
 * @brief RAII helper for automatic provider registration.
 *
 * Usage:
 * static core::ProviderRegistrar<MyDriverProvider> registrar;
 */
template <typename T = IDriverProvider>
    requires std::is_base_of_v<IDriverProvider, T>
class ProviderRegistrar {
   public:
    explicit ProviderRegistrar() {
        DriverManager::instance().register_provider(std::make_shared<T>());
    }
};

}  // namespace kdu::core
