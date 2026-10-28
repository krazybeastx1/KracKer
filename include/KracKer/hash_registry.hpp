#pragma once

#include "KracKer/hash_interface.hpp"

namespace KracKer {

/**
 * Hash algorithm registry - singleton for managing all registered hash algorithms
 */
class HashRegistry {
public:
    static HashRegistry& instance();

    void register_algorithm(std::unique_ptr<IHashAlgorithm> algo);
    void unregister_algorithm(HashType type);

    IHashAlgorithm* get_algorithm(HashType type) const;
    IHashAlgorithm* get_algorithm_by_name(const std::string& name) const;
    IHashAlgorithm* get_algorithm_by_hashcat_mode(uint32_t mode) const;

    std::vector<HashType> list_algorithms() const;
    std::vector<HashType> list_gpu_algorithms() const;

    // Auto-detect hash type from string
    std::vector<HashType> identify_hash(const std::string& hash_string) const;

private:
    HashRegistry() = default;
    std::unordered_map<HashType, std::unique_ptr<IHashAlgorithm>> algorithms_;
    mutable std::shared_mutex mutex_;
};

/**
 * Register all built-in hash algorithms
 * Called automatically at static initialization
 */
void register_all_algorithms();

} // namespace KracKer