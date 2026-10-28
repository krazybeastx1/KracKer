#include "KracKer/hash_registry.hpp"
#include "KracKer/hash_fast.hpp"
#include "KracKer/hash_ntlm.hpp"
#include "KracKer/hash_bcrypt.hpp"
#include "KracKer/hash_scrypt.hpp"
#include "KracKer/hash_argon2.hpp"
#include "KracKer/hash_kerberoast.hpp"

namespace KracKer {

HashRegistry& HashRegistry::instance() {
    static HashRegistry registry;
    return registry;
}

void HashRegistry::register_algorithm(std::unique_ptr<IHashAlgorithm> algo) {
    std::unique_lock lock(mutex_);
    HashType type = algo->type();
    algorithms_[type] = std::move(algo);
}

void HashRegistry::unregister_algorithm(HashType type) {
    std::unique_lock lock(mutex_);
    algorithms_.erase(type);
}

IHashAlgorithm* HashRegistry::get_algorithm(HashType type) const {
    std::shared_lock lock(mutex_);
    auto it = algorithms_.find(type);
    return it != algorithms_.end() ? it->second.get() : nullptr;
}

IHashAlgorithm* HashRegistry::get_algorithm_by_name(const std::string& name) const {
    std::shared_lock lock(mutex_);
    for (const auto& [type, algo] : algorithms_) {
        if (algo->name() == name) return algo.get();
    }
    return nullptr;
}

IHashAlgorithm* HashRegistry::get_algorithm_by_hashcat_mode(uint32_t mode) const {
    std::shared_lock lock(mutex_);
    for (const auto& [type, algo] : algorithms_) {
        if (algo->hashcat_mode() == mode) return algo.get();
    }
    return nullptr;
}

std::vector<HashType> HashRegistry::list_algorithms() const {
    std::shared_lock lock(mutex_);
    std::vector<HashType> result;
    result.reserve(algorithms_.size());
    for (const auto& [type, algo] : algorithms_) {
        result.push_back(type);
    }
    return result;
}

std::vector<HashType> HashRegistry::list_gpu_algorithms() const {
    std::shared_lock lock(mutex_);
    std::vector<HashType> result;
    for (const auto& [type, algo] : algorithms_) {
        if (algo->has_gpu_implementation()) result.push_back(type);
    }
    return result;
}

std::vector<HashType> HashRegistry::identify_hash(const std::string& hash_string) const {
    std::shared_lock lock(mutex_);
    std::vector<HashType> matches;
    for (const auto& [type, algo] : algorithms_) {
        if (algo->identify_hash(hash_string)) {
            matches.push_back(type);
        }
    }
    return matches;
}

// Global registration function called at startup
void register_all_algorithms() {
    auto& registry = HashRegistry::instance();

    // Fast hashes
    registry.register_algorithm(std::make_unique<MD5Hash>());
    registry.register_algorithm(std::make_unique<SHA1Hash>());
    registry.register_algorithm(std::make_unique<SHA224Hash>());
    registry.register_algorithm(std::make_unique<SHA256Hash>());
    registry.register_algorithm(std::make_unique<SHA384Hash>());
    registry.register_algorithm(std::make_unique<SHA512Hash>());

    // NTLM
    registry.register_algorithm(std::make_unique<NTLMHash>());

    // Slow hashes (KDFs)
    registry.register_algorithm(std::make_unique<BcryptHash>());
    registry.register_algorithm(std::make_unique<ScryptHash>());
#ifdef KK_HAVE_ARGON2
    registry.register_algorithm(std::make_unique<Argon2Hash>(Argon2Hash::Variant::Argon2i));
    registry.register_algorithm(std::make_unique<Argon2Hash>(Argon2Hash::Variant::Argon2d));
    registry.register_algorithm(std::make_unique<Argon2Hash>(Argon2Hash::Variant::Argon2id));
#endif

    // Kerberoasting
    registry.register_algorithm(KerberoastHash::create_rc4_hmac());
    registry.register_algorithm(KerberoastHash::create_aes128());
    registry.register_algorithm(KerberoastHash::create_aes256());
    registry.register_algorithm(KerberoastHash::create_des3());
}

// Ensure registration happens at static initialization
struct StaticRegistrar {
    StaticRegistrar() { register_all_algorithms(); }
};
static StaticRegistrar registrar;

} // namespace KracKer