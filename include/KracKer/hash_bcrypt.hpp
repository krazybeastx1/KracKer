#pragma once

#include "KracKer/hash_interface.hpp"
#include <string>
#include <vector>
#include <cstdint>
#include <optional>
#include <array>

namespace KracKer {

/**
 * Bcrypt hash implementation
 * Supports $2a$, $2b$, $2y$ variants with cost factor 4-31
 */
class BcryptHash : public IHashAlgorithm {
public:
    HashType type() const noexcept override { return HashType::BCRYPT; }
    std::string name() const noexcept override { return "bcrypt"; }
    uint32_t hashcat_mode() const noexcept override { return 3200; }

    HashCapabilities capabilities() const noexcept override {
        HashCapabilities caps;
        caps.supports_gpu = false;  // bcrypt is memory-hard, GPU not efficient
        caps.supports_distributed = true;
        caps.is_slow_hash = true;
        caps.requires_salt = true;
        caps.supports_mask = false;  // Not practical for slow hashes
        caps.supports_rules = false;
        caps.min_kernel_duration_ms = 100;
        return caps;
    }

    HashResult hash(const std::string& password, const HashParams& params) const override;
    HashResult hash(const std::vector<uint8_t>& password, const HashParams& params) const override;

    std::vector<HashResult> hash_batch(
        const std::vector<std::string>& passwords,
        const HashParams& params
    ) const override;

    bool verify(const std::string& hash_string, const std::string& password, const HashParams& params) const override;
    bool verify(const std::vector<uint8_t>& hash_bytes, const std::string& password, const HashParams& params) const override;

    std::optional<HashParams> parse_hash(const std::string& hash_string) const override;
    std::string format_hash(const HashResult& result, const HashParams& params) const override;
    bool identify_hash(const std::string& hash_string) const override;

    // bcrypt doesn't benefit from GPU
    bool has_gpu_implementation() const noexcept override { return false; }

    // Virtual destructor for proper vtable emission (defined in cpp)
    virtual ~BcryptHash();

private:
    // Bcrypt internals
    static constexpr size_t BCRYPT_BLOCK_SIZE = 16;
    static constexpr size_t BCRYPT_HASH_SIZE = 23;
    static constexpr size_t BCRYPT_SALT_SIZE = 16;

    struct BcryptState {
        std::array<uint32_t, 18> P;
        std::array<std::array<uint32_t, 256>, 4> S;
    };

    static void bcrypt_init_state(BcryptState& state);
    static void bcrypt_expand_key(BcryptState& state, const uint8_t* key, size_t key_len, const uint8_t* salt, uint8_t cost);
    static void bcrypt_encrypt(BcryptState& state, uint8_t* output);

    static std::string base64_encode(const uint8_t* data, size_t len);
    static std::vector<uint8_t> base64_decode(const std::string& str);
    static bool parse_bcrypt_hash(const std::string& hash_str, uint8_t& version, uint8_t& cost, std::vector<uint8_t>& salt, std::vector<uint8_t>& hash);
};

} // namespace KracKer