#pragma once

#include "KracKer/hash_interface.hpp"
#include <string>
#include <vector>
#include <cstdint>
#include <optional>

namespace KracKer {

/**
 * scrypt hash implementation
 * Supports scrypt with configurable N, r, p parameters
 * Hash format: $s0$<N>$<r>$<p>$<salt>$<hash>
 */
class ScryptHash : public IHashAlgorithm {
public:
    HashType type() const noexcept override { return HashType::SCRYPT; }
    std::string name() const noexcept override { return "scrypt"; }
    uint32_t hashcat_mode() const noexcept override { return 8900; }

    HashCapabilities capabilities() const noexcept override {
        HashCapabilities caps;
        caps.supports_gpu = false;  // Memory-hard, not GPU-friendly
        caps.supports_distributed = true;
        caps.is_slow_hash = true;
        caps.requires_salt = true;
        caps.supports_mask = false;
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

    bool has_gpu_implementation() const noexcept override { return false; }

    // Virtual destructor for proper vtable emission (defined in cpp)
    virtual ~ScryptHash();

private:
    // scrypt internals
    static void scrypt_1024_1_1_256(const uint8_t* passwd, size_t passwdlen,
                                     const uint8_t* salt, size_t saltlen,
                                     uint8_t* buf);

    static void blake2b_init(void* state, size_t outlen);
    static void blake2b_update(void* state, const void* in, size_t inlen);
    static void blake2b_final(void* state, void* out, size_t outlen);

    static void salsa20_8(uint32_t* B);
    static void blockmix_salsa8(uint32_t* out, uint32_t* in, uint32_t* tmp, size_t r);
    static void integerify(uint32_t* out, uint32_t* in, size_t r);
    static void smix(uint8_t* B, size_t r, uint32_t N, uint32_t* V, uint32_t* XY);

    static std::string base64_encode(const uint8_t* data, size_t len);
    static std::vector<uint8_t> base64_decode(const std::string& str);
    static bool parse_scrypt_hash(const std::string& hash_str, uint32_t& N, uint32_t& r, uint32_t& p,
                                   std::vector<uint8_t>& salt, std::vector<uint8_t>& hash);
};

} // namespace KracKer