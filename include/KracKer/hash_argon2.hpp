#pragma once

#include "KracKer/hash_interface.hpp"
#include <string>
#include <vector>
#include <cstdint>
#include <optional>

namespace KracKer {

/**
 * Argon2 hash implementation
 * Supports Argon2i, Argon2d, Argon2id
 * Hash format: $argon2i$v=19$m=4096,t=3,p=1$salt$hash
 */
class Argon2Hash : public IHashAlgorithm {
public:
    enum class Variant { Argon2i = 0, Argon2d = 1, Argon2id = 2 };

    HashType type() const noexcept override { return HashType::ARGON2ID; }
    std::string name() const noexcept override { return "Argon2"; }
    uint32_t hashcat_mode() const noexcept override { return 16900; }

    HashCapabilities capabilities() const noexcept override {
        HashCapabilities caps;
        caps.supports_gpu = false;  // Memory-hard, GPU not efficient
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
    virtual ~Argon2Hash();

    // Factory methods for specific variants
    static std::unique_ptr<Argon2Hash> create_argon2i();
    static std::unique_ptr<Argon2Hash> create_argon2d();
    static std::unique_ptr<Argon2Hash> create_argon2id();

public:
    explicit Argon2Hash(Variant variant) : variant_(variant) {}

private:
    Variant variant_ = Variant::Argon2id;

private:
    static std::string base64_encode(const uint8_t* data, size_t len);
    static std::vector<uint8_t> base64_decode(const std::string& str);
    static bool parse_argon2_hash(const std::string& hash_str, Variant& variant, uint32_t& version,
                                   uint32_t& memory, uint32_t& time, uint32_t& threads,
                                   std::vector<uint8_t>& salt, std::vector<uint8_t>& hash);
};

} // namespace KracKer