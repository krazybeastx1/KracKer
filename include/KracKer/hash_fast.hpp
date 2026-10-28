#pragma once

#include <KracKer/hash_interface.hpp>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <string>
#include <vector>
#include <cstdint>
#include <algorithm>

namespace KracKer {

/**
 * Base class for OpenSSL-based fast hashes (MD5, SHA1, SHA2)
 */
class OpenSSLHashBase : public IHashAlgorithm {
protected:
    HashType hash_type_;
    std::string name_;
    uint32_t hashcat_mode_;
    size_t digest_length_;

public:
    OpenSSLHashBase(HashType type, const std::string& name, uint32_t mode, size_t digest_len)
        : hash_type_(type), name_(name), hashcat_mode_(mode), digest_length_(digest_len) {}

    HashType type() const noexcept override { return hash_type_; }
    std::string name() const noexcept override { return name_; }
    uint32_t hashcat_mode() const noexcept override { return hashcat_mode_; }

    HashCapabilities capabilities() const noexcept override {
        HashCapabilities caps;
        caps.supports_gpu = true;
        caps.supports_distributed = true;
        caps.is_slow_hash = false;
        caps.requires_salt = false;
        caps.supports_mask = true;
        caps.supports_rules = true;
        caps.optimal_workgroup_size = 256;
        return caps;
    }

    // Single hash
    HashResult hash(const std::string& password, const HashParams&) const override {
        return hash(reinterpret_cast<const uint8_t*>(password.data()), password.size());
    }

    HashResult hash(const std::vector<uint8_t>& password, const HashParams&) const override {
        return hash(password.data(), password.size());
    }

    // Batch hashing (CPU fallback)
    std::vector<HashResult> hash_batch(
        const std::vector<std::string>& passwords,
        const HashParams& params
    ) const override {
        std::vector<HashResult> results;
        results.reserve(passwords.size());
        for (const auto& pwd : passwords) {
            results.push_back(hash(pwd, params));
        }
        return results;
    }

    // Verification
    bool verify(const std::string& hash_string, const std::string& password, const HashParams& params) const override {
        auto result = hash(password, params);
        if (!result.success) return false;

        std::string computed = bytes_to_hex(result.digest);
        return constant_time_compare(computed, hash_string);
    }

    bool verify(const std::vector<uint8_t>& hash_bytes, const std::string& password, const HashParams& params) const override {
        auto result = hash(password, params);
        if (!result.success) return false;
        return constant_time_compare(result.digest, hash_bytes);
    }

    // Parsing
    std::optional<HashParams> parse_hash(const std::string& hash_string) const override {
        if (hash_string.length() != digest_length_ * 2) return std::nullopt;
        if (!is_hex(hash_string)) return std::nullopt;
        return HashParams{};
    }

    std::string format_hash(const HashResult& result, const HashParams&) const override {
        return bytes_to_hex(result.digest);
    }

    bool identify_hash(const std::string& hash_string) const override {
        return hash_string.length() == digest_length_ * 2 && is_hex(hash_string);
    }

    bool has_gpu_implementation() const noexcept override { return true; }

protected:
    virtual HashResult hash(const uint8_t* data, size_t len) const = 0;

    static std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
        static const char* hex = "0123456789abcdef";
        std::string result;
        result.reserve(bytes.size() * 2);
        for (uint8_t b : bytes) {
            result.push_back(hex[b >> 4]);
            result.push_back(hex[b & 0xF]);
        }
        return result;
    }

    static bool is_hex(const std::string& s) {
        return std::all_of(s.begin(), s.end(), [](char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        });
    }

    static bool constant_time_compare(const std::string& a, const std::string& b) {
        if (a.size() != b.size()) return false;
        uint8_t diff = 0;
        for (size_t i = 0; i < a.size(); ++i) {
            diff |= static_cast<uint8_t>(std::tolower(a[i]) ^ std::tolower(b[i]));
        }
        return diff == 0;
    }

    static bool constant_time_compare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
        if (a.size() != b.size()) return false;
        uint8_t diff = 0;
        for (size_t i = 0; i < a.size(); ++i) {
            diff |= a[i] ^ b[i];
        }
        return diff == 0;
    }
};

/**
 * MD5 implementation
 */
class MD5Hash : public OpenSSLHashBase {
public:
    MD5Hash() : OpenSSLHashBase(HashType::MD5, "MD5", 0, MD5_DIGEST_LENGTH) {}

protected:
    HashResult hash(const uint8_t* data, size_t len) const override {
        HashResult result;
        result.digest.resize(MD5_DIGEST_LENGTH);
        MD5(data, len, result.digest.data());
        result.success = true;
        return result;
    }
};

/**
 * SHA1 implementation
 */
class SHA1Hash : public OpenSSLHashBase {
public:
    SHA1Hash() : OpenSSLHashBase(HashType::SHA1, "SHA1", 100, SHA_DIGEST_LENGTH) {}

protected:
    HashResult hash(const uint8_t* data, size_t len) const override {
        HashResult result;
        result.digest.resize(SHA_DIGEST_LENGTH);
        SHA1(data, len, result.digest.data());
        result.success = true;
        return result;
    }
};

/**
 * SHA224 implementation
 */
class SHA224Hash : public OpenSSLHashBase {
public:
    SHA224Hash() : OpenSSLHashBase(HashType::SHA224, "SHA224", 110, SHA224_DIGEST_LENGTH) {}

protected:
    HashResult hash(const uint8_t* data, size_t len) const override {
        HashResult result;
        result.digest.resize(SHA224_DIGEST_LENGTH);
        SHA224(data, len, result.digest.data());
        result.success = true;
        return result;
    }
};

/**
 * SHA256 implementation
 */
class SHA256Hash : public OpenSSLHashBase {
public:
    SHA256Hash() : OpenSSLHashBase(HashType::SHA256, "SHA256", 1400, SHA256_DIGEST_LENGTH) {}

protected:
    HashResult hash(const uint8_t* data, size_t len) const override {
        HashResult result;
        result.digest.resize(SHA256_DIGEST_LENGTH);
        SHA256(data, len, result.digest.data());
        result.success = true;
        return result;
    }
};

/**
 * SHA384 implementation
 */
class SHA384Hash : public OpenSSLHashBase {
public:
    SHA384Hash() : OpenSSLHashBase(HashType::SHA384, "SHA384", 10800, SHA384_DIGEST_LENGTH) {}

protected:
    HashResult hash(const uint8_t* data, size_t len) const override {
        HashResult result;
        result.digest.resize(SHA384_DIGEST_LENGTH);
        SHA384(data, len, result.digest.data());
        result.success = true;
        return result;
    }
};

/**
 * SHA512 implementation
 */
class SHA512Hash : public OpenSSLHashBase {
public:
    SHA512Hash() : OpenSSLHashBase(HashType::SHA512, "SHA512", 1700, SHA512_DIGEST_LENGTH) {}

protected:
    HashResult hash(const uint8_t* data, size_t len) const override {
        HashResult result;
        result.digest.resize(SHA512_DIGEST_LENGTH);
        SHA512(data, len, result.digest.data());
        result.success = true;
        return result;
    }
};

} // namespace KracKer