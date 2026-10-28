#pragma once

#include "KracKer/hash_interface.hpp"
#include <openssl/md4.h>
#include <string>
#include <vector>
#include <cstdint>
#include <algorithm>

namespace KracKer {

/**
 * NTLM hash implementation (MD4 of UTF-16LE password)
 */
class NTLMHash : public IHashAlgorithm {
public:
    HashType type() const noexcept override { return HashType::NTLM; }
    std::string name() const noexcept override { return "NTLM"; }
    uint32_t hashcat_mode() const noexcept override { return 1000; }

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

    HashResult hash(const std::string& password, const HashParams&) const override {
        return hash_utf16le(password);
    }

    HashResult hash(const std::vector<uint8_t>& password, const HashParams&) const override {
        // Assume already UTF-16LE encoded
        HashResult result;
        result.digest.resize(MD4_DIGEST_LENGTH);
        MD4(password.data(), password.size(), result.digest.data());
        result.success = true;
        return result;
    }

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

    std::optional<HashParams> parse_hash(const std::string& hash_string) const override {
        if (hash_string.length() != 32) return std::nullopt;
        if (!is_hex(hash_string)) return std::nullopt;
        return HashParams{};
    }

    std::string format_hash(const HashResult& result, const HashParams&) const override {
        return bytes_to_hex(result.digest);
    }

    bool identify_hash(const std::string& hash_string) const override {
        // NTLM is 32 hex chars like MD5, but we can't distinguish without context
        return hash_string.length() == 32 && is_hex(hash_string);
    }

    bool has_gpu_implementation() const noexcept override { return true; }

    size_t recommended_batch_size(DeviceType device) const noexcept override {
        return device == DeviceType::GPU ? 1000000 : 100000;
    }

private:
    HashResult hash_utf16le(const std::string& password) const {
        HashResult result;
        result.digest.resize(MD4_DIGEST_LENGTH);

        // Convert to UTF-16LE
        std::vector<uint8_t> utf16;
        utf16.reserve(password.size() * 2);
        for (unsigned char c : password) {
            utf16.push_back(c);
            utf16.push_back(0);
        }

        MD4(utf16.data(), utf16.size(), result.digest.data());
        result.success = true;
        return result;
    }

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

} // namespace KracKer