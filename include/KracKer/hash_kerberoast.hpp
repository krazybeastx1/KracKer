#pragma once

#include "KracKer/hash_interface.hpp"
#include <string>
#include <vector>
#include <cstdint>
#include <optional>
#include <array>

namespace KracKer {

/**
 * Kerberoasting hash implementations
 * 
 * Kerberos encryption types (etype):
 * - 1: des-cbc-crc (DES)
 * - 3: des-cbc-md5 (DES)
 * - 16: des3-cbc-sha1 (3DES)
 * - 17: aes128-cts-hmac-sha1-96 (AES-128)
 * - 18: aes256-cts-hmac-sha1-96 (AES-256)
 * - 23: rc4-hmac (RC4-HMAC) - most common
 * 
 * Hash formats (hashcat-compatible):
 * - $krb5tgs$<etype>$<realm>$<sname>$<salt>$<checksum>
 * - $krb5tgs$23$<realm>$<sname>$<salt>$<checksum> (RC4-HMAC)
 * - $krb5tgs$17$<realm>$<sname>$<salt>$<checksum> (AES-128)
 * - $krb5tgs$18$<realm>$<sname>$<salt>$<checksum> (AES-256)
 */
class KerberoastHash : public IHashAlgorithm {
public:
    enum class EType : uint32_t {
        DES_CBC_CRC     = 1,
        DES_CBC_MD5     = 3,
        DES3_CBC_SHA1   = 16,
        AES128_CTS_HMAC = 17,
        AES256_CTS_HMAC = 18,
        RC4_HMAC        = 23
    };

    KerberoastHash(EType etype = EType::RC4_HMAC) : etype_(etype) {}

    HashType type() const noexcept override {
        switch (etype_) {
            case EType::RC4_HMAC:        return HashType::KERBEROAST_RC4_HMAC;
            case EType::AES128_CTS_HMAC: return HashType::KERBEROAST_AES128_CTS_HMAC;
            case EType::AES256_CTS_HMAC: return HashType::KERBEROAST_AES256_CTS_HMAC;
            case EType::DES3_CBC_SHA1:   return HashType::KERBEROAST_DES3_CBC_SHA1;
            case EType::DES_CBC_CRC:
            case EType::DES_CBC_MD5:     return HashType::KERBEROAST_DES_CBC_MD5;
            default:                     return HashType::UNKNOWN;
        }
    }

    std::string name() const noexcept override {
        switch (etype_) {
            case EType::RC4_HMAC:        return "Kerberoast-RC4-HMAC";
            case EType::AES128_CTS_HMAC: return "Kerberoast-AES128";
            case EType::AES256_CTS_HMAC: return "Kerberoast-AES256";
            case EType::DES3_CBC_SHA1:   return "Kerberoast-DES3";
            case EType::DES_CBC_CRC:     return "Kerberoast-DES-CRC";
            case EType::DES_CBC_MD5:     return "Kerberoast-DES-MD5";
            default:                     return "Kerberoast-Unknown";
        }
    }

    uint32_t hashcat_mode() const noexcept override {
        switch (etype_) {
            case EType::RC4_HMAC:        return 13100;
            case EType::AES128_CTS_HMAC: return 19600;
            case EType::AES256_CTS_HMAC: return 19700;
            case EType::DES3_CBC_SHA1:   return 13100;
            case EType::DES_CBC_CRC:
            case EType::DES_CBC_MD5:     return 13100;
            default:                     return 0;
        }
    }

    HashCapabilities capabilities() const noexcept override {
        HashCapabilities caps;
        caps.supports_gpu = (etype_ == EType::RC4_HMAC || etype_ == EType::AES128_CTS_HMAC || etype_ == EType::AES256_CTS_HMAC);
        caps.supports_distributed = true;
        caps.is_slow_hash = false;
        caps.requires_salt = true;
        caps.supports_mask = true;
        caps.supports_rules = true;
        caps.optimal_workgroup_size = 256;
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

    bool has_gpu_implementation() const noexcept override {
        return etype_ == EType::RC4_HMAC || etype_ == EType::AES128_CTS_HMAC || etype_ == EType::AES256_CTS_HMAC;
    }

    // Virtual destructor for proper vtable emission (defined in cpp)
    virtual ~KerberoastHash();

    // Factory methods
    static std::unique_ptr<KerberoastHash> create_rc4_hmac();
    static std::unique_ptr<KerberoastHash> create_aes128();
    static std::unique_ptr<KerberoastHash> create_aes256();
    static std::unique_ptr<KerberoastHash> create_des3();
    static std::unique_ptr<KerberoastHash> create_from_etype(uint32_t etype);

private:
    EType etype_;

    // Kerberos crypto primitives
    static void kerberos_string_to_key(const std::string& password, const std::string& salt, EType etype, std::vector<uint8_t>& key);
    static void rc4_hmac_md5(const std::vector<uint8_t>& key, const uint8_t* data, size_t len, uint8_t* checksum);
    static void aes_cts_hmac_sha1(const std::vector<uint8_t>& key, const uint8_t* data, size_t len, uint8_t* checksum, bool aes256);
    static void des3_cbc_sha1(const std::vector<uint8_t>& key, const uint8_t* data, size_t len, uint8_t* checksum);

    static std::string base64_encode(const uint8_t* data, size_t len, bool urlsafe = false);
    static std::vector<uint8_t> base64_decode(const std::string& str, bool urlsafe = false);
    static bool parse_kerberoast_hash(const std::string& hash_str, EType& etype,
                                       std::string& realm, std::string& sname,
                                       std::vector<uint8_t>& salt, std::vector<uint8_t>& checksum);
};

} // namespace KracKer