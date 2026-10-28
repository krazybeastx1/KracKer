#include "KracKer/hash_kerberoast.hpp"
#include "KracKer/utils.hpp"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/md4.h>
#include <openssl/rc4.h>
#include <openssl/des.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <algorithm>
#include <cstring>
#include <sstream>
#include <iomanip>

namespace KracKer {

namespace {

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

// RC4-HMAC (etype 23) key material starts from MD4 over the UTF-16LE password,
// which is the same value as the account's NT hash.
std::vector<uint8_t> md4_utf16le(const std::string& password) {
    std::vector<uint8_t> utf16;
    utf16.reserve(password.size() * 2);
    for (unsigned char c : password) {
        utf16.push_back(c);
        utf16.push_back(0);
    }

    std::vector<uint8_t> digest(16);
    MD4(utf16.data(), utf16.size(), digest.data());
    return digest;
}

std::vector<uint8_t> hmac_md5(const std::vector<uint8_t>& key,
                              const uint8_t* data, size_t len) {
    std::vector<uint8_t> out(16);
    unsigned int out_len = 16;
    HMAC(EVP_md5(), key.data(), static_cast<int>(key.size()),
         data, len, out.data(), &out_len);
    return out;
}

// Plain RC4. `drop` is the number of keystream bytes to discard; etype 23 as
// implemented by Windows (and validated against hashcat's reference vector)
// discards none.
std::vector<uint8_t> rc4_crypt(const std::vector<uint8_t>& key,
                               const uint8_t* data, size_t len,
                               size_t drop) {
    uint8_t s[256];
    for (int i = 0; i < 256; ++i) s[i] = static_cast<uint8_t>(i);

    uint8_t j = 0;
    for (int i = 0; i < 256; ++i) {
        j = static_cast<uint8_t>(j + s[i] + key[i % key.size()]);
        std::swap(s[i], s[j]);
    }

    uint8_t i2 = 0;
    j = 0;  // PRGA starts from fresh indices; the KSA leaves j at its last value.
    auto next_byte = [&]() -> uint8_t {
        i2 = static_cast<uint8_t>(i2 + 1);
        j = static_cast<uint8_t>(j + s[i2]);
        std::swap(s[i2], s[j]);
        return s[static_cast<uint8_t>(s[i2] + s[j])];
    };

    for (size_t k = 0; k < drop; ++k) next_byte();

    std::vector<uint8_t> out(len);
    for (size_t k = 0; k < len; ++k) out[k] = data[k] ^ next_byte();
    return out;
}

#pragma GCC diagnostic pop

int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool hex_decode(const std::string& in, std::vector<uint8_t>& out) {
    if (in.empty() || (in.size() % 2) != 0) return false;
    out.clear();
    out.reserve(in.size() / 2);
    for (size_t i = 0; i < in.size(); i += 2) {
        const int hi = hex_nibble(in[i]);
        const int lo = hex_nibble(in[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

} // namespace

// Base64 encoding (standard and URL-safe)
static const char BASE64_STD[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char BASE64_URL[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

std::string KerberoastHash::base64_encode(const uint8_t* data, size_t len, bool urlsafe) {
    const char* alphabet = urlsafe ? BASE64_URL : BASE64_STD;
    std::string result;
    result.reserve((len + 2) / 3 * 4);

    for (size_t i = 0; i < len; i += 3) {
        uint32_t chunk = data[i] << 16;
        if (i + 1 < len) chunk |= data[i + 1] << 8;
        if (i + 2 < len) chunk |= data[i + 2];

        result.push_back(alphabet[(chunk >> 18) & 0x3F]);
        result.push_back(alphabet[(chunk >> 12) & 0x3F]);
        result.push_back(i + 1 < len ? alphabet[(chunk >> 6) & 0x3F] : (urlsafe ? '.' : '='));
        result.push_back(i + 2 < len ? alphabet[chunk & 0x3F] : (urlsafe ? '.' : '='));
    }

    return result;
}

std::vector<uint8_t> KerberoastHash::base64_decode(const std::string& str, bool urlsafe) {
    std::vector<uint8_t> result;
    result.reserve(str.size() * 3 / 4);

    auto decode_char = [urlsafe](char c) -> uint8_t {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (!urlsafe) {
            if (c == '+') return 62;
            if (c == '/') return 63;
        } else {
            if (c == '-') return 62;
            if (c == '_') return 63;
        }
        return 0xFF;
    };

    for (size_t i = 0; i < str.size(); i += 4) {
        if (i < str.size() && str[i] == '=') break;
        if (i < str.size() && str[i] == '.') break;
        uint32_t chunk = decode_char(str[i]) << 18;
        chunk |= decode_char(str[i + 1]) << 12;
        if (i + 2 < str.size() && str[i + 2] != '=' && str[i + 2] != '.')
            chunk |= decode_char(str[i + 2]) << 6;
        if (i + 3 < str.size() && str[i + 3] != '=' && str[i + 3] != '.')
            chunk |= decode_char(str[i + 3]);

        result.push_back((chunk >> 16) & 0xFF);
        if (i + 2 < str.size() && str[i + 2] != '=' && str[i + 2] != '.')
            result.push_back((chunk >> 8) & 0xFF);
        if (i + 3 < str.size() && str[i + 3] != '=' && str[i + 3] != '.')
            result.push_back(chunk & 0xFF);
    }

    return result;
}

bool KerberoastHash::parse_kerberoast_hash(const std::string& hash_str, EType& etype,
                                            std::string& realm, std::string& sname,
                                            std::vector<uint8_t>& salt, std::vector<uint8_t>& checksum) {
    if (hash_str.size() < 12 || hash_str.substr(0, 9) != "$krb5tgs$") {
        return false;
    }

    // etype
    size_t pos = 9;
    size_t etype_end = hash_str.find('$', pos);
    if (etype_end == std::string::npos) return false;

    try {
        etype = static_cast<EType>(std::stoul(hash_str.substr(pos, etype_end - pos)));
    } catch (...) {
        return false;
    }
    pos = etype_end + 1;
    if (pos >= hash_str.size()) return false;

    // hashcat format 1: $krb5tgs$23$*user$realm$spn*$checksum$edata2
    if (hash_str[pos] == '*') {
        const size_t account_end = hash_str.find("*$", pos);
        if (account_end == std::string::npos) return false;

        const std::string account = hash_str.substr(pos + 1, account_end - (pos + 1));
        const size_t first_sep = account.find('$');
        const size_t second_sep = first_sep == std::string::npos
            ? std::string::npos : account.find('$', first_sep + 1);
        if (second_sep == std::string::npos) return false;

        realm = account.substr(first_sep + 1, second_sep - first_sep - 1);
        sname = account.substr(second_sep + 1);

        pos = account_end + 2;  // skip "*$"
        const size_t checksum_end = hash_str.find('$', pos);
        if (checksum_end == std::string::npos) return false;

        if (!hex_decode(hash_str.substr(pos, checksum_end - pos), checksum)) return false;
        if (!hex_decode(hash_str.substr(checksum_end + 1), salt)) return false;

        return !salt.empty() && !checksum.empty();
    }

    // Split the remaining fields on '$'.
    std::vector<std::string> fields;
    std::string rest = hash_str.substr(pos);
    size_t start = 0;
    while (start <= rest.size()) {
        const size_t sep = rest.find('$', start);
        fields.push_back(rest.substr(start, sep == std::string::npos ? std::string::npos : sep - start));
        if (sep == std::string::npos) break;
        start = sep + 1;
    }

    if (fields.size() == 4) {
        // Native format: etype$realm$sname$<base64 ciphertext>$<base64 checksum>
        realm = fields[0];
        sname = fields[1];
        salt = base64_decode(fields[2], true);
        checksum = base64_decode(fields[3], true);
        return !salt.empty() && !checksum.empty();
    }

    if (fields.size() == 2) {
        // hashcat format 2: $krb5tgs$23$checksum$edata2 (hex)
        realm.clear();
        sname.clear();
        if (!hex_decode(fields[0], checksum)) return false;
        if (!hex_decode(fields[1], salt)) return false;
        return !salt.empty() && !checksum.empty();
    }

    return false;
}

void KerberoastHash::kerberos_string_to_key(const std::string& password, const std::string& salt, EType etype, std::vector<uint8_t>& key) {
    switch (etype) {
        case EType::RC4_HMAC:
            // RFC 4757: the RC4-HMAC base key is the NT hash of the password.
            key = md4_utf16le(password);
            return;
        case EType::AES128_CTS_HMAC:
        case EType::AES256_CTS_HMAC: {
            // RFC 3962: PBKDF2-HMAC-SHA1, 4096 iterations, salt = realm + sname.
            const size_t key_len = (etype == EType::AES256_CTS_HMAC) ? 32 : 16;
            key.assign(key_len, 0);
            PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                              reinterpret_cast<const uint8_t*>(salt.c_str()), salt.length(),
                              4096, EVP_sha1(),
                              static_cast<int>(key_len), key.data());
            return;
        }
        default:
            // DES3 / DES string-to-key use Kerberos n-fold, which is not
            // implemented here; callers reject those etypes before this point.
            key.clear();
            return;
    }
}

void KerberoastHash::rc4_hmac_md5(const std::vector<uint8_t>& key, const uint8_t* data, size_t len, uint8_t* checksum) {
    unsigned int md_len = 16;
    HMAC(EVP_md5(), key.data(), key.size(), data, len, checksum, &md_len);
}

void KerberoastHash::aes_cts_hmac_sha1(const std::vector<uint8_t>& key, const uint8_t* data, size_t len, uint8_t* checksum, bool aes256) {
    std::vector<uint8_t> k1(key.size()), k2(key.size());
    
    for (size_t i = 0; i < key.size(); ++i) {
        k1[i] = key[i] ^ 0xAA;
        k2[i] = key[i] ^ 0x55;
    }

    unsigned int md_len = 20;
    std::vector<uint8_t> hmac_result(20);
    HMAC(EVP_sha1(), k2.data(), k2.size(), data, len, hmac_result.data(), &md_len);
    memcpy(checksum, hmac_result.data(), 12);
}

void KerberoastHash::des3_cbc_sha1(const std::vector<uint8_t>& key, const uint8_t* data, size_t len, uint8_t* checksum) {
    unsigned int md_len = 20;
    HMAC(EVP_sha1(), key.data(), key.size(), data, len, checksum, &md_len);
}

HashResult KerberoastHash::hash(const std::string& password, const HashParams& params) const {
    HashResult result;

    const EType etype = etype_;
    const std::vector<uint8_t>& ciphertext = params.kerb_salt;
    const std::vector<uint8_t>& checksum = params.kerb_checksum;

    if (ciphertext.empty() || checksum.empty()) {
        result.error = "Missing Kerberos parameters (ciphertext, checksum)";
        return result;
    }

    switch (etype) {
        case EType::RC4_HMAC: {
            if (checksum.size() != 16) {
                result.error = "RC4-HMAC checksum must be 16 bytes";
                return result;
            }
            if (ciphertext.size() < 32) {
                result.error = "RC4-HMAC ciphertext is too short";
                return result;
            }

            // RFC 4757: K1 = HMAC_MD5(MD4(UTF16LE(pw)), usage=2 LE)
            const std::vector<uint8_t> base_key = md4_utf16le(password);
            const uint8_t usage[4] = {2, 0, 0, 0};
            const std::vector<uint8_t> k1 = hmac_md5(base_key, usage, sizeof(usage));
            const std::vector<uint8_t> rc4_key = hmac_md5(k1, checksum.data(), checksum.size());

            const std::vector<uint8_t> plaintext =
                rc4_crypt(rc4_key, ciphertext.data(), ciphertext.size(), 0);

            // Integrity check: HMAC_MD5(K1, plaintext) must equal the stored checksum.
            result.digest = hmac_md5(k1, plaintext.data(), plaintext.size());
            result.success = true;
            return result;
        }
        case EType::AES128_CTS_HMAC:
        case EType::AES256_CTS_HMAC:
            result.error = "Kerberos AES (etype 17/18) verification is not implemented";
            return result;
        case EType::DES3_CBC_SHA1:
        case EType::DES_CBC_CRC:
        case EType::DES_CBC_MD5:
            result.error = "Kerberos DES/DES3 (etype 16/1/3) verification is not implemented";
            return result;
        default:
            result.error = "Unsupported Kerberos etype";
            return result;
    }
}

HashResult KerberoastHash::hash(const std::vector<uint8_t>& password, const HashParams& params) const {
    return hash(std::string(password.begin(), password.end()), params);
}

std::vector<HashResult> KerberoastHash::hash_batch(
    const std::vector<std::string>& passwords,
    const HashParams& params
) const {
    std::vector<HashResult> results;
    results.reserve(passwords.size());
    for (const auto& pwd : passwords) {
        results.push_back(hash(pwd, params));
    }
    return results;
}

bool KerberoastHash::verify(const std::string& hash_string, const std::string& password, const HashParams& params) const {
    EType etype;
    std::string realm, sname;
    std::vector<uint8_t> salt, checksum;

    if (!parse_kerberoast_hash(hash_string, etype, realm, sname, salt, checksum)) {
        return false;
    }

    if (etype != etype_) return false;

    HashParams verify_params = params;
    verify_params.kerb_etype = static_cast<uint32_t>(etype);
    verify_params.kerb_realm = realm;
    verify_params.kerb_sname = sname;
    verify_params.kerb_salt = salt;
    verify_params.kerb_checksum = checksum;

    auto result = hash(password, verify_params);
    if (!result.success) return false;

    if (result.digest.size() != checksum.size()) return false;
    return constant_time_compare(result.digest, checksum);
}

bool KerberoastHash::verify(const std::vector<uint8_t>& hash_bytes, const std::string& password, const HashParams& params) const {
    return false;
}

std::optional<HashParams> KerberoastHash::parse_hash(const std::string& hash_string) const {
    HashParams params;
    EType etype;
    std::string realm, sname;
    std::vector<uint8_t> salt, checksum;

    if (!parse_kerberoast_hash(hash_string, etype, realm, sname, salt, checksum)) {
        return std::nullopt;
    }

    params.kerb_etype = static_cast<uint32_t>(etype);
    params.kerb_realm = realm;
    params.kerb_sname = sname;
    params.kerb_salt = salt;
    params.kerb_checksum = checksum;
    return params;
}

std::string KerberoastHash::format_hash(const HashResult& result, const HashParams& params) const {
    if (!result.success) return "";

    std::string salt_b64 = base64_encode(params.kerb_salt.data(), params.kerb_salt.size(), true);
    std::string checksum_b64 = base64_encode(params.kerb_checksum.data(), params.kerb_checksum.size(), true);

    return "$krb5tgs$" + std::to_string(static_cast<uint32_t>(etype_)) + "$" +
           params.kerb_realm + "$" + params.kerb_sname + "$" +
           salt_b64 + "$" + checksum_b64;
}

bool KerberoastHash::identify_hash(const std::string& hash_string) const {
    return hash_string.size() >= 9 && hash_string.substr(0, 9) == "$krb5tgs$";
}

std::unique_ptr<KerberoastHash> KerberoastHash::create_rc4_hmac() {
    return std::make_unique<KerberoastHash>(EType::RC4_HMAC);
}

std::unique_ptr<KerberoastHash> KerberoastHash::create_aes128() {
    return std::make_unique<KerberoastHash>(EType::AES128_CTS_HMAC);
}

std::unique_ptr<KerberoastHash> KerberoastHash::create_aes256() {
    return std::make_unique<KerberoastHash>(EType::AES256_CTS_HMAC);
}

std::unique_ptr<KerberoastHash> KerberoastHash::create_des3() {
    return std::make_unique<KerberoastHash>(EType::DES3_CBC_SHA1);
}

std::unique_ptr<KerberoastHash> KerberoastHash::create_from_etype(uint32_t etype) {
    switch (etype) {
        case 1:  return create_des3();
        case 3:  return create_des3();
        case 16: return create_des3();
        case 17: return create_aes128();
        case 18: return create_aes256();
        case 23: return create_rc4_hmac();
        default: return create_rc4_hmac();
    }
}

KerberoastHash::~KerberoastHash() {
    // Explicit destructor definition for vtable emission
}

} // namespace KracKer