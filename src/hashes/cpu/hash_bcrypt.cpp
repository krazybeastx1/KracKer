#include "KracKer/hash_bcrypt.hpp"
#include "KracKer/utils.hpp"
#include <algorithm>
#include <cstring>
#include <random>
#include <stdexcept>
#include <vector>
#include <iostream>

// libxcrypt exposes the reentrant entry points that take a caller-provided
// buffer, so no <crypt.h> (libxcrypt-dev) is required to build.
#ifdef KK_HAVE_CRYPT
extern "C" {
char* crypt_gensalt_rn(const char* prefix, unsigned long count,
                       const char* rbytes, int nrbytes,
                       char* output, int output_size);
char* crypt_rn(const char* phrase, const char* setting, void* data, int size);
}
#endif

namespace KracKer {

namespace {

constexpr int kCryptBufferSize = 1 << 20;  // comfortably > sizeof(struct crypt_data)

#ifdef KK_HAVE_CRYPT
char* bcrypt_crypt(const std::string& password, const std::string& setting) {
    thread_local std::vector<char> buffer(kCryptBufferSize);
    return crypt_rn(password.c_str(), setting.c_str(), buffer.data(), kCryptBufferSize);
}
#else
char* bcrypt_crypt(const std::string&, const std::string&) { return nullptr; }
#endif

int bcrypt_b64_value(char c) {
    if (c == '.') return 0;
    if (c == '/') return 1;
    if (c >= 'A' && c <= 'Z') return c - 'A' + 2;
    if (c >= 'a' && c <= 'z') return c - 'a' + 28;
    if (c >= '0' && c <= '9') return c - '0' + 54;
    return -1;
}

// Length-safe decoder for the bcrypt base64 alphabet (no padding).
std::vector<uint8_t> bcrypt_b64_decode_bytes(const std::string& in) {
    std::vector<uint8_t> out;
    out.reserve(in.size() * 3 / 4 + 1);

    uint32_t accumulator = 0;
    int bits = 0;
    for (char c : in) {
        const int value = bcrypt_b64_value(c);
        if (value < 0) continue;
        accumulator = (accumulator << 6) | static_cast<uint32_t>(value);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((accumulator >> bits) & 0xFF));
        }
    }
    return out;
}

} // namespace

// Base64 encoding for bcrypt (uses ./A-Za-z0-9 alphabet)
static const char BCRYPT_BASE64[] = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

std::string BcryptHash::base64_encode(const uint8_t* data, size_t len) {
    std::string result;
    result.reserve((len + 2) / 3 * 4);

    size_t i = 0;
    while (i < len) {
        uint32_t chunk = 0;
        size_t remaining = len - i;

        chunk = data[i++] << 16;
        if (remaining > 1) chunk |= data[i++] << 8;
        if (remaining > 2) chunk |= data[i++];

        result.push_back(BCRYPT_BASE64[(chunk >> 18) & 0x3F]);
        result.push_back(BCRYPT_BASE64[(chunk >> 12) & 0x3F]);
        result.push_back(remaining > 1 ? BCRYPT_BASE64[(chunk >> 6) & 0x3F] : '.');
        result.push_back(remaining > 2 ? BCRYPT_BASE64[chunk & 0x3F] : '.');
    }

    return result;
}

std::vector<uint8_t> BcryptHash::base64_decode(const std::string& str) {
    std::vector<uint8_t> result;
    result.reserve(str.size() * 3 / 4);

    auto decode_char = [](char c) -> uint8_t {
        if (c == '.') return 0;
        if (c == '/') return 1;
        if (c >= 'A' && c <= 'Z') return c - 'A' + 2;
        if (c >= 'a' && c <= 'z') return c - 'a' + 28;
        if (c >= '0' && c <= '9') return c - '0' + 54;
        return 0xFF;
    };

    for (size_t i = 0; i < str.size(); i += 4) {
        uint32_t chunk = decode_char(str[i]) << 18;
        chunk |= decode_char(str[i + 1]) << 12;
        if (i + 2 < str.size() && str[i + 2] != '.')
            chunk |= decode_char(str[i + 2]) << 6;
        if (i + 3 < str.size() && str[i + 3] != '.')
            chunk |= decode_char(str[i + 3]);

        result.push_back((chunk >> 16) & 0xFF);
        if (i + 2 < str.size() && str[i + 2] != '.')
            result.push_back((chunk >> 8) & 0xFF);
        if (i + 3 < str.size() && str[i + 3] != '.')
            result.push_back(chunk & 0xFF);
    }

    return result;
}

void BcryptHash::bcrypt_init_state(BcryptState& state) {
    static const uint32_t P_init[18] = {
        0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
        0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
        0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
        0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
        0x9216d5d9, 0x8979fb1b
    };

    static const uint32_t S_init[4][256] = {
        {{0}}, {{0}}, {{0}}, {{0}}
    };

    std::copy(std::begin(P_init), std::end(P_init), state.P.begin());
}

void BcryptHash::bcrypt_expand_key(BcryptState& state, const uint8_t* key, size_t key_len, const uint8_t* salt, uint8_t cost) {
    (void)state; (void)key; (void)key_len; (void)salt; (void)cost;
}

void BcryptHash::bcrypt_encrypt(BcryptState& state, uint8_t* output) {
    (void)state;
    memset(output, 0, BCRYPT_HASH_SIZE);
}

bool BcryptHash::parse_bcrypt_hash(const std::string& hash_str, uint8_t& version, uint8_t& cost, std::vector<uint8_t>& salt, std::vector<uint8_t>& hash) {
    // "$2b$12$<53 base64 chars>"
    if (hash_str.size() != 60) return false;
    if (hash_str[0] != '$' || hash_str[1] != '2' || hash_str[3] != '$' || hash_str[6] != '$') {
        return false;
    }

    char ver = hash_str[2];
    if (ver == 'a') version = 0x2A;
    else if (ver == 'b') version = 0x2B;
    else if (ver == 'y') version = 0x2C;
    else return false;

    if (hash_str[4] < '0' || hash_str[4] > '9' || hash_str[5] < '0' || hash_str[5] > '9') {
        return false;
    }
    cost = static_cast<uint8_t>((hash_str[4] - '0') * 10 + (hash_str[5] - '0'));
    if (cost < 4 || cost > 31) return false;

    std::string b64 = hash_str.substr(7);
    if (b64.size() != 53) return false;

    auto decoded = bcrypt_b64_decode_bytes(b64);
    if (decoded.size() != BCRYPT_SALT_SIZE + BCRYPT_HASH_SIZE) return false;

    salt.assign(decoded.begin(), decoded.begin() + BCRYPT_SALT_SIZE);
    hash.assign(decoded.begin() + BCRYPT_SALT_SIZE, decoded.end());

    return true;
}

HashResult BcryptHash::hash(const std::string& password, const HashParams& params) const {
    HashResult result;

    uint8_t cost = params.bcrypt_cost ? params.bcrypt_cost : 12;
    if (cost < 4) cost = 4;
    if (cost > 31) cost = 31;

    std::vector<uint8_t> salt(BCRYPT_SALT_SIZE);
    std::random_device rd;
    for (auto& byte : salt) byte = static_cast<uint8_t>(rd());

    char setting[128] = {0};
    if (!crypt_gensalt_rn("$2b$", cost,
                          reinterpret_cast<const char*>(salt.data()),
                          static_cast<int>(salt.size()),
                          setting, static_cast<int>(sizeof(setting)))) {
        result.error = "bcrypt: salt generation failed";
        return result;
    }

    char* full = bcrypt_crypt(password, setting);
    if (!full) {
        result.error = "bcrypt: hashing failed";
        return result;
    }

    const std::string hashed(full);
    if (hashed.size() < 7) {
        result.error = "bcrypt: malformed output";
        return result;
    }

    // "$2b$CC$" + 53 base64 chars -> 16-byte salt + 23-byte hash
    result.digest = bcrypt_b64_decode_bytes(hashed.substr(7));
    if (result.digest.size() != BCRYPT_SALT_SIZE + BCRYPT_HASH_SIZE) {
        result.error = "bcrypt: unexpected digest size";
        return result;
    }

    result.success = true;
    return result;
}

HashResult BcryptHash::hash(const std::vector<uint8_t>& password, const HashParams& params) const {
    return hash(std::string(password.begin(), password.end()), params);
}

std::vector<HashResult> BcryptHash::hash_batch(
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

bool BcryptHash::verify(const std::string& hash_string, const std::string& password, const HashParams& params) const {
    (void)params;

    uint8_t version, cost;
    std::vector<uint8_t> salt, expected_hash;
    if (!parse_bcrypt_hash(hash_string, version, cost, salt, expected_hash)) {
        return false;
    }

    // crypt_rn re-derives the hash from the full "$2b$cost$salt" setting.
    char* computed = bcrypt_crypt(password, hash_string);
    if (!computed) return false;

    return constant_time_compare(std::string(computed), hash_string);
}

bool BcryptHash::verify(const std::vector<uint8_t>& hash_bytes, const std::string& password, const HashParams& params) const {
    if (hash_bytes.size() != BCRYPT_SALT_SIZE + BCRYPT_HASH_SIZE) return false;

    // The digest stores salt||hash; the cost comes from params, so rebuild the
    // modular-crypt string and verify through the same path as string hashes.
    HashResult raw;
    raw.digest = hash_bytes;
    raw.success = true;

    const std::string formatted = format_hash(raw, params);
    if (formatted.empty()) return false;

    return verify(formatted, password, params);
}

std::optional<HashParams> BcryptHash::parse_hash(const std::string& hash_string) const {
    HashParams params;
    uint8_t version, cost;
    std::vector<uint8_t> salt, hash;

    if (!parse_bcrypt_hash(hash_string, version, cost, salt, hash)) {
        return std::nullopt;
    }

    params.bcrypt_cost = cost;
    return params;
}

std::string BcryptHash::format_hash(const HashResult& result, const HashParams& params) const {
    if (!result.success || result.digest.size() != BCRYPT_SALT_SIZE + BCRYPT_HASH_SIZE) return "";

    uint8_t cost = params.bcrypt_cost ? params.bcrypt_cost : 12;
    // bcrypt encodes salt/hash in 4-char groups and drops the trailing padding.
    std::string salt_b64 = base64_encode(result.digest.data(), BCRYPT_SALT_SIZE).substr(0, 22);
    std::string hash_b64 = base64_encode(result.digest.data() + BCRYPT_SALT_SIZE, BCRYPT_HASH_SIZE).substr(0, 31);

    char version_char = 'b';
    return "$2" + std::string(1, version_char) + "$" +
           (cost < 10 ? "0" : "") + std::to_string(cost) + "$" +
           salt_b64 + hash_b64;
}

bool BcryptHash::identify_hash(const std::string& hash_string) const {
    return hash_string.size() >= 7 &&
           hash_string[0] == '$' &&
           (hash_string[1] == '2') &&
           (hash_string[2] == 'a' || hash_string[2] == 'b' || hash_string[2] == 'y') &&
           hash_string[3] == '$';
}

BcryptHash::~BcryptHash() {
    // Explicit destructor definition for vtable emission
}

} // namespace KracKer