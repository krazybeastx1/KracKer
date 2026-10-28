#include "KracKer/hash_scrypt.hpp"
#include "KracKer/utils.hpp"
#include <openssl/evp.h>
#include <algorithm>
#include <cstring>
#include <random>
#include <stdexcept>
#include <vector>

namespace KracKer {

// Base64 encoding (standard)
static const char BASE64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string ScryptHash::base64_encode(const uint8_t* data, size_t len) {
    std::string result;
    result.reserve((len + 2) / 3 * 4);

    for (size_t i = 0; i < len; i += 3) {
        uint32_t chunk = data[i] << 16;
        if (i + 1 < len) chunk |= data[i + 1] << 8;
        if (i + 2 < len) chunk |= data[i + 2];

        result.push_back(BASE64[(chunk >> 18) & 0x3F]);
        result.push_back(BASE64[(chunk >> 12) & 0x3F]);
        result.push_back(i + 1 < len ? BASE64[(chunk >> 6) & 0x3F] : '=');
        result.push_back(i + 2 < len ? BASE64[chunk & 0x3F] : '=');
    }

    return result;
}

std::vector<uint8_t> ScryptHash::base64_decode(const std::string& str) {
    std::vector<uint8_t> out;
    out.reserve(str.size() * 3 / 4 + 1);

    auto decode_char = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };

    // Accumulator-based decode: safe for unpadded input and never reads past
    // the end of the string.
    uint32_t accumulator = 0;
    int bits = 0;
    for (char c : str) {
        if (c == '=') break;
        const int value = decode_char(c);
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

bool ScryptHash::parse_scrypt_hash(const std::string& hash_str, uint32_t& N, uint32_t& r, uint32_t& p,
                                    std::vector<uint8_t>& salt, std::vector<uint8_t>& hash) {
    if (hash_str.size() < 6 || hash_str.substr(0, 4) != "$s0$") {
        return false;
    }

    size_t pos = 4;
    auto parse_num = [&](size_t& p) -> std::optional<uint32_t> {
        size_t end = hash_str.find('$', p);
        if (end == std::string::npos) return std::nullopt;
        try {
            uint32_t val = std::stoul(hash_str.substr(p, end - p));
            p = end + 1;
            return val;
        } catch (...) {
            return std::nullopt;
        }
    };

    auto opt_N = parse_num(pos);
    auto opt_r = parse_num(pos);
    auto opt_p = parse_num(pos);
    if (!opt_N || !opt_r || !opt_p) return false;

    N = *opt_N;
    r = *opt_r;
    p = *opt_p;

    if (N < 2 || (N & (N - 1)) != 0) return false;
    if (r == 0 || p == 0) return false;
    if (r > 65535 || p > 65535) return false;
    if ((uint64_t)r * p >= (1ULL << 30)) return false;

    size_t salt_start = pos;
    size_t salt_end = hash_str.find('$', salt_start);
    if (salt_end == std::string::npos) return false;

    std::string salt_b64 = hash_str.substr(salt_start, salt_end - salt_start);
    std::string hash_b64 = hash_str.substr(salt_end + 1);

    salt = base64_decode(salt_b64);
    hash = base64_decode(hash_b64);

    return true;
}

HashResult ScryptHash::hash(const std::string& password, const HashParams& params) const {
    HashResult result;

    uint32_t N = params.scrypt_N ? params.scrypt_N : 16384;
    uint32_t r = params.scrypt_r ? params.scrypt_r : 8;
    uint32_t p = params.scrypt_p ? params.scrypt_p : 1;

    std::vector<uint8_t> salt(16);
    std::random_device rd;
    for (auto& byte : salt) byte = static_cast<uint8_t>(rd());

    constexpr size_t key_len = 32;
    std::vector<uint8_t> key(key_len);

    const uint64_t maxmem = 128ULL * r * (static_cast<uint64_t>(N) + 2) * 2;
    if (EVP_PBE_scrypt(password.data(), password.size(),
                       salt.data(), salt.size(),
                       N, r, p, maxmem,
                       key.data(), key.size()) != 1) {
        result.error = "scrypt: derivation failed";
        return result;
    }

    // digest layout: salt || derived key
    result.digest = salt;
    result.digest.insert(result.digest.end(), key.begin(), key.end());
    result.success = true;
    return result;
}

HashResult ScryptHash::hash(const std::vector<uint8_t>& password, const HashParams& params) const {
    return hash(std::string(password.begin(), password.end()), params);
}

std::vector<HashResult> ScryptHash::hash_batch(
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

bool ScryptHash::verify(const std::string& hash_string, const std::string& password, const HashParams& params) const {
    (void)params;

    uint32_t N, r, p;
    std::vector<uint8_t> salt, expected_hash;

    if (!parse_scrypt_hash(hash_string, N, r, p, salt, expected_hash)) {
        return false;
    }
    if (expected_hash.empty()) return false;

    std::vector<uint8_t> derived(expected_hash.size());
    const uint64_t maxmem = 128ULL * r * (static_cast<uint64_t>(N) + 2) * 2;

    if (EVP_PBE_scrypt(password.data(), password.size(),
                       salt.data(), salt.size(),
                       N, r, p, maxmem,
                       derived.data(), derived.size()) != 1) {
        return false;
    }

    return constant_time_compare(derived, expected_hash);
}

bool ScryptHash::verify(const std::vector<uint8_t>& hash_bytes, const std::string& password, const HashParams& params) const {
    if (hash_bytes.size() <= 16) return false;

    // The digest stores salt||derived key; N/r/p come from params.
    HashResult raw;
    raw.digest = hash_bytes;
    raw.success = true;

    const std::string formatted = format_hash(raw, params);
    if (formatted.empty()) return false;

    return verify(formatted, password, params);
}

std::optional<HashParams> ScryptHash::parse_hash(const std::string& hash_string) const {
    HashParams params;
    uint32_t N, r, p;
    std::vector<uint8_t> salt, hash;

    if (!parse_scrypt_hash(hash_string, N, r, p, salt, hash)) {
        return std::nullopt;
    }

    params.scrypt_N = N;
    params.scrypt_r = r;
    params.scrypt_p = p;
    return params;
}

std::string ScryptHash::format_hash(const HashResult& result, const HashParams& params) const {
    if (!result.success || result.digest.size() <= 16) return "";

    uint32_t N = params.scrypt_N ? params.scrypt_N : 16384;
    uint32_t r = params.scrypt_r ? params.scrypt_r : 8;
    uint32_t p = params.scrypt_p ? params.scrypt_p : 1;

    auto b64 = [](const uint8_t* data, size_t len) {
        std::string encoded = ScryptHash::base64_encode(data, len);
        while (!encoded.empty() && encoded.back() == '=') encoded.pop_back();
        return encoded;
    };

    const std::string salt_b64 = b64(result.digest.data(), 16);
    const std::string hash_b64 = b64(result.digest.data() + 16, result.digest.size() - 16);

    return "$s0$" + std::to_string(N) + "$" + std::to_string(r) + "$" +
           std::to_string(p) + "$" + salt_b64 + "$" + hash_b64;
}

bool ScryptHash::identify_hash(const std::string& hash_string) const {
    return hash_string.size() >= 4 && hash_string.substr(0, 4) == "$s0$";
}

void ScryptHash::salsa20_8(uint32_t* B) { (void)B; }
void ScryptHash::blockmix_salsa8(uint32_t* out, uint32_t* in, uint32_t* tmp, size_t r) { (void)out; (void)in; (void)tmp; (void)r; }
void ScryptHash::integerify(uint32_t* out, uint32_t* in, size_t r) { (void)out; (void)in; (void)r; }
void ScryptHash::smix(uint8_t* B, size_t r, uint32_t N, uint32_t* V, uint32_t* XY) { (void)B; (void)r; (void)N; (void)V; (void)XY; }
void ScryptHash::blake2b_init(void* state, size_t outlen) { (void)state; (void)outlen; }
void ScryptHash::blake2b_update(void* state, const void* in, size_t inlen) { (void)state; (void)in; (void)inlen; }
void ScryptHash::blake2b_final(void* state, void* out, size_t outlen) { (void)state; (void)out; (void)outlen; }
void ScryptHash::scrypt_1024_1_1_256(const uint8_t* passwd, size_t passwdlen,
                                      const uint8_t* salt, size_t saltlen,
                                      uint8_t* buf) { (void)passwd; (void)passwdlen; (void)salt; (void)saltlen; (void)buf; }

ScryptHash::~ScryptHash() {
    // Explicit destructor definition for vtable emission
}

} // namespace KracKer