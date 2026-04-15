#include "hash.h"
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <cstring>

namespace hasher {

namespace {
    std::string bytesToHex(unsigned char* bytes, size_t len) {
        std::stringstream ss;
        for (size_t i = 0; i < len; i++) {
            ss << std::hex << std::setfill('0') << std::setw(2) << (int)bytes[i];
        }
        return ss.str();
    }
}

std::string md5(const std::string& input) {
    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5((unsigned char*)input.c_str(), input.length(), hash);
    return bytesToHex(hash, MD5_DIGEST_LENGTH);
}

std::string sha1(const std::string& input) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1((unsigned char*)input.c_str(), input.length(), hash);
    return bytesToHex(hash, SHA_DIGEST_LENGTH);
}

std::string sha256(const std::string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)input.c_str(), input.length(), hash);
    return bytesToHex(hash, SHA256_DIGEST_LENGTH);
}

std::string sha512(const std::string& input) {
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512((unsigned char*)input.c_str(), input.length(), hash);
    return bytesToHex(hash, SHA512_DIGEST_LENGTH);
}

HashType detectHashType(const std::string& hash) {
    switch (hash.length()) {
        case 32: return HashType::MD5;
        case 40: return HashType::SHA1;
        case 64: return HashType::SHA256;
        case 128: return HashType::SHA512;
        default: return HashType::UNKNOWN;
    }
}

size_t getHashLength(HashType type) {
    switch (type) {
        case HashType::MD5: return 32;
        case HashType::SHA1: return 40;
        case HashType::SHA256: return 64;
        case HashType::SHA512: return 128;
        default: return 0;
    }
}

}
