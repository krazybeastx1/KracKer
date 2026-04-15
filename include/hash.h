#ifndef HASH_H
#define HASH_H

#include <string>
#include <vector>

namespace hasher {
    std::string md5(const std::string& input);
    std::string sha1(const std::string& input);
    std::string sha256(const std::string& input);
    std::string sha512(const std::string& input);

    enum class HashType { MD5, SHA1, SHA256, SHA512, BCRYPT, UNKNOWN };
    HashType detectHashType(const std::string& hash);
    size_t getHashLength(HashType type);
}

#endif
