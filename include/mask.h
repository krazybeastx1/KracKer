#ifndef MASK_H
#define MASK_H

#include <string>
#include <vector>
#include <cstdint>

namespace cracker {

class MaskGenerator {
public:
    MaskGenerator(const std::string& mask);
    bool next(std::string& candidate);
    uint64_t totalCombinations() const;
    void reset();

private:
    std::string mask_;
    std::vector<std::string> tokenCharsets_; // per position
    std::vector<size_t> tokenLengths_; // length of each token's charset
    std::vector<size_t> indices_; // current index for each token
    bool finished_;
    uint64_t total_;

    void parseMask(const std::string& mask);
    static const std::string LOWERCASE;
    static const std::string UPPERCASE;
    static const std::string DIGITS;
    static const std::string SPECIAL;
    static const std::string ALPHANUM;
};

}

#endif