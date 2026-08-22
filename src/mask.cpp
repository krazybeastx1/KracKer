#include "mask.h"
#include <stdexcept>

namespace cracker {

const std::string MaskGenerator::LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
const std::string MaskGenerator::UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const std::string MaskGenerator::DIGITS = "0123456789";
const std::string MaskGenerator::SPECIAL = "!@#$%^&*()_+-=[]{}|;:',.<>?/`~";
const std::string MaskGenerator::ALPHANUM = LOWERCASE + UPPERCASE + DIGITS + SPECIAL;

MaskGenerator::MaskGenerator(const std::string& mask)
    : mask_(mask), finished_(false), total_(1) {
    parseMask(mask);
}

void MaskGenerator::parseMask(const std::string& mask) {
    tokenCharsets_.clear();
    tokenLengths_.clear();
    indices_.clear();

    size_t i = 0;
    while (i < mask.length()) {
        if (mask[i] == '?' && i + 1 < mask.length()) {
            char token = mask[i+1];
            std::string charset;
            switch (token) {
                case 'l': charset = LOWERCASE; break;
                case 'u': charset = UPPERCASE; break;
                case 'd': charset = DIGITS; break;
                case 's': charset = SPECIAL; break;
                case 'a': charset = ALPHANUM; break;
                default:
                    throw std::invalid_argument("Invalid mask token: ?" + std::string(1, token));
            }
            tokenCharsets_.push_back(charset);
            tokenLengths_.push_back(charset.length());
            total_ *= charset.length();
            i += 2;
        } else {
            // Literal character
            std::string charset(1, mask[i]);
            tokenCharsets_.push_back(charset);
            tokenLengths_.push_back(1);
            i++;
        }
    }

    if (tokenCharsets_.empty()) {
        throw std::invalid_argument("Empty mask");
    }

    indices_.assign(tokenCharsets_.size(), 0);
    finished_ = false;
}

bool MaskGenerator::next(std::string& candidate) {
    if (finished_) {
        return false;
    }

    candidate.clear();
    for (size_t pos = 0; pos < tokenCharsets_.size(); ++pos) {
        candidate += tokenCharsets_[pos][indices_[pos]];
    }

    // Increment indices
    for (size_t pos = 0; pos < tokenCharsets_.size(); ++pos) {
        if (++indices_[pos] < tokenLengths_[pos]) {
            break;
        }
        indices_[pos] = 0;
        if (pos == tokenCharsets_.size() - 1) {
            finished_ = true;
        }
    }

    return true;
}

uint64_t MaskGenerator::totalCombinations() const {
    return total_;
}

void MaskGenerator::reset() {
    std::fill(indices_.begin(), indices_.end(), 0);
    finished_ = false;
}

}