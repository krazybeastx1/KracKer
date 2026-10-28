#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace KracKer {

/**
 * Hashcat-style mask parsing and enumeration.
 *
 * Position 0 of a mask is the leftmost character. The rightmost character
 * varies fastest, which matches brute-force ordering and hashcat semantics.
 */
class MaskProcessor {
public:
    struct Charset {
        std::string chars;
        bool builtin = false;
    };

    struct MaskInfo {
        std::vector<Charset> position_charsets;
        uint64_t keyspace = 0;
        size_t min_length = 0;
        size_t max_length = 0;

        bool valid() const {
            if (position_charsets.empty()) return false;
            for (const auto& cs : position_charsets) {
                if (cs.chars.empty()) return false;
            }
            return true;
        }
    };

    static MaskInfo parse_mask(const std::string& mask,
                               const std::array<std::string, 4>& custom_charsets) {
        MaskInfo info;
        info.position_charsets.reserve(mask.size());

        size_t i = 0;
        while (i < mask.size()) {
            Charset cs;
            char c = mask[i];

            if (c == '?' && i + 1 < mask.size()) {
                char next = mask[i + 1];
                cs.builtin = true;
                switch (next) {
                    case 'l': cs.chars = "abcdefghijklmnopqrstuvwxyz"; break;
                    case 'u': cs.chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"; break;
                    case 'd': cs.chars = "0123456789"; break;
                    case 's': cs.chars = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"; break;
                    case 'a': cs.chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"; break;
                    case 'b':
                        cs.chars.resize(256);
                        for (int j = 0; j < 256; ++j) cs.chars[j] = static_cast<char>(j);
                        break;
                    case '1': cs.chars = custom_charsets[0]; break;
                    case '2': cs.chars = custom_charsets[1]; break;
                    case '3': cs.chars = custom_charsets[2]; break;
                    case '4': cs.chars = custom_charsets[3]; break;
                    case '?': cs.chars = "?"; break;
                    default: cs.chars = std::string(1, next); cs.builtin = false; break;
                }
                i += 2;
            } else {
                cs.chars = std::string(1, c);
                i++;
            }

            info.position_charsets.push_back(cs);
        }

        // Calculate keyspace, clamping at UINT64_MAX on overflow.
        info.keyspace = 1;
        for (const auto& cs : info.position_charsets) {
            if (cs.chars.empty()) {
                info.keyspace = 0;
                break;
            }
            if (info.keyspace > UINT64_MAX / cs.chars.size()) {
                info.keyspace = UINT64_MAX;
                break;
            }
            info.keyspace *= cs.chars.size();
        }

        info.min_length = info.position_charsets.size();
        info.max_length = info.min_length;

        return info;
    }

    // Rightmost position varies fastest.
    static std::string index_to_candidate(uint64_t index, const MaskInfo& info) {
        std::string result(info.position_charsets.size(), '\0');
        for (size_t pos = info.position_charsets.size(); pos-- > 0;) {
            const auto& cs = info.position_charsets[pos];
            const uint64_t size = cs.chars.size();
            if (size == 0) return {};
            result[pos] = cs.chars[index % size];
            index /= size;
        }
        return result;
    }

    static uint64_t candidate_to_index(const std::string& candidate, const MaskInfo& info) {
        if (candidate.size() != info.position_charsets.size()) return UINT64_MAX;

        uint64_t index = 0;
        for (size_t pos = 0; pos < info.position_charsets.size(); ++pos) {
            const auto& cs = info.position_charsets[pos];
            if (cs.chars.empty()) return UINT64_MAX;
            size_t where = cs.chars.find(candidate[pos]);
            if (where == std::string::npos) return UINT64_MAX;
            if (index > (UINT64_MAX - where) / cs.chars.size()) return UINT64_MAX;
            index = index * cs.chars.size() + where;
        }
        return index;
    }

    static std::vector<std::string> generate_incremental(const MaskInfo& base_info,
                                                         size_t min_len, size_t max_len) {
        std::vector<std::string> masks;
        for (size_t len = min_len; len <= max_len && len <= base_info.position_charsets.size(); ++len) {
            std::string mask;
            for (size_t i = 0; i < len; ++i) mask += "?a";
            masks.push_back(mask);
        }
        return masks;
    }
};

/**
 * Sequential mask iterator. Mirrors index_to_candidate ordering so that
 * seeking to position N yields the same candidate as index_to_candidate(N).
 */
class MaskIterator {
public:
    explicit MaskIterator(const MaskProcessor::MaskInfo& info) : info_(info) {
        indices_.assign(info.position_charsets.size(), 0);
    }

    bool next(std::string& out) {
        if (position_ >= info_.keyspace) return false;

        out.clear();
        out.reserve(info_.position_charsets.size());
        for (size_t i = 0; i < info_.position_charsets.size(); ++i) {
            const auto& cs = info_.position_charsets[i];
            if (cs.chars.empty()) return false;
            out.push_back(cs.chars[indices_[i]]);
        }

        // Increment from the rightmost position.
        for (size_t i = indices_.size(); i-- > 0;) {
            if (++indices_[i] < info_.position_charsets[i].chars.size()) break;
            indices_[i] = 0;
        }

        position_++;
        return true;
    }

    uint64_t position() const { return position_; }
    uint64_t keyspace() const { return info_.keyspace; }
    double progress() const { return info_.keyspace > 0 ? double(position_) / info_.keyspace : 0.0; }

    void seek(uint64_t pos) {
        if (pos > info_.keyspace) pos = info_.keyspace;
        position_ = pos;
        uint64_t remaining = position_;
        for (size_t i = indices_.size(); i-- > 0;) {
            const uint64_t size = info_.position_charsets[i].chars.size();
            indices_[i] = size ? remaining % size : 0;
            remaining = size ? remaining / size : 0;
        }
    }

private:
    const MaskProcessor::MaskInfo& info_;
    std::vector<uint64_t> indices_;
    uint64_t position_ = 0;
};

} // namespace KracKer
