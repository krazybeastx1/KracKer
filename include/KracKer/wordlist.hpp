#pragma once

#include "KracKer/hash_interface.hpp"
#include <vector>
#include <string>
#include <functional>

namespace KracKer {

/**
 * Wordlist loading utilities
 */
class WordlistLoader {
public:
    // Load entire wordlist into memory
    static bool load(const std::string& path, std::vector<std::string>& words, 
                     size_t max_words = 0, bool unique = false);

    // Load wordlist in chunks (for memory efficiency)
    static bool load_chunked(const std::string& path, 
                             std::function<bool(const std::vector<std::string>&)> callback,
                             size_t chunk_size = 10000);

    // Count valid lines in wordlist
    static size_t count_lines(const std::string& path);
};

/**
 * Wordlist generation for combinatoric attacks
 */
class WordlistGenerator {
public:
    // Generate candidates from mask pattern
    static std::vector<std::string> generate_from_mask(const std::string& mask,
                                                        const std::array<std::string, 4>& custom_charsets);

    // PRINCE generator - combines words from wordlist
    static std::vector<std::string> generate_prince(const std::vector<std::string>& wordlist,
                                                     size_t min_words = 1,
                                                     size_t max_words = 4,
                                                     size_t max_len = 16,
                                                     size_t limit = 1000000);

private:
    static void generate_mask_recursive(const std::string& mask, size_t pos,
                                         std::string& current,
                                         const std::array<std::string, 4>& custom_charsets,
                                         std::vector<std::string>& result);
};

} // namespace KracKer