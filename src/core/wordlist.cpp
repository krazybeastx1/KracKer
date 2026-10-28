#include "KracKer/wordlist.hpp"
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <filesystem>
#include <functional>

namespace KracKer {

bool WordlistLoader::load(const std::string& path, std::vector<std::string>& words, 
                         size_t max_words, bool unique) {
    std::ifstream file(path);
    if (!file.is_open()) return false;

    std::string line;
    while (std::getline(file, line)) {
        // Trim
        while (!line.empty() && std::isspace(line.back())) line.pop_back();
        while (!line.empty() && std::isspace(line.front())) line.erase(line.begin());
        
        if (!line.empty()) {
            words.push_back(std::move(line));
            if (max_words > 0 && words.size() >= max_words) break;
        }
    }

    if (unique) {
        std::sort(words.begin(), words.end());
        words.erase(std::unique(words.begin(), words.end()), words.end());
    }

    return !words.empty();
}

bool WordlistLoader::load_chunked(const std::string& path, 
                                  std::function<bool(const std::vector<std::string>&)> callback,
                                  size_t chunk_size) {
    std::ifstream file(path);
    if (!file.is_open()) return false;

    std::vector<std::string> chunk;
    chunk.reserve(chunk_size);
    std::string line;

    while (std::getline(file, line)) {
        while (!line.empty() && std::isspace(line.back())) line.pop_back();
        while (!line.empty() && std::isspace(line.front())) line.erase(line.begin());
        
        if (!line.empty()) {
            chunk.push_back(std::move(line));
            if (chunk.size() >= chunk_size) {
                if (!callback(chunk)) return false;
                chunk.clear();
            }
        }
    }

    if (!chunk.empty()) {
        return callback(chunk);
    }

    return true;
}

size_t WordlistLoader::count_lines(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return 0;

    size_t count = 0;
    std::string line;
    while (std::getline(file, line)) {
        while (!line.empty() && std::isspace(line.back())) line.pop_back();
        while (!line.empty() && std::isspace(line.front())) line.erase(line.begin());
        if (!line.empty()) ++count;
    }
    return count;
}

std::vector<std::string> WordlistGenerator::generate_from_mask(const std::string& mask,
                                                                const std::array<std::string, 4>& custom_charsets) {
    std::vector<std::string> result;
    std::string current;
    generate_mask_recursive(mask, 0, current, custom_charsets, result);
    return result;
}

void WordlistGenerator::generate_mask_recursive(const std::string& mask, size_t pos,
                                                 std::string& current,
                                                 const std::array<std::string, 4>& custom_charsets,
                                                 std::vector<std::string>& result) {
    if (pos >= mask.size()) {
        result.push_back(current);
        return;
    }

    char c = mask[pos];
    std::string charset;

    if (c == '?' && pos + 1 < mask.size()) {
        char next = mask[pos + 1];
        switch (next) {
            case 'l': charset = "abcdefghijklmnopqrstuvwxyz"; break;
            case 'u': charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"; break;
            case 'd': charset = "0123456789"; break;
            case 's': charset = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"; break;
            case 'a': charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"; break;
            case 'b': 
                charset.resize(256);
                for (int j = 0; j < 256; ++j) charset[j] = static_cast<char>(j);
                break;
            case '1': charset = custom_charsets[0]; break;
            case '2': charset = custom_charsets[1]; break;
            case '3': charset = custom_charsets[2]; break;
            case '4': charset = custom_charsets[3]; break;
            case '?': charset = "?"; break;
            default: charset = std::string(1, next); break;
        }
        pos++;
    } else {
        charset = std::string(1, c);
    }

    for (char ch : charset) {
        current.push_back(ch);
        generate_mask_recursive(mask, pos + 1, current, custom_charsets, result);
        current.pop_back();
    }
}

std::vector<std::string> WordlistGenerator::generate_prince(const std::vector<std::string>& wordlist,
                                                             size_t min_words,
                                                             size_t max_words,
                                                             size_t max_len,
                                                             size_t limit) {
    std::vector<std::string> result;
    result.reserve(std::min(limit, wordlist.size() * 10));

    std::vector<size_t> indices(min_words, 0);
    
    while (result.size() < limit) {
        std::string candidate;
        for (size_t idx : indices) {
            candidate += wordlist[idx];
            if (candidate.size() > max_len) break;
        }
        
        if (candidate.size() <= max_len && !candidate.empty()) {
            result.push_back(candidate);
        }

        // Increment indices
        size_t pos = 0;
        while (pos < indices.size()) {
            indices[pos]++;
            if (indices[pos] < wordlist.size()) break;
            indices[pos] = 0;
            pos++;
        }
        
        if (pos >= indices.size()) {
            if (indices.size() < max_words) {
                indices.push_back(0);
            } else {
                break;
            }
        }
    }

    return result;
}

} // namespace KracKer