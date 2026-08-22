#include "rules.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

namespace cracker {

RuleEngine::RuleEngine() {
    // Default rules: none
}

void RuleEngine::loadRulesFromFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Could not open rules file: " + filename);
    }
    rules_.clear();
    std::string line;
    while (std::getline(file, line)) {
        // Trim whitespace
        auto start = line.find_first_not_of(" \t\r\n");
        auto end = line.find_last_not_of(" \t\r\n");
        if (start == std::string::npos) continue;
        line = line.substr(start, end - start + 1);

        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') continue;

        Rule rule;
        if (line == "lower") {
            rule.type = Rule::LOWER;
        } else if (line == "upper") {
            rule.type = Rule::UPPER;
        } else if (line == "capitalize") {
            rule.type = Rule::CAPITALIZE;
        } else if (line == "reverse") {
            rule.type = Rule::REVERSE;
        } else if (line == "double") {
            rule.type = Rule::DOUBLE;
        } else if (line == "leet") {
            rule.type = Rule::LEET;
        } else if (line.substr(0, 13) == "append_digits") {
            rule.type = Rule::APPEND_DIGITS;
            // Optional parameter: append_digits N
            if (line.length() > 13) {
                std::string paramStr = line.substr(14); // skip space
                rule.param = std::stoi(paramStr);
            } else {
                rule.param = 1; // default
            }
        } else if (line.substr(0, 14) == "append_special") {
            rule.type = Rule::APPEND_SPECIAL;
            if (line.length() > 14) {
                std::string paramStr = line.substr(15); // skip space
                rule.param = std::stoi(paramStr);
            } else {
                rule.param = 1;
            }
        } else if (line.substr(0, 14) == "prepend_digits") {
            rule.type = Rule::PREPEND_DIGITS;
            if (line.length() > 14) {
                std::string paramStr = line.substr(15);
                rule.param = std::stoi(paramStr);
            } else {
                rule.param = 1;
            }
        } else if (line.substr(0, 15) == "prepend_special") {
            rule.type = Rule::PREPEND_SPECIAL;
            if (line.length() > 15) {
                std::string paramStr = line.substr(16); // skip space
                rule.param = std::stoi(paramStr);
            } else {
                rule.param = 1;
            }
        } else {
            throw std::runtime_error("Unknown rule: " + line);
        }
        rules_.push_back(rule);
    }
}

std::vector<std::string> RuleEngine::apply(const std::string& word) const {
    std::vector<std::string> results;
    results.push_back(word); // original

    for (const Rule& rule : rules_) {
        std::string transformed;
        switch (rule.type) {
            case Rule::LOWER:
                transformed = applyLower(word);
                break;
            case Rule::UPPER:
                transformed = applyUpper(word);
                break;
            case Rule::CAPITALIZE:
                transformed = applyCapitalize(word);
                break;
            case Rule::REVERSE:
                transformed = applyReverse(word);
                break;
            case Rule::DOUBLE:
                transformed = applyDouble(word);
                break;
            case Rule::LEET:
                transformed = applyLeet(word);
                break;
            case Rule::APPEND_DIGITS:
                transformed = applyAppendDigits(word, rule.param);
                break;
            case Rule::APPEND_SPECIAL:
                transformed = applyAppendSpecial(word, rule.param);
                break;
            case Rule::PREPEND_DIGITS:
                transformed = applyPrependDigits(word, rule.param);
                break;
            case Rule::PREPEND_SPECIAL:
                transformed = applyPrependSpecial(word, rule.param);
                break;
        }
        if (transformed != word) {
            results.push_back(transformed);
        }
    }

    // Deduplicate
    std::sort(results.begin(), results.end());
    auto last = std::unique(results.begin(), results.end());
    results.erase(last, results.end());

    return results;
}

std::string RuleEngine::applyLower(const std::string& word) const {
    std::string result;
    for (char c : word) result += std::tolower(c);
    return result;
}

std::string RuleEngine::applyUpper(const std::string& word) const {
    std::string result;
    for (char c : word) result += std::toupper(c);
    return result;
}

std::string RuleEngine::applyCapitalize(const std::string& word) const {
    if (word.empty()) return word;
    std::string result;
    result += std::toupper(word[0]);
    for (size_t i = 1; i < word.size(); i++) {
        result += std::tolower(word[i]);
    }
    return result;
}

std::string RuleEngine::applyReverse(const std::string& word) const {
    std::string result = word;
    std::reverse(result.begin(), result.end());
    return result;
}

std::string RuleEngine::applyDouble(const std::string& word) const {
    return word + word;
}

std::string RuleEngine::applyLeet(const std::string& word) const {
    std::string result;
    for (char c : word) {
        switch (c) {
            case 'a': result += '4'; break;
            case 'A': result += '4'; break;
            case 'b': result += '8'; break;
            case 'B': result += '8'; break;
            case 'e': result += '3'; break;
            case 'E': result += '3'; break;
            case 'g': result += '6'; break;
            case 'G': result += '6'; break;
            case 'i': result += '1'; break;
            case 'I': result += '1'; break;
            case 'l': result += '1'; break;
            case 'L': result += '1'; break;
            case 'o': result += '0'; break;
            case 'O': result += '0'; break;
            case 's': result += '5'; break;
            case 'S': result += '5'; break;
            case 't': result += '7'; break;
            case 'T': result += '7'; break;
            case 'z': result += '2'; break;
            case 'Z': result += '2'; break;
            default: result += c;
        }
    }
    return result;
}

std::string RuleEngine::applyAppendDigits(const std::string& word, int count) const {
    std::string result = word;
    for (int i = 0; i < count; i++) {
        result += '0' + (i % 10);
    }
    return result;
}

std::string RuleEngine::applyAppendSpecial(const std::string& word, int count) const {
    std::string result = word;
    const std::string specials = "!@#$%^&*";
    for (int i = 0; i < count; i++) {
        result += specials[i % specials.size()];
    }
    return result;
}

std::string RuleEngine::applyPrependDigits(const std::string& word, int count) const {
    std::string result;
    for (int i = 0; i < count; i++) {
        result += '0' + (i % 10);
    }
    result += word;
    return result;
}

std::string RuleEngine::applyPrependSpecial(const std::string& word, int count) const {
    std::string result;
    const std::string specials = "!@#$%^&*";
    for (int i = 0; i < count; i++) {
        result += specials[i % specials.size()];
    }
    result += word;
    return result;
}

}
