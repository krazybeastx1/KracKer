#ifndef RULES_H
#define RULES_H

#include <string>
#include <vector>

namespace cracker {

class RuleEngine {
public:
    RuleEngine();
    void loadRulesFromFile(const std::string& filename);
    std::vector<std::string> apply(const std::string& word) const;

private:
    struct Rule {
        enum Type {
            LOWER,
            UPPER,
            CAPITALIZE,
            REVERSE,
            DOUBLE,
            LEET,
            APPEND_DIGITS,
            APPEND_SPECIAL,
            PREPEND_DIGITS,
            PREPEND_SPECIAL
        } type;
        int param; // for rules that need a number, like append_digits N
    };
    std::vector<Rule> rules_;

    std::string applyLower(const std::string& word) const;
    std::string applyUpper(const std::string& word) const;
    std::string applyCapitalize(const std::string& word) const;
    std::string applyReverse(const std::string& word) const;
    std::string applyDouble(const std::string& word) const;
    std::string applyLeet(const std::string& word) const;
    std::string applyAppendDigits(const std::string& word, int count) const;
    std::string applyAppendSpecial(const std::string& word, int count) const;
    std::string applyPrependDigits(const std::string& word, int count) const;
    std::string applyPrependSpecial(const std::string& word, int count) const;
};

}

#endif