#pragma once

#include "KracKer/hash_interface.hpp"
#include <vector>
#include <string>
#include <unordered_map>
#include <functional>
#include <fstream>

namespace KracKer {

/**
 * Rules engine for password mangling (hashcat-compatible)
 */
class RuleEngine {
public:
    using RuleFunc = std::function<std::string(const std::string&)>;
    
    struct Rule {
        std::string name;
        RuleFunc func;
    };

    static RuleEngine& instance();

    void register_rule(const std::string& name, RuleFunc func);

    // Apply specific rules to a word
    std::vector<std::string> apply(const std::string& word, const std::vector<std::string>& rule_names) const;

    // Apply all registered rules
    std::vector<std::string> apply_all(const std::string& word) const;

    // Apply each rule line loaded from a rules file as a chain (hashcat style).
    // Returns the original word first, then one variant per rule line.
    std::vector<std::string> apply_file_rules(const std::string& word) const;

    // Load rules from hashcat-format rules file
    bool load_rules_file(const std::string& path);

    const std::unordered_map<std::string, Rule>& get_rules() const;
    const std::vector<std::string>& rule_lines() const { return file_rules_; }

private:
    RuleEngine();
    void register_builtin_rules();
    void parse_rule_line(const std::string& line);
    static std::string apply_rule_chain(const std::string& word, const std::string& rule);

    std::unordered_map<std::string, Rule> rules_;
    std::vector<std::string> file_rules_;
    static std::string trim(const std::string& s);
};

} // namespace KracKer