#include "KracKer/rules.hpp"
#include <fstream>
#include <vector>
#include <string>
#include <unordered_map>
#include <functional>
#include <cctype>
#include <algorithm>

namespace KracKer {

RuleEngine& RuleEngine::instance() {
    static RuleEngine engine;
    return engine;
}

RuleEngine::RuleEngine() {
    register_builtin_rules();
}

void RuleEngine::register_rule(const std::string& name, RuleFunc func) {
    rules_[name] = {name, func};
}

std::vector<std::string> RuleEngine::apply(const std::string& word, const std::vector<std::string>& rule_names) const {
    std::vector<std::string> results;
    results.push_back(word); // Original

    for (const auto& rule_name : rule_names) {
        auto it = rules_.find(rule_name);
        if (it != rules_.end()) {
            std::string transformed = it->second.func(word);
            if (transformed != word) {
                results.push_back(transformed);
            }
        }
    }

    return results;
}

std::vector<std::string> RuleEngine::apply_all(const std::string& word) const {
    std::vector<std::string> results;
    results.push_back(word);

    for (const auto& [name, rule] : rules_) {
        std::string transformed = rule.func(word);
        if (transformed != word) {
            results.push_back(transformed);
        }
    }

    return results;
}

bool RuleEngine::load_rules_file(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return false;

    file_rules_.clear();

    std::string line;
    while (std::getline(file, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;

        file_rules_.push_back(line);
        parse_rule_line(line);
    }
    return true;
}

std::string RuleEngine::apply_rule_chain(const std::string& word, const std::string& rule) {
    std::string out = word;

    for (size_t i = 0; i < rule.size(); ++i) {
        const char op = rule[i];

        auto need_param = [&](char& param) -> bool {
            if (i + 1 >= rule.size()) return false;
            param = rule[++i];
            return true;
        };

        switch (op) {
            case 'l':
                std::transform(out.begin(), out.end(), out.begin(),
                               [](unsigned char c) { return std::tolower(c); });
                break;
            case 'u':
                std::transform(out.begin(), out.end(), out.begin(),
                               [](unsigned char c) { return std::toupper(c); });
                break;
            case 'c':
                if (!out.empty()) {
                    out[0] = static_cast<char>(std::toupper(static_cast<unsigned char>(out[0])));
                    for (size_t k = 1; k < out.size(); ++k) {
                        out[k] = static_cast<char>(std::tolower(static_cast<unsigned char>(out[k])));
                    }
                }
                break;
            case 'C': {
                // Lowercase first character, uppercase the rest (hashcat 'C')
                if (!out.empty()) {
                    out[0] = static_cast<char>(std::tolower(static_cast<unsigned char>(out[0])));
                    for (size_t k = 1; k < out.size(); ++k) {
                        out[k] = static_cast<char>(std::toupper(static_cast<unsigned char>(out[k])));
                    }
                }
                break;
            }
            case 't':
                for (char& c : out) {
                    c = std::isupper(static_cast<unsigned char>(c))
                        ? static_cast<char>(std::tolower(static_cast<unsigned char>(c)))
                        : static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
                }
                break;
            case 'r':
                std::reverse(out.begin(), out.end());
                break;
            case 'd':
                out += out;
                break;
            case 'T': {
                char param = 0;
                if (!need_param(param)) return out;
                if (std::isdigit(static_cast<unsigned char>(param))) {
                    const size_t pos = static_cast<size_t>(param - '0');
                    if (pos < out.size()) {
                        char& c = out[pos];
                        c = std::isupper(static_cast<unsigned char>(c))
                            ? static_cast<char>(std::tolower(static_cast<unsigned char>(c)))
                            : static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
                    }
                }
                break;
            }
            case '$': {
                char param = 0;
                if (!need_param(param)) return out;
                out.push_back(param);
                break;
            }
            case '^': {
                char param = 0;
                if (!need_param(param)) return out;
                out.insert(out.begin(), param);
                break;
            }
            default:
                // Unknown operator: stop applying this rule rather than
                // silently producing a wrong candidate.
                return out;
        }
    }

    return out;
}

std::vector<std::string> RuleEngine::apply_file_rules(const std::string& word) const {
    std::vector<std::string> results;
    results.push_back(word);

    for (const auto& rule : file_rules_) {
        std::string variant = apply_rule_chain(word, rule);
        if (variant != word) results.push_back(std::move(variant));
    }

    return results;
}

const std::unordered_map<std::string, RuleEngine::Rule>& RuleEngine::get_rules() const {
    return rules_;
}

std::string RuleEngine::trim(const std::string& s) {
    size_t start = 0;
    while (start < s.size() && std::isspace(s[start])) ++start;
    size_t end = s.size();
    while (end > start && std::isspace(s[end - 1])) --end;
    return s.substr(start, end - start);
}

void RuleEngine::register_builtin_rules() {
    // Case rules
    register_rule("lower", [](const std::string& w) {
        std::string r = w;
        std::transform(r.begin(), r.end(), r.begin(), ::tolower);
        return r;
    });
    
    register_rule("upper", [](const std::string& w) {
        std::string r = w;
        std::transform(r.begin(), r.end(), r.begin(), ::toupper);
        return r;
    });
    
    register_rule("capitalize", [](const std::string& w) {
        std::string r = w;
        if (!r.empty()) r[0] = std::toupper(r[0]);
        std::transform(r.begin() + 1, r.end(), r.begin() + 1, ::tolower);
        return r;
    });
    
    register_rule("invert", [](const std::string& w) {
        std::string r = w;
        for (char& c : r) c = std::isupper(c) ? std::tolower(c) : std::toupper(c);
        return r;
    });

    // Reverse
    register_rule("reverse", [](const std::string& w) {
        std::string r = w;
        std::reverse(r.begin(), r.end());
        return r;
    });

    // Duplicate
    register_rule("duplicate", [](const std::string& w) { return w + w; });

    // Append/prepend
    register_rule("append_0", [](const std::string& w) { return w + "0"; });
    register_rule("append_1", [](const std::string& w) { return w + "1"; });
    register_rule("append_!", [](const std::string& w) { return w + "!"; });
    register_rule("prepend_0", [](const std::string& w) { return "0" + w; });
    register_rule("prepend_1", [](const std::string& w) { return "1" + w; });

    // Leet speak
    register_rule("leet", [](const std::string& w) {
        std::string r = w;
        for (char& c : r) {
            switch (std::tolower(c)) {
                case 'a': c = '4'; break;
                case 'e': c = '3'; break;
                case 'i': c = '1'; break;
                case 'o': c = '0'; break;
                case 's': c = '5'; break;
                case 't': c = '7'; break;
            }
        }
        return r;
    });

    // Toggle case
    register_rule("TO", [](const std::string& w) {
        std::string r = w;
        for (char& c : r) c = std::isupper(c) ? std::tolower(c) : std::toupper(c);
        return r;
    });

    // Rotate
    register_rule("rotate_left", [](const std::string& w) {
        if (w.size() <= 1) return w;
        return w.substr(1) + w[0];
    });
    
    register_rule("rotate_right", [](const std::string& w) {
        if (w.size() <= 1) return w;
        return w.back() + w.substr(0, w.size() - 1);
    });

    // Delete first/last
    register_rule("delete_first", [](const std::string& w) {
        return w.size() > 1 ? w.substr(1) : "";
    });
    
    register_rule("delete_last", [](const std::string& w) {
        return w.size() > 1 ? w.substr(0, w.size() - 1) : "";
    });
}

void RuleEngine::parse_rule_line(const std::string& line) {
    if (line.size() == 1) {
        char c = line[0];
        switch (c) {
            case 'l': 
                register_rule("lower", [](const std::string& w) {
                    std::string r = w; std::transform(r.begin(), r.end(), r.begin(), ::tolower); return r;
                }); break;
            case 'u': 
                register_rule("upper", [](const std::string& w) {
                    std::string r = w; std::transform(r.begin(), r.end(), r.begin(), ::toupper); return r;
                }); break;
            case 'c': 
                register_rule("capitalize", [](const std::string& w) {
                    std::string r = w; if (!r.empty()) r[0] = std::toupper(r[0]); return r;
                }); break;
            case 'r': 
                register_rule("reverse", [](const std::string& w) {
                    std::string r = w; std::reverse(r.begin(), r.end()); return r;
                }); break;
            case 't': 
                register_rule("toggle", [](const std::string& w) {
                    std::string r = w; for (char& ch : r) ch = std::isupper(ch) ? std::tolower(ch) : std::toupper(ch); return r;
                }); break;
        }
    } else if (line.size() >= 2) {
        char cmd = line[0];
        char param = line[1];
        
        if (cmd == '$') { // Append
            std::string p(1, param);
            register_rule("append_" + p, [p](const std::string& w) { return w + p; });
        } else if (cmd == '^') { // Prepend
            std::string p(1, param);
            register_rule("prepend_" + p, [p](const std::string& w) { return p + w; });
        }
    }
}

} // namespace KracKer