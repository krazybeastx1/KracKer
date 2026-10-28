#include "KracKer/utils.hpp"
#include <random>
#include <chrono>
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>

namespace KracKer {

std::atomic<bool> g_interrupt_requested{false};

bool constant_time_compare(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
    }
    return diff == 0;
}

bool constant_time_compare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); ++i) diff |= a[i] ^ b[i];
    return diff == 0;
}

// Utility functions
std::string to_lower(const std::string& s) {
    std::string result = s;
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return result;
}

std::string to_upper(const std::string& s) {
    std::string result = s;
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c) { return std::toupper(c); });
    return result;
}

std::string trim(const std::string& s) {
    size_t start = 0;
    while (start < s.size() && std::isspace(s[start])) ++start;
    size_t end = s.size();
    while (end > start && std::isspace(s[end - 1])) --end;
    return s.substr(start, end - start);
}

std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> result;
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        result.push_back(item);
    }
    return result;
}

bool is_hex(const std::string& s) {
    if (s.empty()) return false;
    return std::all_of(s.begin(), s.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    });
}

std::string hex_encode(const std::vector<uint8_t>& bytes) {
    static const char* hex = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (uint8_t b : bytes) {
        result.push_back(hex[b >> 4]);
        result.push_back(hex[b & 0xF]);
    }
    return result;
}

std::vector<uint8_t> hex_decode(const std::string& hex_str) {
    std::vector<uint8_t> result;
    result.reserve(hex_str.size() / 2);
    for (size_t i = 0; i + 1 < hex_str.size(); i += 2) {
        std::string byte_str = hex_str.substr(i, 2);
        result.push_back(static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16)));
    }
    return result;
}

std::string random_string(size_t len) {
    static const char alphanum[] = 
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, sizeof(alphanum) - 2);
    
    std::string result;
    result.reserve(len);
    for (size_t i = 0; i < len; ++i) {
        result.push_back(alphanum[dis(gen)]);
    }
    return result;
}

uint64_t get_timestamp_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

std::string format_duration(std::chrono::duration<double> d) {
    auto total_seconds = static_cast<uint64_t>(d.count());
    uint64_t hours = total_seconds / 3600;
    uint64_t minutes = (total_seconds % 3600) / 60;
    uint64_t seconds = total_seconds % 60;
    
    if (hours > 0) {
        return std::to_string(hours) + "h " + std::to_string(minutes) + "m " + std::to_string(seconds) + "s";
    } else if (minutes > 0) {
        return std::to_string(minutes) + "m " + std::to_string(seconds) + "s";
    } else {
        return std::to_string(seconds) + "s";
    }
}

std::string format_speed(double hps) {
    const char* units[] = {"H/s", "KH/s", "MH/s", "GH/s", "TH/s"};
    int unit = 0;
    while (hps >= 1000 && unit < 4) {
        hps /= 1000;
        unit++;
    }
    std::stringstream ss;
    ss << std::fixed << std::setprecision(2) << hps << " " << units[unit];
    return ss.str();
}

bool file_exists(const std::string& path) {
    return std::filesystem::exists(path);
}

size_t file_size(const std::string& path) {
    return std::filesystem::file_size(path);
}

std::vector<std::string> read_lines(const std::string& path) {
    std::vector<std::string> lines;
    std::ifstream file(path);
    std::string line;
    while (std::getline(file, line)) {
        lines.push_back(trim(line));
    }
    return lines;
}

bool write_lines(const std::string& path, const std::vector<std::string>& lines) {
    std::ofstream file(path);
    for (const auto& line : lines) {
        file << line << '\n';
    }
    return true;
}

} // namespace KracKer