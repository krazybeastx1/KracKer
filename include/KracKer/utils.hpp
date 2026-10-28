#pragma once

#include "KracKer/hash_interface.hpp"
#include <string>
#include <vector>
#include <random>
#include <chrono>
#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <iomanip>

namespace KracKer {

// Process-wide interrupt flag. Set from a signal handler (SIGINT/SIGTERM),
// polled by the attack loops so a crack can be aborted cleanly.
extern std::atomic<bool> g_interrupt_requested;

inline void request_interrupt() noexcept { g_interrupt_requested.store(true); }
inline void clear_interrupt() noexcept { g_interrupt_requested.store(false); }
inline bool interrupt_requested() noexcept { return g_interrupt_requested.load(); }

// Constant-time comparison helpers (used by hash verify paths and tests)
bool constant_time_compare(const std::string& a, const std::string& b);
bool constant_time_compare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);

// String utilities
std::string to_lower(const std::string& s);
std::string to_upper(const std::string& s);
std::string trim(const std::string& s);
std::vector<std::string> split(const std::string& s, char delim);
bool is_hex(const std::string& s);

// Hex encoding/decoding
std::string hex_encode(const std::vector<uint8_t>& bytes);
std::vector<uint8_t> hex_decode(const std::string& hex_str);

// Random utilities
std::string random_string(size_t len);

// Time utilities
uint64_t get_timestamp_ms();
std::string format_duration(std::chrono::duration<double> d);
std::string format_speed(double hps);

// File utilities
bool file_exists(const std::string& path);
size_t file_size(const std::string& path);
std::vector<std::string> read_lines(const std::string& path);
bool write_lines(const std::string& path, const std::vector<std::string>& lines);

} // namespace KracKer