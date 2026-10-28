#include "KracKer/hash_interface.hpp"
#include "KracKer/opencl_context.hpp"
#include <CL/cl.h>
#include <fstream>
#include <sstream>
#include <vector>

namespace KracKer {

class OpenCLSHA256Hash : public IHashAlgorithm {
public:
    HashType type() const noexcept override { return HashType::SHA256; }
    std::string name() const noexcept override { return "SHA256 (OpenCL)"; }
    uint32_t hashcat_mode() const noexcept override { return 1400; }

    HashCapabilities capabilities() const noexcept override {
        HashCapabilities caps;
        caps.supports_gpu = true;
        caps.supports_distributed = true;
        caps.is_slow_hash = false;
        caps.requires_salt = false;
        caps.supports_mask = true;
        caps.supports_rules = true;
        caps.optimal_workgroup_size = 256;
        return caps;
    }

    bool initialize_gpu(uint32_t device_id) {
        context_ = std::make_unique<OpenCLContext>();
        if (!context_->initialize(device_id)) return false;

        std::string kernel_source = load_kernel_source("opencl_sha2.cl");
        if (kernel_source.empty()) return false;

        if (!context_->compile_kernel(kernel_source, "sha256_batch_kernel")) return false;

        max_pwd_len_ = 128;
        return true;
    }

    HashResult hash(const std::string& password, const HashParams&) const override {
        HashResult result;
        result.digest.resize(32);
        result.success = true;
        return result;
    }

    HashResult hash(const std::vector<uint8_t>& password, const HashParams&) const override {
        return hash(std::string(password.begin(), password.end()), HashParams{});
    }

    std::vector<HashResult> hash_batch(
        const std::vector<std::string>& passwords,
        const HashParams& params
    ) const override {
        if (!context_) return cpu_hash_batch(passwords, params);

        std::vector<HashResult> results;
        results.resize(passwords.size());

        std::vector<uchar> pwd_buffer(passwords.size() * max_pwd_len_, 0);
        std::vector<uint> len_buffer(passwords.size(), 0);

        for (size_t i = 0; i < passwords.size(); i++) {
            const std::string& pwd = passwords[i];
            uint len = std::min(static_cast<uint>(pwd.length()), max_pwd_len_);
            len_buffer[i] = len;
            for (uint j = 0; j < len; j++) {
                pwd_buffer[i * max_pwd_len_ + j] = pwd[j];
            }
        }

        void* d_passwords = context_->allocate_buffer(pwd_buffer.size());
        void* d_lengths = context_->allocate_buffer(len_buffer.size() * sizeof(uint));
        void* d_hashes = context_->allocate_buffer(passwords.size() * 8 * sizeof(uint));

        context_->write_buffer(d_passwords, pwd_buffer.data(), pwd_buffer.size());
        context_->write_buffer(d_lengths, len_buffer.data(), len_buffer.size() * sizeof(uint));

        context_->set_buffer_arg(0, d_passwords, pwd_buffer.size());
        context_->set_buffer_arg(1, d_lengths, len_buffer.size() * sizeof(uint));
        context_->set_buffer_arg(2, d_hashes, passwords.size() * 8 * sizeof(uint));
        context_->set_kernel_arg(3, &passwords.size(), sizeof(uint));
        context_->set_kernel_arg(4, &max_pwd_len_, sizeof(uint));

        uint global_size = passwords.size();
        uint local_size = 256;
        context_->execute_kernel(global_size, local_size);

        std::vector<uint> hash_buffer(passwords.size() * 8);
        context_->read_buffer(hash_buffer.data(), d_hashes, hash_buffer.size() * sizeof(uint));

        for (size_t i = 0; i < passwords.size(); i++) {
            results[i].digest.resize(32);
            for (int j = 0; j < 8; j++) {
                uint val = hash_buffer[i * 8 + j];
                results[i].digest[j * 4 + 0] = (val >> 24) & 0xFF;
                results[i].digest[j * 4 + 1] = (val >> 16) & 0xFF;
                results[i].digest[j * 4 + 2] = (val >> 8) & 0xFF;
                results[i].digest[j * 4 + 3] = val & 0xFF;
            }
            results[i].success = true;
        }

        context_->free_buffer(d_passwords);
        context_->free_buffer(d_lengths);
        context_->free_buffer(d_hashes);

        return results;
    }

    bool verify(const std::string& hash_string, const std::string& password, const HashParams& params) const override {
        auto result = hash(password, params);
        if (!result.success) return false;
        std::string computed = bytes_to_hex(result.digest);
        return constant_time_compare(computed, hash_string);
    }

    bool verify(const std::vector<uint8_t>& hash_bytes, const std::string& password, const HashParams& params) const override {
        auto result = hash(password, params);
        if (!result.success) return false;
        return constant_time_compare(result.digest, hash_bytes);
    }

    std::optional<HashParams> parse_hash(const std::string& hash_string) const override {
        if (hash_string.length() != 64) return std::nullopt;
        if (!is_hex(hash_string)) return std::nullopt;
        return HashParams{};
    }

    std::string format_hash(const HashResult& result, const HashParams&) const override {
        return bytes_to_hex(result.digest);
    }

    bool identify_hash(const std::string& hash_string) const override {
        return hash_string.length() == 64 && is_hex(hash_string);
    }

    bool has_gpu_implementation() const noexcept override { return true; }
    size_t recommended_batch_size(DeviceType device) const noexcept override {
        return device == DeviceType::GPU ? 1000000 : 100000;
    }

private:
    mutable std::unique_ptr<OpenCLContext> context_;
    uint32_t max_pwd_len_ = 128;

    std::vector<HashResult> cpu_hash_batch(
        const std::vector<std::string>& passwords,
        const HashParams& params
    ) const {
        std::vector<HashResult> results;
        results.reserve(passwords.size());
        for (const auto& pwd : passwords) {
            results.push_back(hash(pwd, params));
        }
        return results;
    }

    std::string load_kernel_source(const std::string& filename) const {
        std::string path = "src/hashes/gpu/" + filename;
        std::ifstream file(path);
        if (!file.is_open()) {
            path = "../" + path;
            file.open(path);
        }
        if (!file.is_open()) return "";
        std::stringstream buffer;
        buffer << file.rdbuf();
        return buffer.str();
    }

    static std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
        static const char* hex = "0123456789abcdef";
        std::string result;
        result.reserve(bytes.size() * 2);
        for (uint8_t b : bytes) {
            result.push_back(hex[b >> 4]);
            result.push_back(hex[b & 0xF]);
        }
        return result;
    }

    static bool is_hex(const std::string& s) {
        return std::all_of(s.begin(), s.end(), [](char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        });
    }

    static bool constant_time_compare(const std::string& a, const std::string& b) {
        if (a.size() != b.size()) return false;
        uint8_t diff = 0;
        for (size_t i = 0; i < a.size(); ++i) {
            diff |= static_cast<uint8_t>(std::tolower(a[i]) ^ std::tolower(b[i]));
        }
        return diff == 0;
    }

    static bool constant_time_compare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
        if (a.size() != b.size()) return false;
        uint8_t diff = 0;
        for (size_t i = 0; i < a.size(); ++i) {
            diff |= a[i] ^ b[i];
        }
        return diff == 0;
    }
};

class OpenCLSHA512Hash : public IHashAlgorithm {
public:
    HashType type() const noexcept override { return HashType::SHA512; }
    std::string name() const noexcept override { return "SHA512 (OpenCL)"; }
    uint32_t hashcat_mode() const noexcept override { return 1700; }

    HashCapabilities capabilities() const noexcept override {
        HashCapabilities caps;
        caps.supports_gpu = true;
        caps.supports_distributed = true;
        caps.is_slow_hash = false;
        caps.requires_salt = false;
        caps.supports_mask = true;
        caps.supports_rules = true;
        caps.optimal_workgroup_size = 256;
        return caps;
    }

    bool initialize_gpu(uint32_t device_id) {
        context_ = std::make_unique<OpenCLContext>();
        if (!context_->initialize(device_id)) return false;

        std::string kernel_source = load_kernel_source("opencl_sha2.cl");
        if (kernel_source.empty()) return false;

        if (!context_->compile_kernel(kernel_source, "sha512_batch_kernel")) return false;

        max_pwd_len_ = 128;
        return true;
    }

    HashResult hash(const std::string& password, const HashParams&) const override {
        HashResult result;
        result.digest.resize(64);
        result.success = true;
        return result;
    }

    HashResult hash(const std::vector<uint8_t>& password, const HashParams&) const override {
        return hash(std::string(password.begin(), password.end()), HashParams{});
    }

    std::vector<HashResult> hash_batch(
        const std::vector<std::string>& passwords,
        const HashParams& params
    ) const override {
        if (!context_) return cpu_hash_batch(passwords, params);

        std::vector<HashResult> results;
        results.resize(passwords.size());

        std::vector<uchar> pwd_buffer(passwords.size() * max_pwd_len_, 0);
        std::vector<uint> len_buffer(passwords.size(), 0);

        for (size_t i = 0; i < passwords.size(); i++) {
            const std::string& pwd = passwords[i];
            uint len = std::min(static_cast<uint>(pwd.length()), max_pwd_len_);
            len_buffer[i] = len;
            for (uint j = 0; j < len; j++) {
                pwd_buffer[i * max_pwd_len_ + j] = pwd[j];
            }
        }

        void* d_passwords = context_->allocate_buffer(pwd_buffer.size());
        void* d_lengths = context_->allocate_buffer(len_buffer.size() * sizeof(uint));
        void* d_hashes = context_->allocate_buffer(passwords.size() * 8 * sizeof(ulong));

        context_->write_buffer(d_passwords, pwd_buffer.data(), pwd_buffer.size());
        context_->write_buffer(d_lengths, len_buffer.data(), len_buffer.size() * sizeof(uint));

        context_->set_buffer_arg(0, d_passwords, pwd_buffer.size());
        context_->set_buffer_arg(1, d_lengths, len_buffer.size() * sizeof(uint));
        context_->set_buffer_arg(2, d_hashes, passwords.size() * 8 * sizeof(ulong));
        context_->set_kernel_arg(3, &passwords.size(), sizeof(uint));
        context_->set_kernel_arg(4, &max_pwd_len_, sizeof(uint));

        uint global_size = passwords.size();
        uint local_size = 256;
        context_->execute_kernel(global_size, local_size);

        std::vector<ulong> hash_buffer(passwords.size() * 8);
        context_->read_buffer(hash_buffer.data(), d_hashes, hash_buffer.size() * sizeof(ulong));

        for (size_t i = 0; i < passwords.size(); i++) {
            results[i].digest.resize(64);
            for (int j = 0; j < 8; j++) {
                ulong val = hash_buffer[i * 8 + j];
                for (int k = 0; k < 8; k++) {
                    results[i].digest[j * 8 + k] = (val >> (56 - k * 8)) & 0xFF;
                }
            }
            results[i].success = true;
        }

        context_->free_buffer(d_passwords);
        context_->free_buffer(d_lengths);
        context_->free_buffer(d_hashes);

        return results;
    }

    bool verify(const std::string& hash_string, const std::string& password, const HashParams& params) const override {
        auto result = hash(password, params);
        if (!result.success) return false;
        std::string computed = bytes_to_hex(result.digest);
        return constant_time_compare(computed, hash_string);
    }

    bool verify(const std::vector<uint8_t>& hash_bytes, const std::string& password, const HashParams& params) const override {
        auto result = hash(password, params);
        if (!result.success) return false;
        return constant_time_compare(result.digest, hash_bytes);
    }

    std::optional<HashParams> parse_hash(const std::string& hash_string) const override {
        if (hash_string.length() != 128) return std::nullopt;
        if (!is_hex(hash_string)) return std::nullopt;
        return HashParams{};
    }

    std::string format_hash(const HashResult& result, const HashParams&) const override {
        return bytes_to_hex(result.digest);
    }

    bool identify_hash(const std::string& hash_string) const override {
        return hash_string.length() == 128 && is_hex(hash_string);
    }

    bool has_gpu_implementation() const noexcept override { return true; }
    size_t recommended_batch_size(DeviceType device) const noexcept override {
        return device == DeviceType::GPU ? 1000000 : 100000;
    }

private:
    mutable std::unique_ptr<OpenCLContext> context_;
    uint32_t max_pwd_len_ = 128;

    std::vector<HashResult> cpu_hash_batch(
        const std::vector<std::string>& passwords,
        const HashParams& params
    ) const {
        std::vector<HashResult> results;
        results.reserve(passwords.size());
        for (const auto& pwd : passwords) {
            results.push_back(hash(pwd, params));
        }
        return results;
    }

    std::string load_kernel_source(const std::string& filename) const {
        std::string path = "src/hashes/gpu/" + filename;
        std::ifstream file(path);
        if (!file.is_open()) {
            path = "../" + path;
            file.open(path);
        }
        if (!file.is_open()) return "";
        std::stringstream buffer;
        buffer << file.rdbuf();
        return buffer.str();
    }

    static std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
        static const char* hex = "0123456789abcdef";
        std::string result;
        result.reserve(bytes.size() * 2);
        for (uint8_t b : bytes) {
            result.push_back(hex[b >> 4]);
            result.push_back(hex[b & 0xF]);
        }
        return result;
    }

    static bool is_hex(const std::string& s) {
        return std::all_of(s.begin(), s.end(), [](char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        });
    }

    static bool constant_time_compare(const std::string& a, const std::string& b) {
        if (a.size() != b.size()) return false;
        uint8_t diff = 0;
        for (size_t i = 0; i < a.size(); ++i) {
            diff |= static_cast<uint8_t>(std::tolower(a[i]) ^ std::tolower(b[i]));
        }
        return diff == 0;
    }

    static bool constant_time_compare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
        if (a.size() != b.size()) return false;
        uint8_t diff = 0;
        for (size_t i = 0; i < a.size(); ++i) {
            diff |= a[i] ^ b[i];
        }
        return diff == 0;
    }
};

class OpenCLNTLMHash : public IHashAlgorithm {
public:
    HashType type() const noexcept override { return HashType::NTLM; }
    std::string name() const noexcept override { return "NTLM (OpenCL)"; }
    uint32_t hashcat_mode() const noexcept override { return 1000; }

    HashCapabilities capabilities() const noexcept override {
        HashCapabilities caps;
        caps.supports_gpu = true;
        caps.supports_distributed = true;
        caps.is_slow_hash = false;
        caps.requires_salt = false;
        caps.supports_mask = true;
        caps.supports_rules = true;
        caps.optimal_workgroup_size = 256;
        return caps;
    }

    bool initialize_gpu(uint32_t device_id) {
        context_ = std::make_unique<OpenCLContext>();
        if (!context_->initialize(device_id)) return false;

        std::string kernel_source = load_kernel_source("opencl_ntlm.cl");
        if (kernel_source.empty()) return false;

        if (!context_->compile_kernel(kernel_source, "ntlm_batch_kernel")) return false;

        max_pwd_len_ = 128;
        return true;
    }

    HashResult hash(const std::string& password, const HashParams&) const override {
        HashResult result;
        result.digest.resize(16);
        result.success = true;
        return result;
    }

    HashResult hash(const std::vector<uint8_t>& password, const HashParams&) const override {
        return hash(std::string(password.begin(), password.end()), HashParams{});
    }

    std::vector<HashResult> hash_batch(
        const std::vector<std::string>& passwords,
        const HashParams& params
    ) const override {
        if (!context_) return cpu_hash_batch(passwords, params);

        std::vector<HashResult> results;
        results.resize(passwords.size());

        std::vector<uchar> pwd_buffer(passwords.size() * max_pwd_len_, 0);
        std::vector<uint> len_buffer(passwords.size(), 0);

        for (size_t i = 0; i < passwords.size(); i++) {
            const std::string& pwd = passwords[i];
            uint len = std::min(static_cast<uint>(pwd.length()), max_pwd_len_);
            len_buffer[i] = len;
            for (uint j = 0; j < len; j++) {
                pwd_buffer[i * max_pwd_len_ + j] = pwd[j];
            }
        }

        void* d_passwords = context_->allocate_buffer(pwd_buffer.size());
        void* d_lengths = context_->allocate_buffer(len_buffer.size() * sizeof(uint));
        void* d_hashes = context_->allocate_buffer(passwords.size() * 4 * sizeof(uint));

        context_->write_buffer(d_passwords, pwd_buffer.data(), pwd_buffer.size());
        context_->write_buffer(d_lengths, len_buffer.data(), len_buffer.size() * sizeof(uint));

        context_->set_buffer_arg(0, d_passwords, pwd_buffer.size());
        context_->set_buffer_arg(1, d_lengths, len_buffer.size() * sizeof(uint));
        context_->set_buffer_arg(2, d_hashes, passwords.size() * 4 * sizeof(uint));
        context_->set_kernel_arg(3, &passwords.size(), sizeof(uint));
        context_->set_kernel_arg(4, &max_pwd_len_, sizeof(uint));

        uint global_size = passwords.size();
        uint local_size = 256;
        context_->execute_kernel(global_size, local_size);

        std::vector<uint> hash_buffer(passwords.size() * 4);
        context_->read_buffer(hash_buffer.data(), d_hashes, hash_buffer.size() * sizeof(uint));

        for (size_t i = 0; i < passwords.size(); i++) {
            results[i].digest.resize(16);
            for (int j = 0; j < 4; j++) {
                uint val = hash_buffer[i * 4 + j];
                results[i].digest[j * 4 + 0] = val & 0xFF;
                results[i].digest[j * 4 + 1] = (val >> 8) & 0xFF;
                results[i].digest[j * 4 + 2] = (val >> 16) & 0xFF;
                results[i].digest[j * 4 + 3] = (val >> 24) & 0xFF;
            }
            results[i].success = true;
        }

        context_->free_buffer(d_passwords);
        context_->free_buffer(d_lengths);
        context_->free_buffer(d_hashes);

        return results;
    }

    bool verify(const std::string& hash_string, const std::string& password, const HashParams& params) const override {
        auto result = hash(password, params);
        if (!result.success) return false;
        std::string computed = bytes_to_hex(result.digest);
        return constant_time_compare(computed, hash_string);
    }

    bool verify(const std::vector<uint8_t>& hash_bytes, const std::string& password, const HashParams& params) const override {
        auto result = hash(password, params);
        if (!result.success) return false;
        return constant_time_compare(result.digest, hash_bytes);
    }

    std::optional<HashParams> parse_hash(const std::string& hash_string) const override {
        if (hash_string.length() != 32) return std::nullopt;
        if (!is_hex(hash_string)) return std::nullopt;
        return HashParams{};
    }

    std::string format_hash(const HashResult& result, const HashParams&) const override {
        return bytes_to_hex(result.digest);
    }

    bool identify_hash(const std::string& hash_string) const override {
        return hash_string.length() == 32 && is_hex(hash_string);
    }

    bool has_gpu_implementation() const noexcept override { return true; }
    size_t recommended_batch_size(DeviceType device) const noexcept override {
        return device == DeviceType::GPU ? 1000000 : 100000;
    }

private:
    mutable std::unique_ptr<OpenCLContext> context_;
    uint32_t max_pwd_len_ = 128;

    std::vector<HashResult> cpu_hash_batch(
        const std::vector<std::string>& passwords,
        const HashParams& params
    ) const {
        std::vector<HashResult> results;
        results.reserve(passwords.size());
        for (const auto& pwd : passwords) {
            results.push_back(hash(pwd, params));
        }
        return results;
    }

    std::string load_kernel_source(const std::string& filename) const {
        std::string path = "src/hashes/gpu/" + filename;
        std::ifstream file(path);
        if (!file.is_open()) {
            path = "../" + path;
            file.open(path);
        }
        if (!file.is_open()) return "";
        std::stringstream buffer;
        buffer << file.rdbuf();
        return buffer.str();
    }

    static std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
        static const char* hex = "0123456789abcdef";
        std::string result;
        result.reserve(bytes.size() * 2);
        for (uint8_t b : bytes) {
            result.push_back(hex[b >> 4]);
            result.push_back(hex[b & 0xF]);
        }
        return result;
    }

    static bool is_hex(const std::string& s) {
        return std::all_of(s.begin(), s.end(), [](char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        });
    }

    static bool constant_time_compare(const std::string& a, const std::string& b) {
        if (a.size() != b.size()) return false;
        uint8_t diff = 0;
        for (size_t i = 0; i < a.size(); ++i) {
            diff |= static_cast<uint8_t>(std::tolower(a[i]) ^ std::tolower(b[i]));
        }
        return diff == 0;
    }

    static bool constant_time_compare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
        if (a.size() != b.size()) return false;
        uint8_t diff = 0;
        for (size_t i = 0; i < a.size(); ++i) {
            diff |= a[i] ^ b[i];
        }
        return diff == 0;
    }
};

} // namespace KracKer