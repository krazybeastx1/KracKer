#pragma once

#include <string>
#include <vector>
#include <memory>
#include <cstdint>
#include <optional>
#include <variant>
#include <chrono>
#include <unordered_map>
#include <shared_mutex>
#include <functional>
#include <mutex>
#include <iomanip>
#include <sstream>

namespace KracKer {

// Forward declarations
class HashContext;
class CrackerContext;

/**
 * Hash algorithm types supported by KracKer
 */
enum class HashType : uint32_t {
    // Fast hashes
    MD5           = 0,
    SHA1          = 100,
    SHA224        = 110,
    SHA256        = 1400,
    SHA384        = 10800,
    SHA512        = 1700,
    SHA3_224      = 17100,
    SHA3_256      = 17200,
    SHA3_384      = 17300,
    SHA3_512      = 17400,

    // NTLM
    NTLM          = 1000,

    // Slow hashes (KDFs)
    BCRYPT        = 3200,
    SCRYPT        = 8900,
    ARGON2I       = 16700,
    ARGON2D       = 16800,
    ARGON2ID      = 16900,

    // Kerberoasting
    KERBEROAST_RC4_HMAC           = 13100,  // etype 23
    KERBEROAST_AES128_CTS_HMAC    = 19600,  // etype 17
    KERBEROAST_AES256_CTS_HMAC    = 19700,  // etype 18
    // DES variants share hashcat mode 13100 with RC4, but need distinct enum
    // values so the registry does not overwrite one algorithm with another.
    KERBEROAST_DES3_CBC_SHA1      = 13101,  // etype 16
    KERBEROAST_DES_CBC_MD5        = 13102,  // etype 1, 3

    // Other
    UNKNOWN       = 0xFFFFFFFF
};

/**
 * Device type for execution
 */
enum class DeviceType : uint8_t {
    CPU  = 0,
    GPU  = 1,
    FPGA = 2
};

/**
 * Hash algorithm capabilities
 */
struct HashCapabilities {
    bool supports_gpu = false;
    bool supports_distributed = true;
    bool is_slow_hash = false;           // bcrypt, scrypt, argon2
    bool requires_salt = false;
    bool supports_mask = true;
    bool supports_rules = true;
    uint32_t min_kernel_duration_ms = 0; // For GPU tuning
    size_t optimal_workgroup_size = 256;
};

/**
 * Hash algorithm parameters (for slow hashes)
 */
struct HashParams {
    // bcrypt
    uint8_t bcrypt_cost = 12;

    // scrypt
    uint32_t scrypt_N = 16384;
    uint32_t scrypt_r = 8;
    uint32_t scrypt_p = 1;

    // Argon2
    uint32_t argon2_time = 3;
    uint32_t argon2_memory = 4096;  // KiB
    uint32_t argon2_threads = 1;
    uint32_t argon2_version = 19;   // 0x13

    // Kerberoasting
    uint32_t kerb_etype = 23;
    std::string kerb_realm;
    std::string kerb_sname;
    std::vector<uint8_t> kerb_salt;
    std::vector<uint8_t> kerb_checksum;
};

/**
 * Result of a hash computation
 */
struct HashResult {
    std::vector<uint8_t> digest;
    bool success = false;
    std::string error;
    std::chrono::nanoseconds duration{0};
};

/**
 * Candidate password for cracking
 */
struct Candidate {
    std::string password;
    uint64_t index = 0;  // Position in search space (for resume)
};

/**
 * Crack result
 */
struct CrackResult {
    bool found = false;
    std::string password;
    uint64_t attempts = 0;
    std::chrono::duration<double> elapsed;
    DeviceType device = DeviceType::CPU;
    uint32_t device_id = 0;
    // Position reached in the attack keyspace, used for session resume.
    uint64_t resume_position = 0;
    // Set when the attack could not run (bad mask, missing wordlist, ...).
    std::string error;
};

/**
 * Progress information
 */
struct ProgressInfo {
    uint64_t attempts = 0;
    uint64_t total_keyspace = 0;
    double progress_pct = 0.0;
    double speed_hps = 0.0;  // Hashes per second
    std::chrono::duration<double> elapsed;
    std::chrono::duration<double> eta;
    std::string current_candidate;
    uint32_t active_devices = 0;
};

/**
 * Session state for resume capability
 */
struct SessionState {
    std::string session_id;
    std::string target_hash;
    HashType hash_type = HashType::UNKNOWN;
    HashParams params;
    std::string attack_mode;  // "dictionary", "bruteforce", "mask", "hybrid", "prince"
    std::string wordlist_path;
    std::string mask_pattern;
    std::string rules_file;
    uint64_t wordlist_position = 0;
    uint64_t bruteforce_position = 0;
    uint64_t mask_position = 0;
    std::vector<std::string> rule_indices;
    std::chrono::system_clock::time_point created;
    std::chrono::system_clock::time_point last_update;
    uint32_t version = 2;
};

/**
 * Abstract hash algorithm interface
 * All hash implementations must derive from this
 */
class IHashAlgorithm {
public:
    virtual ~IHashAlgorithm() = default;

    // Identification
    virtual HashType type() const noexcept = 0;
    virtual std::string name() const noexcept = 0;
    virtual uint32_t hashcat_mode() const noexcept = 0;
    virtual HashCapabilities capabilities() const noexcept = 0;

    // Hash computation
    virtual HashResult hash(const std::string& password, const HashParams& params) const = 0;
    virtual HashResult hash(const std::vector<uint8_t>& password, const HashParams& params) const = 0;

    // Batch hashing (for GPU/optimized CPU)
    virtual std::vector<HashResult> hash_batch(
        const std::vector<std::string>& passwords,
        const HashParams& params
    ) const = 0;

    // Verification
    virtual bool verify(const std::string& hash_string, const std::string& password, const HashParams& params) const = 0;
    virtual bool verify(const std::vector<uint8_t>& hash_bytes, const std::string& password, const HashParams& params) const = 0;

    // Parsing
    virtual std::optional<HashParams> parse_hash(const std::string& hash_string) const = 0;
    virtual std::string format_hash(const HashResult& result, const HashParams& params) const = 0;
    virtual bool identify_hash(const std::string& hash_string) const = 0;

    // GPU support (optional)
    virtual bool has_gpu_implementation() const noexcept { return false; }
    virtual std::string gpu_kernel_source() const { return ""; }
    virtual std::string gpu_kernel_name() const { return ""; }

    // Performance hints
    virtual size_t recommended_batch_size(DeviceType device) const noexcept { return 10000; }
    virtual uint32_t recommended_workgroup_size() const noexcept { return 256; }
};

/**
 * GPU context abstraction
 */
class IGPUContext {
public:
    virtual ~IGPUContext() = default;

    virtual bool initialize(uint32_t device_id) = 0;
    virtual void shutdown() = 0;

    virtual bool compile_kernel(const std::string& source, const std::string& kernel_name) = 0;
    virtual bool set_kernel_arg(uint32_t index, const void* data, size_t size) = 0;
    virtual bool set_buffer_arg(uint32_t index, void* buffer, size_t size) = 0;

    virtual bool execute_kernel(uint64_t global_size, uint64_t local_size) = 0;
    virtual bool read_buffer(void* host_ptr, void* device_buffer, size_t size) = 0;
    virtual bool write_buffer(void* device_buffer, const void* host_ptr, size_t size) = 0;

    virtual void* allocate_buffer(size_t size, bool host_access = false) = 0;
    virtual void free_buffer(void* buffer) = 0;

    virtual uint32_t get_max_workgroup_size() const = 0;
    virtual uint64_t get_max_global_size() const = 0;
    virtual size_t get_device_memory() const = 0;
    virtual std::string get_device_name() const = 0;
};

/**
 * Device information
 */
struct DeviceInfo {
    uint32_t id = 0;
    DeviceType type = DeviceType::CPU;
    std::string name;
    std::string vendor;
    std::string version;
    uint32_t compute_units = 0;
    size_t global_memory = 0;
    size_t local_memory = 0;
    uint32_t max_workgroup_size = 0;
    bool available = true;
};

/**
 * Enumerate available devices
 */
std::vector<DeviceInfo> enumerate_devices(DeviceType type = DeviceType::GPU);

/**
 * Create GPU context for a device
 */
std::unique_ptr<IGPUContext> create_gpu_context(DeviceType type, uint32_t device_id);

// HashRegistry is defined in hash_registry.hpp

/**
 * Cracker configuration
 */
struct CrackerConfig {
    HashType hash_type = HashType::UNKNOWN;
    std::string target_hash;
    HashParams params;

    // Attack configuration
    enum class AttackMode { Dictionary, BruteForce, Mask, Hybrid, Prince, Association } attack_mode = AttackMode::Dictionary;

    // Dictionary attack
    std::string wordlist_path;
    std::string rules_file;
    bool case_permutations = false;

    // Brute force / Mask
    std::string mask_pattern;  // hashcat-style mask
    std::string custom_charset[4];  // ?1, ?2, ?3, ?4
    std::string charset = "abcdefghijklmnopqrstuvwxyz0123456789";  // default charset for brute force
    uint32_t min_length = 1;
    uint32_t max_length = 8;

    // Hybrid
    std::string hybrid_wordlist;
    std::string hybrid_mask_left;
    std::string hybrid_mask_right;

    // PRINCE
    uint32_t prince_min_words = 1;
    uint32_t prince_max_words = 4;
    uint32_t prince_max_length = 16;

    // Execution
    std::vector<uint32_t> device_ids = {0};  // GPU device IDs, empty = CPU only
    uint32_t cpu_threads = 0;  // 0 = auto
    uint64_t batch_size = 100000;
    uint64_t keyspace_limit = 0;  // 0 = unlimited

    // Session
    std::string session_file;
    bool auto_save = true;
    uint32_t autosave_interval_sec = 30;

    // Distributed
    bool distributed_mode = false;
    std::string master_host = "127.0.0.1";
    uint16_t master_port = 1337;
    std::string worker_name;
    bool is_master = false;

    // Output
    bool show_progress = true;
    bool quiet = false;
    std::string output_file;
    std::string output_format = "hash:pass";  // hashcat format

    // Config file I/O
    bool load_from_file(const std::string& path);
    bool save_to_file(const std::string& path) const;
    
    // Hex encoding helpers
    static std::vector<uint8_t> string_to_bytes(const std::string& s);
    static std::string bytes_to_string(const std::vector<uint8_t>& bytes);
};

/**
 * Main cracker interface
 */
class ICracker {
public:
    virtual ~ICracker() = default;

    // Initialize with configuration
    virtual bool initialize(const CrackerConfig& config) = 0;

    // Start cracking (blocking)
    virtual CrackResult crack() = 0;

    // Start cracking (async)
    virtual void start_async() = 0;
    virtual void stop() = 0;
    virtual bool is_running() const = 0;

    // Progress callback
    using ProgressCallback = std::function<void(const ProgressInfo&)>;
    virtual void set_progress_callback(ProgressCallback cb) = 0;

    // Session management
    virtual bool save_session(const std::string& path) = 0;
    virtual bool load_session(const std::string& path) = 0;

    // Distributed
    virtual bool start_master(uint16_t port) = 0;
    virtual bool connect_worker(const std::string& host, uint16_t port) = 0;
};

/**
 * Concrete cracker implementation
 */
class Cracker : public ICracker {
public:
    Cracker();
    ~Cracker() override;

    bool initialize(const CrackerConfig& config) override;
    CrackResult crack() override;
    void start_async() override;
    void stop() override;
    bool is_running() const override;
    void set_progress_callback(ProgressCallback cb) override;
    bool save_session(const std::string& path) override;
    bool load_session(const std::string& path) override;
    bool start_master(uint16_t port) override;
    bool connect_worker(const std::string& host, uint16_t port) override;

private:
    struct Impl;
    std::unique_ptr<Impl> pimpl_;

    // Helper for session ID generation
    static std::string generate_session_id();
};

/**
 * Session manager for checkpoint/resume functionality
 */
class SessionManager {
public:
    SessionManager();
    ~SessionManager();

    bool create_session(const CrackerConfig& config, const std::string& target_hash);
    bool load_session(const std::string& path);
    bool save_session();
    bool update_progress(uint64_t wordlist_pos, uint64_t bf_pos, uint64_t mask_pos);
    bool update_rules(const std::vector<std::string>& rule_indices);
    
    void set_autosave(bool enabled, std::chrono::seconds interval);
    void set_checkpoint_callback(std::function<void(const SessionState&)> cb);
    
    const SessionState& get_state() const;

private:
    struct Impl;
    std::unique_ptr<Impl> pimpl_;
    
    // Autosave methods (private, called internally)
    void start_autosave();
    void stop_autosave();
    
    static std::string generate_session_id();

public:
    // Public static utility methods
    static std::string hex_encode(const std::vector<uint8_t>& bytes);
    static std::vector<uint8_t> hex_decode(const std::string& hex_str);
};

} // namespace KracKer