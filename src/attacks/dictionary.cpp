#include "KracKer/hash_interface.hpp"
#include "KracKer/wordlist.hpp"
#include <vector>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <functional>

namespace KracKer {

// Dictionary attack implementation
struct DictionaryAttack::Impl {
    CrackerConfig config;
    IHashAlgorithm* hash_algo = nullptr;
    HashParams hash_params;
    std::vector<std::string> wordlist;
    std::atomic<size_t> position{0};
    std::atomic<uint64_t> attempts{0};
    std::atomic<bool> found{false};
    std::string found_password;
    std::mutex result_mutex;
    std::function<void(const ProgressInfo&)> progress_cb;
    size_t batch_size = 10000;
    size_t num_threads = 0;
    bool use_rules = false;
    std::vector<std::string> rule_list;
};

DictionaryAttack::DictionaryAttack() : pimpl_(std::make_unique<Impl>()) {}
DictionaryAttack::~DictionaryAttack() = default;

bool DictionaryAttack::initialize(const CrackerConfig& config, IHashAlgorithm* algo, const HashParams& params) {
    pimpl_->config = config;
    pimpl_->hash_algo = algo;
    pimpl_->hash_params = params;
    pimpl_->batch_size = config.batch_size;
    pimpl_->num_threads = config.cpu_threads > 0 ? config.cpu_threads : std::thread::hardware_concurrency();
    pimpl_->use_rules = !config.rules_file.empty();
    
    // Load wordlist
    if (!WordlistLoader::load(config.wordlist_path, pimpl_->wordlist)) {
        return false;
    }
    
    // Load rules if specified
    if (pimpl_->use_rules) {
        RuleEngine& engine = RuleEngine::instance();
        if (engine.load_rules_file(config.rules_file)) {
            // Use all rules from file
            for (const auto& [name, rule] : engine.get_rules()) {
                pimpl_->rule_list.push_back(name);
            }
        }
    }
    
    return true;
}

CrackResult DictionaryAttack::execute() {
    CrackResult result;
    pimpl_->found = false;
    pimpl_->attempts = 0;
    pimpl_->position = 0;
    pimpl_->found_password.clear();
    auto start_time = std::chrono::steady_clock::now();
    
    // Progress reporting thread
    std::thread progress_thread([this, start_time]() {
        auto last_time = start_time;
        uint64_t last_attempts = 0;
        
        while (!pimpl_->found.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            if (pimpl_->found.load()) break;
            
            auto now = std::chrono::steady_clock::now();
            uint64_t current = pimpl_->attempts.load();
            double elapsed = std::chrono::duration<double>(now - last_time).count();
            
            ProgressInfo info;
            info.attempts = current;
            info.total_keyspace = pimpl_->wordlist.size() * (pimpl_->use_rules ? pimpl_->rule_list.size() + 1 : 1);
            info.progress_pct = info.total_keyspace > 0 ? 
                double(pimpl_->position.load()) / pimpl_->wordlist.size() * 100 : 0;
            info.speed_hps = elapsed > 0 ? (current - last_attempts) / elapsed : 0;
            info.elapsed = now - start_time;
            info.active_devices = 1;
            
            if (pimpl_->progress_cb) pimpl_->progress_cb(info);
            
            last_attempts = current;
            last_time = now;
        }
    });
    
    // Worker threads
    std::vector<std::thread> workers;
    for (size_t t = 0; t < pimpl_->num_threads; ++t) {
        workers.emplace_back([this]() {
            std::vector<std::string> batch;
            batch.reserve(pimpl_->batch_size);
            
            while (!pimpl_->found.load()) {
                batch.clear();
                
                // Get batch
                size_t start = pimpl_->position.fetch_add(pimpl_->batch_size);
                if (start >= pimpl_->wordlist.size()) break;
                
                size_t end = std::min(start + pimpl_->batch_size, pimpl_->wordlist.size());
                for (size_t i = start; i < end; ++i) {
                    batch.push_back(pimpl_->wordlist[i]);
                }
                
                // Process batch
                for (const auto& word : batch) {
                    if (pimpl_->found.load()) break;
                    pimpl_->attempts++;
                    
                    // Check base word
                    if (pimpl_->hash_algo->verify(pimpl_->config.target_hash, word, pimpl_->hash_params)) {
                        pimpl_->found = true;
                        std::lock_guard lock(pimpl_->result_mutex);
                        pimpl_->found_password = word;
                        result.found = true;
                        result.password = word;
                        result.attempts = pimpl_->attempts.load();
                        return;
                    }
                    
                    // Apply rules
                    if (pimpl_->use_rules) {
                        auto variants = RuleEngine::instance().apply(word, pimpl_->rule_list);
                        for (size_t i = 1; i < variants.size(); ++i) { // Skip original
                            if (pimpl_->found.load()) break;
                            pimpl_->attempts++;
                            if (pimpl_->hash_algo->verify(pimpl_->config.target_hash, variants[i], pimpl_->hash_params)) {
                                pimpl_->found = true;
                                std::lock_guard lock(pimpl_->result_mutex);
                                pimpl_->found_password = variants[i];
                                result.found = true;
                                result.password = variants[i];
                                result.attempts = pimpl_->attempts.load();
                                return;
                            }
                        }
                    }
                }
            }
        });
    }
    
    for (auto& w : workers) w.join();
    if (progress_thread.joinable()) progress_thread.join();
    
    if (!result.found) {
        result.attempts = pimpl_->attempts.load();
    }
    
    return result;
}

void DictionaryAttack::set_progress_callback(std::function<void(const ProgressInfo&)> cb) {
    pimpl_->progress_cb = std::move(cb);
}

// Brute force attack
struct BruteForceAttack::Impl {
    CrackerConfig config;
    IHashAlgorithm* hash_algo = nullptr;
    HashParams hash_params;
    std::string charset;
    uint32_t min_len = 1;
    uint32_t max_len = 8;
    std::atomic<uint64_t> position{0};
    std::atomic<uint64_t> attempts{0};
    std::atomic<bool> found{false};
    std::string found_password;
    std::mutex result_mutex;
    std::function<void(const ProgressInfo&)> progress_cb;
    size_t num_threads = 0;
};

BruteForceAttack::BruteForceAttack() : pimpl_(std::make_unique<Impl>()) {}
BruteForceAttack::~BruteForceAttack() = default;

bool BruteForceAttack::initialize(const CrackerConfig& config, IHashAlgorithm* algo, const HashParams& params) {
    pimpl_->config = config;
    pimpl_->hash_algo = algo;
    pimpl_->hash_params = params;
    pimpl_->charset = config.charset;
    pimpl_->min_len = config.min_length;
    pimpl_->max_len = config.max_length;
    pimpl_->num_threads = config.cpu_threads > 0 ? config.cpu_threads : std::thread::hardware_concurrency();
    return true;
}

CrackResult BruteForceAttack::execute() {
    CrackResult result;
    pimpl_->found = false;
    pimpl_->attempts = 0;
    pimpl_->position = 0;
    pimpl_->found_password.clear();
    auto start_time = std::chrono::steady_clock::now();
    
    // Calculate total keyspace
    uint64_t total_keyspace = 0;
    for (uint32_t l = pimpl_->min_len; l <= pimpl_->max_len; ++l) {
        uint64_t add = 1;
        for (uint32_t i = 0; i < l; ++i) {
            if (add > UINT64_MAX / pimpl_->charset.size()) {
                add = UINT64_MAX;
                break;
            }
            add *= pimpl_->charset.size();
        }
        if (total_keyspace > UINT64_MAX - add) {
            total_keyspace = UINT64_MAX;
            break;
        }
        total_keyspace += add;
    }
    
    uint64_t per_thread = total_keyspace / pimpl_->num_threads;
    
    // Progress thread
    std::thread progress_thread([this, start_time, total_keyspace]() {
        auto last_time = start_time;
        uint64_t last_attempts = 0;
        
        while (!pimpl_->found.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            if (pimpl_->found.load()) break;
            
            auto now = std::chrono::steady_clock::now();
            uint64_t current = pimpl_->attempts.load();
            double elapsed = std::chrono::duration<double>(now - last_time).count();
            
            ProgressInfo info;
            info.attempts = current;
            info.total_keyspace = total_keyspace;
            info.progress_pct = total_keyspace > 0 ? double(pimpl_->position.load()) / total_keyspace * 100 : 0;
            info.speed_hps = elapsed > 0 ? (current - last_attempts) / elapsed : 0;
            info.elapsed = now - start_time;
            info.active_devices = 1;
            
            if (pimpl_->progress_cb) pimpl_->progress_cb(info);
            
            last_attempts = current;
            last_time = now;
        }
    });
    
    // Worker threads
    std::vector<std::thread> workers;
    for (size_t t = 0; t < pimpl_->num_threads; ++t) {
        workers.emplace_back([this, t, per_thread, total_keyspace]() {
            uint64_t start_idx = t * per_thread;
            uint64_t end_idx = (t == pimpl_->num_threads - 1) ? total_keyspace : start_idx + per_thread;
            
            // Convert index to password
            auto idx_to_pwd = [this](uint64_t idx, uint32_t len) -> std::string {
                std::string pwd(len, ' ');
                for (uint32_t i = 0; i < len; ++i) {
                    pwd[len - 1 - i] = pimpl_->charset[idx % pimpl_->charset.size()];
                    idx /= pimpl_->charset.size();
                }
                return pwd;
            };
            
            // Find starting length for this thread
            uint64_t idx = start_idx;
            uint32_t current_len = pimpl_->min_len;
            while (current_len <= pimpl_->max_len) {
                uint64_t len_space = 1;
                for (uint32_t i = 0; i < current_len; ++i) len_space *= pimpl_->charset.size();
                if (idx < len_space) break;
                idx -= len_space;
                ++current_len;
            }
            
            for (uint64_t pos = start_idx; pos < end_idx && !pimpl_->found.load(); ++pos) {
                pimpl_->position = pos;
                pimpl_->attempts++;
                
                std::string candidate = idx_to_pwd(pos, current_len);
                
                if (pimpl_->hash_algo->verify(pimpl_->config.target_hash, candidate, pimpl_->hash_params)) {
                    pimpl_->found = true;
                    std::lock_guard lock(pimpl_->result_mutex);
                    pimpl_->found_password = candidate;
                    result.found = true;
                    result.password = candidate;
                    result.attempts = pimpl_->attempts.load();
                    return;
                }
            }
        });
    }
    
    for (auto& w : workers) w.join();
    if (progress_thread.joinable()) progress_thread.join();
    
    if (!result.found) {
        result.attempts = pimpl_->attempts.load();
    }
    
    return result;
}

void BruteForceAttack::set_progress_callback(std::function<void(const ProgressInfo&)> cb) {
    pimpl_->progress_cb = std::move(cb);
}

// Mask attack
struct MaskAttack::Impl {
    CrackerConfig config;
    IHashAlgorithm* hash_algo = nullptr;
    HashParams hash_params;
    MaskProcessor::MaskInfo mask_info;
    std::atomic<uint64_t> position{0};
    std::atomic<uint64_t> attempts{0};
    std::atomic<bool> found{false};
    std::string found_password;
    std::mutex result_mutex;
    std::function<void(const ProgressInfo&)> progress_cb;
    size_t num_threads = 0;
};

MaskAttack::MaskAttack() : pimpl_(std::make_unique<Impl>()) {}
MaskAttack::~MaskAttack() = default;

bool MaskAttack::initialize(const CrackerConfig& config, IHashAlgorithm* algo, const HashParams& params) {
    pimpl_->config = config;
    pimpl_->hash_algo = algo;
    pimpl_->hash_params = params;
    pimpl_->num_threads = config.cpu_threads > 0 ? config.cpu_threads : std::thread::hardware_concurrency();
    
    // Parse mask
    pimpl_->mask_info = MaskProcessor::parse_mask(config.mask_pattern, config.custom_charset);
    return true;
}

CrackResult MaskAttack::execute() {
    CrackResult result;
    pimpl_->found = false;
    pimpl_->attempts = 0;
    pimpl_->position = 0;
    pimpl_->found_password.clear();
    auto start_time = std::chrono::steady_clock::now();
    
    uint64_t total_keyspace = pimpl_->mask_info.keyspace;
    uint64_t per_thread = total_keyspace / pimpl_->num_threads;
    
    // Progress thread
    std::thread progress_thread([this, start_time, total_keyspace]() {
        auto last_time = start_time;
        uint64_t last_attempts = 0;
        
        while (!pimpl_->found.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            if (pimpl_->found.load()) break;
            
            auto now = std::chrono::steady_clock::now();
            uint64_t current = pimpl_->attempts.load();
            double elapsed = std::chrono::duration<double>(now - last_time).count();
            
            ProgressInfo info;
            info.attempts = current;
            info.total_keyspace = total_keyspace;
            info.progress_pct = total_keyspace > 0 ? double(pimpl_->position.load()) / total_keyspace * 100 : 0;
            info.speed_hps = elapsed > 0 ? (current - last_attempts) / elapsed : 0;
            info.elapsed = now - start_time;
            info.active_devices = 1;
            
            if (pimpl_->progress_cb) pimpl_->progress_cb(info);
            
            last_attempts = current;
            last_time = now;
        }
    });
    
    // Worker threads
    std::vector<std::thread> workers;
    for (size_t t = 0; t < pimpl_->num_threads; ++t) {
        workers.emplace_back([this, t, per_thread, total_keyspace]() {
            uint64_t start_idx = t * per_thread;
            uint64_t end_idx = (t == pimpl_->num_threads - 1) ? total_keyspace : start_idx + per_thread;
            
            MaskProcessor::MaskIterator iter(pimpl_->mask_info);
            iter.seek(start_idx);
            
            std::string candidate;
            for (uint64_t pos = start_idx; pos < end_idx && !pimpl_->found.load(); ++pos) {
                pimpl_->position = pos;
                pimpl_->attempts++;
                
                if (!iter.next(candidate)) break;
                
                if (pimpl_->hash_algo->verify(pimpl_->config.target_hash, candidate, pimpl_->hash_params)) {
                    pimpl_->found = true;
                    std::lock_guard lock(pimpl_->result_mutex);
                    pimpl_->found_password = candidate;
                    result.found = true;
                    result.password = candidate;
                    result.attempts = pimpl_->attempts.load();
                    return;
                }
            }
        });
    }
    
    for (auto& w : workers) w.join();
    if (progress_thread.joinable()) progress_thread.join();
    
    if (!result.found) {
        result.attempts = pimpl_->attempts.load();
    }
    
    return result;
}

void MaskAttack::set_progress_callback(std::function<void(const ProgressInfo&)> cb) {
    pimpl_->progress_cb = std::move(cb);
}

} // namespace KracKer