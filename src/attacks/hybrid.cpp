#include "KracKer/hash_interface.hpp"
#include "KracKer/wordlist.hpp"
#include <vector>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>

namespace KracKer {

// Hybrid attack (dictionary + mask)
struct HybridAttack::Impl {
    CrackerConfig config;
    IHashAlgorithm* hash_algo = nullptr;
    HashParams hash_params;
    std::vector<std::string> wordlist;
    MaskProcessor::MaskInfo left_mask;
    MaskProcessor::MaskInfo right_mask;
    std::atomic<uint64_t> attempts{0};
    std::atomic<bool> found{false};
    std::string found_password;
    std::mutex result_mutex;
    std::function<void(const ProgressInfo&)> progress_cb;
    size_t num_threads = 0;
};

HybridAttack::HybridAttack() : pimpl_(std::make_unique<Impl>()) {}
HybridAttack::~HybridAttack() = default;

bool HybridAttack::initialize(const CrackerConfig& config, IHashAlgorithm* algo, const HashParams& params) {
    pimpl_->config = config;
    pimpl_->hash_algo = algo;
    pimpl_->hash_params = params;
    pimpl_->num_threads = config.cpu_threads > 0 ? config.cpu_threads : std::thread::hardware_concurrency();
    
    if (!WordlistLoader::load(config.hybrid_wordlist, pimpl_->wordlist)) return false;
    
    pimpl_->left_mask = MaskProcessor::parse_mask(config.hybrid_mask_left, config.custom_charset);
    pimpl_->right_mask = MaskProcessor::parse_mask(config.hybrid_mask_right, config.custom_charset);
    
    return true;
}

CrackResult HybridAttack::execute() {
    CrackResult result;
    pimpl_->found = false;
    pimpl_->attempts = 0;
    pimpl_->found_password.clear();
    auto start_time = std::chrono::steady_clock::now();
    
    uint64_t left_keyspace = pimpl_->left_mask.keyspace;
    uint64_t right_keyspace = pimpl_->right_mask.keyspace;
    uint64_t total_keyspace = pimpl_->wordlist.size() * left_keyspace * right_keyspace;
    
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
            info.progress_pct = total_keyspace > 0 ? double(current) / total_keyspace * 100 : 0;
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
        workers.emplace_back([this, t, total_keyspace]() {
            MaskProcessor::MaskIterator left_iter(pimpl_->left_mask);
            MaskProcessor::MaskIterator right_iter(pimpl_->right_mask);
            
            // Distribute wordlist among threads
            size_t words_per_thread = pimpl_->wordlist.size() / pimpl_->num_threads;
            size_t start_word = t * words_per_thread;
            size_t end_word = (t == pimpl_->num_threads - 1) ? pimpl_->wordlist.size() : start_word + words_per_thread;
            
            for (size_t wi = start_word; wi < end_word && !pimpl_->found.load(); ++wi) {
                const std::string& word = pimpl_->wordlist[wi];
                
                // Reset iterators for each word
                left_iter.seek(0);
                right_iter.seek(0);
                
                std::string left_part, right_part;
                while (left_iter.next(left_part) && !pimpl_->found.load()) {
                    right_iter.seek(0);
                    while (right_iter.next(right_part) && !pimpl_->found.load()) {
                        pimpl_->attempts++;
                        
                        std::string candidate = left_part + word + right_part;
                        
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

void HybridAttack::set_progress_callback(std::function<void(const ProgressInfo&)> cb) {
    pimpl_->progress_cb = std::move(cb);
}

// PRINCE attack
struct PrinceAttack::Impl {
    CrackerConfig config;
    IHashAlgorithm* hash_algo = nullptr;
    HashParams hash_params;
    std::vector<std::string> wordlist;
    uint32_t min_words = 1;
    uint32_t max_words = 4;
    uint32_t max_len = 16;
    std::atomic<uint64_t> attempts{0};
    std::atomic<bool> found{false};
    std::string found_password;
    std::mutex result_mutex;
    std::function<void(const ProgressInfo&)> progress_cb;
    size_t num_threads = 0;
};

PrinceAttack::PrinceAttack() : pimpl_(std::make_unique<Impl>()) {}
PrinceAttack::~PrinceAttack() = default;

bool PrinceAttack::initialize(const CrackerConfig& config, IHashAlgorithm* algo, const HashParams& params) {
    pimpl_->config = config;
    pimpl_->hash_algo = algo;
    pimpl_->hash_params = params;
    pimpl_->min_words = config.prince_min_words;
    pimpl_->max_words = config.prince_max_words;
    pimpl_->max_len = config.prince_max_length;
    pimpl_->num_threads = config.cpu_threads > 0 ? config.cpu_threads : std::thread::hardware_concurrency();
    
    if (!WordlistLoader::load(config.wordlist_path, pimpl_->wordlist)) return false;
    
    return true;
}

CrackResult PrinceAttack::execute() {
    CrackResult result;
    pimpl_->found = false;
    pimpl_->attempts = 0;
    pimpl_->found_password.clear();
    auto start_time = std::chrono::steady_clock::now();
    
    // Generate PRINCE candidates
    auto candidates = WordlistGenerator::generate_prince(
        pimpl_->wordlist, pimpl_->min_words, pimpl_->max_words, pimpl_->max_len
    );
    
    // Progress thread
    std::thread progress_thread([this, start_time, total = candidates.size()]() {
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
            info.total_keyspace = total;
            info.progress_pct = total > 0 ? double(current) / total * 100 : 0;
            info.speed_hps = elapsed > 0 ? (current - last_attempts) / elapsed : 0;
            info.elapsed = now - start_time;
            info.active_devices = 1;
            
            if (pimpl_->progress_cb) pimpl_->progress_cb(info);
            
            last_attempts = current;
            last_time = now;
        }
    });
    
    // Process candidates
    size_t per_thread = candidates.size() / pimpl_->num_threads;
    std::vector<std::thread> workers;
    for (size_t t = 0; t < pimpl_->num_threads; ++t) {
        workers.emplace_back([this, t, per_thread, &candidates]() {
            size_t start = t * per_thread;
            size_t end = (t == pimpl_->num_threads - 1) ? candidates.size() : start + per_thread;
            
            for (size_t i = start; i < end && !pimpl_->found.load(); ++i) {
                pimpl_->attempts++;
                const std::string& candidate = candidates[i];
                
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

void PrinceAttack::set_progress_callback(std::function<void(const ProgressInfo&)> cb) {
    pimpl_->progress_cb = std::move(cb);
}

// Association attack
struct AssociationAttack::Impl {
    CrackerConfig config;
    IHashAlgorithm* hash_algo = nullptr;
    HashParams hash_params;
    std::vector<std::string> keywords;
    std::atomic<uint64_t> attempts{0};
    std::atomic<bool> found{false};
    std::string found_password;
    std::mutex result_mutex;
    std::function<void(const ProgressInfo&)> progress_cb;
    size_t num_threads = 0;
};

AssociationAttack::AssociationAttack() : pimpl_(std::make_unique<Impl>()) {}
AssociationAttack::~AssociationAttack() = default;

bool AssociationAttack::initialize(const CrackerConfig& config, IHashAlgorithm* algo, const HashParams& params) {
    pimpl_->config = config;
    pimpl_->hash_algo = algo;
    pimpl_->hash_params = params;
    pimpl_->num_threads = config.cpu_threads > 0 ? config.cpu_threads : std::thread::hardware_concurrency();
    
    // Load keywords from wordlist
    WordlistLoader::load(config.wordlist_path, pimpl_->keywords);
    
    return true;
}

CrackResult AssociationAttack::execute() {
    CrackResult result;
    pimpl_->found = false;
    pimpl_->attempts = 0;
    pimpl_->found_password.clear();
    auto start_time = std::chrono::steady_clock::now();
    
    // Generate variations: keyword + numbers, keyword + special, keyword1 + keyword2, etc.
    std::vector<std::string> candidates;
    candidates.reserve(pimpl_->keywords.size() * 100);
    
    for (const auto& kw : pimpl_->keywords) {
        candidates.push_back(kw);
        // Append numbers
        for (int i = 0; i <= 9999; ++i) candidates.push_back(kw + std::to_string(i));
        // Append special chars
        for (char c : "!@#$%^&*") candidates.push_back(kw + c);
        // Prepend
        for (int i = 0; i <= 99; ++i) candidates.push_back(std::to_string(i) + kw);
    }
    
    // Add combinations
    for (size_t i = 0; i < pimpl_->keywords.size() && i < 100; ++i) {
        for (size_t j = 0; j < pimpl_->keywords.size() && j < 100; ++j) {
            candidates.push_back(pimpl_->keywords[i] + pimpl_->keywords[j]);
        }
    }
    
    // Progress thread
    std::thread progress_thread([this, start_time, total = candidates.size()]() {
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
            info.total_keyspace = total;
            info.progress_pct = total > 0 ? double(current) / total * 100 : 0;
            info.speed_hps = elapsed > 0 ? (current - last_attempts) / elapsed : 0;
            info.elapsed = now - start_time;
            info.active_devices = 1;
            
            if (pimpl_->progress_cb) pimpl_->progress_cb(info);
            
            last_attempts = current;
            last_time = now;
        }
    });
    
    // Process
    size_t per_thread = candidates.size() / pimpl_->num_threads;
    std::vector<std::thread> workers;
    for (size_t t = 0; t < pimpl_->num_threads; ++t) {
        workers.emplace_back([this, t, per_thread, &candidates]() {
            size_t start = t * per_thread;
            size_t end = (t == pimpl_->num_threads - 1) ? candidates.size() : start + per_thread;
            
            for (size_t i = start; i < end && !pimpl_->found.load(); ++i) {
                pimpl_->attempts++;
                if (pimpl_->hash_algo->verify(pimpl_->config.target_hash, candidates[i], pimpl_->hash_params)) {
                    pimpl_->found = true;
                    std::lock_guard lock(pimpl_->result_mutex);
                    pimpl_->found_password = candidates[i];
                    result.found = true;
                    result.password = candidates[i];
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

void AssociationAttack::set_progress_callback(std::function<void(const ProgressInfo&)> cb) {
    pimpl_->progress_cb = std::move(cb);
}

} // namespace KracKer