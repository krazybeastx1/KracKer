#include "KracKer/hash_interface.hpp"
#include "KracKer/hash_registry.hpp"
#include "KracKer/mask.hpp"
#include "KracKer/wordlist.hpp"
#include "KracKer/utils.hpp"
#include "KracKer/rules.hpp"
#include <fstream>
#include <thread>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <chrono>
#include <atomic>
#include <functional>
#include <algorithm>
#include <random>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <sstream>

namespace KracKer {

// Forward declarations for attack functions
namespace {
    CrackResult run_dictionary_attack(const CrackerConfig& config, IHashAlgorithm* hash_algo, const HashParams& hash_params,
                                       const std::vector<std::string>& wordlist, const ICracker::ProgressCallback& progress_cb,
                                       std::atomic<bool>& stop, uint64_t start_pos);
    CrackResult run_brute_force_attack(const CrackerConfig& config, IHashAlgorithm* hash_algo, const HashParams& hash_params,
                                        const ICracker::ProgressCallback& progress_cb, std::atomic<bool>& stop, uint64_t start_pos);
    CrackResult run_mask_attack(const CrackerConfig& config, IHashAlgorithm* hash_algo, const HashParams& hash_params,
                                 const ICracker::ProgressCallback& progress_cb, std::atomic<bool>& stop, uint64_t start_pos);
    CrackResult run_hybrid_attack(const CrackerConfig& config, IHashAlgorithm* hash_algo, const HashParams& hash_params,
                                   const ICracker::ProgressCallback& progress_cb, std::atomic<bool>& stop, uint64_t start_pos);
    CrackResult run_prince_attack(const CrackerConfig& config, IHashAlgorithm* hash_algo, const HashParams& hash_params,
                                   const ICracker::ProgressCallback& progress_cb, std::atomic<bool>& stop, uint64_t start_pos);
    CrackResult run_association_attack(const CrackerConfig& config, IHashAlgorithm* hash_algo, const HashParams& hash_params,
                                        const ICracker::ProgressCallback& progress_cb, std::atomic<bool>& stop, uint64_t start_pos);
}

struct Cracker::Impl {
    CrackerConfig config;
    std::atomic<bool> running{false};
    std::atomic<bool> stop_requested{false};
    std::atomic<uint64_t> attempts{0};
    std::atomic<uint64_t> found_index{0};
    std::string found_password;
    std::mutex result_mutex;
    std::condition_variable result_cv;
    std::chrono::steady_clock::time_point start_time;
    ProgressCallback progress_cb;

    // Session
    std::string session_file;
    std::atomic<bool> auto_save{true};
    std::chrono::seconds autosave_interval{30};
    std::thread autosave_thread;
    std::atomic<bool> autosave_running{false};

    // Wordlist
    std::vector<std::string> wordlist;
    std::atomic<size_t> wordlist_pos{0};

    // Brute force state
    std::string charset;
    uint32_t min_len = 1;
    uint32_t max_len = 8;
    std::atomic<uint64_t> bf_position{0};

    // Mask state
    std::string mask_pattern;
    std::vector<std::string> mask_charsets;
    std::atomic<uint64_t> mask_position{0};

    // Hash algorithm
    IHashAlgorithm* hash_algo = nullptr;
    HashParams hash_params;

    // Distributed
    bool is_master = false;
    bool distributed_mode = false;
};

Cracker::Cracker() : pimpl_(std::make_unique<Impl>()) {}
Cracker::~Cracker() { stop(); }

bool Cracker::initialize(const CrackerConfig& config) {
    pimpl_->config = config;

    // Get hash algorithm
    auto& registry = HashRegistry::instance();
    pimpl_->hash_algo = registry.get_algorithm(config.hash_type);
    if (!pimpl_->hash_algo) {
        return false;
    }

    pimpl_->hash_params = config.params;

    // Setup wordlist
    if (!config.wordlist_path.empty() && 
        (config.attack_mode == CrackerConfig::AttackMode::Dictionary ||
         config.attack_mode == CrackerConfig::AttackMode::Hybrid ||
         config.attack_mode == CrackerConfig::AttackMode::Prince ||
         config.attack_mode == CrackerConfig::AttackMode::Association)) {
        if (!WordlistLoader::load(config.wordlist_path, pimpl_->wordlist)) {
            return false;
        }
    }

    // Setup brute force
    if (config.attack_mode == CrackerConfig::AttackMode::BruteForce ||
        config.attack_mode == CrackerConfig::AttackMode::Mask) {
        pimpl_->charset = config.charset;
        pimpl_->min_len = config.min_length;
        pimpl_->max_len = config.max_length;
        pimpl_->mask_pattern = config.mask_pattern;
    }

    // Setup session
    pimpl_->session_file = config.session_file;
    pimpl_->auto_save = config.auto_save;
    pimpl_->autosave_interval = std::chrono::seconds(config.autosave_interval_sec);

    // Setup distributed
    pimpl_->distributed_mode = config.distributed_mode;
    pimpl_->is_master = config.is_master;

    // Resume a previous session when one exists
    if (!config.session_file.empty() && file_exists(config.session_file)) {
        load_session(config.session_file);
    }

    return true;
}

CrackResult Cracker::crack() {
    pimpl_->running = true;
    pimpl_->stop_requested = false;
    pimpl_->attempts = 0;
    pimpl_->found_index = 0;
    pimpl_->found_password.clear();
    pimpl_->start_time = std::chrono::steady_clock::now();

    CrackResult result;

    // Resume offsets come from a loaded session (0 when starting fresh).
    const uint64_t wordlist_start = pimpl_->wordlist_pos.load();
    const uint64_t bf_start = pimpl_->bf_position.load();
    const uint64_t mask_start = pimpl_->mask_position.load();

    // Run appropriate attack
    switch (pimpl_->config.attack_mode) {
        case CrackerConfig::AttackMode::Dictionary:
            result = run_dictionary_attack(pimpl_->config, pimpl_->hash_algo, pimpl_->hash_params,
                                           pimpl_->wordlist, pimpl_->progress_cb,
                                           pimpl_->stop_requested, wordlist_start);
            break;
        case CrackerConfig::AttackMode::BruteForce:
            result = run_brute_force_attack(pimpl_->config, pimpl_->hash_algo, pimpl_->hash_params,
                                            pimpl_->progress_cb, pimpl_->stop_requested, bf_start);
            break;
        case CrackerConfig::AttackMode::Mask:
            result = run_mask_attack(pimpl_->config, pimpl_->hash_algo, pimpl_->hash_params,
                                     pimpl_->progress_cb, pimpl_->stop_requested, mask_start);
            break;
        case CrackerConfig::AttackMode::Hybrid:
            result = run_hybrid_attack(pimpl_->config, pimpl_->hash_algo, pimpl_->hash_params,
                                       pimpl_->progress_cb, pimpl_->stop_requested, 0);
            break;
        case CrackerConfig::AttackMode::Prince:
            result = run_prince_attack(pimpl_->config, pimpl_->hash_algo, pimpl_->hash_params,
                                       pimpl_->progress_cb, pimpl_->stop_requested, 0);
            break;
        case CrackerConfig::AttackMode::Association:
            result = run_association_attack(pimpl_->config, pimpl_->hash_algo, pimpl_->hash_params,
                                            pimpl_->progress_cb, pimpl_->stop_requested, 0);
            break;
    }

    // Record progress for the next session checkpoint.
    switch (pimpl_->config.attack_mode) {
        case CrackerConfig::AttackMode::Dictionary: pimpl_->wordlist_pos = result.resume_position; break;
        case CrackerConfig::AttackMode::BruteForce: pimpl_->bf_position = result.resume_position; break;
        case CrackerConfig::AttackMode::Mask:       pimpl_->mask_position = result.resume_position; break;
        default: break;
    }
    pimpl_->attempts = result.attempts;

    if (pimpl_->auto_save && !pimpl_->config.session_file.empty() && !result.found) {
        save_session(pimpl_->config.session_file);
    }

    pimpl_->running = false;

    auto end_time = std::chrono::steady_clock::now();
    result.elapsed = end_time - pimpl_->start_time;
    
    return result;
}

void Cracker::start_async() {
    std::thread([this]() { crack(); }).detach();
}

void Cracker::stop() {
    pimpl_->stop_requested = true;
    pimpl_->running = false;
    pimpl_->autosave_running = false;
}

bool Cracker::is_running() const {
    return pimpl_->running.load();
}

void Cracker::set_progress_callback(ProgressCallback cb) {
    pimpl_->progress_cb = std::move(cb);
}

bool Cracker::save_session(const std::string& path) {
    // Save session state to JSON
    nlohmann::json j;
    j["version"] = 2;
    j["session_id"] = generate_session_id();
    j["target_hash"] = pimpl_->config.target_hash;
    j["hash_type"] = static_cast<uint32_t>(pimpl_->config.hash_type);
    j["attack_mode"] = static_cast<uint32_t>(pimpl_->config.attack_mode);
    j["wordlist_path"] = pimpl_->config.wordlist_path;
    j["wordlist_position"] = pimpl_->wordlist_pos.load();
    j["bruteforce_position"] = pimpl_->bf_position.load();
    j["mask_position"] = pimpl_->mask_position.load();
    j["attempts"] = pimpl_->attempts.load();
    j["timestamp"] = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    
    try {
        std::ofstream file(path);
        file << j.dump(4);
        return true;
    } catch (...) {
        return false;
    }
}

bool Cracker::load_session(const std::string& path) {
    try {
        std::ifstream file(path);
        nlohmann::json j;
        file >> j;
        
        // Restore state
        pimpl_->wordlist_pos = j.value("wordlist_position", 0);
        pimpl_->bf_position = j.value("bruteforce_position", 0);
        pimpl_->mask_position = j.value("mask_position", 0);
        pimpl_->attempts = j.value("attempts", 0);
        
        return true;
    } catch (...) {
        return false;
    }
}

bool Cracker::start_master(uint16_t port) {
    // TODO: Implement master server
    return false;
}

bool Cracker::connect_worker(const std::string& host, uint16_t port) {
    // TODO: Implement worker connection
    return false;
}

std::string Cracker::generate_session_id() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;
    std::stringstream ss;
    ss << std::hex << dis(gen);
    return ss.str();
}

// ============================================================================
// Attack implementations (internal)
// ============================================================================

namespace {

using SteadyClock = std::chrono::steady_clock;

// A crack stops when the caller asks it to, or when a signal was received.
bool abort_requested(const std::atomic<bool>& stop) {
    return stop.load(std::memory_order_relaxed) || interrupt_requested();
}

std::vector<std::string> apply_rules_local(const std::string& word) {
    return RuleEngine::instance().apply_file_rules(word);
}

// Background progress reporter. It owns a thread that is always joined, so a
// finished or unsuccessful run can never block on it.
class ProgressMonitor {
public:
    ProgressMonitor() = default;
    ~ProgressMonitor() { stop(); }

    ProgressMonitor(const ProgressMonitor&) = delete;
    ProgressMonitor& operator=(const ProgressMonitor&) = delete;

    void start(const ICracker::ProgressCallback& cb,
               SteadyClock::time_point start_time,
               std::function<uint64_t()> attempts_fn,
               std::function<uint64_t()> position_fn,
               std::function<uint64_t()> total_fn) {
        if (!cb) return;

        cb_ = cb;
        start_time_ = start_time;
        attempts_fn_ = std::move(attempts_fn);
        position_fn_ = std::move(position_fn);
        total_fn_ = std::move(total_fn);

        thread_ = std::thread([this] {
            auto last_time = start_time_;
            uint64_t last_attempts = 0;

            while (!done_.load()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
                if (done_.load()) break;

                const auto now = SteadyClock::now();
                const uint64_t attempts = attempts_fn_();
                const uint64_t position = position_fn_();
                const uint64_t total = total_fn_();
                const double interval = std::chrono::duration<double>(now - last_time).count();

                ProgressInfo info;
                info.attempts = attempts;
                info.total_keyspace = total;
                info.progress_pct = total > 0
                    ? std::min(100.0, static_cast<double>(position) / static_cast<double>(total) * 100.0)
                    : 0.0;
                info.speed_hps = interval > 0
                    ? static_cast<double>(attempts - last_attempts) / interval
                    : 0.0;
                info.elapsed = now - start_time_;
                if (info.speed_hps > 0 && total > attempts) {
                    info.eta = std::chrono::duration<double>(
                        static_cast<double>(total - attempts) / info.speed_hps);
                }
                info.active_devices = 1;

                cb_(info);

                last_time = now;
                last_attempts = attempts;
            }
        });
    }

    void stop() {
        done_.store(true);
        if (thread_.joinable()) thread_.join();
    }

private:
    ICracker::ProgressCallback cb_;
    SteadyClock::time_point start_time_{};
    std::function<uint64_t()> attempts_fn_;
    std::function<uint64_t()> position_fn_;
    std::function<uint64_t()> total_fn_;
    std::atomic<bool> done_{false};
    std::thread thread_;
};

// Shared worker pool for any attack that can be expressed as "candidate N of M".
// Each index is claimed exactly once, so no candidate is skipped.
CrackResult run_indexed_attack(const CrackerConfig& config,
                               IHashAlgorithm* hash_algo,
                               const HashParams& hash_params,
                               uint64_t total_keyspace,
                               const std::function<std::string(uint64_t)>& generator,
                               const ICracker::ProgressCallback& progress_cb,
                               std::atomic<bool>& stop,
                               uint64_t start_pos) {
    CrackResult result;

    if (!hash_algo) {
        result.error = "No hash algorithm selected";
        return result;
    }
    if (total_keyspace == 0) {
        result.error = "Empty keyspace";
        return result;
    }

    std::atomic<bool> found{false};
    std::atomic<uint64_t> attempts{0};
    std::atomic<uint64_t> next{std::min(start_pos, total_keyspace)};
    std::atomic<uint64_t> completed{0};
    std::mutex result_mutex;

    const auto start_time = SteadyClock::now();

    ProgressMonitor monitor;
    monitor.start(progress_cb, start_time,
                  [&attempts] { return attempts.load(); },
                  [&next] { return next.load(); },
                  [total_keyspace] { return total_keyspace; });

    const size_t num_threads = config.cpu_threads > 0
        ? config.cpu_threads
        : std::max(1u, std::thread::hardware_concurrency());

    std::vector<std::thread> workers;
    workers.reserve(num_threads);

    for (size_t t = 0; t < num_threads; ++t) {
        workers.emplace_back([&] {
            while (!found.load(std::memory_order_relaxed)) {
                if (abort_requested(stop)) break;

                const uint64_t index = next.fetch_add(1, std::memory_order_relaxed);
                if (index >= total_keyspace) break;

                std::string candidate = generator(index);
                attempts.fetch_add(1, std::memory_order_relaxed);

                if (hash_algo->verify(config.target_hash, candidate, hash_params)) {
                    bool expected = false;
                    if (found.compare_exchange_strong(expected, true)) {
                        std::lock_guard lock(result_mutex);
                        result.found = true;
                        result.password = std::move(candidate);
                    }
                    break;
                }
                completed.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }

    for (auto& worker : workers) worker.join();
    monitor.stop();

    result.attempts = attempts.load();
    // Completed work (never ahead of the keyspace) so a resume cannot skip.
    result.resume_position = std::min(start_pos + completed.load(), total_keyspace);
    result.elapsed = SteadyClock::now() - start_time;
    return result;
}

CrackResult run_dictionary_attack(const CrackerConfig& config, IHashAlgorithm* hash_algo,
                                  const HashParams& hash_params,
                                  const std::vector<std::string>& wordlist,
                                  const ICracker::ProgressCallback& progress_cb,
                                  std::atomic<bool>& stop, uint64_t start_pos) {
    CrackResult result;

    if (!hash_algo) {
        result.error = "No hash algorithm selected";
        return result;
    }
    if (wordlist.empty()) {
        result.error = "Wordlist is empty or could not be read";
        return result;
    }

    const bool use_rules = !config.rules_file.empty();
    if (use_rules) {
        RuleEngine::instance().load_rules_file(config.rules_file);
    }

    std::atomic<bool> found{false};
    std::atomic<uint64_t> attempts{0};
    std::atomic<uint64_t> next{std::min<uint64_t>(start_pos, wordlist.size())};
    std::atomic<uint64_t> completed{0};
    std::mutex result_mutex;

    const auto start_time = SteadyClock::now();

    ProgressMonitor monitor;
    monitor.start(progress_cb, start_time,
                  [&attempts] { return attempts.load(); },
                  [&next] { return next.load(); },
                  [&wordlist] { return static_cast<uint64_t>(wordlist.size()); });

    const size_t num_threads = config.cpu_threads > 0
        ? config.cpu_threads
        : std::max(1u, std::thread::hardware_concurrency());

    std::vector<std::thread> workers;
    workers.reserve(num_threads);

    for (size_t t = 0; t < num_threads; ++t) {
        workers.emplace_back([&] {
            while (!found.load(std::memory_order_relaxed)) {
                if (abort_requested(stop)) break;

                const uint64_t index = next.fetch_add(1, std::memory_order_relaxed);
                if (index >= wordlist.size()) break;

                const std::string& word = wordlist[index];

                attempts.fetch_add(1, std::memory_order_relaxed);
                if (hash_algo->verify(config.target_hash, word, hash_params)) {
                    bool expected = false;
                    if (found.compare_exchange_strong(expected, true)) {
                        std::lock_guard lock(result_mutex);
                        result.found = true;
                        result.password = word;
                    }
                    break;
                }

                if (use_rules) {
                    const auto variants = apply_rules_local(word);
                    for (size_t v = 1; v < variants.size(); ++v) {
                        if (found.load(std::memory_order_relaxed)) break;

                        attempts.fetch_add(1, std::memory_order_relaxed);
                        if (hash_algo->verify(config.target_hash, variants[v], hash_params)) {
                            bool expected = false;
                            if (found.compare_exchange_strong(expected, true)) {
                                std::lock_guard lock(result_mutex);
                                result.found = true;
                                result.password = variants[v];
                            }
                            break;
                        }
                    }
                }

                completed.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }

    for (auto& worker : workers) worker.join();
    monitor.stop();

    result.attempts = attempts.load();
    result.resume_position = std::min<uint64_t>(start_pos + completed.load(), wordlist.size());
    result.elapsed = SteadyClock::now() - start_time;
    return result;
}

// Builds the per-length index blocks for a brute-force keyspace, so that
// absolute index -> (length, offset within length block) is unambiguous.
struct BruteForceLayout {
    struct Block {
        uint32_t length;
        uint64_t start;
        uint64_t space;
    };
    std::vector<Block> blocks;
    uint64_t total = 0;
};

BruteForceLayout build_bruteforce_layout(uint32_t min_len, uint32_t max_len, size_t charset_size) {
    BruteForceLayout layout;
    if (charset_size == 0 || min_len == 0 || max_len < min_len) return layout;

    uint64_t cursor = 0;
    for (uint32_t length = min_len; length <= max_len; ++length) {
        uint64_t space = 1;
        bool overflow = false;
        for (uint32_t i = 0; i < length; ++i) {
            if (space > UINT64_MAX / charset_size) { overflow = true; break; }
            space *= charset_size;
        }
        const uint64_t effective = overflow ? UINT64_MAX : space;

        BruteForceLayout::Block block{length, cursor, effective};
        layout.blocks.push_back(block);

        if (overflow || cursor > UINT64_MAX - effective) {
            layout.total = UINT64_MAX;
            break;
        }
        cursor += effective;
        layout.total = cursor;
    }
    return layout;
}

std::string bruteforce_candidate(uint64_t index, const BruteForceLayout& layout,
                                 const std::string& charset) {
    if (layout.blocks.empty() || charset.empty()) return {};

    const BruteForceLayout::Block* block = &layout.blocks.front();
    for (const auto& candidate_block : layout.blocks) {
        if (index >= candidate_block.start) block = &candidate_block;
        else break;
    }

    uint64_t remainder = index - block->start;
    std::string candidate(block->length, '\0');
    for (size_t pos = block->length; pos-- > 0;) {
        candidate[pos] = charset[remainder % charset.size()];
        remainder /= charset.size();
    }
    return candidate;
}

CrackResult run_brute_force_attack(const CrackerConfig& config, IHashAlgorithm* hash_algo,
                                   const HashParams& hash_params,
                                   const ICracker::ProgressCallback& progress_cb,
                                   std::atomic<bool>& stop, uint64_t start_pos) {
    CrackResult result;

    if (config.charset.empty()) {
        result.error = "Charset is empty";
        return result;
    }

    const uint32_t min_len = std::max<uint32_t>(1, config.min_length);
    const uint32_t max_len = std::max(min_len, config.max_length);
    const BruteForceLayout layout = build_bruteforce_layout(min_len, max_len, config.charset.size());

    if (layout.blocks.empty()) {
        result.error = "Invalid length range";
        return result;
    }

    const std::string charset = config.charset;
    auto generator = [layout, charset](uint64_t index) {
        return bruteforce_candidate(index, layout, charset);
    };

    return run_indexed_attack(config, hash_algo, hash_params, layout.total, generator,
                              progress_cb, stop, start_pos);
}

CrackResult run_mask_attack(const CrackerConfig& config, IHashAlgorithm* hash_algo,
                            const HashParams& hash_params,
                            const ICracker::ProgressCallback& progress_cb,
                            std::atomic<bool>& stop, uint64_t start_pos) {
    CrackResult result;

    const std::array<std::string, 4> custom = {
        config.custom_charset[0], config.custom_charset[1],
        config.custom_charset[2], config.custom_charset[3]
    };

    if (config.mask_pattern.empty()) {
        result.error = "Mask attack requires -m/--mask";
        return result;
    }

    auto info = MaskProcessor::parse_mask(config.mask_pattern, custom);
    if (!info.valid()) {
        result.error = "Invalid mask pattern (empty custom charset?): " + config.mask_pattern;
        return result;
    }

    auto generator = [info](uint64_t index) {
        return MaskProcessor::index_to_candidate(index, info);
    };

    return run_indexed_attack(config, hash_algo, hash_params, info.keyspace, generator,
                              progress_cb, stop, start_pos);
}

CrackResult run_hybrid_attack(const CrackerConfig& config, IHashAlgorithm* hash_algo,
                              const HashParams& hash_params,
                              const ICracker::ProgressCallback& progress_cb,
                              std::atomic<bool>& stop, uint64_t start_pos) {
    CrackResult result;

    std::vector<std::string> words;
    const std::string& source = !config.hybrid_wordlist.empty()
        ? config.hybrid_wordlist
        : config.wordlist_path;

    if (source.empty() || !WordlistLoader::load(source, words) || words.empty()) {
        result.error = "Hybrid attack requires a readable wordlist";
        return result;
    }

    if (config.hybrid_mask_left.empty() && config.hybrid_mask_right.empty()) {
        result.error = "Hybrid attack requires --hybrid-left and/or --hybrid-right";
        return result;
    }

    const std::array<std::string, 4> custom = {
        config.custom_charset[0], config.custom_charset[1],
        config.custom_charset[2], config.custom_charset[3]
    };

    const bool has_left = !config.hybrid_mask_left.empty();
    const bool has_right = !config.hybrid_mask_right.empty();

    auto left_info = has_left
        ? MaskProcessor::parse_mask(config.hybrid_mask_left, custom)
        : MaskProcessor::MaskInfo{};
    auto right_info = has_right
        ? MaskProcessor::parse_mask(config.hybrid_mask_right, custom)
        : MaskProcessor::MaskInfo{};

    if ((has_left && !left_info.valid()) || (has_right && !right_info.valid())) {
        result.error = "Invalid hybrid mask pattern";
        return result;
    }

    const uint64_t left_keyspace = has_left ? left_info.keyspace : 1;
    const uint64_t right_keyspace = has_right ? right_info.keyspace : 1;

    if (left_keyspace != 0 && right_keyspace != 0 &&
        words.size() > UINT64_MAX / left_keyspace / right_keyspace) {
        result.error = "Hybrid keyspace is too large";
        return result;
    }

    const uint64_t per_word = left_keyspace * right_keyspace;
    const uint64_t total = static_cast<uint64_t>(words.size()) * per_word;

    auto generator = [words, left_info, right_info, has_left, has_right,
                      per_word, left_keyspace, right_keyspace](uint64_t index) -> std::string {
        const size_t word_index = static_cast<size_t>(index / per_word);
        const uint64_t remainder = index % per_word;
        const uint64_t left_index = right_keyspace ? remainder / right_keyspace : 0;
        const uint64_t right_index = right_keyspace ? remainder % right_keyspace : 0;

        std::string candidate;
        if (has_left) candidate += MaskProcessor::index_to_candidate(left_index, left_info);
        candidate += words[word_index];
        if (has_right) candidate += MaskProcessor::index_to_candidate(right_index, right_info);
        return candidate;
    };

    return run_indexed_attack(config, hash_algo, hash_params, total, generator,
                              progress_cb, stop, start_pos);
}

CrackResult run_prince_attack(const CrackerConfig& config, IHashAlgorithm* hash_algo,
                              const HashParams& hash_params,
                              const ICracker::ProgressCallback& progress_cb,
                              std::atomic<bool>& stop, uint64_t start_pos) {
    CrackResult result;

    std::vector<std::string> words;
    if (config.wordlist_path.empty() || !WordlistLoader::load(config.wordlist_path, words) || words.empty()) {
        result.error = "PRINCE attack requires a readable wordlist";
        return result;
    }

    const size_t limit = config.keyspace_limit > 0
        ? static_cast<size_t>(config.keyspace_limit)
        : 1000000;

    auto candidates = WordlistGenerator::generate_prince(
        words,
        config.prince_min_words,
        config.prince_max_words,
        config.prince_max_length,
        limit);

    if (candidates.empty()) {
        result.error = "PRINCE generated no candidates (check --prince-* options)";
        return result;
    }

    auto generator = [&candidates](uint64_t index) { return candidates[index]; };

    return run_indexed_attack(config, hash_algo, hash_params, candidates.size(), generator,
                              progress_cb, stop, start_pos);
}

// Association attack: deterministic mutations of each keyword, generated on the
// fly so that large wordlists do not blow up memory.
namespace {

constexpr uint64_t kAssociationVariantsPerWord = 31;

std::string association_variant(const std::string& word, uint64_t variant) {
    static const char* const append_chars[] = {
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "!", "@", "#"
    };
    constexpr uint64_t append_count = sizeof(append_chars) / sizeof(append_chars[0]);

    auto leet = [](const std::string& in) {
        std::string out = in;
        for (char& c : out) {
            switch (c) {
                case 'a': case 'A': c = '4'; break;
                case 'e': case 'E': c = '3'; break;
                case 'i': case 'I': c = '1'; break;
                case 'o': case 'O': c = '0'; break;
                case 's': case 'S': c = '5'; break;
                default: break;
            }
        }
        return out;
    };

    auto capitalize = [](const std::string& in) {
        std::string out = in;
        if (!out.empty()) out[0] = static_cast<char>(std::toupper(static_cast<unsigned char>(out[0])));
        return out;
    };

    const std::string cap = capitalize(word);

    if (variant == 0) return to_upper(word);
    if (variant == 1) return to_lower(word);
    if (variant == 2) return cap;
    if (variant == 3) return std::string(word.rbegin(), word.rend());
    if (variant == 4) return leet(word);

    // Remaining variants: append a symbol to the word or its capitalised form.
    const uint64_t tail = variant - 5;
    if (tail < append_count) return word + append_chars[tail];
    const uint64_t second = tail - append_count;
    if (second < append_count) return cap + append_chars[second];

    return word;
}

} // namespace

CrackResult run_association_attack(const CrackerConfig& config, IHashAlgorithm* hash_algo,
                                   const HashParams& hash_params,
                                   const ICracker::ProgressCallback& progress_cb,
                                   std::atomic<bool>& stop, uint64_t start_pos) {
    CrackResult result;

    std::vector<std::string> words;
    if (config.wordlist_path.empty() || !WordlistLoader::load(config.wordlist_path, words) || words.empty()) {
        result.error = "Association attack requires a readable wordlist";
        return result;
    }

    if (words.size() > UINT64_MAX / kAssociationVariantsPerWord) {
        result.error = "Association keyspace is too large";
        return result;
    }

    auto generator = [words](uint64_t index) {
        const size_t word_index = static_cast<size_t>(index / kAssociationVariantsPerWord);
        const uint64_t variant = index % kAssociationVariantsPerWord;
        return association_variant(words[word_index], variant);
    };

    return run_indexed_attack(config, hash_algo, hash_params,
                              words.size() * kAssociationVariantsPerWord,
                              generator, progress_cb, stop, start_pos);
}

} // anonymous namespace

} // namespace KracKer
