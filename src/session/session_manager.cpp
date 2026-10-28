#include "KracKer/hash_interface.hpp"
#include <nlohmann/json.hpp>
#include <fstream>
#include <chrono>
#include <random>
#include <filesystem>
#include <atomic>
#include <thread>
#include <condition_variable>
#include <mutex>
#include <sstream>
#include <iomanip>

namespace KracKer {

struct SessionManager::Impl {
    SessionState state;
    std::string session_file;
    std::atomic<bool> auto_save{true};
    std::chrono::seconds autosave_interval{30};
    std::thread autosave_thread;
    std::atomic<bool> autosave_running{false};
    std::mutex autosave_mutex;
    std::condition_variable autosave_cv;
    std::function<void(const SessionState&)> on_checkpoint;
};

SessionManager::SessionManager() : pimpl_(std::make_unique<Impl>()) {}
SessionManager::~SessionManager() { stop_autosave(); }

bool SessionManager::create_session(const CrackerConfig& config, const std::string& target_hash) {
    pimpl_->state.session_id = generate_session_id();
    pimpl_->state.target_hash = target_hash;
    pimpl_->state.hash_type = config.hash_type;
    pimpl_->state.params = config.params;
    
    switch (config.attack_mode) {
        case CrackerConfig::AttackMode::Dictionary: pimpl_->state.attack_mode = "dictionary"; break;
        case CrackerConfig::AttackMode::BruteForce: pimpl_->state.attack_mode = "bruteforce"; break;
        case CrackerConfig::AttackMode::Mask: pimpl_->state.attack_mode = "mask"; break;
        case CrackerConfig::AttackMode::Hybrid: pimpl_->state.attack_mode = "hybrid"; break;
        case CrackerConfig::AttackMode::Prince: pimpl_->state.attack_mode = "prince"; break;
        case CrackerConfig::AttackMode::Association: pimpl_->state.attack_mode = "association"; break;
    }
    
    pimpl_->state.wordlist_path = config.wordlist_path;
    pimpl_->state.mask_pattern = config.mask_pattern;
    pimpl_->state.rules_file = config.rules_file;
    pimpl_->state.created = std::chrono::system_clock::now();
    pimpl_->state.last_update = pimpl_->state.created;
    pimpl_->state.version = 2;
    
    pimpl_->session_file = config.session_file.empty() ? 
        (pimpl_->state.session_id + ".session") : config.session_file;
    
    return save_session();
}

bool SessionManager::load_session(const std::string& path) {
    try {
        std::ifstream file(path);
        nlohmann::json j;
        file >> j;
        
        pimpl_->state.session_id = j.value("session_id", "");
        pimpl_->state.target_hash = j.value("target_hash", "");
        pimpl_->state.hash_type = static_cast<HashType>(j.value("hash_type", 0));
        pimpl_->state.attack_mode = j.value("attack_mode", "");
        pimpl_->state.wordlist_path = j.value("wordlist_path", "");
        pimpl_->state.mask_pattern = j.value("mask_pattern", "");
        pimpl_->state.rules_file = j.value("rules_file", "");
        pimpl_->state.wordlist_position = j.value("wordlist_position", 0);
        pimpl_->state.bruteforce_position = j.value("bruteforce_position", 0);
        pimpl_->state.mask_position = j.value("mask_position", 0);
        
        // Load params
        if (j.contains("params")) {
            auto& p = j["params"];
            pimpl_->state.params.bcrypt_cost = p.value("bcrypt_cost", 12);
            pimpl_->state.params.scrypt_N = p.value("scrypt_N", 16384);
            pimpl_->state.params.scrypt_r = p.value("scrypt_r", 8);
            pimpl_->state.params.scrypt_p = p.value("scrypt_p", 1);
            pimpl_->state.params.argon2_time = p.value("argon2_time", 3);
            pimpl_->state.params.argon2_memory = p.value("argon2_memory", 4096);
            pimpl_->state.params.argon2_threads = p.value("argon2_threads", 1);
            pimpl_->state.params.argon2_version = p.value("argon2_version", 19);
            pimpl_->state.params.kerb_etype = p.value("kerb_etype", 23);
            pimpl_->state.params.kerb_realm = p.value("kerb_realm", "");
            pimpl_->state.params.kerb_sname = p.value("kerb_sname", "");
            pimpl_->state.params.kerb_salt = hex_decode(p.value("kerb_salt", ""));
            pimpl_->state.params.kerb_checksum = hex_decode(p.value("kerb_checksum", ""));
        }
        
        pimpl_->state.version = j.value("version", 2);
        
        pimpl_->session_file = path;
        return true;
    } catch (...) {
        return false;
    }
}

bool SessionManager::save_session() {
    if (pimpl_->session_file.empty()) return false;
    
    try {
        nlohmann::json j;
        j["version"] = pimpl_->state.version;
        j["session_id"] = pimpl_->state.session_id;
        j["target_hash"] = pimpl_->state.target_hash;
        j["hash_type"] = static_cast<uint32_t>(pimpl_->state.hash_type);
        j["attack_mode"] = pimpl_->state.attack_mode;
        j["wordlist_path"] = pimpl_->state.wordlist_path;
        j["mask_pattern"] = pimpl_->state.mask_pattern;
        j["rules_file"] = pimpl_->state.rules_file;
        j["wordlist_position"] = pimpl_->state.wordlist_position;
        j["bruteforce_position"] = pimpl_->state.bruteforce_position;
        j["mask_position"] = pimpl_->state.mask_position;
        j["rule_indices"] = pimpl_->state.rule_indices;
        
        // Params
        nlohmann::json p;
        p["bcrypt_cost"] = pimpl_->state.params.bcrypt_cost;
        p["scrypt_N"] = pimpl_->state.params.scrypt_N;
        p["scrypt_r"] = pimpl_->state.params.scrypt_r;
        p["scrypt_p"] = pimpl_->state.params.scrypt_p;
        p["argon2_time"] = pimpl_->state.params.argon2_time;
        p["argon2_memory"] = pimpl_->state.params.argon2_memory;
        p["argon2_threads"] = pimpl_->state.params.argon2_threads;
        p["argon2_version"] = pimpl_->state.params.argon2_version;
        p["kerb_etype"] = pimpl_->state.params.kerb_etype;
        p["kerb_realm"] = pimpl_->state.params.kerb_realm;
        p["kerb_sname"] = pimpl_->state.params.kerb_sname;
        p["kerb_salt"] = hex_encode(pimpl_->state.params.kerb_salt);
        p["kerb_checksum"] = hex_encode(pimpl_->state.params.kerb_checksum);
        j["params"] = p;
        
        j["created"] = std::chrono::system_clock::to_time_t(pimpl_->state.created);
        j["last_update"] = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        
        std::ofstream file(pimpl_->session_file);
        file << j.dump(4);
        
        if (pimpl_->on_checkpoint) pimpl_->on_checkpoint(pimpl_->state);
        
        return true;
    } catch (...) {
        return false;
    }
}

bool SessionManager::update_progress(uint64_t wordlist_pos, uint64_t bf_pos, uint64_t mask_pos) {
    pimpl_->state.wordlist_position = wordlist_pos;
    pimpl_->state.bruteforce_position = bf_pos;
    pimpl_->state.mask_position = mask_pos;
    pimpl_->state.last_update = std::chrono::system_clock::now();
    return true;
}

bool SessionManager::update_rules(const std::vector<std::string>& rule_indices) {
    pimpl_->state.rule_indices = rule_indices;
    pimpl_->state.last_update = std::chrono::system_clock::now();
    return true;
}

void SessionManager::set_autosave(bool enabled, std::chrono::seconds interval) {
    pimpl_->auto_save = enabled;
    pimpl_->autosave_interval = interval;
    
    if (enabled && !pimpl_->autosave_running) {
        start_autosave();
    } else if (!enabled && pimpl_->autosave_running) {
        stop_autosave();
    }
}

void SessionManager::start_autosave() {
    pimpl_->autosave_running = true;
    pimpl_->autosave_thread = std::thread([this]() {
        std::unique_lock lock(pimpl_->autosave_mutex);
        while (pimpl_->autosave_running.load()) {
            // Wakes early when stop_autosave() notifies, so shutdown does not
            // have to wait out the full interval.
            if (pimpl_->autosave_cv.wait_for(lock, pimpl_->autosave_interval,
                                             [this] { return !pimpl_->autosave_running.load(); })) {
                break;
            }
            lock.unlock();
            save_session();
            lock.lock();
        }
    });
}

void SessionManager::stop_autosave() {
    {
        std::lock_guard lock(pimpl_->autosave_mutex);
        pimpl_->autosave_running = false;
    }
    pimpl_->autosave_cv.notify_all();
    if (pimpl_->autosave_thread.joinable()) {
        pimpl_->autosave_thread.join();
    }
}

void SessionManager::set_checkpoint_callback(std::function<void(const SessionState&)> cb) {
    pimpl_->on_checkpoint = std::move(cb);
}

const SessionState& SessionManager::get_state() const {
    return pimpl_->state;
}

std::string SessionManager::generate_session_id() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;
    std::stringstream ss;
    ss << std::hex << dis(gen);
    return ss.str();
}

std::string SessionManager::hex_encode(const std::vector<uint8_t>& bytes) {
    static const char* hex = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (uint8_t b : bytes) {
        result.push_back(hex[b >> 4]);
        result.push_back(hex[b & 0xF]);
    }
    return result;
}

std::vector<uint8_t> SessionManager::hex_decode(const std::string& hex_str) {
    std::vector<uint8_t> result;
    result.reserve(hex_str.size() / 2);
    for (size_t i = 0; i + 1 < hex_str.size(); i += 2) {
        std::string byte_str = hex_str.substr(i, 2);
        result.push_back(static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16)));
    }
    return result;
}

} // namespace KracKer