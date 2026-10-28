#include "KracKer/hash_interface.hpp"
#include <nlohmann/json.hpp>
#include <fstream>
#include <sstream>

namespace KracKer {

bool CrackerConfig::load_from_file(const std::string& path) {
    try {
        std::ifstream file(path);
        nlohmann::json j;
        file >> j;
        
        hash_type = static_cast<HashType>(j.value("hash_type", 0));
        target_hash = j.value("target_hash", "");
        
        // Load hash params
        if (j.contains("params")) {
            auto& p = j["params"];
            params.bcrypt_cost = p.value("bcrypt_cost", 12);
            params.scrypt_N = p.value("scrypt_N", 16384);
            params.scrypt_r = p.value("scrypt_r", 8);
            params.scrypt_p = p.value("scrypt_p", 1);
            params.argon2_time = p.value("argon2_time", 3);
            params.argon2_memory = p.value("argon2_memory", 4096);
            params.argon2_threads = p.value("argon2_threads", 1);
            params.argon2_version = p.value("argon2_version", 19);
            params.kerb_etype = p.value("kerb_etype", 23);
            params.kerb_realm = p.value("kerb_realm", "");
            params.kerb_sname = p.value("kerb_sname", "");
            params.kerb_salt = string_to_bytes(p.value("kerb_salt", ""));
            params.kerb_checksum = string_to_bytes(p.value("kerb_checksum", ""));
        }
        
        attack_mode = static_cast<AttackMode>(j.value("attack_mode", 0));
        wordlist_path = j.value("wordlist_path", "");
        rules_file = j.value("rules_file", "");
        case_permutations = j.value("case_permutations", false);
        mask_pattern = j.value("mask_pattern", "");
        
        for (int i = 0; i < 4; ++i) {
            std::string key = "custom_charset_" + std::to_string(i + 1);
            custom_charset[i] = j.value(key, "");
        }
        
        min_length = j.value("min_length", 1);
        max_length = j.value("max_length", 8);
        
        device_ids = j.value("device_ids", std::vector<uint32_t>{0});
        cpu_threads = j.value("cpu_threads", 0);
        batch_size = j.value("batch_size", 100000);
        keyspace_limit = j.value("keyspace_limit", 0);
        
        session_file = j.value("session_file", "");
        auto_save = j.value("auto_save", true);
        autosave_interval_sec = j.value("autosave_interval_sec", 30);
        
        distributed_mode = j.value("distributed_mode", false);
        master_host = j.value("master_host", "127.0.0.1");
        master_port = j.value("master_port", 1337);
        worker_name = j.value("worker_name", "");
        is_master = j.value("is_master", false);
        
        show_progress = j.value("show_progress", true);
        quiet = j.value("quiet", false);
        output_file = j.value("output_file", "");
        output_format = j.value("output_format", "hash:pass");
        
        return true;
    } catch (...) {
        return false;
    }
}

bool CrackerConfig::save_to_file(const std::string& path) const {
    try {
        nlohmann::json j;
        j["hash_type"] = static_cast<uint32_t>(hash_type);
        j["target_hash"] = target_hash;
        
        nlohmann::json p;
        p["bcrypt_cost"] = params.bcrypt_cost;
        p["scrypt_N"] = params.scrypt_N;
        p["scrypt_r"] = params.scrypt_r;
        p["scrypt_p"] = params.scrypt_p;
        p["argon2_time"] = params.argon2_time;
        p["argon2_memory"] = params.argon2_memory;
        p["argon2_threads"] = params.argon2_threads;
        p["argon2_version"] = params.argon2_version;
        p["kerb_etype"] = params.kerb_etype;
        p["kerb_realm"] = params.kerb_realm;
        p["kerb_sname"] = params.kerb_sname;
        p["kerb_salt"] = bytes_to_string(params.kerb_salt);
        p["kerb_checksum"] = bytes_to_string(params.kerb_checksum);
        j["params"] = p;
        
        j["attack_mode"] = static_cast<uint32_t>(attack_mode);
        j["wordlist_path"] = wordlist_path;
        j["rules_file"] = rules_file;
        j["case_permutations"] = case_permutations;
        j["mask_pattern"] = mask_pattern;
        
        for (int i = 0; i < 4; ++i) {
            j["custom_charset_" + std::to_string(i + 1)] = custom_charset[i];
        }
        
        j["min_length"] = min_length;
        j["max_length"] = max_length;
        
        j["device_ids"] = device_ids;
        j["cpu_threads"] = cpu_threads;
        j["batch_size"] = batch_size;
        j["keyspace_limit"] = keyspace_limit;
        
        j["session_file"] = session_file;
        j["auto_save"] = auto_save;
        j["autosave_interval_sec"] = autosave_interval_sec;
        
        j["distributed_mode"] = distributed_mode;
        j["master_host"] = master_host;
        j["master_port"] = master_port;
        j["worker_name"] = worker_name;
        j["is_master"] = is_master;
        
        j["show_progress"] = show_progress;
        j["quiet"] = quiet;
        j["output_file"] = output_file;
        j["output_format"] = output_format;
        
        std::ofstream file(path);
        file << j.dump(4);
        return true;
    } catch (...) {
        return false;
    }
}

std::vector<uint8_t> CrackerConfig::string_to_bytes(const std::string& s) {
    std::vector<uint8_t> result;
    for (size_t i = 0; i < s.size(); i += 2) {
        std::string byte_str = s.substr(i, 2);
        result.push_back(static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16)));
    }
    return result;
}

std::string CrackerConfig::bytes_to_string(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    for (uint8_t b : bytes) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return ss.str();
}

} // namespace KracKer