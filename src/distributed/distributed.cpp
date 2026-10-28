#include "KracKer/hash_interface.hpp"
#include "KracKer/utils.hpp"
#include <asio.hpp>
#include <nlohmann/json.hpp>
#include <thread>
#include <atomic>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <chrono>
#include <memory>
#include <functional>

namespace KracKer {

using asio::ip::tcp;

// Message types for master/worker protocol
enum class MessageType : uint8_t {
    Hello = 1,
    WorkRequest = 2,
    WorkAssign = 3,
    WorkComplete = 4,
    Found = 5,
    Status = 6,
    Shutdown = 7,
    Heartbeat = 8
};

struct Message {
    MessageType type;
    uint32_t sequence = 0;
    nlohmann::json payload;
    
    std::vector<uint8_t> serialize() const {
        nlohmann::json j;
        j["type"] = static_cast<uint8_t>(type);
        j["seq"] = sequence;
        j["data"] = payload;
        std::string s = j.dump();
        return std::vector<uint8_t>(s.begin(), s.end());
    }
    
    static std::optional<Message> deserialize(const std::vector<uint8_t>& data) {
        try {
            std::string s(data.begin(), data.end());
            nlohmann::json j = nlohmann::json::parse(s);
            Message msg;
            msg.type = static_cast<MessageType>(j.value("type", 0));
            msg.sequence = j.value("seq", 0);
            msg.payload = j.value("data", nlohmann::json{});
            return msg;
        } catch (...) {
            return std::nullopt;
        }
    }
};

// Forward declarations for Master and Worker classes
class Master;
class Worker;

// Master and Worker class definitions
class Master {
public:
    Master();
    ~Master();
    bool initialize(const CrackerConfig& config, IHashAlgorithm* algo, const HashParams& params);
    bool start();
    void stop();
    bool is_running() const { return pimpl_->running; }
    void set_progress_callback(std::function<void(const ProgressInfo&)> cb);
    static std::string hex_encode(const std::vector<uint8_t>& bytes);
    void remove_client(uint32_t client_id);
    nlohmann::json serialize_params(const HashParams& params);

private:
    struct Impl;
    std::unique_ptr<Impl> pimpl_;
};

class Worker {
public:
    Worker();
    ~Worker();
    bool initialize(const CrackerConfig& config, IHashAlgorithm* algo, const HashParams& params);
    bool connect();
    void stop();
    bool is_running() const { return pimpl_->running; }
    void set_progress_callback(std::function<void(const ProgressInfo&)> cb);

    // Internal methods (public for implementation)
    void request_work();
    void handle_message(const Message& msg);
    void process_work(const nlohmann::json& payload);
    void heartbeat_loop();
    void work_loop();

private:
    struct Impl;
    std::unique_ptr<Impl> pimpl_;
};

// Master implementation
struct Master::Impl {
    CrackerConfig config;
    IHashAlgorithm* hash_algo = nullptr;
    HashParams hash_params;
    
    asio::io_context io_context;
    std::unique_ptr<tcp::acceptor> acceptor;
    uint16_t port = 1337;
    
    std::mutex clients_mutex;
    std::map<uint32_t, std::shared_ptr<tcp::socket>> clients;
    uint32_t next_client_id = 1;
    
    std::mutex work_mutex;
    std::queue<WorkUnit> work_queue;
    std::map<uint32_t, WorkUnit> assigned_work;
    std::atomic<uint64_t> total_work_units{0};
    std::atomic<uint64_t> completed_work_units{0};
    std::atomic<bool> running{false};
    std::atomic<bool> found{false};
    std::string found_password;
    
    std::thread io_thread;
    std::thread work_distributor_thread;
    
    std::function<void(const ProgressInfo&)> progress_cb;
    std::chrono::steady_clock::time_point start_time;
};

Master::Master() : pimpl_(std::make_unique<Impl>()) {}
Master::~Master() { stop(); }

bool Master::initialize(const CrackerConfig& config, IHashAlgorithm* algo, const HashParams& params) {
    pimpl_->config = config;
    pimpl_->hash_algo = algo;
    pimpl_->hash_params = params;
    pimpl_->port = config.master_port;
    return true;
}

bool Master::start() {
    if (pimpl_->running) return false;
    
    try {
        pimpl_->acceptor = std::make_unique<tcp::acceptor>(
            pimpl_->io_context, tcp::endpoint(tcp::v4(), pimpl_->port));
        
        pimpl_->running = true;
        pimpl_->found = false;
        pimpl_->start_time = std::chrono::steady_clock::now();
        
        // Generate work units
        generate_work_units();
        
        // Start accepting connections
        accept_connections();
        
        // Start IO thread
        pimpl_->io_thread = std::thread([this]() { pimpl_->io_context.run(); });
        
        // Start work distributor
        pimpl_->work_distributor_thread = std::thread([this]() { distribute_work_loop(); });
        
        return true;
    } catch (...) {
        return false;
    }
}

void Master::stop() {
    pimpl_->running = false;
    pimpl_->io_context.stop();
    
    if (pimpl_->io_thread.joinable()) pimpl_->io_thread.join();
    if (pimpl_->work_distributor_thread.joinable()) pimpl_->work_distributor_thread.join();
    
    // Notify all clients to shutdown
    std::lock_guard lock(pimpl_->clients_mutex);
    for (auto& [id, socket] : pimpl_->clients) {
        try {
            Message msg{MessageType::Shutdown, 0, {}};
            asio::write(*socket, asio::buffer(msg.serialize()));
        } catch (...) {}
    }
}

void Master::generate_work_units() {
    // Simplified: create work units based on attack mode
    switch (pimpl_->config.attack_mode) {
        case CrackerConfig::AttackMode::Dictionary: {
            // Load wordlist and split into chunks
            std::vector<std::string> words;
            WordlistLoader::load(pimpl_->config.wordlist_path, words);
            
            size_t chunk_size = 10000;
            for (size_t i = 0; i < words.size(); i += chunk_size) {
                WorkUnit wu;
                wu.id = pimpl_->total_work_units++;
                wu.type = "dictionary";
                wu.start_index = i;
                wu.end_index = std::min(i + chunk_size, words.size());
                wu.data = nlohmann::json{{"words", std::vector<std::string>(words.begin() + i, 
                    words.begin() + std::min(i + chunk_size, words.size()))}};
                pimpl_->work_queue.push(wu);
            }
            break;
        }
        case CrackerConfig::AttackMode::BruteForce: {
            // Split keyspace
            uint64_t total = 0;
            for (uint32_t l = pimpl_->config.min_length; l <= pimpl_->config.max_length; ++l) {
                uint64_t add = 1;
                for (uint32_t i = 0; i < l; ++i) add *= pimpl_->config.charset.size();
                total += add;
            }
            
            uint64_t chunk = total / 1000 + 1;
            for (uint64_t i = 0; i < total; i += chunk) {
                WorkUnit wu;
                wu.id = pimpl_->total_work_units++;
                wu.type = "bruteforce";
                wu.start_index = i;
                wu.end_index = std::min(i + chunk, total);
                wu.data = nlohmann::json{
                    {"charset", pimpl_->config.charset},
                    {"min_len", pimpl_->config.min_length},
                    {"max_len", pimpl_->config.max_length}
                };
                pimpl_->work_queue.push(wu);
            }
            break;
        }
    }
}

void Master::accept_connections() {
    auto socket = std::make_shared<tcp::socket>(pimpl_->io_context);
    pimpl_->acceptor->async_accept(*socket, [this, socket](std::error_code ec) {
        if (!ec && pimpl_->running) {
            uint32_t client_id = pimpl_->next_client_id++;
            {
                std::lock_guard lock(pimpl_->clients_mutex);
                pimpl_->clients[client_id] = socket;
            }
            
            // Send hello with config
            Message hello{MessageType::Hello, 0, {
                {"client_id", client_id},
                {"hash_type", static_cast<uint32_t>(pimpl_->config.hash_type)},
                {"target_hash", pimpl_->config.target_hash},
                {"hash_params", serialize_params(pimpl_->hash_params)}
            }};
            asio::async_write(*socket, asio::buffer(hello.serialize()),
                [this, socket, client_id](std::error_code ec, size_t) {
                    if (!ec) {
                        read_client_messages(socket, client_id);
                    } else {
                        remove_client(client_id);
                    }
                });
            
            // Accept next
            accept_connections();
        }
    });
}

void Master::read_client_messages(std::shared_ptr<tcp::socket> socket, uint32_t client_id) {
    auto buffer = std::make_shared<std::vector<uint8_t>>(4096);
    socket->async_read_some(asio::buffer(*buffer), 
        [this, socket, client_id, buffer](std::error_code ec, size_t bytes) {
            if (!ec && bytes > 0) {
                buffer->resize(bytes);
                auto msg = Message::deserialize(*buffer);
                if (msg) handle_message(client_id, *msg);
                read_client_messages(socket, client_id);
            } else {
                remove_client(client_id);
            }
        });
}

void Master::handle_message(uint32_t client_id, const Message& msg) {
    switch (msg.type) {
        case MessageType::WorkRequest:
            assign_work(client_id);
            break;
        case MessageType::WorkComplete:
            handle_work_complete(client_id, msg.payload);
            break;
        case MessageType::Found:
            handle_found(msg.payload);
            break;
        case MessageType::Status:
            // Client status update
            break;
        case MessageType::Heartbeat:
            // Client alive
            break;
    }
}

void Master::assign_work(uint32_t client_id) {
    WorkUnit wu;
    {
        std::lock_guard lock(pimpl_->work_mutex);
        if (pimpl_->work_queue.empty()) return;
        wu = pimpl_->work_queue.front();
        pimpl_->work_queue.pop();
        pimpl_->assigned_work[wu.id] = wu;
    }
    
    auto it = pimpl_->clients.find(client_id);
    if (it != pimpl_->clients.end()) {
        Message msg{MessageType::WorkAssign, 0, {
            {"work_id", wu.id},
            {"type", wu.type},
            {"start", wu.start_index},
            {"end", wu.end_index},
            {"data", wu.data}
        }};
        asio::async_write(*it->second, asio::buffer(msg.serialize()),
            [this, client_id](std::error_code ec, size_t) {
                if (ec) remove_client(client_id);
            });
    }
}

void Master::handle_work_complete(uint32_t client_id, const nlohmann::json& payload) {
    uint32_t work_id = payload.value("work_id", 0);
    uint64_t attempts = payload.value("attempts", 0);
    
    {
        std::lock_guard lock(pimpl_->work_mutex);
        pimpl_->assigned_work.erase(work_id);
        pimpl_->completed_work_units++;
    }
    
    // Request more work
    assign_work(client_id);
}

void Master::handle_found(const nlohmann::json& payload) {
    pimpl_->found = true;
    pimpl_->found_password = payload.value("password", "");
    pimpl_->running = false;
    pimpl_->io_context.stop();
}

void Master::distribute_work_loop() {
    auto last_time = std::chrono::steady_clock::now();
    uint64_t last_completed = 0;
    
    while (pimpl_->running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        auto now = std::chrono::steady_clock::now();
        uint64_t completed = pimpl_->completed_work_units.load();
        double elapsed = std::chrono::duration<double>(now - last_time).count();
        
        ProgressInfo info;
        info.attempts = completed; // Approximate
        info.total_keyspace = pimpl_->total_work_units.load();
        info.progress_pct = pimpl_->total_work_units > 0 ? 
            double(completed) / pimpl_->total_work_units * 100 : 0;
        info.speed_hps = elapsed > 0 ? (completed - last_completed) / elapsed : 0;
        info.elapsed = now - pimpl_->start_time;
        info.active_devices = pimpl_->clients.size();
        
        if (pimpl_->progress_cb) pimpl_->progress_cb(info);
        
        last_completed = completed;
        last_time = now;
        
        // Check for stalled work
        check_stalled_work();
    }
}

void Master::check_stalled_work() {
    // Re-queue work that hasn't completed in time
    // Implementation omitted for brevity
}

void Master::remove_client(uint32_t client_id) {
    std::lock_guard lock(pimpl_->clients_mutex);
    pimpl_->clients.erase(client_id);
}

nlohmann::json Master::serialize_params(const HashParams& params) {
    nlohmann::json j;
    j["bcrypt_cost"] = params.bcrypt_cost;
    j["scrypt_N"] = params.scrypt_N;
    j["scrypt_r"] = params.scrypt_r;
    j["scrypt_p"] = params.scrypt_p;
    j["argon2_time"] = params.argon2_time;
    j["argon2_memory"] = params.argon2_memory;
    j["argon2_threads"] = params.argon2_threads;
    j["argon2_version"] = params.argon2_version;
    j["kerb_etype"] = params.kerb_etype;
    j["kerb_realm"] = params.kerb_realm;
    j["kerb_sname"] = params.kerb_sname;
    j["kerb_salt"] = hex_encode(params.kerb_salt);
    j["kerb_checksum"] = hex_encode(params.kerb_checksum);
    return j;
}

std::string Master::hex_encode(const std::vector<uint8_t>& bytes) {
    static const char* hex = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (uint8_t b : bytes) {
        result.push_back(hex[b >> 4]);
        result.push_back(hex[b & 0xF]);
    }
    return result;
}

void Master::set_progress_callback(std::function<void(const ProgressInfo&)> cb) {
    pimpl_->progress_cb = std::move(cb);
}

// Worker implementation
struct Worker::Impl {
    CrackerConfig config;
    IHashAlgorithm* hash_algo = nullptr;
    HashParams hash_params;
    
    asio::io_context io_context;
    std::shared_ptr<tcp::socket> socket;
    std::string master_host;
    uint16_t master_port;
    std::string worker_name;
    
    uint32_t client_id = 0;
    uint32_t sequence = 0;
    
    std::atomic<bool> running{false};
    std::atomic<bool> connected{false};
    std::thread io_thread;
    std::thread heartbeat_thread;
    std::thread worker_thread;
    
    std::function<void(const ProgressInfo&)> progress_cb;
    std::chrono::steady_clock::time_point start_time;
};

Worker::Worker() : pimpl_(std::make_unique<Impl>()) {}
Worker::~Worker() { stop(); }

bool Worker::initialize(const CrackerConfig& config, IHashAlgorithm* algo, const HashParams& params) {
    pimpl_->config = config;
    pimpl_->hash_algo = algo;
    pimpl_->hash_params = params;
    pimpl_->master_host = config.master_host;
    pimpl_->master_port = config.master_port;
    pimpl_->worker_name = config.worker_name.empty() ? 
        "worker-" + std::to_string(get_timestamp_ms()) : config.worker_name;
    return true;
}

bool Worker::connect() {
    try {
        pimpl_->socket = std::make_shared<tcp::socket>(pimpl_->io_context);
        tcp::resolver resolver(pimpl_->io_context);
        auto endpoints = resolver.resolve(pimpl_->master_host, std::to_string(pimpl_->master_port));
        asio::connect(*pimpl_->socket, endpoints);
        
        // Read hello message
        std::vector<uint8_t> buffer(4096);
        size_t bytes = pimpl_->socket->read_some(asio::buffer(buffer));
        buffer.resize(bytes);
        
        auto msg = Message::deserialize(buffer);
        if (msg && msg->type == MessageType::Hello) {
            pimpl_->client_id = msg->payload.value("client_id", 0);
            pimpl_->connected = true;
            pimpl_->running = true;
            pimpl_->start_time = std::chrono::steady_clock::now();
            
            // Start threads
            pimpl_->io_thread = std::thread([this]() { pimpl_->io_context.run(); });
            pimpl_->worker_thread = std::thread([this]() { work_loop(); });
            pimpl_->heartbeat_thread = std::thread([this]() { heartbeat_loop(); });
            
            return true;
        }
        return false;
    } catch (...) {
        return false;
    }
}

void Worker::stop() {
    pimpl_->running = false;
    pimpl_->connected = false;
    pimpl_->io_context.stop();
    
    if (pimpl_->io_thread.joinable()) pimpl_->io_thread.join();
    if (pimpl_->worker_thread.joinable()) pimpl_->worker_thread.join();
    if (pimpl_->heartbeat_thread.joinable()) pimpl_->heartbeat_thread.join();
}

void Worker::work_loop() {
    // Request initial work
    request_work();
    
    while (pimpl_->running && pimpl_->connected) {
        // Read messages
        std::vector<uint8_t> buffer(4096);
        try {
            size_t bytes = pimpl_->socket->read_some(asio::buffer(buffer));
            if (bytes == 0) break;
            buffer.resize(bytes);
            
            auto msg = Message::deserialize(buffer);
            if (msg) handle_message(*msg);
        } catch (...) {
            break;
        }
    }
    
    pimpl_->connected = false;
}

void Worker::request_work() {
    Message msg{MessageType::WorkRequest, ++pimpl_->sequence, {
        {"worker_name", pimpl_->worker_name}
    }};
    try {
        asio::write(*pimpl_->socket, asio::buffer(msg.serialize()));
    } catch (...) {
        pimpl_->connected = false;
    }
}

void Worker::handle_message(const Message& msg) {
    switch (msg.type) {
        case MessageType::WorkAssign:
            process_work(msg.payload);
            break;
        case MessageType::Shutdown:
            pimpl_->running = false;
            break;
    }
}

void Worker::process_work(const nlohmann::json& payload) {
    uint32_t work_id = payload.value("work_id", 0);
    std::string type = payload.value("type", "");
    uint64_t start = payload.value("start", 0);
    uint64_t end = payload.value("end", 0);
    
    uint64_t attempts = 0;
    bool found = false;
    std::string password;
    
    if (type == "dictionary") {
        auto words = payload["data"]["words"].get<std::vector<std::string>>();
        for (const auto& word : words) {
            attempts++;
            if (pimpl_->hash_algo->verify(pimpl_->config.target_hash, word, pimpl_->hash_params)) {
                found = true;
                password = word;
                break;
            }
        }
    } else if (type == "bruteforce") {
        // Process brute force range
        std::string charset = payload["data"]["charset"].get<std::string>();
        uint32_t min_len = payload["data"]["min_len"].get<uint32_t>();
        uint32_t max_len = payload["data"]["max_len"].get<uint32_t>();
        
        // Simplified: just count attempts
        attempts = end - start;
        // Real implementation would iterate through range
    }
    
    // Send completion
    Message complete{MessageType::WorkComplete, ++pimpl_->sequence, {
        {"work_id", work_id},
        {"attempts", attempts},
        {"found", found},
        {"password", password}
    }};
    
    try {
        asio::write(*pimpl_->socket, asio::buffer(complete.serialize()));
    } catch (...) {
        pimpl_->connected = false;
    }
    
    if (found) {
        Message found_msg{MessageType::Found, ++pimpl_->sequence, {
            {"password", password}
        }};
        try {
            asio::write(*pimpl_->socket, asio::buffer(found_msg.serialize()));
        } catch (...) {}
        pimpl_->running = false;
    } else {
        // Request more work
        request_work();
    }
}

void Worker::heartbeat_loop() {
    while (pimpl_->running && pimpl_->connected) {
        std::this_thread::sleep_for(std::chrono::seconds(10));
        if (!pimpl_->connected) break;
        
        Message hb{MessageType::Heartbeat, ++pimpl_->sequence, {
            {"worker_name", pimpl_->worker_name}
        }};
        try {
            asio::write(*pimpl_->socket, asio::buffer(hb.serialize()));
        } catch (...) {
            pimpl_->connected = false;
            break;
        }
    }
}

void Worker::set_progress_callback(std::function<void(const ProgressInfo&)> cb) {
    pimpl_->progress_cb = std::move(cb);
}

} // namespace KracKer