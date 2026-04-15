#include "cracker.h"
#include <fstream>
#include <thread>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <chrono>
#include <algorithm>
#include <cctype>
#include <iostream>

namespace cracker {

Cracker::Cracker(const CrackConfig& config)
    : config_(config), attempts_(0), running_(false) {}

void Cracker::startProgressReporter() {
    progressRunning_.store(true);
    progressThread_ = std::thread([this]() {
        auto lastTime = std::chrono::high_resolution_clock::now();
        size_t lastAttempts = 0;
        while (progressRunning_.load() && running_.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            auto now = std::chrono::high_resolution_clock::now();
            size_t current = attempts_.load();
            double elapsed = std::chrono::duration<double>(now - lastTime).count();
            if (elapsed > 0) {
                size_t rate = static_cast<size_t>((current - lastAttempts) / elapsed);
                std::cout << "\r[*] Attempts: " << current << " | Rate: " << rate << "/s" << std::flush;
            }
            lastAttempts = current;
            lastTime = now;
        }
    });
}

void Cracker::stopProgressReporter() {
    progressRunning_.store(false);
    if (progressThread_.joinable()) {
        progressThread_.join();
    }
    std::cout << "\n";
}

CrackResult Cracker::crack() {
    running_.store(true);
    attempts_.store(0);
    auto start = std::chrono::high_resolution_clock::now();

    startProgressReporter();

    CrackResult result;
    switch (config_.hashType) {
        case hasher::HashType::MD5:
        case hasher::HashType::SHA1:
        case hasher::HashType::SHA256:
        case hasher::HashType::SHA512:
            if (!config_.wordlistPath.empty()) {
                result = dictionaryAttack();
            } else {
                result = bruteForce();
            }
            break;
        default:
            result.found = false;
            result.attempts = 0;
    }

    stopProgressReporter();
    auto end = std::chrono::high_resolution_clock::now();
    result.timeElapsed = std::chrono::duration<double>(end - start).count();
    return result;
}

CrackResult Cracker::dictionaryAttack() {
    std::ifstream file(config_.wordlistPath);
    if (!file.is_open()) {
        return {false, "", 0, 0};
    }

    std::queue<std::string> workQueue;
    std::mutex queueMutex;
    std::condition_variable cv;
    std::atomic<bool> found{false};
    std::string foundPassword;
    std::mutex resultMutex;

    const size_t BATCH_SIZE = 1000;

    std::vector<std::thread> workers;
    int numThreads = config_.threads > 0 ? config_.threads : std::thread::hardware_concurrency();

    for (int i = 0; i < numThreads; i++) {
        workers.emplace_back([&, this]() {
            while (running_.load()) {
                std::string candidate;
                {
                    std::unique_lock<std::mutex> lock(queueMutex);
                    cv.wait(lock, [&]() { return !workQueue.empty() || !running_.load(); });

                    if (!running_.load() && workQueue.empty()) break;
                    if (workQueue.empty()) continue;

                    candidate = workQueue.front();
                    workQueue.pop();
                }

                attempts_++;

                // Check base word
                if (checkHash(candidate, config_.targetHash)) {
                    found.store(true);
                    {
                        std::lock_guard<std::mutex> lock(resultMutex);
                        foundPassword = candidate;
                    }
                    running_.store(false);
                    return;
                }

                // Check case permutations if enabled
                if (config_.casePermutations) {
                    auto perms = generatePermutations(candidate);
                    for (const auto& perm : perms) {
                        if (!running_.load()) return;
                        attempts_++;
                        if (checkHash(perm, config_.targetHash)) {
                            found.store(true);
                            {
                                std::lock_guard<std::mutex> lock(resultMutex);
                                foundPassword = perm;
                            }
                            running_.store(false);
                            return;
                        }
                    }
                }
            }
        });
    }

    // Producer - batch loading
    std::vector<std::string> batch;
    std::string line;
    while (std::getline(file, line) && running_.load()) {
        if (!line.empty()) {
            while (!line.empty() && std::isspace(line.back())) {
                line.pop_back();
            }
            batch.push_back(line);

            if (batch.size() >= BATCH_SIZE) {
                {
                    std::lock_guard<std::mutex> lock(queueMutex);
                    for (auto& item : batch) {
                        workQueue.push(item);
                    }
                }
                cv.notify_all();
                batch.clear();
            }
        }
    }

    // Flush remaining
    if (!batch.empty() && running_.load()) {
        {
            std::lock_guard<std::mutex> lock(queueMutex);
            for (auto& item : batch) {
                workQueue.push(item);
            }
        }
        cv.notify_all();
    }

    file.close();

    // Signal workers to stop when done
    running_.store(false);
    cv.notify_all();

    for (auto& worker : workers) {
        worker.join();
    }

    if (found.load()) {
        return {true, foundPassword, attempts_.load(), 0};
    }
    return {false, "", attempts_.load(), 0};
}

CrackResult Cracker::bruteForce() {
    std::mutex resultMutex;
    std::atomic<bool> found{false};
    std::string foundPassword;

    std::function<void(std::string, int)> bruteRecursive;
    bruteRecursive = [&](std::string current, int depth) -> void {
        if (!running_.load() || found.load()) return;

        if (depth >= config_.maxLength) return;

        for (char c : config_.charset) {
            if (!running_.load() || found.load()) return;

            std::string candidate = current + c;
            attempts_++;

            if (checkHash(candidate, config_.targetHash)) {
                found.store(true);
                {
                    std::lock_guard<std::mutex> lock(resultMutex);
                    foundPassword = candidate;
                }
                return;
            }

            if (depth + 1 < config_.maxLength) {
                bruteRecursive(candidate, depth + 1);
            }
        }
    };

    // Multi-threaded brute force would need work distribution
    // For simplicity, single-threaded recursive approach
    bruteRecursive("", 0);

    if (found.load()) {
        return {true, foundPassword, attempts_.load(), 0};
    }
    return {false, "", attempts_.load(), 0};
}

CrackResult Cracker::hybridAttack() {
    // Dictionary + brute force modifications
    std::ifstream file(config_.wordlistPath);
    if (!file.is_open()) {
        return {false, "", 0, 0};
    }

    std::string line;
    while (std::getline(file, line) && running_.load()) {
        if (!line.empty()) {
            // Base word
            if (checkHash(line, config_.targetHash)) {
                return {true, line, attempts_.load(), 0};
            }

            // Add numbers
            for (int i = 0; i <= 99; i++) {
                std::string candidate = line + std::to_string(i);
                attempts_++;
                if (checkHash(candidate, config_.targetHash)) {
                    return {true, candidate, attempts_.load(), 0};
                }
            }

            // Add special chars
            std::string specials = "!@#$%^&*";
            for (char s : specials) {
                std::string candidate = line + s;
                attempts_++;
                if (checkHash(candidate, config_.targetHash)) {
                    return {true, candidate, attempts_.load(), 0};
                }
            }
        }
    }

    return {false, "", attempts_.load(), 0};
}

std::vector<std::string> Cracker::generatePermutations(const std::string& base) {
    std::vector<std::string> result;
    result.push_back(base);

    // All lowercase
    std::string lower;
    for (char c : base) lower += std::tolower(c);
    if (lower != base) result.push_back(lower);

    // All uppercase
    std::string upper;
    for (char c : base) upper += std::toupper(c);
    if (upper != base) result.push_back(upper);

    // Capitalized
    if (!base.empty()) {
        std::string capped;
        capped += std::toupper(base[0]);
        for (size_t i = 1; i < base.length(); i++) {
            capped += std::tolower(base[i]);
        }
        if (capped != base) result.push_back(capped);
    }

    return result;
}

std::vector<std::string> Cracker::applyRules(const std::string& word) {
    std::vector<std::string> result;

    // Basic rules
    result.push_back(word);  // Original

    std::string reversed = word;
    std::reverse(reversed.begin(), reversed.end());
    result.push_back(reversed);  // Reversed

    std::string doubled = word + word;
    result.push_back(doubled);  // Duplicated

    // Leet speak
    std::string leet;
    for (char c : word) {
        switch (c) {
            case 'a': leet += '4'; break;
            case 'e': leet += '3'; break;
            case 'i': leet += '1'; break;
            case 'o': leet += '0'; break;
            case 's': leet += '5'; break;
            case 't': leet += '7'; break;
            default: leet += c;
        }
    }
    if (leet != word) result.push_back(leet);

    return result;
}

bool Cracker::checkHash(const std::string& candidate, const std::string& target) {
    std::string computed = hashInput(candidate, config_.hashType);
    if (computed.length() != target.length()) return false;
    // Case-insensitive compare for hex
    for (size_t i = 0; i < target.length(); i++) {
        if (std::tolower(computed[i]) != std::tolower(target[i])) return false;
    }
    return true;
}

std::string Cracker::hashInput(const std::string& input, hasher::HashType type) {
    switch (type) {
        case hasher::HashType::MD5: return hasher::md5(input);
        case hasher::HashType::SHA1: return hasher::sha1(input);
        case hasher::HashType::SHA256: return hasher::sha256(input);
        case hasher::HashType::SHA512: return hasher::sha512(input);
        default: return "";
    }
}

}
