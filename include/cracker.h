#ifndef CRACKER_H
#define CRACKER_H

#include <string>
#include <vector>
#include <atomic>
#include <functional>
#include <thread>
#include <queue>
#include "hash.h"

namespace cracker {

    struct CrackResult {
        bool found;
        std::string password;
        size_t attempts;
        double timeElapsed;
    };

    struct CrackConfig {
        hasher::HashType hashType;
        std::string targetHash;
        std::string charset;
        int minLength;
        int maxLength;
        std::string wordlistPath;
        int threads;
        bool casePermutations;
    };

    class Cracker {
    public:
        Cracker(const CrackConfig& config);
        CrackResult crack();

        // Attack modes
        CrackResult dictionaryAttack();
        CrackResult bruteForce();
        CrackResult hybridAttack();

        // Utilities
        std::vector<std::string> generatePermutations(const std::string& base);
        std::vector<std::string> applyRules(const std::string& word);

        // Getters
        size_t getAttempts() const { return attempts_.load(); }
        bool isRunning() const { return running_.load(); }
        void stop() { running_.store(false); }

    private:
        CrackConfig config_;
        std::atomic<size_t> attempts_;
        std::atomic<bool> running_;
        std::atomic<bool> progressRunning_;
        std::thread progressThread_;

        void startProgressReporter();
        void stopProgressReporter();
        bool checkHash(const std::string& candidate, const std::string& target);
        std::string hashInput(const std::string& input, hasher::HashType type);
    };

}

#endif
