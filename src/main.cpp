#include <iostream>
#include <string>
#include <cstring>
#include <chrono>
#include <iomanip>
#include "cracker.h"
#include "hash.h"

void printBanner() {
    std::cout << "========================================\n";
    std::cout << "           Kracker v1.0                 \n";
    std::cout << "========================================\n\n";
}

void printHashInfo(const std::string& hash) {
    std::cout << "========================================\n";
    std::cout << "         Hash Identification            \n";
    std::cout << "========================================\n\n";
    std::cout << "Input: " << hash << "\n";
    std::cout << "Length: " << hash.length() << " characters\n\n";

    hasher::HashType type = hasher::detectHashType(hash);
    std::cout << "Possible hash types:\n";

    switch (type) {
        case hasher::HashType::MD5:
            std::cout << "  - MD5 (32 char hex)\n";
            std::cout << "    Common uses: Linux passwords, web sessions\n";
            std::cout << "    Format: 32 lowercase hex\n";
            break;
        case hasher::HashType::SHA1:
            std::cout << "  - SHA1 (40 char hex)\n";
            std::cout << "    Common uses: Git commits, old password hashes\n";
            std::cout << "    Format: 40 lowercase hex\n";
            break;
        case hasher::HashType::SHA256:
            std::cout << "  - SHA256 (64 char hex)\n";
            std::cout << "    Common uses: Bitcoin, modern password hashes\n";
            std::cout << "    Format: 64 lowercase hex\n";
            break;
        case hasher::HashType::SHA512:
            std::cout << "  - SHA512 (128 char hex)\n";
            std::cout << "    Common uses: Linux /etc/shadow, high-security apps\n";
            std::cout << "    Format: 128 lowercase hex\n";
            break;
        default:
            std::cout << "  - Unknown hash type\n";
            std::cout << "\nOther possibilities:\n";
            std::cout << "  - NTLM (32 char): Windows password hashes\n";
            std::cout << "  - bcrypt ($2a$...): Starts with $2a$, $2b$, or $2y$\n";
            std::cout << "  - scrypt: Starts with $s0$\n";
            std::cout << "  - Argon2: Starts with $argon2$\n";
            std::cout << "  - Base64 encoded: Contains +/= characters\n";
            std::cout << "  - Hex string: Could be raw hex data, not a hash\n";
    }

    std::cout << "\nTip: Try cracking with most likely type first.\n";
    std::cout << "========================================\n";
}

void printUsage(const char* prog) {
    std::cout << "Usage: " << prog << " [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  -h, --hash <hash>       Target hash to crack\n";
    std::cout << "  -t, --type <type>       Hash type: md5, sha1, sha256, sha512 (auto-detect if omitted)\n";
    std::cout << "  -w, --wordlist <file>   Wordlist file for dictionary attack\n";
    std::cout << "  -b, --brute             Use brute force attack\n";
    std::cout << "  -c, --charset <chars>   Charset for brute force (default: a-z0-9)\n";
    std::cout << "  -l, --length <min-max>  Password length range for brute (default: 1-8)\n";
    std::cout << "  -T, --threads <num>     Number of threads (default: auto)\n";
    std::cout << "  --hash <hash>           Identify hash type and exit when used alone\n";
    std::cout << "  --case-perm             Try case permutations\n";
    std::cout << "  --help                  Show this help\n\n";
    std::cout << "Examples:\n";
    std::cout << "  " << prog << " -h 5f4dcc3b5aa765d61d8327deb882cf99 -w rockyou.txt\n";
    std::cout << "  " << prog << " -h 5f4dcc3b5aa765d61d8327deb882cf99 -b -l 1-5\n";
    std::cout << "  " << prog << " --hash 5f4dcc3b5aa765d61d8327deb882cf99\n";
    std::cout << "  " << prog << " -h <hash> -w wordlist.txt --case-perm\n\n";
}

int main(int argc, char* argv[]) {
    printBanner();

    std::string targetHash;
    std::string hashTypeStr;
    std::string wordlistPath = "/usr/share/wordlists/rockyou.txt";
    bool bruteMode = false;
    bool identifyMode = false;
    std::string charset = "abcdefghijklmnopqrstuvwxyz0123456789";
    int minLength = 1, maxLength = 8;
    int threads = 0;
    bool casePermutations = false;

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--hash") == 0) {
            if (i + 1 < argc) targetHash = argv[++i];
        } else if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--type") == 0) {
            if (i + 1 < argc) hashTypeStr = argv[++i];
        } else if (strcmp(argv[i], "-w") == 0 || strcmp(argv[i], "--wordlist") == 0) {
            if (i + 1 < argc) wordlistPath = argv[++i];
        } else if (strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "--brute") == 0) {
            bruteMode = true;
        } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--charset") == 0) {
            if (i + 1 < argc) charset = argv[++i];
        } else if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--length") == 0) {
            if (i + 1 < argc) {
                std::string range = argv[++i];
                size_t dashPos = range.find('-');
                if (dashPos != std::string::npos) {
                    minLength = std::stoi(range.substr(0, dashPos));
                    maxLength = std::stoi(range.substr(dashPos + 1));
                }
            }
        } else if (strcmp(argv[i], "-T") == 0 || strcmp(argv[i], "--threads") == 0) {
            if (i + 1 < argc) threads = std::stoi(argv[++i]);
        } else if (strcmp(argv[i], "--case-perm") == 0) {
            casePermutations = true;
        } else if (strcmp(argv[i], "--help") == 0) {
            printUsage(argv[0]);
            return 0;
        }
    }

    if (targetHash.empty()) {
        std::cerr << "Error: No target hash provided\n\n";
        printUsage(argv[0]);
        return 1;
    }

    // Hash identification mode - auto detect when only --hash provided
    if (!targetHash.empty() && wordlistPath.empty() && !bruteMode) {
        printHashInfo(targetHash);
        return 0;
    }

    if (wordlistPath.empty() && !bruteMode) {
        std::cerr << "Error: Specify wordlist (-w) or brute mode (-b)\n\n";
        printUsage(argv[0]);
        return 1;
    }

    // Detect or set hash type
    hasher::HashType hashType;
    if (!hashTypeStr.empty()) {
        if (hashTypeStr == "md5") hashType = hasher::HashType::MD5;
        else if (hashTypeStr == "sha1") hashType = hasher::HashType::SHA1;
        else if (hashTypeStr == "sha256") hashType = hasher::HashType::SHA256;
        else if (hashTypeStr == "sha512") hashType = hasher::HashType::SHA512;
        else {
            std::cerr << "Error: Unknown hash type: " << hashTypeStr << "\n";
            return 1;
        }
    } else {
        hashType = hasher::detectHashType(targetHash);
        if (hashType == hasher::HashType::UNKNOWN) {
            std::cerr << "Error: Could not auto-detect hash type. Specify with -t\n";
            return 1;
        }
        std::cout << "Auto-detected hash type: ";
        switch (hashType) {
            case hasher::HashType::MD5: std::cout << "MD5"; break;
            case hasher::HashType::SHA1: std::cout << "SHA1"; break;
            case hasher::HashType::SHA256: std::cout << "SHA256"; break;
            case hasher::HashType::SHA512: std::cout << "SHA512"; break;
            default: break;
        }
        std::cout << "\n";
    }

    // Build config
    cracker::CrackConfig config;
    config.hashType = hashType;
    config.targetHash = targetHash;
    config.wordlistPath = wordlistPath;
    config.charset = charset;
    config.minLength = minLength;
    config.maxLength = maxLength;
    config.threads = threads;
    config.casePermutations = casePermutations;

    // Start cracking
    cracker::Cracker cracker(config);
    std::cout << "\n[*] Starting crack...\n";
    std::cout << "    Mode: " << (wordlistPath.empty() ? "Brute Force" : "Dictionary") << "\n";
    if (!wordlistPath.empty()) {
        std::cout << "    Wordlist: " << wordlistPath << "\n";
    }
    std::cout << "    Threads: " << (threads > 0 ? std::to_string(threads) : "auto") << "\n\n";

    cracker::CrackResult result = cracker.crack();

    // Print results
    std::cout << "\n========================================\n";
    if (result.found) {
        std::cout << "[+] PASSWORD FOUND: " << result.password << "\n";
        std::cout << "    Attempts: " << result.attempts << "\n";
        std::cout << "    Time: " << std::fixed << std::setprecision(2) << result.timeElapsed << "s\n";
    } else {
        std::cout << "[-] Password not found\n";
        std::cout << "    Attempts: " << result.attempts << "\n";
        std::cout << "    Time: " << std::fixed << std::setprecision(2) << result.timeElapsed << "s\n";
    }
    std::cout << "========================================\n";

    return result.found ? 0 : 1;
}
