#include <gtest/gtest.h>
#include "KracKer/hash_interface.hpp"
#include "KracKer/hash_registry.hpp"
#include "KracKer/hash_fast.hpp"
#include "KracKer/hash_ntlm.hpp"
#include "KracKer/utils.hpp"
#include "KracKer/wordlist.hpp"
#include "KracKer/mask.hpp"
#include "KracKer/rules.hpp"

using namespace KracKer;

TEST(HashRegistry, RegisterAndRetrieve) {
    auto& registry = HashRegistry::instance();
    
    // Test that all standard algorithms are registered
    EXPECT_NE(registry.get_algorithm(HashType::MD5), nullptr);
    EXPECT_NE(registry.get_algorithm(HashType::SHA1), nullptr);
    EXPECT_NE(registry.get_algorithm(HashType::SHA256), nullptr);
    EXPECT_NE(registry.get_algorithm(HashType::SHA512), nullptr);
    EXPECT_NE(registry.get_algorithm(HashType::NTLM), nullptr);
    EXPECT_NE(registry.get_algorithm(HashType::BCRYPT), nullptr);
    EXPECT_NE(registry.get_algorithm(HashType::SCRYPT), nullptr);
#ifdef KK_HAVE_ARGON2
    EXPECT_NE(registry.get_algorithm(HashType::ARGON2I), nullptr);
    EXPECT_NE(registry.get_algorithm(HashType::ARGON2D), nullptr);
    EXPECT_NE(registry.get_algorithm(HashType::ARGON2ID), nullptr);
#else
    // Argon2 is only registered when the library is available at build time.
    EXPECT_EQ(registry.get_algorithm(HashType::ARGON2ID), nullptr);
#endif
    EXPECT_NE(registry.get_algorithm(HashType::KERBEROAST_RC4_HMAC), nullptr);
    EXPECT_NE(registry.get_algorithm(HashType::KERBEROAST_AES128_CTS_HMAC), nullptr);
    EXPECT_NE(registry.get_algorithm(HashType::KERBEROAST_AES256_CTS_HMAC), nullptr);
}

TEST(HashRegistry, IdentifyHash) {
    auto& registry = HashRegistry::instance();
    
    // MD5
    auto md5_matches = registry.identify_hash("5f4dcc3b5aa765d61d8327deb882cf99");
    EXPECT_TRUE(std::find(md5_matches.begin(), md5_matches.end(), HashType::MD5) != md5_matches.end());
    EXPECT_TRUE(std::find(md5_matches.begin(), md5_matches.end(), HashType::NTLM) != md5_matches.end());
    
    // SHA1
    auto sha1_matches = registry.identify_hash("7c4a8d09ca3762af61e59520943dc26494f8941b");
    EXPECT_TRUE(std::find(sha1_matches.begin(), sha1_matches.end(), HashType::SHA1) != sha1_matches.end());
    
    // SHA256
    auto sha256_matches = registry.identify_hash("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8");
    EXPECT_TRUE(std::find(sha256_matches.begin(), sha256_matches.end(), HashType::SHA256) != sha256_matches.end());
    
    // bcrypt
    auto bcrypt_matches = registry.identify_hash("$2b$12$KIX/3ZQYqXJ9K5J5J5J5JOK5J5J5J5J5J5J5J5J5J5J5J5J5J5J5O");
    EXPECT_TRUE(std::find(bcrypt_matches.begin(), bcrypt_matches.end(), HashType::BCRYPT) != bcrypt_matches.end());
    
    // Kerberoast
    auto kerb_matches = registry.identify_hash("$krb5tgs$23$EXAMPLE.COM$HTTP/server$base64salt$base64checksum");
    EXPECT_TRUE(std::find(kerb_matches.begin(), kerb_matches.end(), HashType::KERBEROAST_RC4_HMAC) != kerb_matches.end());
}

TEST(MD5Hash, BasicHash) {
    auto& registry = HashRegistry::instance();
    auto* algo = registry.get_algorithm(HashType::MD5);
    ASSERT_NE(algo, nullptr);
    
    HashParams params;
    HashResult result = algo->hash("password", params);
    
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.digest.size(), 16);
    
    // Known MD5 of "password"
    std::string expected = "5f4dcc3b5aa765d61d8327deb882cf99";
    std::string actual = algo->format_hash(result, params);
    EXPECT_EQ(actual, expected);
}

TEST(MD5Hash, Verify) {
    auto& registry = HashRegistry::instance();
    auto* algo = registry.get_algorithm(HashType::MD5);
    ASSERT_NE(algo, nullptr);
    
    HashParams params;
    EXPECT_TRUE(algo->verify("5f4dcc3b5aa765d61d8327deb882cf99", "password", params));
    EXPECT_FALSE(algo->verify("5f4dcc3b5aa765d61d8327deb882cf99", "wrong", params));
}

TEST(SHA1Hash, BasicHash) {
    auto& registry = HashRegistry::instance();
    auto* algo = registry.get_algorithm(HashType::SHA1);
    ASSERT_NE(algo, nullptr);
    
    HashParams params;
    HashResult result = algo->hash("password", params);
    
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.digest.size(), 20);
    
    std::string expected = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8";
    std::string actual = algo->format_hash(result, params);
    EXPECT_EQ(actual, expected);
}

TEST(SHA256Hash, BasicHash) {
    auto& registry = HashRegistry::instance();
    auto* algo = registry.get_algorithm(HashType::SHA256);
    ASSERT_NE(algo, nullptr);
    
    HashParams params;
    HashResult result = algo->hash("password", params);
    
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.digest.size(), 32);
    
    std::string expected = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";
    std::string actual = algo->format_hash(result, params);
    EXPECT_EQ(actual, expected);
}

TEST(NTLMHash, BasicHash) {
    auto& registry = HashRegistry::instance();
    auto* algo = registry.get_algorithm(HashType::NTLM);
    ASSERT_NE(algo, nullptr);
    
    HashParams params;
    HashResult result = algo->hash("password", params);
    
    EXPECT_TRUE(result.success);
    EXPECT_EQ(result.digest.size(), 16);
    
    // NTLM of "password"
    std::string expected = "8846f7eaee8fb117ad06bdd830b7586c";
    std::string actual = algo->format_hash(result, params);
    EXPECT_EQ(actual, expected);
}

TEST(Utils, HexEncodeDecode) {
    std::vector<uint8_t> data = {0xde, 0xad, 0xbe, 0xef, 0x00, 0xff};
    std::string encoded = hex_encode(data);
    EXPECT_EQ(encoded, "deadbeef00ff");
    
    std::vector<uint8_t> decoded = hex_decode(encoded);
    EXPECT_EQ(decoded, data);
}

TEST(Utils, ConstantTimeCompare) {
    std::string a = "5f4dcc3b5aa765d61d8327deb882cf99";
    std::string b = "5f4dcc3b5aa765d61d8327deb882cf99";
    std::string c = "5f4dcc3b5aa765d61d8327deb882cf98";
    
    EXPECT_TRUE(constant_time_compare(a, b));
    EXPECT_FALSE(constant_time_compare(a, c));
    EXPECT_FALSE(constant_time_compare(a, "short"));
}

TEST(Utils, Trim) {
    EXPECT_EQ(trim("  hello  "), "hello");
    EXPECT_EQ(trim("\t\nhello\r\n"), "hello");
    EXPECT_EQ(trim(""), "");
    EXPECT_EQ(trim("   "), "");
}

TEST(Utils, Split) {
    auto parts = split("a,b,c,d", ',');
    EXPECT_EQ(parts.size(), 4);
    EXPECT_EQ(parts[0], "a");
    EXPECT_EQ(parts[1], "b");
    EXPECT_EQ(parts[2], "c");
    EXPECT_EQ(parts[3], "d");
    
    parts = split("a", ',');
    EXPECT_EQ(parts.size(), 1);
    EXPECT_EQ(parts[0], "a");
}

TEST(Utils, IsHex) {
    EXPECT_TRUE(is_hex("5f4dcc3b5aa765d61d8327deb882cf99"));
    EXPECT_TRUE(is_hex("ABCDEFabcdef0123456789"));
    EXPECT_FALSE(is_hex("5f4dcc3b5aa765d61d8327deb882cf9g"));
    EXPECT_FALSE(is_hex(""));
    EXPECT_FALSE(is_hex("xyz"));
}

TEST(MaskProcessor, ParseMask) {
    std::array<std::string, 4> custom = {"", "", "", ""};
    
    // Simple mask
    auto info = MaskProcessor::parse_mask("?l?l?l?l", custom);
    EXPECT_EQ(info.position_charsets.size(), 4);
    EXPECT_EQ(info.keyspace, 26*26*26*26);
    
    // Mixed mask
    info = MaskProcessor::parse_mask("?u?l?l?d?d", custom);
    EXPECT_EQ(info.position_charsets.size(), 5);
    EXPECT_EQ(info.keyspace, 26*26*26*10*10);
    
    // Custom charset
    custom[0] = "abc";
    info = MaskProcessor::parse_mask("?1?1?1", custom);
    EXPECT_EQ(info.keyspace, 3*3*3);
}

TEST(MaskProcessor, IndexConversion) {
    std::array<std::string, 4> custom = {"", "", "", ""};
    auto info = MaskProcessor::parse_mask("?l?l?l", custom);
    
    // Test round-trip
    for (uint64_t i = 0; i < 100; i++) {
        std::string candidate = MaskProcessor::index_to_candidate(i, info);
        uint64_t back = MaskProcessor::candidate_to_index(candidate, info);
        EXPECT_EQ(back, i) << "Failed at index " << i << ": " << candidate;
    }
}

TEST(MaskIterator, Iteration) {
    std::array<std::string, 4> custom = {"", "", "", ""};
    auto info = MaskProcessor::parse_mask("?l?l", custom);
    
    MaskIterator iter(info);
    std::string candidate;
    uint64_t count = 0;
    
    while (iter.next(candidate)) {
        EXPECT_EQ(candidate.size(), 2);
        count++;
    }
    
    EXPECT_EQ(count, 26*26);
    EXPECT_EQ(iter.position(), 26*26);
}

TEST(RuleEngine, BuiltinRules) {
    auto& engine = RuleEngine::instance();
    
    std::string word = "Password";
    
    auto results = engine.apply_all(word);
    EXPECT_GT(results.size(), 1);
    
    // Check specific rules
    auto lower_results = engine.apply(word, {"lower"});
    EXPECT_TRUE(std::find(lower_results.begin(), lower_results.end(), "password") != lower_results.end());
    
    auto upper_results = engine.apply(word, {"upper"});
    EXPECT_TRUE(std::find(upper_results.begin(), upper_results.end(), "PASSWORD") != upper_results.end());
    
    auto reverse_results = engine.apply(word, {"reverse"});
    EXPECT_TRUE(std::find(reverse_results.begin(), reverse_results.end(), "drowssaP") != reverse_results.end());
    
    // Full 1337 substitution: a->4, e->3, i->1, o->0, s->5, t->7
    auto leet_results = engine.apply(word, {"leet"});
    EXPECT_TRUE(std::find(leet_results.begin(), leet_results.end(), "P455w0rd") != leet_results.end());
}

TEST(WordlistLoader, LoadAndCount) {
    // Create temp file
    std::string temp_file = "/tmp/test_wordlist.txt";
    {
        std::ofstream f(temp_file);
        f << "password\n";
        f << "123456\n";
        f << "qwerty\n";
        f << "\n";  // empty line
        f << "  spaced  \n";
    }
    
    std::vector<std::string> words;
    EXPECT_TRUE(WordlistLoader::load(temp_file, words));
    EXPECT_EQ(words.size(), 4);
    EXPECT_EQ(words[0], "password");
    EXPECT_EQ(words[3], "spaced");
    
    size_t count = WordlistLoader::count_lines(temp_file);
    EXPECT_EQ(count, 4);
    
    std::remove(temp_file.c_str());
}

TEST(WordlistGenerator, PRINCE) {
    std::vector<std::string> wordlist = {"pass", "word", "123", "test"};
    
    auto candidates = WordlistGenerator::generate_prince(wordlist, 1, 2, 16, 100);
    
    EXPECT_GT(candidates.size(), 0);
    EXPECT_LE(candidates.size(), 100);
    
    // Should contain single words
    EXPECT_TRUE(std::find(candidates.begin(), candidates.end(), "pass") != candidates.end());
    EXPECT_TRUE(std::find(candidates.begin(), candidates.end(), "word") != candidates.end());
    
    // Should contain combinations
    EXPECT_TRUE(std::find(candidates.begin(), candidates.end(), "password") != candidates.end());
    EXPECT_TRUE(std::find(candidates.begin(), candidates.end(), "wordpass") != candidates.end());
}

TEST(SessionManager, SaveLoad) {
    SessionManager mgr;
    CrackerConfig config;
    config.hash_type = HashType::MD5;
    config.target_hash = "5f4dcc3b5aa765d61d8327deb882cf99";
    config.attack_mode = CrackerConfig::AttackMode::Dictionary;
    config.wordlist_path = "/tmp/wordlist.txt";
    config.session_file = "/tmp/test_session.json";
    
    EXPECT_TRUE(mgr.create_session(config, config.target_hash));
    
    // Update progress
    mgr.update_progress(1000, 0, 0);
    
    // Save
    EXPECT_TRUE(mgr.save_session());
    
    // Load into new manager
    SessionManager mgr2;
    EXPECT_TRUE(mgr2.load_session("/tmp/test_session.json"));
    
    const auto& state = mgr2.get_state();
    EXPECT_EQ(state.session_id, mgr.get_state().session_id);
    EXPECT_EQ(state.target_hash, config.target_hash);
    EXPECT_EQ(state.hash_type, config.hash_type);
    EXPECT_EQ(state.wordlist_position, 1000);
    
    std::remove("/tmp/test_session.json");
}

TEST(KerberoastHash, ParseFormat) {
    auto& registry = HashRegistry::instance();
    auto* algo = registry.get_algorithm(HashType::KERBEROAST_RC4_HMAC);
    ASSERT_NE(algo, nullptr);
    
    // Valid RC4-HMAC hash
    std::string hash = "$krb5tgs$23$EXAMPLE.COM$HTTP/server$base64salt$base64checksum";
    auto params = algo->parse_hash(hash);
    EXPECT_TRUE(params.has_value());
    EXPECT_EQ(params->kerb_etype, 23);
    EXPECT_EQ(params->kerb_realm, "EXAMPLE.COM");
    EXPECT_EQ(params->kerb_sname, "HTTP/server");
    
    // Invalid hash
    params = algo->parse_hash("invalid");
    EXPECT_FALSE(params.has_value());
}

TEST(KerberoastHash, Rc4HmacKnownVector) {
    // hashcat's reference TGS-REP etype 23 vector (password: "hashcat").
    auto& registry = HashRegistry::instance();
    auto* algo = registry.get_algorithm(HashType::KERBEROAST_RC4_HMAC);
    ASSERT_NE(algo, nullptr);

    const std::string hash =
        "$krb5tgs$23$*user$realm$test/spn*$b548e10f5694ae018d7ad63c257af7dc$"
        "35e8e45658860bc31a859b41a08989265f4ef8afd75652ab4d7a30ef151bf6350d879ae189a8cb769e01fa573c6315"
        "232b37e4bcad9105520640a781e5fd85c09615e78267e494f433f067cc6958200a82f70627ce0eebc2ac445729c2a8"
        "a0255dc3ede2c4973d2d93ac8c1a56b26444df300cb93045d05ff2326affaa3ae97f5cd866c14b78a459f0933a550"
        "e0b6507bf8af27c2391ef69fbdd649dd059a4b9ae2440edd96c82479645ccdb06bae0eead3b7f639178a90cf24d9a";

    EXPECT_TRUE(algo->verify(hash, "hashcat", HashParams{}));
    EXPECT_FALSE(algo->verify(hash, "hashcaT", HashParams{}));
    EXPECT_FALSE(algo->verify(hash, "hashcat1", HashParams{}));
}

TEST(SlowHashes, Identify) {
    auto& registry = HashRegistry::instance();
    
    // bcrypt
    auto bcrypt_matches = registry.identify_hash("$2b$12$KIX/3ZQYqXJ9K5J5J5J5JOK5J5J5J5J5J5J5J5J5J5J5J5J5J5J5O");
    EXPECT_TRUE(std::find(bcrypt_matches.begin(), bcrypt_matches.end(), HashType::BCRYPT) != bcrypt_matches.end());
    
    // scrypt
    auto scrypt_matches = registry.identify_hash("$s0$16384$8$1$salt$hash");
    EXPECT_TRUE(std::find(scrypt_matches.begin(), scrypt_matches.end(), HashType::SCRYPT) != scrypt_matches.end());
    
    // Argon2 (only present when the library was available at build time)
#ifdef KK_HAVE_ARGON2
    auto argon2_matches = registry.identify_hash("$argon2id$v=19$m=4096,t=3,p=1$salt$hash");
    EXPECT_TRUE(std::find(argon2_matches.begin(), argon2_matches.end(), HashType::ARGON2ID) != argon2_matches.end());
#endif
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}