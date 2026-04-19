# KracKer

CTF password cracker written in C++. Fast, multi-threaded, supports MD5/SHA1/SHA256/SHA512.

## Features

- **Hash types**: MD5, SHA1, SHA256, SHA512 (auto-detect)
- **Attack modes**: Dictionary, Brute Force, Hybrid
- **Multi-threaded**: Configurable thread count
- **Case permutations**: Try upper/lower/capitalized variants
- **Rule-based mangling**: Reverse, double, leet speak
- **Progress display**: Real-time attempt counter

## Build

```bash
cd KracKer
mkdir build && cd build
cmake ..
make
```

### Dependencies

- CMake 3.10+
- OpenSSL
- C++17 compiler

**Install deps (macOS):**
```bash
brew install cmake openssl
```

**Install deps (Ubuntu/Debian):**
```bash
sudo apt install cmake libssl-dev g++
```

## Usage

```bash
./KracKer [options]
```

### Options

| Option | Description |
|--------|-------------|
| `-h, --hash <hash>` | Target hash to crack |
| `-t, --type <type>` | Hash type: md5, sha1, sha256, sha512 (auto-detect if omitted) |
| `-w, --wordlist <file>` | Wordlist file for dictionary attack (default: `/usr/share/wordlists/rockyou.txt`) |
| `-b, --brute` | Use brute force attack |
| `-c, --charset <chars>` | Charset for brute force (default: a-z0-9) |
| `-l, --length <min-max>` | Password length range for brute (default: 1-8) |
| `-T, --threads <num>` | Number of threads (default: auto) |
| `--case-perm` | Try case permutations |
| `--help` | Show help |

### Examples

**Dictionary attack (MD5):**
```bash
./KracKer -h 5f4dcc3b5aa765d61d8327deb882cf99 -w rockyou.txt
```

**Brute force (short passwords):**
```bash
./KracKer -h 5f4dcc3b5aa765d61d8327deb882cf99 -b -l 1-5
```

**Brute force with custom charset:**
```bash
./KracKer -h 5f4dcc3b5aa765d61d8327deb882cf99 -b -l 1-6 -c abcdefgh
```

**With case permutations:**
```bash
./KracKer -h 5f4dcc3b5aa765d61d8327deb882cf99 -w wordlist.txt --case-perm
```

**SHA256 crack:**
```bash
./KracKer -h 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 -w rockyou.txt
```

**Auto-detect hash type:**
```bash
./KracKer -h 5f4dcc3b5aa765d61d8327deb882cf99 -w rockyou.txt
# Auto-detects as MD5 (32 chars)
```

## Attack Modes

### Dictionary Attack
Uses wordlist file. Fast, effective against weak passwords.

```bash
./KracKer -h <hash> -w rockyou.txt
```

### Brute Force
Tries all combinations. Slow but guaranteed given enough time.

```bash
./KracKer -h <hash> -b -l 1-8 -c abcdefghijklmnopqrstuvwxyz0123456789
```

### Hybrid Attack
Dictionary + number/special char suffixes. Good for `password123` style.

```bash
# Automatically tries: word, word1, word2, ... word99, word!, word@, etc.
./KracKer -h <hash> -w wordlist.txt
```

## Wordlists

Recommended wordlists:

| Wordlist | Size | Description |
|----------|------|-------------|
| [rockyou.txt](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt) | ~14MB | Classic, most common passwords |
| [SecLists](https://github.com/danielmiessler/SecLists) | Various | Curated password lists |
| [crackstation-human](https://crackstation.net/crackstation-wordlist-password-dictionary.html) | ~150MB | Human-readable passwords |

## Hash Type Reference

| Hash Type | Length | Example |
|-----------|--------|---------|
| MD5 | 32 | `5f4dcc3b5aa765d61d8327deb882cf99` |
| SHA1 | 40 | `7c4a8d09ca3762af61e59520943dc26494f8941b` |
| SHA256 | 64 | `5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8` |
| SHA512 | 128 | `b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86` |

## CTF Tips

1. **Identify hash type first**: Use hash length or try `--identify` mode
2. **Start with rockyou**: Catches 60%+ of CTF passwords
3. **Try case permutations**: `Password` vs `password`
4. **Check for leet speak**: `p4ssw0rd` vs `password`
5. **Combine with other tools**: Use Hashcat for GPU acceleration

## Project Structure

```
KracKer/
├── CMakeLists.txt      # Build config
├── README.md           # This file
├── include/
│   ├── hash.h          # Hash function declarations
│   └── cracker.h       # Cracker class declaration
└── src/
    ├── hash.cpp        # Hash implementations (MD5, SHA*)
    ├── cracker.cpp     # Cracking logic
    └── main.cpp        # CLI entry point
```

## Limitations

- No bcrypt/scrypt/Argon2 support (slow by design)
- No GPU acceleration
- No session resume
- No distributed cracking

## License

MIT - Use for CTF, education, authorized pentesting only.

## Contributing

PRs welcome. Areas to add:
- [ ] bcrypt support
- [ ] Progress bar / ETA
- [ ] Mask attacks (?a?l?l?l?l?l?l)
- [ ] Custom rule language
- [ ] Session save/resume
