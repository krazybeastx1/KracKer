# KracKer v2.0.0

A cross-platform hash cracker written in C++20. CPU-only, multi-threaded, with
session resume, hashcat-style masks and rules, and support for slow hashes
(bcrypt, scrypt) plus Kerberoast RC4-HMAC.

> **Status:** this is a working CPU cracker, not a GPU/distributed one. Every
> feature listed as *implemented* below is covered by the unit tests and was
> exercised through the CLI. Everything else is called out explicitly in
> [Limitations](#limitations) so you do not go looking for it.

---

## What works

| Area | Status |
|------|--------|
| Fast hashes (MD5, SHA-1, SHA-2 family, NTLM) | ✅ implemented |
| bcrypt (`$2a$` / `$2b$` / `$2y$`) | ✅ implemented (libxcrypt) |
| scrypt (`$s0$…`) | ✅ implemented (OpenSSL `EVP_PBE_scrypt`) |
| Kerberoast RC4-HMAC (etype 23) | ✅ implemented |
| Dictionary, brute-force, mask, hybrid, PRINCE, association attacks | ✅ implemented |
| Chained hashcat-style rules (`-r`) | ✅ implemented (subset, see below) |
| Session save/resume | ✅ implemented |
| Progress display, ETA, SIGINT/SIGTERM handling | ✅ implemented |
| Argon2i/d/i | ⚠️ only if built against `libargon2` (not bundled) |
| Kerberoast AES128/AES256/DES3 | ⚠️ recognised/parsed, verification not implemented |
| OpenCL / CUDA backends | ⚠️ experimental, off by default, **not part of a verified build** |
| Distributed master/worker | ❌ not implemented (CLI exits with an error) |

---

## Supported algorithms

All types below are printed by `KracKer --list-hashes`.

### Fast hashes

| Algorithm | hashcat mode | Notes |
|-----------|--------------|-------|
| MD5 | 0 | OpenSSL |
| SHA-1 | 100 | OpenSSL |
| SHA-224 | 110 | OpenSSL |
| SHA-256 | 1400 | OpenSSL |
| SHA-384 | 10800 | OpenSSL |
| SHA-512 | 1700 | OpenSSL |
| NTLM | 1000 | MD4 over UTF-16LE |

### Slow hashes / KDFs

| Algorithm | hashcat mode | Format |
|-----------|--------------|--------|
| bcrypt | 3200 | `$2b$12$<salt><hash>` (cost 4–31) |
| scrypt | 8900 | `$s0$N$r$p$<salt>$<hash>` |
| Argon2i / Argon2d / Argon2id | 16700 / 16800 / 16900 | `$argon2id$v=19$m=…,t=…,p=…$salt$hash` — *only when built with libargon2* |

### Kerberoasting

| Algorithm | hashcat mode | etype | Verification |
|-----------|--------------|-------|--------------|
| RC4-HMAC (`Kerberoast-RC4-HMAC`) | 13100 | 23 | ✅ |
| AES128-CTS-HMAC (`Kerberoast-AES128`) | 19600 | 17 | ❌ parsed only |
| AES256-CTS-HMAC (`Kerberoast-AES256`) | 19700 | 18 | ❌ parsed only |
| DES3-CBC-SHA1 (`Kerberoast-DES3`) | 13100 | 16 | ❌ parsed only |

Accepted Kerberos input formats:

```
$krb5tgs$23$*user$realm$spn*$<checksum>$<edata>     # hashcat format
$krb5tgs$23$<edata>                                  # hashcat, no salt block
<base64>                                             # native KracKer format
```

The last form requires `--kerb-realm`, `--kerb-sname`, and `--kerb-checksum`
(the latter as base64). For AES/DES3 types the cracker exits with an explicit
"verification is not implemented in this build" error rather than silently
reporting "not found".

---

## Attack modes

| Mode | Flag | Description |
|------|------|-------------|
| Dictionary | `-a dict` (default) | Wordlist, optional rules |
| Brute force | `-a brute` | Charset × length range, `-c`, `-l min-max` |
| Mask | `-a mask` | hashcat mask syntax, `?1`–`?4` custom charsets |
| Hybrid | `-a hybrid` | Wordlist + mask on the left/right |
| PRINCE | `-a prince` | Word combinations up to `--prince-max-words` |
| Association | `-a assoc` | Keyword mutations (case, leet, suffixes, combinations) |

All modes run on a shared indexed worker pool, honour `-T/--threads`, report
progress, and can be interrupted cleanly with Ctrl+C.

### Mask syntax

| Token | Charset |
|-------|---------|
| `?l` | `abcdefghijklmnopqrstuvwxyz` |
| `?u` | `ABCDEFGHIJKLMNOPQRSTUVWXYZ` |
| `?d` | `0123456789` |
| `?s` | ` !"#$%&'()*+,-./:;<=>?@[\]^_\`{|}~` |
| `?a` | `?l?u?d?s` |
| `?b` | `0x00`–`0xFF` |
| `?1`–`?4` | `--custom-charset1…4` |
| `??` | literal `?` |

### Rules

`-r rules.txt` loads a hashcat-format rules file. Each non-empty, non-`#` line
is a rule chain applied to every candidate. Supported operators:

| Operator | Meaning |
|----------|---------|
| `l` / `u` | lowercase / uppercase everything |
| `c` / `C` | capitalise / invert capitalisation |
| `t` | toggle case |
| `r` | reverse |
| `d` | duplicate the word |
| `T<n>` | toggle case of character *n* |
| `$<c>` | append character *c* |
| `^<c>` | prepend character *c* |

An unknown operator ends that rule chain (the candidate is not silently
mis-transformed). This is a practical subset — full hashcat rule compatibility
is not claimed.

---

## Build

### Dependencies

Required:

- CMake ≥ 3.20 and a C++20 compiler (GCC 11+, Clang 14+, MSVC 19.30+)
- OpenSSL 3 development headers (`libssl-dev`)
- nlohmann/json (`nlohmann-json3-dev`) — downloaded automatically if absent
- libxcrypt runtime (`libcrypt.so.1`) for bcrypt

Optional:

- `libargon2-dev` — enables Argon2 hashes
- `libgtest-dev` — enables the unit tests
- OpenCL / CUDA toolkits — experimental GPU backends only

```bash
# Debian / Ubuntu / Kali
sudo apt update && sudo apt install -y \
    cmake g++ libssl-dev nlohmann-json3-dev libgtest-dev

# Arch
sudo pacman -S --needed base-devel cmake openssl nlohmann-json gtest

# Fedora
sudo dnf install gcc-c++ cmake openssl-devel nlohmann-json-devel gtest-devel
```

### Build with CMake

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure   # optional
./build/bin/KracKer --list-hashes
```

### Build with make

```bash
make            # configure + build
make test       # build + run tests
sudo make install PREFIX=/usr/local
make distclean
```

### Installer

```bash
./install.sh                        # build + install to /usr/local
./install.sh --prefix ~/.local      # custom prefix
./install.sh --no-install           # build only
./install.sh --clean --run-tests    # clean rebuild + tests
```

### CMake options

| Option | Default | Meaning |
|--------|---------|---------|
| `BUILD_TESTS` | `ON` | Build unit tests; skipped automatically if GTest is missing |
| `WITH_ARGON2` | `ON` | Enable Argon2 if `libargon2` is found |
| `WITH_BCRYPT` | `ON` | bcrypt via libxcrypt |
| `WITH_OPENCL` | `OFF` | Experimental OpenCL backend |
| `WITH_CUDA` | `OFF` | Experimental CUDA backend |
| `WITH_DISTRIBUTED` | `OFF` | Reserved for the unimplemented master/worker mode |
| `WITH_TLS` | `OFF` | TLS for the distributed mode (unused) |

---

## Quick start

```bash
# Dictionary attack (MD5 of "password")
KracKer -t md5 -h 5f4dcc3b5aa765d61d8327deb882cf99 -w /usr/share/wordlists/rockyou.txt

# -w is optional: dictionary/hybrid/PRINCE/association modes fall back to
# /usr/share/wordlists/rockyou.txt when it exists
KracKer -t md5 -h 5f4dcc3b5aa765d61d8327deb882cf99

# Specify the type explicitly
KracKer -h 8846f7eaee8fb117ad06bdd830b7586c -t ntlm -w rockyou.txt

# Auto-detect and only print the type
KracKer --identify -h 5f4dcc3b5aa765d61d8327deb882cf99

# Rules
KracKer -h <hash> -w rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Brute force, 1–6 lowercase characters
KracKer -h <hash> -a brute -l 1-6 -c abcdefghijklmnopqrstuvwxyz

# Mask: Upper + 5 lower + 2 digits
KracKer -h <hash> -a mask -m '?u?l?l?l?l?l?d?d'

# Hybrid: wordlist + 2 digits, e.g. "admin42"
KracKer -h <hash> -a hybrid -w names.txt --hybrid-right '?d?d'

# Write results to a file
KracKer -h <hash> -w rockyou.txt -o cracked.txt --format hash:pass

# Session resume
KracKer -h <hash> -w rockyou.txt -s session.json   # Ctrl+C to stop
KracKer -h <hash> -w rockyou.txt -s session.json   # resumes where it stopped
```

### Hash examples

Every sample below was cracked with this build. The plaintext is `password`
(except the Kerberoast vector, whose plaintext is `hashcat`).

```bash
printf 'password\n' > pw.txt
KracKer -t <type> -h '<hash>' -w pw.txt
```

| Type | Example hash | `-t` |
|------|--------------|------|
| MD5 | `5f4dcc3b5aa765d61d8327deb882cf99` | `md5` |
| SHA-1 | `5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8` | `sha1` |
| SHA-224 | `d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01` | `sha224` |
| SHA-256 | `5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8` | `sha256` |
| SHA-384 | `a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7` | `sha384` |
| SHA-512 | `b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86` | `sha512` |
| NTLM | `8846f7eaee8fb117ad06bdd830b7586c` | `ntlm` |
| bcrypt (cost 6) | `$2b$06$VSQMWJzELBJ8CN2WZAWyPu6R3cwb1dgcgNviLK4qIQdZeiPauDkp6` | `bcrypt` (auto-detected) |
| scrypt (N=16384, r=8, p=1) | `$s0$16384$8$1$MDEyMzQ1Njc4OWFiY2RlZg$ApdFWK8NumyY29Er9pEt++7OZiECvcqPQXeIayRc7Ck` | `scrypt` (auto-detected) |
| Kerberoast RC4-HMAC | `$krb5tgs$23$*user$realm$test/spn*$b548e10f5694ae018d7ad63c257af7dc$35e8e456…cf24d9a` | `kerberoast-rc4` (auto-detected) |

Full Kerberoast vector (hashcat's reference TGS-REP, plaintext `hashcat`):

```
$krb5tgs$23$*user$realm$test/spn*$b548e10f5694ae018d7ad63c257af7dc$35e8e45658860bc31a859b41a08989265f4ef8afd75652ab4d7a30ef151bf6350d879ae189a8cb769e01fa573c6315232b37e4bcad9105520640a781e5fd85c09615e78267e494f433f067cc6958200a82f70627ce0eebc2ac445729c2a8a0255dc3ede2c4973d2d93ac8c1a56b26444df300cb93045d05ff2326affaa3ae97f5cd866c14b78a459f0933a550e0b6507bf8af27c2391ef69fbdd649dd059a4b9ae2440edd96c82479645ccdb06bae0eead3b7f639178a90cf24d9a
```

```bash
printf 'hashcat\n' > pw.txt
KracKer -h '$krb5tgs$23$*user$realm$test/spn*$b548e10f…$35e8e456…' -w pw.txt
```

> 32-hex hashes are ambiguous between MD5 and NTLM, so pass `-t md5` or
> `-t ntlm`. bcrypt, scrypt and `$krb5tgs$` hashes are auto-detected.

### bcrypt and scrypt

```bash
KracKer -h '$2b$06$VSQMWJzELBJ8CN2WZAWyPu6R3cwb1dgcgNviLK4qIQdZeiPauDkp6' \
        -t bcrypt -w rockyou.txt

KracKer -h '$s0$16384$8$1$<salt>$<hash>' -t scrypt -w rockyou.txt
```

Cost/parameters come from the hash itself; `--bcrypt-cost`, `--scrypt-N`,
`--scrypt-r`, `--scrypt-p`, `--argon2-*` only affect hashing/formatting, not
verification.

### Kerberoasting

```bash
KracKer -h '$krb5tgs$23$*svc$EXAMPLE.COM$HTTP/server.example.com*$...' \
        -w rockyou.txt
```

The hashcat `$krb5tgs$23$…` format is auto-detected; `-t kerberoast-rc4` forces
the type. AES128/AES256/DES3 hashes parse correctly but then report that
verification is not implemented.

---

## Command line reference

```
Hash Options:
  -h, --hash <hash>           Target hash to crack
  -t, --type <type>           Hash type (md5, sha1, sha224, sha256, sha384,
                              sha512, ntlm, bcrypt, scrypt, argon2i, argon2d,
                              argon2id, kerberoast-rc4, kerberoast-aes128,
                              kerberoast-aes256, kerberoast-des3)
  --identify                  Identify possible hash types and exit
  --list-hashes               List all registered hash types

Attack Modes:
  -a, --attack <mode>         dict, brute, mask, hybrid, prince, assoc
  -w, --wordlist <file>       Wordlist for dict/hybrid/prince/assoc
                              (default: /usr/share/wordlists/rockyou.txt
                              when it exists)
  -r, --rules <file>          Rules file for dictionary attack
  -m, --mask <pattern>        Mask pattern for mask attack
  --custom-charset1..4        Custom charsets ?1–?4
  -l, --length <min-max>      Password length range (default: 1-8)
  -c, --charset <chars>       Charset for brute force
  --hybrid-left/right <mask>  Hybrid masks
  --prince-min-words <n>      PRINCE minimum words (default: 1)
  --prince-max-words <n>      PRINCE maximum words (default: 4)
  --prince-max-len <n>        PRINCE maximum length (default: 16)

Slow Hash Parameters:
  --bcrypt-cost <n>           Bcrypt cost (default: 12)
  --scrypt-N/-r/-p <n>        scrypt parameters
  --argon2-time/-memory/-threads <n>

Kerberoasting Parameters:
  --kerb-realm <str>          Kerberos realm
  --kerb-sname <str>          Service name (SPN)
  --kerb-salt <base64>        Salt
  --kerb-checksum <base64>    Checksum

Execution Options:
  -T, --threads <n>           Worker threads (default: auto)
  -b, --batch-size <n>        Batch size (default: 100000)
  --keyspace-limit <n>        Max candidates generated by PRINCE
                              (default: 1000000)
  -d, --device <ids>          Accepted for compatibility; no GPU backend in
                              the default build

Session Options:
  -s, --session <file>        Session file for save/resume
  --no-session                Disable session saving
  --autosave-interval <sec>   Autosave interval (default: 30)

Output Options:
  -o, --output <file>         Write cracked passwords to a file
  --format <fmt>              hash:pass (default), pass, hashcat
  -q, --quiet                 Suppress the progress line
```

### Session file

Sessions are JSON and record the *completed* position, so a resumed run may
re-test a few candidates but never skips any:

```json
{
  "version": 2,
  "target_hash": "5f4dcc3b5aa765d61d8327deb882cf99",
  "hash_type": 0,
  "attack_mode": "dictionary",
  "wordlist_path": "/usr/share/wordlists/rockyou.txt",
  "wordlist_position": 1234567,
  "bruteforce_position": 0,
  "mask_position": 0
}
```

---

## Limitations

These are deliberate, documented gaps — not silent failures:

- **No GPU acceleration in a normal build.** OpenCL/CUDA targets exist but are
  experimental, off by default, and not verified. `-d` is accepted and ignored.
- **No distributed cracking.** `--master` / `--worker` exit immediately with
  `Error: Distributed mode is not available in this build`.
- **Argon2 requires `libargon2`.** Without it the Argon2 types are not
  registered at all (they will not appear in `--list-hashes`).
- **Kerberoast AES128/AES256/DES3 verification is not implemented.** Parsing and
  type detection work; cracking returns an explicit error.
- **Rules are a subset** of hashcat's rule language (operators listed above).
- **No GPU benchmark claims.** Throughput depends entirely on your CPU, chosen
  hash, and thread count.

---

## Architecture

```
KracKer-v2/
├── include/KracKer/          # Public headers (interfaces, hashes, mask, rules)
├── src/
│   ├── cli/main.cpp          # Argument parsing + progress reporting
│   ├── core/                 # Registry, cracker engine, wordlist, mask, rules
│   ├── hashes/cpu/           # MD5, SHA-1/2, NTLM, bcrypt, scrypt, Argon2, Kerberoast
│   ├── hashes/gpu/           # Experimental OpenCL/CUDA sources (not built by default)
│   ├── session/              # JSON session save/resume
│   └── attacks/, distributed/ # Reserved; not compiled
├── tests/                    # GoogleTest suite (22 tests)
├── cmake/KracKerConfig.cmake.in
├── CMakeLists.txt
├── Makefile
└── install.sh
```

Algorithms implement `IHashAlgorithm` and are registered in
`src/core/hash_registry.cpp`:

```cpp
HashRegistry::instance().register_algorithm(std::make_unique<MyHash>());
```

### Tests

`ctest --test-dir build --output-on-failure` runs the GoogleTest suite covering
every implemented algorithm (including a known-good Kerberoast RC4 vector),
rule chaining, mask iteration, session persistence, and hash identification.

---

## Contributing

1. Add the algorithm under `src/hashes/cpu/` (and, if applicable, `gpu/`).
2. Register it in `src/core/hash_registry.cpp`.
3. Add tests to `tests/test_hashes.cpp` — include a real reference vector.
4. Keep comparisons constant-time (`constant_time_compare`).
5. Run `make test` before opening a PR.

---

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE).

Use only for CTF, education, and authorized security testing.

## Acknowledgments

- **hashcat** — hash formats, mask syntax and rule conventions
- **John the Ripper** — attack-mode inspiration
- **OpenSSL** and **libxcrypt** — cryptographic primitives
- **Rubeus / impacket** — Kerberoasting extraction workflows
- **Original KracKer** — by krazybeastx1
