// OpenCL Kernel for SHA-256 and SHA-512
// Based on FIPS 180-4

#pragma OPENCL EXTENSION cl_khr_byte_addressable_store : enable

// SHA-256 Constants
__constant uint K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

inline uint rotr32(uint x, uchar n) {
    return (x >> n) | (x << (32 - n));
}

inline uint sha256_sigma0(uint x) { return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22); }
inline uint sha256_sigma1(uint x) { return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25); }
inline uint sha256_Sigma0(uint x) { return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3); }
inline uint sha256_Sigma1(uint x) { return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10); }
inline uint sha256_Ch(uint x, uint y, uint z) { return (x & y) ^ (~x & z); }
inline uint sha256_Maj(uint x, uint y, uint z) { return (x & y) ^ (x & z) ^ (y & z); }

// SHA-256 Kernel
__kernel void sha256_kernel(
    __global const uchar* passwords,
    __global const uint* pwd_lengths,
    __global uint* output_hashes,
    uint num_passwords,
    uint max_pwd_len
) {
    uint gid = get_global_id(0);
    if (gid >= num_passwords) return;

    uint pwd_len = pwd_lengths[gid];
    if (pwd_len > max_pwd_len) pwd_len = max_pwd_len;

    uchar pwd[128];
    for (uint i = 0; i < pwd_len; i++) {
        pwd[i] = passwords[gid * max_pwd_len + i];
    }

    // SHA-256 initialization
    uint h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    uint W[64] = {0};
    for (uint i = 0; i < pwd_len; i += 4) {
        uint val = 0;
        val |= (uint)pwd[i] << 24;
        if (i+1 < pwd_len) val |= (uint)pwd[i+1] << 16;
        if (i+2 < pwd_len) val |= (uint)pwd[i+2] << 8;
        if (i+3 < pwd_len) val |= (uint)pwd[i+3];
        W[i/4] = val;
    }

    W[pwd_len/4] |= (uint)0x80 << (24 - ((pwd_len % 4) * 8));
    W[15] = pwd_len * 8;

    for (uint t = 16; t < 64; t++) {
        W[t] = sha256_sigma1(W[t-2]) + W[t-7] + sha256_sigma0(W[t-15]) + W[t-16];
    }

    uint a = h[0], b = h[1], c = h[2], d = h[3];
    uint e = h[4], f = h[5], g = h[6], h_ = h[7];

    for (uint t = 0; t < 64; t++) {
        uint T1 = h_ + sha256_Sigma1(e) + sha256_Ch(e, f, g) + K256[t] + W[t];
        uint T2 = sha256_Sigma0(a) + sha256_Maj(a, b, c);
        h_ = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += h_;

    // Store result (8 uints = 32 bytes = 256 bits)
    for (uint i = 0; i < 8; i++) {
        output_hashes[gid * 8 + i] = h[i];
    }
}

__kernel void sha256_batch_kernel(
    __global const uchar* passwords,
    __global const uint* pwd_lengths,
    __global uint* output_hashes,
    uint num_passwords,
    uint max_pwd_len
) {
    uint gid = get_global_id(0);
    uint stride = get_global_size(0);

    for (uint idx = gid; idx < num_passwords; idx += stride) {
        uint pwd_len = pwd_lengths[idx];
        if (pwd_len > max_pwd_len) pwd_len = max_pwd_len;

        uchar pwd[128];
        for (uint i = 0; i < pwd_len; i++) {
            pwd[i] = passwords[idx * max_pwd_len + i];
        }

        uint h[8] = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };

        uint W[64] = {0};
        for (uint i = 0; i < pwd_len; i += 4) {
            uint val = 0;
            val |= (uint)pwd[i] << 24;
            if (i+1 < pwd_len) val |= (uint)pwd[i+1] << 16;
            if (i+2 < pwd_len) val |= (uint)pwd[i+2] << 8;
            if (i+3 < pwd_len) val |= (uint)pwd[i+3];
            W[i/4] = val;
        }

        W[pwd_len/4] |= (uint)0x80 << (24 - ((pwd_len % 4) * 8));
        W[15] = pwd_len * 8;

        for (uint t = 16; t < 64; t++) {
            W[t] = sha256_sigma1(W[t-2]) + W[t-7] + sha256_sigma0(W[t-15]) + W[t-16];
        }

        uint a = h[0], b = h[1], c = h[2], d = h[3];
        uint e = h[4], f = h[5], g = h[6], h_ = h[7];

        for (uint t = 0; t < 64; t++) {
            uint T1 = h_ + sha256_Sigma1(e) + sha256_Ch(e, f, g) + K256[t] + W[t];
            uint T2 = sha256_Sigma0(a) + sha256_Maj(a, b, c);
            h_ = g; g = f; f = e; e = d + T1;
            d = c; c = b; b = a; a = T1 + T2;
        }

        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += h_;

        for (uint i = 0; i < 8; i++) {
            output_hashes[idx * 8 + i] = h[i];
        }
    }
}

// SHA-512 Constants (64-bit)
__constant ulong K512[80] = {
    0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL, 0xe9b5dba58189dbbcUL,
    0x3956c25bf348b538UL, 0x59f111f1b605d019UL, 0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL,
    0xd807aa98a3030242UL, 0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
    0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL, 0xc19bf174cf692694UL,
    0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL, 0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL,
    0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da5305c353UL,
    0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL, 0xbf597fc7beef0ee4UL,
    0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL, 0x06ca6351e003826fUL, 0x142929670a0e6e70UL,
    0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
    0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL, 0x92722c851482353bUL,
    0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL, 0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL,
    0xd192e819d6ef5218UL, 0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
    0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL, 0x34b0bcb5e19b48a8UL,
    0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL, 0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL,
    0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
    0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL, 0xc67178f2e372532bUL,
    0xca273eceea26619cUL, 0xd186b8c721c0c207UL, 0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL,
    0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
    0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL, 0x431d67c49c100d4cUL,
    0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL, 0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL
};

inline ulong rotr64(ulong x, uchar n) {
    return (x >> n) | (x << (64 - n));
}

inline ulong sha512_sigma0(ulong x) { return rotr64(x, 1) ^ rotr64(x, 8) ^ (x >> 7); }
inline ulong sha512_sigma1(ulong x) { return rotr64(x, 19) ^ rotr64(x, 61) ^ (x >> 6); }
inline ulong sha512_Sigma0(ulong x) { return rotr64(x, 28) ^ rotr64(x, 34) ^ rotr64(x, 39); }
inline ulong sha512_Sigma1(ulong x) { return rotr64(x, 14) ^ rotr64(x, 18) ^ rotr64(x, 41); }
inline ulong sha512_Ch(ulong x, ulong y, ulong z) { return (x & y) ^ (~x & z); }
inline ulong sha512_Maj(ulong x, ulong y, ulong z) { return (x & y) ^ (x & z) ^ (y & z); }

// SHA-512 Kernel
__kernel void sha512_kernel(
    __global const uchar* passwords,
    __global const uint* pwd_lengths,
    __global ulong* output_hashes,
    uint num_passwords,
    uint max_pwd_len
) {
    uint gid = get_global_id(0);
    if (gid >= num_passwords) return;

    uint pwd_len = pwd_lengths[gid];
    if (pwd_len > max_pwd_len) pwd_len = max_pwd_len;

    uchar pwd[128];
    for (uint i = 0; i < pwd_len; i++) {
        pwd[i] = passwords[gid * max_pwd_len + i];
    }

    // SHA-512 initialization
    ulong h[8] = {
        0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL,
        0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
        0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL,
        0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL
    };

    ulong W[80] = {0};
    for (uint i = 0; i < pwd_len; i += 8) {
        ulong val = 0;
        val |= (ulong)pwd[i] << 56;
        if (i+1 < pwd_len) val |= (ulong)pwd[i+1] << 48;
        if (i+2 < pwd_len) val |= (ulong)pwd[i+2] << 40;
        if (i+3 < pwd_len) val |= (ulong)pwd[i+3] << 32;
        if (i+4 < pwd_len) val |= (ulong)pwd[i+4] << 24;
        if (i+5 < pwd_len) val |= (ulong)pwd[i+5] << 16;
        if (i+6 < pwd_len) val |= (ulong)pwd[i+6] << 8;
        if (i+7 < pwd_len) val |= (ulong)pwd[i+7];
        W[i/8] = val;
    }

    W[pwd_len/8] |= (ulong)0x80 << (56 - ((pwd_len % 8) * 8));
    W[15] = (ulong)pwd_len * 8;

    for (uint t = 16; t < 80; t++) {
        W[t] = sha512_sigma1(W[t-2]) + W[t-7] + sha512_sigma0(W[t-15]) + W[t-16];
    }

    ulong a = h[0], b = h[1], c = h[2], d = h[3];
    ulong e = h[4], f = h[5], g = h[6], h_ = h[7];

    for (uint t = 0; t < 80; t++) {
        ulong T1 = h_ + sha512_Sigma1(e) + sha512_Ch(e, f, g) + K512[t] + W[t];
        ulong T2 = sha512_Sigma0(a) + sha512_Maj(a, b, c);
        h_ = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += h_;

    // Store result (8 ulongs = 64 bytes = 512 bits)
    for (uint i = 0; i < 8; i++) {
        output_hashes[gid * 8 + i] = h[i];
    }
}

__kernel void sha512_batch_kernel(
    __global const uchar* passwords,
    __global const uint* pwd_lengths,
    __global ulong* output_hashes,
    uint num_passwords,
    uint max_pwd_len
) {
    uint gid = get_global_id(0);
    uint stride = get_global_size(0);

    for (uint idx = gid; idx < num_passwords; idx += stride) {
        uint pwd_len = pwd_lengths[idx];
        if (pwd_len > max_pwd_len) pwd_len = max_pwd_len;

        uchar pwd[128];
        for (uint i = 0; i < pwd_len; i++) {
            pwd[i] = passwords[idx * max_pwd_len + i];
        }

        ulong h[8] = {
            0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL,
            0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
            0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL,
            0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL
        };

        ulong W[80] = {0};
        for (uint i = 0; i < pwd_len; i += 8) {
            ulong val = 0;
            val |= (ulong)pwd[i] << 56;
            if (i+1 < pwd_len) val |= (ulong)pwd[i+1] << 48;
            if (i+2 < pwd_len) val |= (ulong)pwd[i+2] << 40;
            if (i+3 < pwd_len) val |= (ulong)pwd[i+3] << 32;
            if (i+4 < pwd_len) val |= (ulong)pwd[i+4] << 24;
            if (i+5 < pwd_len) val |= (ulong)pwd[i+5] << 16;
            if (i+6 < pwd_len) val |= (ulong)pwd[i+6] << 8;
            if (i+7 < pwd_len) val |= (ulong)pwd[i+7];
            W[i/8] = val;
        }

        W[pwd_len/8] |= (ulong)0x80 << (56 - ((pwd_len % 8) * 8));
        W[15] = (ulong)pwd_len * 8;

        for (uint t = 16; t < 80; t++) {
            W[t] = sha512_sigma1(W[t-2]) + W[t-7] + sha512_sigma0(W[t-15]) + W[t-16];
        }

        ulong a = h[0], b = h[1], c = h[2], d = h[3];
        ulong e = h[4], f = h[5], g = h[6], h_ = h[7];

        for (uint t = 0; t < 80; t++) {
            ulong T1 = h_ + sha512_Sigma1(e) + sha512_Ch(e, f, g) + K512[t] + W[t];
            ulong T2 = sha512_Sigma0(a) + sha512_Maj(a, b, c);
            h_ = g; g = f; f = e; e = d + T1;
            d = c; c = b; b = a; a = T1 + T2;
        }

        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += h_;

        for (uint i = 0; i < 8; i++) {
            output_hashes[idx * 8 + i] = h[i];
        }
    }
}