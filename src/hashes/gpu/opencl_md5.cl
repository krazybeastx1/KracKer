// OpenCL Kernel for MD5
// Based on RFC 1321

#pragma OPENCL EXTENSION cl_khr_byte_addressable_store : enable

__constant uint K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

__constant uchar S[64] = {
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
};

inline uint rotl(uint x, uchar n) {
    return (x << n) | (x >> (32 - n));
}

inline uint F(uint x, uint y, uint z) { return (x & y) | (~x & z); }
inline uint G(uint x, uint y, uint z) { return (x & z) | (y & ~z); }
inline uint H(uint x, uint y, uint z) { return x ^ y ^ z; }
inline uint I(uint x, uint y, uint z) { return y ^ (x | ~z); }

__kernel void md5_kernel(
    __global const uchar* passwords,
    __global const uint* pwd_lengths,
    __global uint* output_hashes,
    uint num_passwords,
    uint max_pwd_len
) {
    uint gid = get_global_id(0);
    if (gid >= num_passwords) return;

    // Load password
    uint pwd_len = pwd_lengths[gid];
    if (pwd_len > max_pwd_len) pwd_len = max_pwd_len;

    uchar pwd[128]; // Max password length
    for (uint i = 0; i < pwd_len; i++) {
        pwd[i] = passwords[gid * max_pwd_len + i];
    }

    // MD5 initialization
    uint a = 0x67452301;
    uint b = 0xefcdab89;
    uint c = 0x98badcfe;
    uint d = 0x10325476;

    // Prepare message schedule (single block for passwords <= 55 bytes)
    uint M[16] = {0};
    for (uint i = 0; i < pwd_len; i += 4) {
        M[i/4] |= (uint)pwd[i] << 0;
        if (i+1 < pwd_len) M[i/4] |= (uint)pwd[i+1] << 8;
        if (i+2 < pwd_len) M[i/4] |= (uint)pwd[i+2] << 16;
        if (i+3 < pwd_len) M[i/4] |= (uint)pwd[i+3] << 24;
    }

    // Padding
    M[pwd_len/4] |= (uint)0x80 << ((pwd_len % 4) * 8);
    M[14] = pwd_len * 8; // Length in bits

    uint AA = a, BB = b, CC = c, DD = d;

    // Round 1
    for (uint i = 0; i < 16; i++) {
        uint g = i;
        uint f = F(b, c, d);
        uint temp = d;
        d = c;
        c = b;
        b = b + rotl(a + f + K[i] + M[g], S[i]);
        a = temp;
    }

    // Round 2
    for (uint i = 16; i < 32; i++) {
        uint g = (5*i + 1) % 16;
        uint f = G(b, c, d);
        uint temp = d;
        d = c;
        c = b;
        b = b + rotl(a + f + K[i] + M[g], S[i]);
        a = temp;
    }

    // Round 3
    for (uint i = 32; i < 48; i++) {
        uint g = (3*i + 5) % 16;
        uint f = H(b, c, d);
        uint temp = d;
        d = c;
        c = b;
        b = b + rotl(a + f + K[i] + M[g], S[i]);
        a = temp;
    }

    // Round 4
    for (uint i = 48; i < 64; i++) {
        uint g = (7*i) % 16;
        uint f = I(b, c, d);
        uint temp = d;
        d = c;
        c = b;
        b = b + rotl(a + f + K[i] + M[g], S[i]);
        a = temp;
    }

    a += AA; b += BB; c += CC; d += DD;

    // Store result (4 uints = 16 bytes = 128 bits)
    output_hashes[gid * 4 + 0] = a;
    output_hashes[gid * 4 + 1] = b;
    output_hashes[gid * 4 + 2] = c;
    output_hashes[gid * 4 + 3] = d;
}

// Batch kernel for multiple passwords
__kernel void md5_batch_kernel(
    __global const uchar* passwords,
    __global const uint* pwd_lengths,
    __global uint* output_hashes,
    uint num_passwords,
    uint max_pwd_len
) {
    uint gid = get_global_id(0);
    uint stride = get_global_size(0);

    for (uint idx = gid; idx < num_passwords; idx += stride) {
        // Same as above but process multiple
        uint pwd_len = pwd_lengths[idx];
        if (pwd_len > max_pwd_len) pwd_len = max_pwd_len;

        uchar pwd[128];
        for (uint i = 0; i < pwd_len; i++) {
            pwd[i] = passwords[idx * max_pwd_len + i];
        }

        uint a = 0x67452301;
        uint b = 0xefcdab89;
        uint c = 0x98badcfe;
        uint d = 0x10325476;

        uint M[16] = {0};
        for (uint i = 0; i < pwd_len; i += 4) {
            M[i/4] |= (uint)pwd[i] << 0;
            if (i+1 < pwd_len) M[i/4] |= (uint)pwd[i+1] << 8;
            if (i+2 < pwd_len) M[i/4] |= (uint)pwd[i+2] << 16;
            if (i+3 < pwd_len) M[i/4] |= (uint)pwd[i+3] << 24;
        }

        M[pwd_len/4] |= (uint)0x80 << ((pwd_len % 4) * 8);
        M[14] = pwd_len * 8;

        uint AA = a, BB = b, CC = c, DD = d;

        // Rounds (unrolled for performance)
        #pragma unroll
        for (uint i = 0; i < 16; i++) {
            uint g = i;
            uint f = F(b, c, d);
            uint temp = d; d = c; c = b;
            b = b + rotl(a + f + K[i] + M[g], S[i]);
            a = temp;
        }
        #pragma unroll
        for (uint i = 16; i < 32; i++) {
            uint g = (5*i + 1) % 16;
            uint f = G(b, c, d);
            uint temp = d; d = c; c = b;
            b = b + rotl(a + f + K[i] + M[g], S[i]);
            a = temp;
        }
        #pragma unroll
        for (uint i = 32; i < 48; i++) {
            uint g = (3*i + 5) % 16;
            uint f = H(b, c, d);
            uint temp = d; d = c; c = b;
            b = b + rotl(a + f + K[i] + M[g], S[i]);
            a = temp;
        }
        #pragma unroll
        for (uint i = 48; i < 64; i++) {
            uint g = (7*i) % 16;
            uint f = I(b, c, d);
            uint temp = d; d = c; c = b;
            b = b + rotl(a + f + K[i] + M[g], S[i]);
            a = temp;
        }

        a += AA; b += BB; c += CC; d += DD;

        output_hashes[idx * 4 + 0] = a;
        output_hashes[idx * 4 + 1] = b;
        output_hashes[idx * 4 + 2] = c;
        output_hashes[idx * 4 + 3] = d;
    }
}