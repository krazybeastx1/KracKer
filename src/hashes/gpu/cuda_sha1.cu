// CUDA Kernel for SHA-1
// Based on FIPS 180-4

#include <cstdint>
#include <cuda_runtime.h>

using uchar = unsigned char;
using uint = unsigned int;

__constant__ uint K_SHA1[80] = {
    0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
    0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
    0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
    0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
    0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999,
    0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
    0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
    0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
    0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1,
    0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc,
    0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc,
    0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc,
    0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc,
    0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6,
    0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6,
    0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6,
    0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6
};

__device__ inline uint rotl32(uint x, uchar n) {
    return (x << n) | (x >> (32 - n));
}

__device__ inline uint sha1_f1(uint x, uint y, uint z) { return (x & y) | (~x & z); }
__device__ inline uint sha1_f2(uint x, uint y, uint z) { return x ^ y ^ z; }
__device__ inline uint sha1_f3(uint x, uint y, uint z) { return (x & y) | (x & z) | (y & z); }
__device__ inline uint sha1_f4(uint x, uint y, uint z) { return x ^ y ^ z; }

__global__ void sha1_kernel(
    const uchar* __restrict__ passwords,
    const uint* __restrict__ pwd_lengths,
    uint* __restrict__ output_hashes,
    uint num_passwords,
    uint max_pwd_len
) {
    uint gid = blockIdx.x * blockDim.x + threadIdx.x;
    if (gid >= num_passwords) return;

    uint pwd_len = pwd_lengths[gid];
    if (pwd_len > max_pwd_len) pwd_len = max_pwd_len;

    uchar pwd[128];
    for (uint i = 0; i < pwd_len; i++) {
        pwd[i] = passwords[gid * max_pwd_len + i];
    }

    uint h0 = 0x67452301;
    uint h1 = 0xefcdab89;
    uint h2 = 0x98badcfe;
    uint h3 = 0x10325476;
    uint h4 = 0xc3d2e1f0;

    uint W[80] = {0};
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

    for (uint t = 16; t < 80; t++) {
        W[t] = rotl32(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1);
    }

    uint a = h0, b = h1, c = h2, d = h3, e = h4;

    for (uint t = 0; t < 80; t++) {
        uint f, k;
        if (t < 20) { f = sha1_f1(b, c, d); k = K_SHA1[t]; }
        else if (t < 40) { f = sha1_f2(b, c, d); k = K_SHA1[t]; }
        else if (t < 60) { f = sha1_f3(b, c, d); k = K_SHA1[t]; }
        else { f = sha1_f4(b, c, d); k = K_SHA1[t]; }

        uint temp = rotl32(a, 5) + f + e + k + W[t];
        e = d; d = c; c = rotl32(b, 30); b = a; a = temp;
    }

    h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;

    output_hashes[gid * 5 + 0] = h0;
    output_hashes[gid * 5 + 1] = h1;
    output_hashes[gid * 5 + 2] = h2;
    output_hashes[gid * 5 + 3] = h3;
    output_hashes[gid * 5 + 4] = h4;
}

__global__ void sha1_batch_kernel(
    const uchar* __restrict__ passwords,
    const uint* __restrict__ pwd_lengths,
    uint* __restrict__ output_hashes,
    uint num_passwords,
    uint max_pwd_len
) {
    uint tid = blockIdx.x * blockDim.x + threadIdx.x;
    uint stride = gridDim.x * blockDim.x;

    for (uint idx = tid; idx < num_passwords; idx += stride) {
        uint pwd_len = pwd_lengths[idx];
        if (pwd_len > max_pwd_len) pwd_len = max_pwd_len;

        uchar pwd[128];
        for (uint i = 0; i < pwd_len; i++) {
            pwd[i] = passwords[idx * max_pwd_len + i];
        }

        uint h0 = 0x67452301;
        uint h1 = 0xefcdab89;
        uint h2 = 0x98badcfe;
        uint h3 = 0x10325476;
        uint h4 = 0xc3d2e1f0;

        uint W[80] = {0};
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

        for (uint t = 16; t < 80; t++) {
            W[t] = rotl32(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1);
        }

        uint a = h0, b = h1, c = h2, d = h3, e = h4;

        for (uint t = 0; t < 80; t++) {
            uint f, k;
            if (t < 20) { f = sha1_f1(b, c, d); k = K_SHA1[t]; }
            else if (t < 40) { f = sha1_f2(b, c, d); k = K_SHA1[t]; }
            else if (t < 60) { f = sha1_f3(b, c, d); k = K_SHA1[t]; }
            else { f = sha1_f4(b, c, d); k = K_SHA1[t]; }

            uint temp = rotl32(a, 5) + f + e + k + W[t];
            e = d; d = c; c = rotl32(b, 30); b = a; a = temp;
        }

        h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;

        output_hashes[idx * 5 + 0] = h0;
        output_hashes[idx * 5 + 1] = h1;
        output_hashes[idx * 5 + 2] = h2;
        output_hashes[idx * 5 + 3] = h3;
        output_hashes[idx * 5 + 4] = h4;
    }
}

extern "C" {
    void launch_sha1_kernel(const uchar* d_passwords, const uint* d_lengths,
                            uint* d_hashes, uint num_passwords, uint max_pwd_len) {
        dim3 block(256);
        dim3 grid((num_passwords + block.x - 1) / block.x);
        sha1_kernel<<<grid, block>>>(d_passwords, d_lengths, d_hashes, num_passwords, max_pwd_len);
        cudaDeviceSynchronize();
    }

    void launch_sha1_batch_kernel(const uchar* d_passwords, const uint* d_lengths,
                                  uint* d_hashes, uint num_passwords, uint max_pwd_len) {
        dim3 block(256);
        dim3 grid(1024);
        sha1_batch_kernel<<<grid, block>>>(d_passwords, d_lengths, d_hashes, num_passwords, max_pwd_len);
        cudaDeviceSynchronize();
    }
}