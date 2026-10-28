// CUDA Kernel for MD5
// Based on RFC 1321

#include <cstdint>
#include <cuda_runtime.h>

using uchar = unsigned char;
using uint = unsigned int;

__constant__ uint K_MD5[64] = {
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

__constant__ unsigned char S_MD5[64] = {
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
};

__device__ inline uint rotl(uint x, unsigned char n) {
    return (x << n) | (x >> (32 - n));
}

__device__ inline uint F_md5(uint x, uint y, uint z) { return (x & y) | (~x & z); }
__device__ inline uint G_md5(uint x, uint y, uint z) { return (x & z) | (y & ~z); }
__device__ inline uint H_md5(uint x, uint y, uint z) { return x ^ y ^ z; }
__device__ inline uint I_md5(uint x, uint y, uint z) { return y ^ (x | ~z); }

__global__ void md5_kernel(
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

    // Round 1
    #pragma unroll
    for (uint i = 0; i < 16; i++) {
        uint g = i;
        uint f = F_md5(b, c, d);
        uint temp = d; d = c; c = b;
        b = b + rotl(a + f + K_MD5[i] + M[g], S_MD5[i]);
        a = temp;
    }

    // Round 2
    #pragma unroll
    for (uint i = 16; i < 32; i++) {
        uint g = (5*i + 1) % 16;
        uint f = G_md5(b, c, d);
        uint temp = d; d = c; c = b;
        b = b + rotl(a + f + K_MD5[i] + M[g], S_MD5[i]);
        a = temp;
    }

    // Round 3
    #pragma unroll
    for (uint i = 32; i < 48; i++) {
        uint g = (3*i + 5) % 16;
        uint f = H_md5(b, c, d);
        uint temp = d; d = c; c = b;
        b = b + rotl(a + f + K_MD5[i] + M[g], S_MD5[i]);
        a = temp;
    }

    // Round 4
    #pragma unroll
    for (uint i = 48; i < 64; i++) {
        uint g = (7*i) % 16;
        uint f = I_md5(b, c, d);
        uint temp = d; d = c; c = b;
        b = b + rotl(a + f + K_MD5[i] + M[g], S_MD5[i]);
        a = temp;
    }

    a += AA; b += BB; c += CC; d += DD;

    output_hashes[gid * 4 + 0] = a;
    output_hashes[gid * 4 + 1] = b;
    output_hashes[gid * 4 + 2] = c;
    output_hashes[gid * 4 + 3] = d;
}

// Batch kernel with grid-stride loop
__global__ void md5_batch_kernel(
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

        #pragma unroll
        for (uint i = 0; i < 16; i++) {
            uint g = i; uint f = F_md5(b,c,d); uint t = d; d=c; c=b;
            b = b + rotl(a + f + K_MD5[i] + M[g], S_MD5[i]); a = t;
        }
        #pragma unroll
        for (uint i = 16; i < 32; i++) {
            uint g = (5*i + 1) % 16; uint f = G_md5(b,c,d); uint t = d; d=c; c=b;
            b = b + rotl(a + f + K_MD5[i] + M[g], S_MD5[i]); a = t;
        }
        #pragma unroll
        for (uint i = 32; i < 48; i++) {
            uint g = (3*i + 5) % 16; uint f = H_md5(b,c,d); uint t = d; d=c; c=b;
            b = b + rotl(a + f + K_MD5[i] + M[g], S_MD5[i]); a = t;
        }
        #pragma unroll
        for (uint i = 48; i < 64; i++) {
            uint g = (7*i) % 16; uint f = I_md5(b,c,d); uint t = d; d=c; c=b;
            b = b + rotl(a + f + K_MD5[i] + M[g], S_MD5[i]); a = t;
        }

        a += AA; b += BB; c += CC; d += DD;

        output_hashes[idx * 4 + 0] = a;
        output_hashes[idx * 4 + 1] = b;
        output_hashes[idx * 4 + 2] = c;
        output_hashes[idx * 4 + 3] = d;
    }
}

// Host launch functions
extern "C" {
    void launch_md5_kernel(const uchar* d_passwords, const uint* d_lengths,
                           uint* d_hashes, uint num_passwords, uint max_pwd_len) {
        dim3 block(256);
        dim3 grid((num_passwords + block.x - 1) / block.x);
        md5_kernel<<<grid, block>>>(d_passwords, d_lengths, d_hashes, num_passwords, max_pwd_len);
        cudaDeviceSynchronize();
    }

    void launch_md5_batch_kernel(const uchar* d_passwords, const uint* d_lengths,
                                 uint* d_hashes, uint num_passwords, uint max_pwd_len) {
        dim3 block(256);
        dim3 grid(1024);  // Multiple blocks for better occupancy
        md5_batch_kernel<<<grid, block>>>(d_passwords, d_lengths, d_hashes, num_passwords, max_pwd_len);
        cudaDeviceSynchronize();
    }
}