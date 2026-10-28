// CUDA Kernel for NTLM (MD4 of UTF-16LE)

#include <cstdint>
#include <cuda_runtime.h>

using uchar = unsigned char;
using uint = unsigned int;

__device__ inline uint rotl32_md4(uint x, uchar n) {
    return (x << n) | (x >> (32 - n));
}

__device__ inline uint MD4_F(uint x, uint y, uint z) { return (x & y) | (~x & z); }
__device__ inline uint MD4_G(uint x, uint y, uint z) { return (x & y) | (x & z) | (y & z); }
__device__ inline uint MD4_H(uint x, uint y, uint z) { return x ^ y ^ z; }

#define MD4_ROUND1(a,b,c,d,k,s) a = rotl32_md4(a + MD4_F(b,c,d) + M[k], s)
#define MD4_ROUND2(a,b,c,d,k,s) a = rotl32_md4(a + MD4_G(b,c,d) + M[k] + 0x5a827999, s)
#define MD4_ROUND3(a,b,c,d,k,s) a = rotl32_md4(a + MD4_H(b,c,d) + M[k] + 0x6ed9eba1, s)

__global__ void ntlm_kernel(
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

    // Convert to UTF-16LE
    uchar utf16[256];
    for (uint i = 0; i < pwd_len; i++) {
        uchar c = passwords[gid * max_pwd_len + i];
        utf16[i * 2] = c;
        utf16[i * 2 + 1] = 0;
    }
    uint utf16_len = pwd_len * 2;

    uint a = 0x67452301;
    uint b = 0xefcdab89;
    uint c = 0x98badcfe;
    uint d = 0x10325476;

    uint M[16] = {0};
    for (uint i = 0; i < utf16_len; i += 4) {
        M[i/4] |= (uint)utf16[i] << 0;
        if (i+1 < utf16_len) M[i/4] |= (uint)utf16[i+1] << 8;
        if (i+2 < utf16_len) M[i/4] |= (uint)utf16[i+2] << 16;
        if (i+3 < utf16_len) M[i/4] |= (uint)utf16[i+3] << 24;
    }

    M[utf16_len/4] |= (uint)0x80 << ((utf16_len % 4) * 8);
    M[14] = utf16_len * 8;

    uint AA = a, BB = b, CC = c, DD = d;

    MD4_ROUND1(a,b,c,d, 0, 3); MD4_ROUND1(d,a,b,c, 1, 7); MD4_ROUND1(c,d,a,b, 2,11); MD4_ROUND1(b,c,d,a, 3,19);
    MD4_ROUND1(a,b,c,d, 4, 3); MD4_ROUND1(d,a,b,c, 5, 7); MD4_ROUND1(c,d,a,b, 6,11); MD4_ROUND1(b,c,d,a, 7,19);
    MD4_ROUND1(a,b,c,d, 8, 3); MD4_ROUND1(d,a,b,c, 9, 7); MD4_ROUND1(c,d,a,b,10,11); MD4_ROUND1(b,c,d,a,11,19);
    MD4_ROUND1(a,b,c,d,12, 3); MD4_ROUND1(d,a,b,c,13, 7); MD4_ROUND1(c,d,a,b,14,11); MD4_ROUND1(b,c,d,a,15,19);

    MD4_ROUND2(a,b,c,d, 0, 3); MD4_ROUND2(d,a,b,c, 4, 5); MD4_ROUND2(c,d,a,b, 8, 9); MD4_ROUND2(b,c,d,a,12,13);
    MD4_ROUND2(a,b,c,d, 1, 3); MD4_ROUND2(d,a,b,c, 5, 5); MD4_ROUND2(c,d,a,b, 9, 9); MD4_ROUND2(b,c,d,a,13,13);
    MD4_ROUND2(a,b,c,d, 2, 3); MD4_ROUND2(d,a,b,c, 6, 5); MD4_ROUND2(c,d,a,b,10, 9); MD4_ROUND2(b,c,d,a,14,13);
    MD4_ROUND2(a,b,c,d, 3, 3); MD4_ROUND2(d,a,b,c, 7, 5); MD4_ROUND2(c,d,a,b,11, 9); MD4_ROUND2(b,c,d,a,15,13);

    MD4_ROUND3(a,b,c,d, 0, 3); MD4_ROUND3(d,a,b,c, 8, 9); MD4_ROUND3(c,d,a,b, 4,11); MD4_ROUND3(b,c,d,a,12,15);
    MD4_ROUND3(a,b,c,d, 2, 3); MD4_ROUND3(d,a,b,c,10, 9); MD4_ROUND3(c,d,a,b, 6,11); MD4_ROUND3(b,c,d,a,14,15);
    MD4_ROUND3(a,b,c,d, 1, 3); MD4_ROUND3(d,a,b,c, 9, 9); MD4_ROUND3(c,d,a,b, 5,11); MD4_ROUND3(b,c,d,a,13,15);
    MD4_ROUND3(a,b,c,d, 3, 3); MD4_ROUND3(d,a,b,c,11, 9); MD4_ROUND3(c,d,a,b, 7,11); MD4_ROUND3(b,c,d,a,15,15);

    a += AA; b += BB; c += CC; d += DD;

    output_hashes[gid * 4 + 0] = a;
    output_hashes[gid * 4 + 1] = b;
    output_hashes[gid * 4 + 2] = c;
    output_hashes[gid * 4 + 3] = d;
}

__global__ void ntlm_batch_kernel(
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

        uchar utf16[256];
        for (uint i = 0; i < pwd_len; i++) {
            uchar c = passwords[idx * max_pwd_len + i];
            utf16[i * 2] = c;
            utf16[i * 2 + 1] = 0;
        }
        uint utf16_len = pwd_len * 2;

        uint a = 0x67452301;
        uint b = 0xefcdab89;
        uint c = 0x98badcfe;
        uint d = 0x10325476;

        uint M[16] = {0};
        for (uint i = 0; i < utf16_len; i += 4) {
            M[i/4] |= (uint)utf16[i] << 0;
            if (i+1 < utf16_len) M[i/4] |= (uint)utf16[i+1] << 8;
            if (i+2 < utf16_len) M[i/4] |= (uint)utf16[i+2] << 16;
            if (i+3 < utf16_len) M[i/4] |= (uint)utf16[i+3] << 24;
        }

        M[utf16_len/4] |= (uint)0x80 << ((utf16_len % 4) * 8);
        M[14] = utf16_len * 8;

        uint AA = a, BB = b, CC = c, DD = d;

        MD4_ROUND1(a,b,c,d, 0, 3); MD4_ROUND1(d,a,b,c, 1, 7); MD4_ROUND1(c,d,a,b, 2,11); MD4_ROUND1(b,c,d,a, 3,19);
        MD4_ROUND1(a,b,c,d, 4, 3); MD4_ROUND1(d,a,b,c, 5, 7); MD4_ROUND1(c,d,a,b, 6,11); MD4_ROUND1(b,c,d,a, 7,19);
        MD4_ROUND1(a,b,c,d, 8, 3); MD4_ROUND1(d,a,b,c, 9, 7); MD4_ROUND1(c,d,a,b,10,11); MD4_ROUND1(b,c,d,a,11,19);
        MD4_ROUND1(a,b,c,d,12, 3); MD4_ROUND1(d,a,b,c,13, 7); MD4_ROUND1(c,d,a,b,14,11); MD4_ROUND1(b,c,d,a,15,19);

        MD4_ROUND2(a,b,c,d, 0, 3); MD4_ROUND2(d,a,b,c, 4, 5); MD4_ROUND2(c,d,a,b, 8, 9); MD4_ROUND2(b,c,d,a,12,13);
        MD4_ROUND2(a,b,c,d, 1, 3); MD4_ROUND2(d,a,b,c, 5, 5); MD4_ROUND2(c,d,a,b, 9, 9); MD4_ROUND2(b,c,d,a,13,13);
        MD4_ROUND2(a,b,c,d, 2, 3); MD4_ROUND2(d,a,b,c, 6, 5); MD4_ROUND2(c,d,a,b,10, 9); MD4_ROUND2(b,c,d,a,14,13);
        MD4_ROUND2(a,b,c,d, 3, 3); MD4_ROUND2(d,a,b,c, 7, 5); MD4_ROUND2(c,d,a,b,11, 9); MD4_ROUND2(b,c,d,a,15,13);

        MD4_ROUND3(a,b,c,d, 0, 3); MD4_ROUND3(d,a,b,c, 8, 9); MD4_ROUND3(c,d,a,b, 4,11); MD4_ROUND3(b,c,d,a,12,15);
        MD4_ROUND3(a,b,c,d, 2, 3); MD4_ROUND3(d,a,b,c,10, 9); MD4_ROUND3(c,d,a,b, 6,11); MD4_ROUND3(b,c,d,a,14,15);
        MD4_ROUND3(a,b,c,d, 1, 3); MD4_ROUND3(d,a,b,c, 9, 9); MD4_ROUND3(c,d,a,b, 5,11); MD4_ROUND3(b,c,d,a,13,15);
        MD4_ROUND3(a,b,c,d, 3, 3); MD4_ROUND3(d,a,b,c,11, 9); MD4_ROUND3(c,d,a,b, 7,11); MD4_ROUND3(b,c,d,a,15,15);

        a += AA; b += BB; c += CC; d += DD;

        output_hashes[idx * 4 + 0] = a;
        output_hashes[idx * 4 + 1] = b;
        output_hashes[idx * 4 + 2] = c;
        output_hashes[idx * 4 + 3] = d;
    }
}

extern "C" {
    void launch_ntlm_kernel(const uchar* d_passwords, const uint* d_lengths,
                            uint* d_hashes, uint num_passwords, uint max_pwd_len) {
        dim3 block(256);
        dim3 grid((num_passwords + block.x - 1) / block.x);
        ntlm_kernel<<<grid, block>>>(d_passwords, d_lengths, d_hashes, num_passwords, max_pwd_len);
        cudaDeviceSynchronize();
    }

    void launch_ntlm_batch_kernel(const uchar* d_passwords, const uint* d_lengths,
                                  uint* d_hashes, uint num_passwords, uint max_pwd_len) {
        dim3 block(256);
        dim3 grid(1024);
        ntlm_batch_kernel<<<grid, block>>>(d_passwords, d_lengths, d_hashes, num_passwords, max_pwd_len);
        cudaDeviceSynchronize();
    }
}