#pragma once

#include <ntifs.h>

typedef unsigned short WORD;
typedef unsigned char BYTE;
typedef unsigned long DWORD;

#define SHA256_BLOCK_SIZE 32

void SHA256Transform(UINT32 state[8], const BYTE buffer[64]);
void SHA256Init(SHA256_CTX* context);
void SHA256Update(SHA256_CTX* context, const BYTE* data, size_t len);
void SHA256Final(BYTE digest[SHA256_BLOCK_SIZE], SHA256_CTX* context);

#define ROTATE_RIGHT(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTATE_RIGHT(x, 2) ^ ROTATE_RIGHT(x, 13) ^ ROTATE_RIGHT(x, 22))
#define EP1(x) (ROTATE_RIGHT(x, 6) ^ ROTATE_RIGHT(x, 11) ^ ROTATE_RIGHT(x, 25))
#define SIG0(x) (ROTATE_RIGHT(x, 7) ^ ROTATE_RIGHT(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTATE_RIGHT(x, 17) ^ ROTATE_RIGHT(x, 19) ^ ((x) >> 10))

static const UINT32 k[64] = {
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

void SHA256Transform(UINT32 state[8], const BYTE buffer[64]) {
    UINT32 a, b, c, d, e, f, g, h, t1, t2, m[64];
    int i, j;

    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (buffer[j] << 24) | (buffer[j + 1] << 16) | (buffer[j + 2] << 8) | (buffer[j + 3]);
    for (; i < 64; ++i)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void SHA256Init(SHA256_CTX* context) {
    context->count[0] = context->count[1] = 0;
    context->state[0] = 0x6a09e667;
    context->state[1] = 0xbb67ae85;
    context->state[2] = 0x3c6ef372;
    context->state[3] = 0xa54ff53a;
    context->state[4] = 0x510e527f;
    context->state[5] = 0x9b05688c;
    context->state[6] = 0x1f83d9ab;
    context->state[7] = 0x5be0cd19;
}

void SHA256Update(SHA256_CTX* context, const BYTE* data, size_t len) {
    UINT32 i, index, partLen;

    index = (UINT32)((context->count[1] >> 3) & 0x3F);
    if ((context->count[1] += ((UINT32)len << 3)) < ((UINT32)len << 3))
        context->count[0]++;
    context->count[0] += ((UINT32)len >> 29);

    partLen = 64 - index;

    if (len >= partLen) {
        RtlCopyMemory(&context->buffer[index], data, partLen);
        SHA256Transform(context->state, context->buffer);

        for (i = partLen; i + 63 < len; i += 64)
            SHA256Transform(context->state, &data[i]);

        index = 0;
    }
    else {
        i = 0;
    }

    RtlCopyMemory(&context->buffer[index], &data[i], len - i);
}

static const BYTE PADDING[64] = { 0x80 };

void SHA256Final(BYTE digest[SHA256_BLOCK_SIZE], SHA256_CTX* context) {
    BYTE bits[8];
    UINT32 index, padLen;

    bits[7] = context->count[1] & 0xFF;
    bits[6] = (context->count[1] >> 8) & 0xFF;
    bits[5] = (context->count[1] >> 16) & 0xFF;
    bits[4] = (context->count[1] >> 24) & 0xFF;
    bits[3] = context->count[0] & 0xFF;
    bits[2] = (context->count[0] >> 8) & 0xFF;
    bits[1] = (context->count[0] >> 16) & 0xFF;
    bits[0] = (context->count[0] >> 24) & 0xFF;

    index = (UINT32)((context->count[1] >> 3) & 0x3F);
    padLen = (index < 56) ? (56 - index) : (120 - index);
    SHA256Update(context, PADDING, padLen);
    SHA256Update(context, bits, 8);

    for (int i = 0; i < 8; i++) {
        digest[i * 4] = (context->state[i] >> 24) & 0xFF;
        digest[i * 4 + 1] = (context->state[i] >> 16) & 0xFF;
        digest[i * 4 + 2] = (context->state[i] >> 8) & 0xFF;
        digest[i * 4 + 3] = context->state[i] & 0xFF;
    }
}

bool IsSHA256Hash(const char* str) {

    if (str == NULL) {
        return false;
    }

    size_t len = strlen(str);
    if (len != 64) {
        return false;
    }

    for (size_t i = 0; i < len; i++) {
        if (!isxdigit((unsigned char)str[i])) {
            return false;
        }
    }

    return true;
}