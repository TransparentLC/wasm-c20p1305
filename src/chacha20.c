#include "chacha20.h"

static uint32_t rotl32(uint32_t x, int n)
{
    return (x << n) | (x >> (32 - n));
}

static uint32_t pack4(const uint8_t *a)
{
    uint32_t res = 0;
    res |= (uint32_t)a[0] << 0 * 8;
    res |= (uint32_t)a[1] << 1 * 8;
    res |= (uint32_t)a[2] << 2 * 8;
    res |= (uint32_t)a[3] << 3 * 8;
    return res;
}

static void unpack4(uint32_t src, uint8_t *dst) {
    dst[0] = (src >> 0 * 8) & 0xFF;
    dst[1] = (src >> 1 * 8) & 0xFF;
    dst[2] = (src >> 2 * 8) & 0xFF;
    dst[3] = (src >> 3 * 8) & 0xFF;
}

static void chacha20_init_block(struct chacha20_context *ctx, uint8_t key[32], uint8_t nonce[12])
{
    memcpy(ctx->key, key, sizeof(ctx->key));
    memcpy(ctx->nonce, nonce, sizeof(ctx->nonce));

    ctx->state[0] = 0x61707865;
    ctx->state[1] = 0x3320646E;
    ctx->state[2] = 0x79622D32;
    ctx->state[3] = 0x6B206574;
    ctx->state[4] = pack4(key + 0 * 4);
    ctx->state[5] = pack4(key + 1 * 4);
    ctx->state[6] = pack4(key + 2 * 4);
    ctx->state[7] = pack4(key + 3 * 4);
    ctx->state[8] = pack4(key + 4 * 4);
    ctx->state[9] = pack4(key + 5 * 4);
    ctx->state[10] = pack4(key + 6 * 4);
    ctx->state[11] = pack4(key + 7 * 4);
    // 64 bit counter initialized to zero by default.
    ctx->state[12] = 0;
    ctx->state[13] = pack4(nonce + 0 * 4);
    ctx->state[14] = pack4(nonce + 1 * 4);
    ctx->state[15] = pack4(nonce + 2 * 4);

    memcpy(ctx->nonce, nonce, sizeof(ctx->nonce));
}

static void chacha20_block_set_counter(struct chacha20_context *ctx, uint64_t counter)
{
    ctx->state[12] = (uint32_t)counter;
    ctx->state[13] = pack4(ctx->nonce + 0 * 4) + (uint32_t)(counter >> 32);
}

static void chacha20_block_next(struct chacha20_context *ctx) {
    // This is where the crazy voodoo magic happens.
    // Mix the bytes a lot and hope that nobody finds out how to undo it.
    for (int i = 0; i < 16; i++) ctx->keystream32[i] = ctx->state[i];

#define CHACHA20_QUARTERROUND(x, a, b, c, d) \
    x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 16); \
    x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 12); \
    x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 8); \
    x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 7);

    for (int i = 0; i < 10; i++)
    {
        CHACHA20_QUARTERROUND(ctx->keystream32, 0x0, 0x4, 0x8, 0xC)
        CHACHA20_QUARTERROUND(ctx->keystream32, 0x1, 0x5, 0x9, 0xD)
        CHACHA20_QUARTERROUND(ctx->keystream32, 0x2, 0x6, 0xA, 0xE)
        CHACHA20_QUARTERROUND(ctx->keystream32, 0x3, 0x7, 0xB, 0xF)
        CHACHA20_QUARTERROUND(ctx->keystream32, 0x0, 0x5, 0xA, 0xF)
        CHACHA20_QUARTERROUND(ctx->keystream32, 0x1, 0x6, 0xB, 0xC)
        CHACHA20_QUARTERROUND(ctx->keystream32, 0x2, 0x7, 0x8, 0xD)
        CHACHA20_QUARTERROUND(ctx->keystream32, 0x3, 0x4, 0x9, 0xE)
    }

    for (int i = 0; i < 16; i++) ctx->keystream32[i] += ctx->state[i];

    uint32_t *counter = ctx->state + 12;
    // increment counter
    counter[0]++;
    if (0 == counter[0])
    {
        // wrap around occured, increment higher 32 bits of counter
        counter[1]++;
        // Limited to 2^64 blocks of 64 bytes each.
        // If you want to process more than 1180591620717411303424 bytes
        // you have other problems.
        // We could keep counting with counter[2] and counter[3] (nonce),
        // but then we risk reusing the nonce which is very bad.
        // assert(0 != counter[1]);
    }
}

void chacha20_init_context(struct chacha20_context *ctx, uint8_t key[], uint8_t nonce[])
{
    memset(ctx, 0, sizeof(struct chacha20_context));

    uint64_t counter = 0;
    chacha20_init_block(ctx, key, nonce);
    chacha20_block_set_counter(ctx, counter);

    ctx->counter = counter;
    ctx->position = 64;
}

void chacha20_xor(struct chacha20_context *ctx, uint8_t *bytes, size_t n_bytes)
{
    uint8_t *keystream8 = (uint8_t*)ctx->keystream32;
    for (size_t i = 0; i < n_bytes; i++)
    {
        if (ctx->position >= 64)
        {
            chacha20_block_next(ctx);
            ctx->position = 0;
        }
        bytes[i] ^= keystream8[ctx->position];
        ctx->position++;
    }
}