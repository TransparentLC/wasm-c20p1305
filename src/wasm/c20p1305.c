#include <stddef.h>
#include <stdint.h>
#include "chacha20.h"
#include "poly1305-donna.h"

#include "emscripten-exports.h"
#define c20p1305_ctx_init __WASMEXPORTS_c20p1305_ctx_init__
#define c20p1305_encrypt __WASMEXPORTS_c20p1305_encrypt__
#define c20p1305_decrypt __WASMEXPORTS_c20p1305_decrypt__
#define c20p1305_finish __WASMEXPORTS_c20p1305_finish__

// c20p1305就是chacha20poly1305的简写了

// 加密和认证过程参见：
// https://tex2e.github.io/blog/crypto/chacha20poly1305
// 或者直接看这两张图：
// https://tex2e.github.io/blog/media/post/tikz/chacha20poly1305/chacha20poly1305-enc.png
// https://tex2e.github.io/blog/media/post/tikz/chacha20poly1305/chacha20poly1305-dec.png

// 336 bytes
struct c20p1305_ctx {
    struct chacha20_context c_ctx;
    struct poly1305_context p_ctx;
    size_t auth_length;
    size_t data_length;
};

static uint8_t zeros[16] = { 0 };

EMSCRIPTEN_KEEPALIVE
void c20p1305_ctx_init(struct c20p1305_ctx *ctx, uint8_t key[32], uint8_t nonce[12], uint8_t *auth, size_t auth_length) {
    // 设置chacha20 context
    chacha20_init_context(&ctx->c_ctx, key, nonce);

    // 让chacha20生成第一个64 bytes密钥流使counter从0变成1
    // 然后取前32 bytes作为poly1305的key
    uint8_t buf[64] = { 0 };
    chacha20_xor(&ctx->c_ctx, buf, 64);

    // 设置poly1305 context
    poly1305_init_context(&ctx->p_ctx, buf);

    // 完成认证数据的auth部分并处理填充
    poly1305_update(&ctx->p_ctx, auth, auth_length);
    if (auth_length & 0xF) {
        poly1305_update(&ctx->p_ctx, zeros, 16 - (auth_length & 0xF));
    }
    ctx->auth_length = auth_length;
    ctx->data_length = 0;
}

EMSCRIPTEN_KEEPALIVE
void c20p1305_encrypt(struct c20p1305_ctx *ctx, uint8_t *data, size_t data_length) {
    // 先加密
    chacha20_xor(&ctx->c_ctx, data, data_length);
    // 然后将生成的密文拿去认证
    poly1305_update(&ctx->p_ctx, data, data_length);
    ctx->data_length += data_length;
}

EMSCRIPTEN_KEEPALIVE
void c20p1305_decrypt(struct c20p1305_ctx *ctx, uint8_t *data, size_t data_length) {
    // 先将输入的密文拿去认证
    poly1305_update(&ctx->p_ctx, data, data_length);
    ctx->data_length += data_length;
    // 然后解密
    chacha20_xor(&ctx->c_ctx, data, data_length);
}

EMSCRIPTEN_KEEPALIVE
void c20p1305_finish(struct c20p1305_ctx *ctx, uint8_t mac[16]) {
    // 完成认证的密文部分的填充
    if (ctx->data_length & 0xF) {
        poly1305_update(&ctx->p_ctx, zeros, 16 - (ctx->data_length & 0xF));
    }
    // 完成认证的长度部分
    uint64_t size[2] = { ctx->auth_length, ctx->data_length };
    poly1305_update(&ctx->p_ctx, (uint8_t *)size, 16);
    // 获得mac
    // 如果是加密的话需要和密文一起发送给对方
    // 如果是解密的话需要和与密文一起提供的mac进行验证
    poly1305_finish(&ctx->p_ctx, mac);
}