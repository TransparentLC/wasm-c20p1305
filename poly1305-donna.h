#include <stddef.h>

/* auto detect between 32bit / 64bit */
#define HAS_SIZEOF_INT128_64BIT (defined(__SIZEOF_INT128__) && defined(__LP64__))
#define HAS_MSVC_64BIT (defined(_MSC_VER) && defined(_M_X64))
#define HAS_GCC_4_4_64BIT (defined(__GNUC__) && defined(__LP64__) && ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC_MINOR__ >= 4))))

/* poly1305 implementation using 32 bit * 32 bit = 64 bit multiplication and 64 bit addition */

#if defined(_MSC_VER)
	#define POLY1305_NOINLINE __declspec(noinline)
#elif defined(__GNUC__)
	#define POLY1305_NOINLINE __attribute__((noinline))
#else
	#define POLY1305_NOINLINE
#endif

#define poly1305_block_size 16

// 140 bytes
typedef struct poly1305_context {
	size_t aligner;
	unsigned char opaque[136];
} poly1305_context;

/* 17 + sizeof(size_t) + 14*sizeof(unsigned long) */
typedef struct poly1305_state_internal_t {
	unsigned long r[5];
	unsigned long h[5];
	unsigned long pad[4];
	size_t leftover;
	unsigned char buffer[poly1305_block_size];
	unsigned char final;
} poly1305_state_internal_t;

static void poly1305_blocks(poly1305_state_internal_t *st, const unsigned char *m, size_t bytes);

int poly1305_verify(const unsigned char mac1[16], const unsigned char mac2[16]);

void poly1305_init_context(poly1305_context *ctx, const unsigned char key[32]);

void poly1305_update(poly1305_context *ctx, const unsigned char *m, size_t bytes);

POLY1305_NOINLINE
void poly1305_finish(poly1305_context *ctx, unsigned char mac[16]);