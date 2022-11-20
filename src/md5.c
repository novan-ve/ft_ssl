#include "md5.h"
#include "libft.h"
#include "bitwise.h"
#include "hex_utils.h"

static uint32_t S[] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

static uint32_t K[] = {
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

void md5_init(_s_md5_context *context)
{
    context->size = 0;
    context->words[0] = 0x67452301;
    context->words[1] = 0xefcdab89;
    context->words[2] = 0x98badcfe;
    context->words[3] = 0x10325476;
}

void md5_calc(uint32_t *input, _s_md5_context *context)
{
    uint32_t A = context->words[0];
    uint32_t B = context->words[1];
    uint32_t C = context->words[2];
    uint32_t D = context->words[3];
	uint32_t F = 0;
	uint32_t G = 0;

    for (int i = 0; i < 64; i++) {
        if (i >= 0 && i <= 15) {
            F = (B & C) | ((~B) & D);
            G = i;
        }
        else if (i >= 16 && i <= 31) {
            F = (D & B) | ((~D) & C);
            G = (5 * i + 1) % 16;
        }
        else if (i >= 32 && i <= 47) {
            F = B ^ C ^ D;
            G = (3 * i + 5) % 16;
        }
        else if (i >= 48 && i <= 63) {
            F = C ^ (B | (~D));
            G = (7 * i) % 16;
        }
        F += A + K[i] + input[G];
        A = D;
        D = C;
        C = B;
        B += rotl(F, S[i]);
    }
    context->words[0] += A;
    context->words[1] += B;
    context->words[2] += C;
    context->words[3] += D;
}

void md5_update(uint8_t *buf, size_t buf_len, _s_md5_context *context)
{
    uint32_t input[16];
    uint32_t offset = context->size % 64;

    for (size_t i = 0; i < buf_len; i++) {
        context->buffer[offset++] = buf[i];
        if (offset % 64 == 0) {
            for (int j = 0; j < 16; j++) {
                input[j] = uint8_to_uint32(context->buffer + (j * 4));
            }
            md5_calc(input, context);
            offset = 0;
        }
    }
    context->size += buf_len;
}

void md5_finalize(_s_md5_context *context)
{
    uint32_t input[16];
    uint64_t offset = context->size % 64;
    uint8_t padding[64];
    uint64_t padding_len = offset < 56 ? 56 - offset : 120 - offset;

    ft_bzero(padding, 64);
    padding[0] = 0x80;

    md5_update(padding, padding_len, context);
    context->size -= padding_len;

    for (int i = 0; i < 14; i++) {
        input[i] = uint8_to_uint32(context->buffer + (i * 4));
    }
    input[14] = (uint32_t)(context->size * 8);
    input[15] = (uint32_t)((context->size * 8) >> 32);

    md5_calc(input, context);
    for (int i = 0; i < 4; i++) {
        context->digest[i * 4] = (uint8_t)(context->words[i] & 0x000000FF);
        context->digest[i * 4 + 1] = (uint8_t)((context->words[i] & 0x0000FF00) >> 8);
        context->digest[i * 4 + 2] = (uint8_t)((context->words[i] & 0x00FF0000) >> 16);
        context->digest[i * 4 + 3] = (uint8_t)((context->words[i] & 0xFF000000) >> 24);
    }
}

char *md5_digest_to_str(uint8_t *digest, size_t len) {
    char *hash;

    hash = malloc(len);
    ft_memcpy(hash, digest, len);

    return (hash);
}

char *md5_fd(unsigned int fd, int print_contents, int encode)
{
    _s_md5_context context;
    char buffer[MD5_BUFFER_SIZE + 1];
    ssize_t bytes_read;

    md5_init(&context);
    while (1) {
        bytes_read = read(fd, buffer, MD5_BUFFER_SIZE);
        if (bytes_read < 0) {
            return (NULL);
        }
        if (!bytes_read) {
            break;
        }
        buffer[bytes_read] = '\0';
        md5_update((uint8_t*)buffer, bytes_read, &context);
        if (print_contents) {
            if (buffer[bytes_read - 1] == '\n') {
                buffer[bytes_read - 1] = '\0';
            }
            ft_printf("%s", buffer);
        }
    }
    md5_finalize(&context);

    if (encode) {
        return (bytes_to_hex_str(context.digest, 0, MD5_OUTPUT_SIZE));
    }
    return (md5_digest_to_str(context.digest, MD5_OUTPUT_SIZE));
}

char *md5_str(char *str, size_t len, int encode)
{
    _s_md5_context context;

    md5_init(&context);
    md5_update((uint8_t*)str, len, &context);
    md5_finalize(&context);

    if (encode) {
        return (bytes_to_hex_str(context.digest, 0, MD5_OUTPUT_SIZE));
    }
    return (md5_digest_to_str(context.digest, MD5_OUTPUT_SIZE));
}
