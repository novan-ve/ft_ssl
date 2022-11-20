#include "sha256.h"
#include "libft.h"
#include "bitwise.h"
#include "hex_utils.h"

static uint32_t K[] = {
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

void sha256_init(_s_sha256_context *context)
{
    context->size = 0;
    context->hash[0] = 0x6a09e667;
    context->hash[1] = 0xbb67ae85;
    context->hash[2] = 0x3c6ef372;
    context->hash[3] = 0xa54ff53a;
    context->hash[4] = 0x510e527f;
    context->hash[5] = 0x9b05688c;
    context->hash[6] = 0x1f83d9ab;
    context->hash[7] = 0x5be0cd19;
}

void sha256_calc(uint32_t *input, _s_sha256_context *context)
{
    uint32_t a, b, c, d, e, f, g, h, s0, s1, ch, maj, temp1, temp2;
    uint32_t w[64];

    ft_bzero(w, 256);

    for (int i = 0; i < 16; i++) {
        if (little_endian()) {
            w[i] = byteswap32(input[i]);
        }
        else {
            w[i] = input[i];
        }
    }

    for (int i = 16; i < 64; i++) {
        s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = context->hash[0];
    b = context->hash[1];
    c = context->hash[2];
    d = context->hash[3];
    e = context->hash[4];
    f = context->hash[5];
    g = context->hash[6];
    h = context->hash[7];

    for (int i = 0; i < 64; i++) {
        s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        ch = (e & f) ^ ((~e) & g);
        temp1 = h + s1 + ch + K[i] + w[i];
        s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        maj = (a & b) ^ (a & c) ^ (b & c);
        temp2 = s0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }
    context->hash[0] += a;
    context->hash[1] += b;
    context->hash[2] += c;
    context->hash[3] += d;
    context->hash[4] += e;
    context->hash[5] += f;
    context->hash[6] += g;
    context->hash[7] += h;
}

void sha256_update(uint8_t *buf, size_t buf_len, _s_sha256_context *context)
{
    uint32_t input[16];
    uint32_t offset = context->size % 64;

    for (size_t i = 0; i < buf_len; i++) {
        context->buffer[offset++] = buf[i];
        if (offset % 64 == 0) {
            for (int j = 0; j < 16; j++) {
                input[j] = uint8_to_uint32(context->buffer + (j * 4));
            }
            sha256_calc(input, context);
            offset = 0;
        }
    }
    context->size += buf_len;
}

void sha256_finalize(_s_sha256_context *context)
{
    uint32_t input[16];
    uint64_t offset = context->size % 64;
    uint8_t padding[64];
    uint64_t padding_len = offset < 56 ? 56 - offset : 120 - offset;
    uint64_t size;

    ft_bzero(padding, 64);
    padding[0] = 0x80;

    sha256_update(padding, padding_len, context);
    context->size -= padding_len;

    for (int i = 0; i < 14; i++) {
        input[i] = uint8_to_uint32(context->buffer + (i * 4));
    }

    size = little_endian() ? byteswap64(context->size * 8) : context->size * 8;
    input[14] = (uint32_t)(size);
    input[15] = (uint32_t)(size >> 32);

    sha256_calc(input, context);

    for (int i = 0; i < 8; i++) {
        context->digest[i * 4] = (uint8_t)((context->hash[i] & 0xFF000000) >> 24);
        context->digest[i * 4 + 1] = (uint8_t)((context->hash[i] & 0x00FF0000) >> 16);
        context->digest[i * 4 + 2] = (uint8_t)((context->hash[i] & 0x0000FF00) >> 8);
        context->digest[i * 4 + 3] = (uint8_t)(context->hash[i] & 0x000000FF);
    }
}

char *sha256_digest_to_str(uint8_t *digest, size_t len) {
    char *hash;

    hash = malloc(len + 1);
    ft_memcpy(hash, digest, len);

    return (hash);
}

char *sha256_fd(unsigned int fd, int print_contents, int encode)
{
    _s_sha256_context context;
    char buffer[SHA256_BUFFER_SIZE + 1];
    ssize_t bytes_read;

    sha256_init(&context);
    while (1) {
        bytes_read = read(fd, buffer, SHA256_BUFFER_SIZE);
        if (bytes_read < 0) {
            return (NULL);
        }
        if (!bytes_read) {
            break;
        }
        buffer[bytes_read] = '\0';
        sha256_update((uint8_t*)buffer, bytes_read, &context);
        if (print_contents) {
            if (buffer[bytes_read - 1] == '\n') {
                buffer[bytes_read - 1] = '\0';
            }
            ft_printf("%s", buffer);
        }
    }
    sha256_finalize(&context);

    if (encode) {
        return (bytes_to_hex_str(context.digest, 0, SHA256_OUTPUT_SIZE));
    }
    return (sha256_digest_to_str(context.digest, SHA256_OUTPUT_SIZE));
}

char *sha256_str(char *str, size_t len, int encode)
{
    _s_sha256_context context;

    sha256_init(&context);
    sha256_update((uint8_t*)str, len, &context);
    sha256_finalize(&context);

    if (encode) {
        return (bytes_to_hex_str(context.digest, 0, SHA256_OUTPUT_SIZE));
    }
    return (sha256_digest_to_str(context.digest, SHA256_OUTPUT_SIZE));
}
