#include "sha1.h"
#include "libft.h"
#include "bitwise.h"
#include "hex_utils.h"

void sha1_init(_s_sha1_context *context)
{
    context->size = 0;
    context->hash[0] = 0x67452301;
    context->hash[1] = 0xEFCDAB89;
    context->hash[2] = 0x98BADCFE;
    context->hash[3] = 0x10325476;
    context->hash[4] = 0xC3D2E1F0;
}

void sha1_calc(uint32_t *input, _s_sha1_context *context)
{
    uint32_t a, b, c, d, e, f, k, temp;
    uint32_t w[80];

    ft_bzero(w, 320);

    for (int i = 0; i < 16; i++) {
        if (little_endian()) {
            w[i] = byteswap32(input[i]);
        }
        else {
            w[i] = input[i];
        }
    }

    for (int i = 16; i <= 79; i++) {
        w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    a = context->hash[0];
    b = context->hash[1];
    c = context->hash[2];
    d = context->hash[3];
    e = context->hash[4];

    for (int i = 0; i <= 79; i++) {
        if (i >= 0 && i <= 19) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999;
        }
        else if (i >= 20 && i <= 39) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        }
        else if (i >= 40 && i <= 59) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        }
        else if (i >= 60 && i <= 79) {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }
        temp = rotl(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rotl(b, 30);
        b = a;
        a = temp;
    }
    context->hash[0] += a;
    context->hash[1] += b;
    context->hash[2] += c;
    context->hash[3] += d;
    context->hash[4] += e;
}

void sha1_update(uint8_t *buf, size_t buf_len, _s_sha1_context *context)
{
    uint32_t input[16];
    uint32_t offset = context->size % 64;

    for (size_t i = 0; i < buf_len; i++) {
        context->buffer[offset++] = buf[i];
        if (offset % 64 == 0) {
            for (int j = 0; j < 16; j++) {
                input[j] = uint8_to_uint32(context->buffer + (j * 4));
            }
            sha1_calc(input, context);
            offset = 0;
        }
    }
    context->size += buf_len;
}

void sha1_finalize(_s_sha1_context *context)
{
    uint32_t input[16];
    uint64_t offset = context->size % 64;
    uint8_t padding[64];
    uint64_t padding_len = offset < 56 ? 56 - offset : 120 - offset;
    uint64_t size;

    ft_bzero(padding, 64);
    padding[0] = 0x80;

    sha1_update(padding, padding_len, context);
    context->size -= padding_len;

    for (int i = 0; i < 14; i++) {
        input[i] = uint8_to_uint32(context->buffer + (i * 4));
    }

    size = little_endian() ? byteswap64(context->size * 8) : context->size * 8;
    input[14] = (uint32_t)(size);
    input[15] = (uint32_t)(size >> 32);

    sha1_calc(input, context);

    for (int i = 0; i < 5; i++) {
        context->digest[i * 4] = (uint8_t)((context->hash[i] & 0xFF000000) >> 24);
        context->digest[i * 4 + 1] = (uint8_t)((context->hash[i] & 0x00FF0000) >> 16);
        context->digest[i * 4 + 2] = (uint8_t)((context->hash[i] & 0x0000FF00) >> 8);
        context->digest[i * 4 + 3] = (uint8_t)(context->hash[i] & 0x000000FF);
    }
}

char *sha1_digest_to_str(uint8_t *digest, size_t len) {
    char *hash;

    hash = malloc(len + 1);
    ft_memcpy(hash, digest, len);

    return (hash);
}

char *sha1_fd(unsigned int fd, int print_contents, int encode)
{
    _s_sha1_context context;
    char buffer[SHA1_BUFFER_SIZE + 1];
    ssize_t bytes_read;

    sha1_init(&context);
    while (1) {
        bytes_read = read(fd, buffer, SHA1_BUFFER_SIZE);
        if (bytes_read < 0) {
            return (NULL);
        }
        if (!bytes_read) {
            break;
        }
        buffer[bytes_read] = '\0';
        sha1_update((uint8_t*)buffer, bytes_read, &context);
        if (print_contents) {
            if (buffer[bytes_read - 1] == '\n') {
                buffer[bytes_read - 1] = '\0';
            }
            ft_printf("%s", buffer);
        }
    }
    sha1_finalize(&context);

    if (encode) {
        return (bytes_to_hex_str(context.digest, 0, SHA1_OUTPUT_SIZE));
    }
    return (sha1_digest_to_str(context.digest, SHA1_OUTPUT_SIZE));
}

char *sha1_str(char *str, size_t len, int encode)
{
    _s_sha1_context context;

    sha1_init(&context);
    sha1_update((uint8_t*)str, len, &context);
    sha1_finalize(&context);

    if (encode) {
        return (bytes_to_hex_str(context.digest, 0, SHA1_OUTPUT_SIZE));
    }
    return (sha1_digest_to_str(context.digest, SHA1_OUTPUT_SIZE));
}
