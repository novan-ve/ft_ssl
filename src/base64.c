#include "base64.h"
#include "libft.h"
#include "fterror.h"

#include <unistd.h>
#include <stdint.h>

static const char base64_enc_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const int base64_dec_table[] = {
    62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1,
    -1, -1, -1, -1, -1, -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
    10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    -1, -1, -1, -1, -1, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
    36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51
};

int is_base64(char c)
{
    return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '+' || c == '/');
}

size_t base64_max_input_len()
{
    size_t newlines = (SIZE_MAX - (SIZE_MAX % 64)) / 64;
    return (((SIZE_MAX - newlines) - (SIZE_MAX - newlines) % 4) / 4 * 3);
}

size_t base64_encode_len(size_t input_len)
{
    size_t len;

    len = (input_len + 2) / 3 * 4;
    if (len % 64) {
        len += len / 64 + 1;
    }
    else {
        len += len / 64;
    }
    return (len);
}

size_t base64_decode_len(const uint8_t *input, size_t input_len)
{
    size_t len = 0;
    int padding = 0;

    for (size_t i = 0; i < input_len; i++) {
        if (!ft_isspace(input[i])) {
            len++;
        }
    }
    while (input_len > 0) {
        if (input[input_len - 1] == '=') {
            padding++;
        }
        else if (!ft_isspace(input[input_len - 1])) {
            break;
        }
        input_len--;
    }

    return (len / 4 * 3 - padding);
}

uint8_t *base64_encode(const uint8_t *input, size_t input_len, size_t *output_len)
{
    uint8_t octet_1, octet_2, octet_3;
    uint8_t *output;
    size_t j = 0;
    size_t i = 0;
    size_t lines = 0;

    if (input_len > base64_max_input_len()) {
        error_str("base64", ERR_INPUT_OVERFLOW);
        return (NULL);
    }
    *output_len = base64_encode_len(input_len);
    output = malloc(*output_len + 1);
    if (!output) {
        error_str("base64", ERR_MALLOC);
        return (NULL);
    }
    while (i < input_len && j < *output_len - 1) {
        octet_1 = input[i++];
        octet_2 = i < input_len ? input[i++] : 0;
        octet_3 = i < input_len ? input[i++] : 0;

        output[j++] = base64_enc_table[(octet_1 >> 2)];
        output[j++] = base64_enc_table[(octet_1 << 4 | octet_2 >> 4) & 0x3F];
        output[j++] = base64_enc_table[(octet_2 << 2 | octet_3 >> 6) & 0x3F];
        output[j++] = base64_enc_table[octet_3 & 0x3F];

        if (i < input_len && (j - lines) % 64 == 0) {
            output[j++] = '\n';
            lines++;
        }
    }
    if (i % 3 >= 1) {
        output[j - 1] = '=';
        if (i % 3 == 1) {
            output[j - 2] = '=';
        }
    }
    output[j++] = '\n';
    output[j] = '\0';
    return (output);
}

int base64_validate(const uint8_t *input, size_t input_len, int eof)
{
    size_t chars = 0;
    size_t padding = 0;
    int newline_found = 0;

    if (!input) {
        return (0);
    }
    while (input_len > 0) {
        if (eof && input[input_len - 1] == '\n' && !newline_found) {
            newline_found = 1;
        }
        else if (!ft_isspace(input[input_len - 1])) {
            if (eof && !newline_found) {
                return (0);
            }
            if (input[input_len - 1] == '=') {
                if (!eof || chars > padding || padding >= 2) {
                    return (0);
                }
                padding++;
            }
            else if (!is_base64(input[input_len - 1])) {
                return (0);
            }
            chars++;
        }
        input_len--;
    }
    return (chars && (chars % 4 == 0 || !eof));
}

uint8_t *base64_decode(const uint8_t *buf, size_t buf_len,
                       size_t *output_len, int eof)
{
    uint8_t sextet[4];
    static uint8_t excess[3];
    static uint8_t excess_size = 0;
    size_t input_len = buf_len + excess_size;
    uint8_t input[input_len];
    uint8_t *output;
    size_t i = 0;
    size_t j = 0;
    int k = 0;

    for (i = 0; i < excess_size; i++) {
        input[i] = excess[i];
    }
    ft_memcpy(input + i, buf, buf_len);
    if (!base64_validate(input, input_len, eof)) {
        return (NULL);
    }
    *output_len = base64_decode_len(input, input_len);
    output = malloc(*output_len);
    if (!output) {
        error_str("base64", ERR_MALLOC);
        return (NULL);
    }
    for (i = 0; i < input_len && j < *output_len;) {
        k = 0;
        for (; i < input_len && k < 4; i++) {
            if (ft_isspace(input[i])) {
                continue;
            }
            sextet[k++] = input[i] == '=' ?
                0x40 : base64_dec_table[input[i] - 43];
        }
        if (k < 4) {
            break;
        }
        output[j++] = (sextet[0] << 2) | (sextet[1] >> 4);
        if (sextet[2] != 0x40) {
            output[j++] = (sextet[1] << 4) | (sextet[2] >> 2);
            if (sextet[3] != 0x40) {
                output[j++] = (sextet[2] << 6) | (sextet[3]);
            }
        }
    }
    if (i < input_len) {
        excess_size = input_len - i;
        for (j = 0; i < input_len; i++, j++) {
            excess[j] = input[i];
        }
    }
    return (output);
}

int base64_io(int in_fd, int out_fd, int decode)
{
    uint8_t buffer[BASE64_BUFFER_SIZE];
    uint8_t buffer2[BASE64_BUFFER_SIZE];
    uint8_t *result = NULL;
    ssize_t bytes_read = 1;
    ssize_t bytes_read2 = 0;
    size_t len;

    ssize_t count;
    while (bytes_read) {
        count = 0;
        if (bytes_read2) {
            ft_memcpy(buffer, buffer2, bytes_read2);
            count += bytes_read2;
            bytes_read2 = 0;
        }
        while (count < BASE64_BUFFER_SIZE) {
            bytes_read = read(in_fd, buffer + count, BASE64_BUFFER_SIZE - count);
            if (bytes_read < 0) {
                error_other("base64");
                return (-1);
            }
            if (bytes_read == 0 && count == 0) {
                return (0);
            }
            count += bytes_read;
            if (bytes_read == 0) {
                break;
            }
            if (count == BASE64_BUFFER_SIZE) {
                bytes_read2 = read(in_fd, buffer2, BASE64_BUFFER_SIZE);
                if (bytes_read2 < 0) {
                    return (-1);
                }
                break;
            }
        }
        if (decode) {
            result = base64_decode(buffer, count, &len, !bytes_read || !bytes_read2);
        }
        else {
            result = base64_encode(buffer, count, &len);
        }
        if (!result) {
            return (-1);
        }
        if (write(out_fd, result, len) < 0) {
            free(result);
            error_other("base64");
            return (-1);
        }
        free(result);
    }
    return (0);
}
