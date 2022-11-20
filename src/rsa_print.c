#include "rsa.h"
#include "libft.h"
#include "fterror.h"
#include "ftmath.h"
#include "rand.h"
#include "hex_utils.h"
#include "base64.h"
#include "des.h"

#include <errno.h>

size_t rsa_encrypt_des(uint8_t *dst, uint8_t *src, char *pass,
                       size_t len, uint8_t *salt, size_t saltlen,
                       e_command command)
{
    char *password = pass ? pass : rsa_read_password_enc(command);
    unsigned char input[8];
    unsigned char key[8];
    unsigned char iv[8];
    size_t i = 0;

    if (!dst || !src || !salt) {
        error_errno(commands[command].str, "rsa_encrypt_des()", EINVAL);
        return (0);
    }
    if (!password || !password[0]) {
        ft_dprintf(STDERR_FILENO, "unable to write key\n");
        return (0);
    }
    if (des_generate_keyiv(password, salt, saltlen, key, sizeof(key), command) < 0) {
        ft_dprintf(STDERR_FILENO, "unable to generate key\n");
        return (0);
    }
    ft_memcpy(iv, salt, saltlen);
    while (i <= len) {
        for (size_t j = 0; j < 8; j++) {
            if (i + j < len) {
                input[j] = src[i + j];
            }
            else {
                input[j] = 8 - (len - i);
            }
        }
        des_block(dst + i, input, key, iv, 0);
        ft_memcpy(iv, dst + i, 8);
        i += 8;
    }
    return (i);
}

size_t rsa_key_to_asn1(s_rsa_key *key, uint8_t *buf, size_t len)
{
    if (!key) {
        errno = EINVAL;
        return (0);
    }
    uint64_t components[] = {
        key->version, key->modulus, key->pub_exp, key->priv_exp, key->prime1,
        key->prime2, key->exponent1, key->exponent2, key->coefficient
    };
    size_t component_len = 0;
    size_t i = 2;

    buf[0] = 0x30;
    for (size_t j = 0; j < sizeof(components) / sizeof(components[0]); j++) {
        component_len = intlen(components[j]);
        if (i + 3 + component_len >= len) {
            errno = EOVERFLOW;
            return (0);
        }
        buf[i++] = 0x2;
        if (components[j] >> (component_len * 8 - 1)) {
            buf[i++] = (component_len & 0xFF) + 1;
            buf[i++] = 0x0;
        }
        else {
            buf[i++] = component_len & 0xFF;
        }
        while (component_len > 0) {
            buf[i++] = components[j] >> (8 * (component_len - 1));
            component_len--;
        }
    }
    buf[1] = (i & 0xFF) - 2;

    return (i);
}

int rsa_print_priv_hdr(int fd, int des, uint8_t *salt, size_t saltlen)
{
    char *salt_hex;

    if (write(fd, RSA_PRIV_HDR, ft_strlen(RSA_PRIV_HDR)) < 0) {
        return (-1);
    }
    if (write(fd, "\n", 1) < 0) {
        return (-1);
    }
    if (des) {
        if (write(fd, RSA_PROC_HDR, ft_strlen(RSA_PROC_HDR)) < 0) {
            return (-1);
        }
        if (write(fd, "\n", 1) < 0) {
            return (-1);
        }
        if (write(fd, RSA_DEK_HDR, ft_strlen(RSA_DEK_HDR)) < 0) {
            return (-1);
        }
        salt_hex = bytes_to_hex_str(salt, 1, saltlen);
        if (!salt_hex) {
            return (-1);
        }
        if (write(fd, salt_hex, saltlen * 2) < 0) {
            free(salt_hex);
            return (-1);
        }
        free(salt_hex);
        if (write(fd, "\n\n", 2) < 0) {
            return (-1);
        }
    }
    return (0);
}

int rsa_print_priv(int fd, const char *filename, s_rsa_key *key,
                   e_rsa_encoding encoding, int des, char *pass,
                   e_command command)
{
    uint8_t buf[256];
    uint8_t key_data[sizeof(buf) + 8];
    uint8_t salt[8] = {0};
    ssize_t len = 0;

    if (!key || (des && !pass)) {
        error_errno(commands[command].str, "rsa_print_priv()", EINVAL);
        return (-1);
    }
    len = rsa_key_to_asn1(key, buf, sizeof(buf));
    if (!len) {
        error_errno(commands[command].str, "rsa_print_priv()", errno);
        return (-1);
    }
    if (!des) {
        ft_memcpy(key_data, buf, len);
    }
    else {
        if (rand_fill(salt, sizeof(salt)) < 0) {
            error_other(commands[command].str);
            return (-1);
        }
        len = rsa_encrypt_des(key_data, buf, pass[0] ? pass : NULL, len,
                              salt, sizeof(salt), command);
        if (!len) {
            return (-1);
        }
    }
    if (encoding == PEM) {
        size_t base_len;
        uint8_t *key_data_enc = base64_encode(key_data, len, &base_len);
        if (!key_data_enc) {
            return (-1);
        }
        if (rsa_print_priv_hdr(fd, des, salt, sizeof(salt)) < 0) {
            error_file(commands[command].str, filename);
            return (-1);
        }
        if (write(fd, key_data_enc, base_len) < 0) {
            error_file(commands[command].str, filename);
            return (-1);
        }
        if (write(fd, RSA_PRIV_FTR, ft_strlen(RSA_PRIV_FTR)) < 0) {
            error_file(commands[command].str, filename);
            return (-1);
        }
        if (write(fd, "\n", 1) < 0) {
            error_file(commands[command].str, filename);
            return (-1);
        }
    }
    else if (write(fd, key_data, len) < 0) {
        return (-1);
    }
    return (0);
}

int rsa_print_pub(int fd, const char *filename, s_rsa_key *key,
                  e_rsa_encoding encoding, e_command command)
{
    size_t obj_len = ft_strlen(RSA_ASN1_OBJ_ID);

    if (!key || obj_len > 0xFF) {
        errno = EINVAL;
        return (-1);
    }
    uint8_t buf[256] = {'\x30', '\x0', '\x30', obj_len + 4, '\x6', '\x9'};
    uint64_t components[2] = {key->modulus, key->pub_exp};
    size_t component_len = 0;
    size_t i = 6;

    ft_memcpy(buf + i, RSA_ASN1_OBJ_ID, obj_len);
    i += obj_len;
    ft_memcpy(buf + i, "\x5\x0\x3\x0\x0\x30\x0", 7);
    i += 7;
    for (size_t j = 0; j < sizeof(components) / sizeof(components[0]); j++) {
        component_len = intlen(components[j]);
        buf[i++] = 0x2;
        if (components[j] >> (component_len * 8 - 1)) {
            buf[i++] = (component_len & 0xFF) + 1;
            buf[i++] = 0x0;
        }
        else {
            buf[i++] = component_len & 0xFF;
        }
        while (component_len > 0) {
            buf[i++] = components[j] >> (8 * (component_len - 1));
            component_len--;
        }
    }
    buf[1] = i - 2;
    buf[9 + obj_len] = i - obj_len - 10;
    buf[12 + obj_len] = i - obj_len - 13;
    if (encoding == PEM) {
        size_t len;
        uint8_t *enc = base64_encode(buf, i, &len);
        if (!enc) {
            return (-1);
        }
        if (write(fd, RSA_PUB_HDR, ft_strlen(RSA_PUB_HDR)) < 0 ||
            write(fd, "\n", 1) < 0 ||
            write(fd, enc, len) < 0 ||
            write(fd, RSA_PUB_FTR, ft_strlen(RSA_PUB_FTR)) < 0 ||
            write(fd, "\n", 1) < 0)
        {
            error_file(commands[command].str, filename);
            return (-1);
        }
    }
    else if (write(fd, buf, i) < 0) {
        return (-1);
    }
    return (0);
}

int rsa_print_text_pub(int fd, s_rsa_key *key)
{
    if (write(fd, "Public-Key: ", 12) < 0) {
        return (-1);
    }
    if (ft_dprintf(fd, "(%u bit)\n", bitlen(key->modulus)) < 0) {
        return (-1);
    }
    if (write(fd, "Modulus: ", 9) < 0) {
        return (-1);
    }
    if (ft_putulong_fd(key->modulus, fd) < 0) {
        return (-1);
    }
    if (ft_dprintf(fd, " (%p)\n", key->modulus) < 0) {
        return (-1);
    }
    if (write(fd, "Exponent: ", 10) < 0) {
        return (-1);
    }
    if (ft_putulong_fd(key->pub_exp, fd) < 0) {
        return (-1);
    }
    if (ft_dprintf(fd, " (%p)\n", key->pub_exp) < 0) {
        return (-1);
    }
    return (0);
}

int rsa_print_text_priv(int fd, s_rsa_key *key)
{
    uint64_t values[8] = {
        key->modulus, key->pub_exp, key->priv_exp, key->prime1,
        key->prime2, key->exponent1, key->exponent2, key->coefficient
    };
    const char *value_names[8] = {
        "modulus", "publicExponent", "privateExponent", "prime1",
        "prime2", "exponent1", "exponent2", "coefficient"
    };

    if (write(fd, "Private-Key: ", 13) < 0) {
        return (-1);
    }
    if (ft_dprintf(fd, "(%u bit)\n", bitlen(key->modulus)) < 0) {
        return (-1);
    }
    for (size_t i = 0; i < sizeof(values) / sizeof(*values); i++) {
        if (ft_dprintf(fd, "%s: ", value_names[i]) < 0) {
            return (-1);
        }
        if (ft_putulong_fd(values[i], fd) < 0) {
            return (-1);
        }
        if (ft_dprintf(fd, " (%p)\n", values[i]) < 0) {
            return (-1);
        }
    }
    return (0);
}


int rsa_print_text(int fd, s_rsa_key *key, e_command command)
{
    if (!key) {
        error_errno(commands[command].str, "rsa_print_text()", EINVAL);
        return (-1);
    }
    if (key->type == PUBLIC) {
        return (rsa_print_text_pub(fd, key));
    }
    return (rsa_print_text_priv(fd, key));
}
