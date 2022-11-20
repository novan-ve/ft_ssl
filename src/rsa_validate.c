#include "rsa.h"
#include "libft.h"
#include "fterror.h"
#include "ftmath.h"
#include "hex_utils.h"
#include "base64.h"

#include <errno.h>

char *rsa_skip_newline(char *data, int encrypted, size_t max_line)
{
    size_t spaces = 0;
    char *tmp = data;

    if (!data) {
        return (NULL);
    }
    while (ft_isspace(*data) && *data != '\n') {
        spaces++;
        data++;
    }
    if (spaces > max_line || (encrypted && *data != '\n')) {
        return (NULL);
    }
    if (*data == '\n') {
        return (data + 1);
    }
    else {
        return (tmp);
    }
}

char *rsa_skip_spaces(char *data, size_t max_line)
{
    size_t spaces = 0;

    if (!data) {
        return (NULL);
    }
    while (ft_isspace(*data) && *data != '\n') {
        spaces++;
        data++;
    }
    if (spaces > max_line || *data != '\n') {
        return (NULL);
    }
    return (data + 1);
}

char *rsa_check_encryption(char *data, int *encrypted, size_t max_line)
{
    size_t proc_header_len = ft_strlen(RSA_PROC_HDR);
    size_t dek_header_len = ft_strlen(RSA_DEK_HDR);

    if (!ft_strncmp(data, RSA_PROC_HDR, proc_header_len)) {
        data += proc_header_len;
        if (!(data = rsa_skip_spaces(data, max_line - proc_header_len))) {
            return (NULL);
        }
        if (ft_strncmp(data, RSA_DEK_HDR, dek_header_len)) {
            return (NULL);
        }
        data += dek_header_len;
        for (size_t j = 0; j < 16; j++, data++) {
            if (!is_hex(*data)) {
                return (NULL);
            }
        }
        if (!(data = rsa_skip_spaces(data, max_line - 16 - dek_header_len))) {
            return (NULL);
        }
        *encrypted = 1;
    }
    return (data);
}

char *rsa_check_key_line(char *data, int encrypted, size_t max_chars, size_t max_line)
{
    size_t spaces = 0;
    size_t chars = 0;

    if (!data) {
        return (NULL);
    }
    if (!encrypted) {
        while (ft_isspace(*data) && *data != '\n') {
            spaces++;
            data++;
        }
    }
    while (is_base64(*data) || *data == '=') {
        chars++;
        data++;
    }
    while (ft_isspace(*data) && *data != '\n') {
        spaces++;
        data++;
    }
    if (*data != '\n' || chars == 0 || chars > max_chars || chars + spaces > max_line) {
        return (NULL);
    }
    return (data + 1);
}

int rsa_check_key_data(char *data, int public)
{
    size_t header_len = public ? ft_strlen(RSA_PUB_HDR) : ft_strlen(RSA_PRIV_HDR);
    int encrypted = 0;

    if (!data) {
        return (-1);
    }
    if (!(data = rsa_skip_spaces(data, 505 - header_len))) {
        return (-1);
    }
    if (!(data = rsa_check_encryption(data, &encrypted, 252))) {
        return (-1);
    }
    if (!(data = rsa_skip_newline(data, encrypted, 252))) {
        return (-1);
    }
    while (*data) {
        if (!(data = rsa_check_key_line(data, encrypted, 79, 252))) {
            return (-1);
        }
    }
    return (0);
}

int rsa_check_key(s_rsa_key *key, e_command command)
{
    uint64_t totient = 0;
    uint64_t inverse = 0;
    int ret = 0;

    if (!key || key->type == PUBLIC) {
        error_errno(commands[command].str, "rsa_check_key()", EINVAL);
        return (-1);
    }
    if (!is_prime(key->prime1, RSA_PRECISION, 0)) {
        error_str(commands[command].str, ERR_RSA_PRIME_1);
        ret = -1;
    }
    if (!is_prime(key->prime2, RSA_PRECISION, 0)) {
        error_str(commands[command].str, ERR_RSA_PRIME_2);
        ret = -1;
    }
    if (key->modulus != (uint64_t)key->prime1 * (uint64_t)key->prime2) {
        error_str(commands[command].str, ERR_RSA_MODULUS);
        ret = -1;
    }
    totient = (uint64_t)(key->prime1 - 1) * (uint64_t)(key->prime2 - 1);
    inverse = modular_inverse(totient, key->pub_exp);
    if (key->priv_exp && !inverse) {
        error_str(commands[command].str, ERR_RSA_NO_INVERSE);
        ret = -1;
    }
    else if (key->priv_exp != inverse) {
        error_str(commands[command].str, ERR_RSA_PRIV_EXP);
        ret = -1;
    }
    if (key->exponent1 != key->priv_exp % (key->prime1 - 1)) {
        error_str(commands[command].str, ERR_RSA_EXP_1);
        ret = -1;
    }
    if (key->exponent2 != key->priv_exp % (key->prime2 - 1)) {
        error_str(commands[command].str, ERR_RSA_EXP_2);
        ret = -1;
    }
    inverse = modular_inverse(key->prime1, key->prime2);
    if (key->coefficient && !inverse) {
        error_str(commands[command].str, ERR_RSA_NO_INVERSE);
        ret = -1;
    }
    else if (key->coefficient != inverse) {
        error_str(commands[command].str, ERR_RSA_COEFFICIENT);
        ret = -1;
    }
    return (ret);
}
