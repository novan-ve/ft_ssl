#include "rsa.h"
#include "libft.h"
#include "fterror.h"
#include "ftmath.h"
#include "base64.h"
#include "rand.h"
#include "des.h"
#include "hex_utils.h"

#include <errno.h>

int rsa_create_priv(const char *rand_file, s_rsa_key *key, e_command command)
{
    uint64_t totient;

    if (!key) {
        ft_dprintf(STDERR_FILENO, "%s: %s: invalid key parameter (NULL)\n",
            PROGRAM_NAME, commands[command].str);
        return (-1);
    }
    key->version = RSA_VERSION;
    key->pub_exp = RSA_PUBLIC_EXPONENT;
    key->prime1 = srandom_prime(rand_file, RSA_PRECISION, 1);
    if (key->prime1) {
        key->prime2 = srandom_prime(rand_file, RSA_PRECISION, 1);
    }
    if (!key->prime1 || !key->prime2) {
        error_other(commands[command].str);
        return (-1);
    }
    totient = (uint64_t)(key->prime1 - 1) * (uint64_t)(key->prime2 - 1);

    key->modulus = (uint64_t)key->prime1 * (uint64_t)key->prime2;
    key->priv_exp = modular_inverse(totient, key->pub_exp);
    if (!key->priv_exp) {
        error_str(commands[command].str, ERR_MODULAR_INVERSE);
        return (-1);
    }
    key->coefficient = modular_inverse(key->prime1, key->prime2);
    if (!key->coefficient) {
        error_str(commands[command].str, ERR_MODULAR_INVERSE);
        return (-1);
    }
    key->exponent1 = key->priv_exp % (key->prime1 - 1);
    key->exponent2 = key->priv_exp % (key->prime2 - 1);

    return (1);
}

unsigned char *rsa_pem_to_der(char *data, int encrypted, size_t salt_len,
                              size_t *der_len, e_command command)
{
    size_t data_len = 0;
    size_t start = 0;
    char *header = NULL;

    if (!data) {
        error_errno(commands[command].str, "rsa_pem_to_der()", EINVAL);
        return (NULL);
    }
    data_len = ft_strlen(data);
    if (encrypted) {
        header = ft_strnstr(data, RSA_DEK_HDR, data_len);
        if (!header) {
            return (NULL);
        }
        start = header - data + ft_strlen(RSA_DEK_HDR) + salt_len * 2;
    }
    return (base64_decode((uint8_t*)(data + start), data_len - start, der_len, 1));
}

int rsa_get_salt(char *key, unsigned char *salt, size_t len, e_command command)
{
    char *salt_data;
    int converted_hex;

    if (!key || !salt || len % 2) {
        error_errno(commands[command].str, "rsa_get_salt()", EINVAL);
        return (-1);
    }

    salt_data = ft_strnstr(key, RSA_DEK_HDR, ft_strlen(key));
    if (!salt_data) {
        return (0);
    }
    salt_data += ft_strlen(RSA_DEK_HDR);

    for (size_t i = 0; i < len / 2; i++, salt_data += 2) {
        converted_hex = hex_str_to_int(salt_data);
        if (converted_hex < 0) {
            return (-1);
        }
        salt[i] = converted_hex;
    }
    return (1);
}

unsigned char *rsa_decrypt_des(const char *filename, unsigned char *input,
                               unsigned char *salt, size_t salt_len,
                               char *passin, size_t *len, int public, e_command command)
{
    char *password = passin ? passin : rsa_read_password_dec(filename, command);
    unsigned char iv[salt_len];
    unsigned char key[8];
    unsigned char *result = NULL;
    unsigned char padding_char = 0;
    int padding_found = 0;
    size_t i = 0;

    if (!input || !len) {
        error_errno(commands[command].str, "rsa_decrypt_des()", EINVAL);
        return (NULL);
    }
    if (!password || !password[0]) {
        ft_dprintf(STDERR_FILENO, "unable to write key\n");
        return (NULL);
    }
    if (des_generate_keyiv(password, salt, salt_len, key, sizeof(key), command) < 0) {
        ft_dprintf(STDERR_FILENO, "unable to generate key\n");
        return (NULL);
    }
    ft_memcpy(iv, salt, salt_len);

    unsigned char output[*len];

    for (i = 0; i + 8 <= *len; i += 8) {
        des_block(output + i, input + i, key, iv, 1);
        ft_memcpy(iv, input + i, 8);
    }
    if (i == *len) {
        padding_char = output[i - 1];
        for (size_t j = i; j > 0 && j > i - 8; j--) {
            if (output[j - 1] == padding_char) {
                padding_found++;
            }
            if (padding_found == padding_char) {
                i -= padding_found;
                break;
            }
        }
    }
    if (padding_found != padding_char || i + padding_found < *len) {
        error_str(commands[command].str, public ? ERR_PUB_KEY : ERR_PRIV_KEY);
        return (NULL);
    }
    result = (unsigned char*)malloc(sizeof(unsigned char) * (*len));
    if (!result) {
        error_str(commands[command].str, ERR_MALLOC);
    }
    else {
        *len = i;
        ft_memcpy(result, output, *len);
    }
    return (result);
}

int rsa_parse_priv(const unsigned char *data, s_rsa_key *key,
                   size_t len, e_command command)
{
    if (!data || !key) {
        error_errno(commands[command].str, "rsa_parse_key()", EINVAL);
        return (-1);
    }

    uint64_t lengths[] = {
        sizeof(key->version), sizeof(key->modulus), sizeof(key->pub_exp),
        sizeof(key->priv_exp), sizeof(key->prime1), sizeof(key->prime2),
        sizeof(key->exponent1), sizeof(key->exponent2), sizeof(key->coefficient)
    };
    size_t components = sizeof(lengths) / sizeof(*lengths);
    uint64_t nbs[components];
    size_t component_len = 0;
    size_t i = 2;

    key->type = PRIVATE;
    if (len < 2 || data[0] != 0x30 || data[1] >= 0x80 || data[1] != len - 2) {
        return (-1);
    }
    for (size_t j = 0; j < components; j++) {
        if (i + 2 > len || data[i] != 0x2) {
            return (-1);
        }
        component_len = data[i + 1];
        i += 2;
        if (component_len > lengths[j] + 1 || (component_len > lengths[j] && data[i])) {
            return (-1);
        }
        if (i + component_len > len) {
            return (-1);
        }
        nbs[j] = 0;
        for (size_t k = 0; k < component_len; k++) {
            nbs[j] |= (uint64_t)data[i++] << ((component_len - 1 - k) * 8);
        }
    }
    key->version = nbs[0];
    key->modulus = nbs[1];
    key->pub_exp = nbs[2];
    key->priv_exp = nbs[3];
    key->prime1 = nbs[4];
    key->prime2 = nbs[5];
    key->exponent1 = nbs[6];
    key->exponent2 = nbs[7];
    key->coefficient = nbs[8];

    return (0);
}

int rsa_parse_pub(const unsigned char *data, s_rsa_key *key,
                  size_t len, e_command command)
{
    size_t i = 0;
    size_t int_len = 0;
    size_t obj_id_len = ft_strlen(RSA_ASN1_OBJ_ID);
    unsigned char algo_id[obj_id_len + 8];
    unsigned char bitstring[5] = "\x03\x00\x00\x30\x00";
    uint64_t lengths[2] = {sizeof(key->modulus), sizeof(key->pub_exp)};
    uint64_t nbs[2] = {0, 0};

    if (!data || !key) {
        error_errno(commands[command].str, "rsa_parse_key()", EINVAL);
        return (-1);
    }
    if (len < 19 + obj_id_len || len > 17 + obj_id_len + lengths[0] + lengths[1]) {
        return (-1);
    }
    algo_id[0] = 0x30;
    algo_id[1] = len - 2;
    algo_id[2] = 0x30;
    algo_id[3] = obj_id_len + 4;
    algo_id[4] = 0x06;
    algo_id[5] = obj_id_len;
    ft_memcpy(algo_id + 6, RSA_ASN1_OBJ_ID, obj_id_len);
    algo_id[6 + obj_id_len] = 0x05;
    algo_id[7 + obj_id_len] = 0x00;
    if (ft_memcmp(data, algo_id, sizeof(algo_id))) {
        return (-1);
    }
    i += sizeof(algo_id);

    bitstring[1] = len - obj_id_len - 10;
    bitstring[4] = len - obj_id_len - 13;
    if (ft_memcmp(data + i, bitstring, sizeof(bitstring))) {
        return (-1);
    }
    i += sizeof(bitstring);

    for (size_t comp = 0; comp < 2; comp++) {
        if (data[i++] != 0x02 || i + data[i] >= len) {
            return (-1);
        }
        int_len = data[i++];
        if (int_len == 0 || int_len > lengths[comp] + 1 ||
            (int_len > lengths[comp] && data[i] != 0x00)) {
            return (-1);
        }
        for (size_t j = 0; j < int_len; j++) {
            nbs[comp] |= (uint64_t)data[i++] << ((int_len - j - 1) * 8);
        }
    }
    if (i != len) {
        return (-1);
    }
    key->type = PUBLIC;
    key->modulus = nbs[0];
    key->pub_exp = nbs[1];

    return (0);
}

int rsa_get_key(int fd, const char *filename, s_rsa_key *key, int public,
                char *passin, int passin_set, e_command command)
{
    unsigned char *der_data = NULL;
    unsigned char *data = NULL;
    unsigned char salt[8] = {0};
    char pem_data[RSA_BUFFER_SIZE] = {0};
    int des_encrypted = 0;
    size_t len = 0;
    int ret = 0;

    if (!key) {
        error_errno(commands[command].str, "rsa_get_key()", EINVAL);
        return (-1);
    }
    if (rsa_read_key(fd, pem_data, sizeof(pem_data), public, command) < 0) {
        error_str(commands[command].str, public ? ERR_PUB_KEY : ERR_PRIV_KEY);
        return (-1);
    }
    if (rsa_check_key_data(pem_data, public) < 0) {
        error_str(commands[command].str, public ? ERR_PUB_KEY : ERR_PRIV_KEY);
        return (-1);
    }
    des_encrypted = rsa_get_salt(pem_data, salt, sizeof(salt) * 2, command);
    if (des_encrypted < 0) {
        error_str(commands[command].str, public ? ERR_PUB_KEY : ERR_PRIV_KEY);
        return (-1);
    }
    der_data = rsa_pem_to_der(pem_data, des_encrypted, sizeof(salt), &len, command);
    if (!der_data) {
        error_str(commands[command].str, public ? ERR_PUB_KEY : ERR_PRIV_KEY);
        return (-1);
    }
    if (des_encrypted) {
        if (passin_set && !passin[0]) {
            error_str(commands[command].str, public ? ERR_PUB_KEY : ERR_PRIV_KEY);
            return (-1);
        }
        data = rsa_decrypt_des(filename, der_data, salt, sizeof(salt),
                               passin_set ? passin : NULL, &len, public, command);
        free(der_data);
        if (!data) {
            return (-1);
        }
    }
    else {
        data = der_data;
    }
    ret = public ? rsa_parse_pub(data, key, len, command) :
                   rsa_parse_priv(data, key, len, command);
    free(data);
    if (ret < 0) {
        error_str(commands[command].str, public ? ERR_PUB_KEY : ERR_PRIV_KEY);
    }
    return (ret);
}
