#include "des.h"
#include "libft.h"
#include "ftarg.h"
#include "fterror.h"
#include "hex_utils.h"
#include "base64.h"
#include "pbkdf.h"
#include "rand.h"
#include "md5.h"
#include "sha256.h"

#include <fcntl.h>
#include <assert.h>
#include <unistd.h>

void print_des_usage(int fd, e_command command)
{
    ft_dprintf(fd, "usage: ft_ssl %s [options]\n", commands[command].str);
    ft_dprintf(fd, "Valid options are:\n");
    ft_dprintf(fd, " %-18s%s\n", "-a", "Base64 encode/decode");
    ft_dprintf(fd, " %-18s%s\n", "-d", "Decrypt");
    ft_dprintf(fd, " %-18s%s\n", "-e", "Encrypt");
    ft_dprintf(fd, " %-18s%s\n", "-i infile", "Input file");
    ft_dprintf(fd, " %-18s%s\n", "-k val", "Key, in hex");
    ft_dprintf(fd, " %-18s%s\n", "-o outfile", "Output file");
    ft_dprintf(fd, " %-18s%s\n", "-p val", "Password, in ascii");
    ft_dprintf(fd, " %-18s%s\n", "-s val", "Salt, in hex");
    ft_dprintf(fd, " %-18s%s\n", "-v val", "IV, in hex");
}

int read_password(char **dst, e_command command, const char *postfix, int verify)
{
    const char *command_str;
    size_t size = 0;
    size_t tmp_size = 0;

    command = (command == des) ? des_cbc : command;
    command_str = commands[command].str;

    ft_printf("enter %s %s password:", command_str, postfix);
    *dst = getpass("");
    if (*dst == NULL) {
        error_str(command_str, ERR_GETPASS);
        return (-1);
    }
    size = ft_strlen(*dst);
    tmp_size = size;
    if (verify && size <= DES_MAX_PASS_LEN) {
        size_t tmp_size = size;
        char tmp[tmp_size + 1];

        ft_memcpy(tmp, *dst, tmp_size + 1);
        ft_printf("Verifying - enter %s %s password:", command_str, postfix);
        *dst = getpass("");
        if (*dst == NULL) {
            error_str(command_str, ERR_GETPASS);
            return (-1);
        }
        size = ft_strlen(*dst);
        if (size <= DES_MAX_PASS_LEN && (size != tmp_size || ft_strcmp(*dst, tmp))) {
            ft_dprintf(STDERR_FILENO, "Verify failure\nbad password read\n");
            return (-1);
        }
    }
    if (size > DES_MAX_PASS_LEN || tmp_size > DES_MAX_PASS_LEN) {
        ft_dprintf(STDERR_FILENO,
            "bad password read\nmaximum length is %d characters\n", DES_MAX_PASS_LEN);
        return (-1);
    }
    return (*dst[0] == 0 ? -1 : 0);
}

int des_arg_to_hex(unsigned char *dst, const char *arg, size_t len,
                   const char *param, e_command command)
{
    const char *command_str = commands[command].str;
    size_t arg_len = ft_strlen(arg);
    int val;

    if (arg_len > len * 2) {
        ft_dprintf(STDERR_FILENO, "%s: %s: ", PROGRAM_NAME, command_str);
        ft_dprintf(STDERR_FILENO, "hex string is too long, ignoring excess\n");
    }
    else if (arg_len < len * 2) {
        ft_dprintf(STDERR_FILENO, "%s: %s: hex string is too", PROGRAM_NAME, command_str);
        ft_dprintf(STDERR_FILENO, " short, padding with zero bytes to length\n");
    }
    ft_bzero(dst, len);
    for (size_t i = 0, j = 0; i < len && j < arg_len; i++, j+=2) {
        val = hex_str_to_int(arg + j);
        if (val < 0) {
            ft_dprintf(STDERR_FILENO, "%s: %s: non-hex ", PROGRAM_NAME, command_str);
            ft_dprintf(STDERR_FILENO, "digit, invalid hex %s value\n", param);
            return (-1);
        }
        dst[i] = val;
    }
    return (0);
}

int des_generate_keyiv(char *pass, unsigned char *salt, size_t salt_len,
                       unsigned char *buf, size_t len, e_command command)
{
    int ret;

    if (!pass || !salt || !buf) {
        error_str(commands[command].str,
                  "invalid arguments passed to des_generate_keyiv()");
        return (-1);
    }
    if (ENABLE_PBKDF2) {
        ret = pbkdf2(pass, ft_strlen(pass), salt, salt_len,
                     DES_PBKDF2_ITERATIONS, sha256_str, SHA256_BLOCK_SIZE,
                     SHA256_OUTPUT_SIZE, len, buf);
    }
    else {
        ret = pbkdf1(pass, ft_strlen(pass), salt, salt_len,
                     DES_PBKDF1_ITERATIONS, md5_str, MD5_OUTPUT_SIZE, len, buf);
    }
    if (ret < 0) {
        error_other(commands[command].str);
    }
    return (ret);
}

int des_encode(_s_des_config *config, e_command command)
{
    int ret = 0;
    ssize_t bytes_read = 1;
    size_t magic_len = ft_strlen(DES_SALT_MAGIC) + sizeof(config->salt);
    size_t i = 0;
    unsigned char rbuffer[DES_BUFFER_SIZE];
    unsigned char wbuffer[DES_BUFFER_SIZE + magic_len + 8];
    unsigned char input[8];

    if (!config->key_param || config->password) {
        i = magic_len;
        ft_memcpy(wbuffer, DES_SALT_MAGIC, ft_strlen(DES_SALT_MAGIC));
        ft_memcpy(wbuffer + ft_strlen(DES_SALT_MAGIC),
                config->salt, sizeof(config->salt));
    }
    else {
        magic_len = 0;
    }
    for (size_t count = 0; bytes_read; count = 0) {
        while (count < DES_BUFFER_SIZE) {
            bytes_read = read(config->io.in_fd, rbuffer + count,
                              DES_BUFFER_SIZE - count);
            if (bytes_read < 0) {
                error_file(commands[command].str, config->io.in_file);
                return (-1);
            }
            count += bytes_read;
            if (!bytes_read || count == DES_BUFFER_SIZE) {
                break;
            }
        }
        while (i - magic_len < count || (i - magic_len == count && !bytes_read)) {
            for (ssize_t j = 0; j < 8; j++) {
                if (i - magic_len + j < count) {
                    input[j] = rbuffer[i - magic_len + j];
                }
                else {
                    input[j] = 8 - (count - (i - magic_len));
                }
            }
            if (command != des_ecb) {
                des_block(wbuffer + i, input, config->key, config->iv, 0);
                ft_memcpy(config->iv, wbuffer + i, 8);
            }
            else {
                des_block(wbuffer + i, input, config->key, NULL, 0);
            }
            i += 8;
        }
        if (config->base) {
            uint8_t *tmp = base64_encode(wbuffer, i, &i);
            if (!tmp) {
                return (-1);
            }
            ret = write(config->io.out_fd, tmp, i);
            free(tmp);
        }
        else {
            ret = write(config->io.out_fd, wbuffer, i);
        }
        if (ret < 0) {
            error_file(commands[command].str, config->io.out_file);
            return (-1);
        }
        magic_len = 0;
        i = 0;
    }
    return (0);
}

int des_decode(_s_des_config *config, e_command command)
{
    ssize_t bytes_read = 1;
    ssize_t bytes_read2 = 0;
    uint8_t padding_char = 0;
    uint8_t padding_found = 0;
    size_t magic_len = 0;
    unsigned char rbuffer[DES_BUFFER_SIZE];
    unsigned char rbuffer2[DES_BUFFER_SIZE];
    unsigned char wbuffer[DES_BUFFER_SIZE];
    int key_set = (config->key_param && !config->password);

    if (!key_set) {
        magic_len = ft_strlen(DES_SALT_MAGIC) + sizeof(config->salt);
    }
    for (size_t count = 0, i = 0; bytes_read; count = 0, i = 0) {
        if (bytes_read2) {
            ft_memcpy(rbuffer, rbuffer2, bytes_read2);
            count += bytes_read2;
            bytes_read2 = 0;
        }
        while (count < DES_BUFFER_SIZE) {
            bytes_read = read(config->io.in_fd, rbuffer + count,
                              DES_BUFFER_SIZE - count);
            if (bytes_read < 0 || (!bytes_read && !count)) {
                error_str(commands[command].str, "Error reading input file");
                return (-1);
            }
            count += bytes_read;
            if (!bytes_read) {
                break;
            }
            if (count == DES_BUFFER_SIZE) {
                bytes_read2 = read(config->io.in_fd, rbuffer2, BASE64_BUFFER_SIZE);
                if (bytes_read2 < 0) {
                    return (-1);
                }
                break;
            }
        }
        if (config->base) {
            uint8_t *tmp = base64_decode(rbuffer, count, &count,
                                         !bytes_read || !bytes_read2);
            if (!tmp) {
                error_str(commands[command].str, (!bytes_read || !bytes_read2) ?
                    "error reading input file" : "bad decrypt");
                return (-1);
            }
            ft_memcpy(rbuffer, tmp, count);
            free(tmp);
        }
        if (!key_set) {
            if (count < magic_len) {
                error_str(commands[command].str, "error reading input file");
                return (-1);
            }
            if (ft_memcmp(rbuffer, DES_SALT_MAGIC, ft_strlen(DES_SALT_MAGIC))) {
                error_str(commands[command].str, "bad magic number");
                return (-1);
            }
            ft_memcpy(config->salt, rbuffer + ft_strlen(DES_SALT_MAGIC),
                       sizeof(config->salt));

            unsigned char tmpkeyiv[sizeof(config->key) + sizeof(config->iv)];
            if (des_generate_keyiv(config->password, config->salt, sizeof(config->salt),
                                   tmpkeyiv, sizeof(tmpkeyiv), command) < 0) {
                return (-1);
            }
            if (!config->key_param) {
                ft_memcpy(config->key, tmpkeyiv, sizeof(config->key));
            }
            if (command != des_ecb && !config->iv_param) {
                ft_memcpy(config->iv, tmpkeyiv + sizeof(config->key), sizeof(config->iv));
            }
            key_set = 1;
            i += magic_len;
        }
        for (; i + 8 <= count; i += 8) {
            if (command != des_ecb) {
                des_block(wbuffer + (i - magic_len), rbuffer + i,
                          config->key, config->iv, 1);
                ft_memcpy(config->iv, rbuffer + i, 8);
            }
            else {
                des_block(wbuffer + (i - magic_len), rbuffer + i,
                          config->key, NULL, 1);
            }
        }
        if (i == count && !bytes_read2) {
            padding_char = wbuffer[i - magic_len - 1];
            padding_found = 0;
            for (size_t j = i; j > 0 && j > i - 8; j--) {
                if (wbuffer[j - magic_len - 1] == padding_char) {
                    padding_found++;
                }
                if (padding_found == padding_char) {
                    i -= padding_found;
                    break;
                }
            }
        }
        if (write(config->io.out_fd, wbuffer, i - magic_len) < 0) {
            error_file(commands[command].str, config->io.out_file);
            return (-1);
        }
        if (padding_found != padding_char || i + padding_found < count) {
            error_str(commands[command].str, "bad decrypt");
            return (-1);
        }
        if (!bytes_read2) {
            break;
        }
    }
    return (0);
}

int parse_des_options(int argc, char *argv[],
                      _s_des_config *config, e_command command)
{
    s_ftarg_opt options[] = {{'a', 'a', NULL, 0}, {'d', 'd', NULL, 0},
                             {'e', 'e', NULL, 0}, {'i', 'i', NULL, 1},
                             {'k', 'k', NULL, 1}, {'o', 'o', NULL, 1},
                             {'p', 'p', NULL, 1}, {'s', 's', NULL, 1},
                             {'v', 'v', NULL, 1}};
    int optcount = sizeof(options) / sizeof((options)[0]);
    int opt;

    optind = 2;
    while ((opt = ftarg_getopt(argc, argv, options, optcount)) != -1)
    {
        if (opt == '?') {
            error_arg(commands[command].str, optarg, ARG_UNRECOGNIZED);
            return (-1);
        }
        if (optarg[1] == '=' && (opt == 'a' || opt == 'd' || opt == 'e')) {
            error_arg(commands[command].str, optarg, ARG_NO_VALUE);
            return (-1);
        }
        if (!optval && opt != 'a' && opt != 'd' && opt != 'e') {
            error_arg(commands[command].str, optarg, ARG_MISSING_VALUE);
            return (-1);
        }
        if (opt == 'a') {
            config->base = 1;
        }
        else if (opt == 'd') {
            config->decode = 1;
        }
        else if (opt == 'e') {
            config->decode = 0;
        }
        else if (opt == 'i') {
            config->io.in_file = optval;
        }
        else if (opt == 'k') {
            config->key_param = optval;
        }
        else if (opt == 'o') {
            config->io.out_file = optval;
        }
        else if (opt == 'p') {
            config->password = optval;
        }
        else if (opt == 's') {
            config->salt_param = optval;
        }
        else if (opt == 'v') {
            config->iv_param = optval;
        }
    }
    if (optind < argc) {
        error_arg(commands[command].str, NULL, ARG_EXTRA);
        return (-1);
    }
    return (optind);
}

int handle_des(int argc, char *argv[], e_command command)
{
    _s_des_config config =
        {0, 0, {NULL, NULL, 0, 0}, NULL, NULL, NULL, NULL, {0}, {0}, {0}};
    int ret = 0;
    int index;

    assert(command == des || command == des_cbc || command == des_ecb);

    index = parse_des_options(argc, argv, &config, command);
    if (index < 0) {
        print_des_usage(STDERR_FILENO, command);
        return (1);
    }
    if (command != des_ecb && config.key_param && !config.iv_param && !config.password) {
        ft_dprintf(STDERR_FILENO, "iv undefined\n");
        return (1);
    }
    if (set_fds(&config.io, commands[command].str) < 0) {
        return (1);
    }
    if (config.iv_param && command != des_ecb &&
        des_arg_to_hex(config.iv, config.iv_param, sizeof(config.iv), "iv", command) < 0) {
        close_fds(&config.io, commands[command].str);
        return (1);
    }
    if (config.key_param &&
        des_arg_to_hex(config.key, config.key_param, sizeof(config.key), "key", command) < 0) {
        close_fds(&config.io, commands[command].str);
        return (1);
    }
    if (((command != des_ecb && (!config.key_param || !config.iv_param)) ||
        (command == des_ecb && !config.key_param)) && !config.password) {
        char *postfix = config.decode ? "decryption" : "encryption";
        if (read_password(&config.password, command, postfix, !config.decode) < 0) {
            close_fds(&config.io, commands[command].str);
            return (1);
        }
    }
    if (!config.decode && (!config.key_param || config.password)) {
        if (config.salt_param) {
            if (des_arg_to_hex(config.salt, config.salt_param,
                               sizeof(config.salt), "salt", command) < 0) {
                close_fds(&config.io, commands[command].str);
                return (1);
            }
        }
        else if (rand_fill(config.salt, sizeof(config.salt)) < 0) {
            error_other(commands[command].str);
            close_fds(&config.io, commands[command].str);
            return (1);
        }
        unsigned char tmpkeyiv[sizeof(config.key) + sizeof(config.iv)];

        if (des_generate_keyiv(config.password, config.salt, sizeof(config.salt),
                               tmpkeyiv, sizeof(tmpkeyiv), command) < 0) {
            close_fds(&config.io, commands[command].str);
            return (1);
        }
        if (!config.key_param) {
            ft_memcpy(config.key, tmpkeyiv, sizeof(config.key));
        }
        if (command != des_ecb && !config.iv_param) {
            ft_memcpy(config.iv, tmpkeyiv + sizeof(config.key), sizeof(config.iv));
        }
    }
    ret = config.decode ? des_decode(&config, command) : des_encode(&config, command);
    if (close_fds(&config.io, commands[command].str) < 0) {
        return (1);
    }
    return (ret < 0 ? 1 : 0);
}
