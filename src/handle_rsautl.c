#include "rsa.h"
#include "libft.h"
#include "ftarg.h"
#include "fterror.h"
#include "ftmath.h"
#include "bitwise.h"
#include "hex_utils.h"

#include <assert.h>
#include <fcntl.h>
#include <errno.h>

void print_rsautl_usage(int fd, e_command command)
{
    ft_dprintf(fd, "usage: %s %s [options]\n", PROGRAM_NAME, commands[command].str);
    ft_dprintf(fd, "Valid options are:\n");
    ft_dprintf(fd, " %-18s%s\n", "-in infile", "Input file");
    ft_dprintf(fd, " %-18s%s\n", "-out outfile", "Output file");
    ft_dprintf(fd, " %-18s%s\n", "-inkey val", "Input key");
    ft_dprintf(fd, " %-18s%s\n", "-pubin", "Input is an RSA public");
    ft_dprintf(fd, " %-18s%s\n", "-encrypt", "Encrypt with public key");
    ft_dprintf(fd, " %-18s%s\n", "-decrypt", "Decrypt with private key");
    ft_dprintf(fd, " %-18s%s\n", "-hexdump", "Hex dump output");
}

int rsautl_hexdump(int fd, uint64_t input, e_command command) {
    char output[64];
    char *hex_str;
    unsigned char c;
    ssize_t i = 0;
    size_t len = sizeof(input);
    size_t zeroes = 0;

    for (size_t j = 0; j < sizeof(input); j++) {
        c = input >> (j * 8) & 0xFF;
        if (c != 0 && c != ' ') {
            break;
        }
        zeroes++;
    }
    ft_memcpy(output, "0000 -", 6);
    i += 6;
    hex_str = bytes_to_hex_str((unsigned char*)(&input), 0, len);
    if (!hex_str) {
        error_str(commands[command].str, ERR_MALLOC);
        return (-1);
    }
    for (ssize_t j = len * 2 - 1; j > (ssize_t)zeroes * 2 - 1; j -= 2) {
        output[i++] = ' ';
        output[i++] = hex_str[j - 1];
        output[i++] = hex_str[j];
    }
    free(hex_str);
    if (!zeroes) {
        output[i++] = '-';
    }
    while (i < 57) {
        output[i++] = ' ';
    }
    for (size_t j = 0; j < len - zeroes; j++) {
        c = input >> ((8 - j - 1) * 8) & 0xFF;
        if (!ft_isprint(c)) {
            c = '.';
        }
        output[i++] = c;
    }
    output[i++] = '\n';
    if (zeroes != len && write(fd, output, i) < 0) {
        return (-1);
    }
    if (zeroes && write(fd, "0008 - <SPACES/NULS>\n", 21) < 0) {
        return (-1);
    }
    return (0);
}

int rsautl_print(_s_rsautl_config *conf, s_rsa_key *key, unsigned char *input,
                 ssize_t len, e_command command)
{
    uint64_t exp;
    uint64_t mod;
    uint64_t res;
    uint64_t msg = 0;
    size_t size = sizeof(uint64_t);
    unsigned char c;

    if (!conf || !input || !key) {
        error_errno(commands[command].str, "rsautl_print()", EINVAL);
        return (-1);
    }
    exp = conf->decrypt ? key->priv_exp : key->pub_exp;
    mod = key->modulus;
    for (size_t i = 0, j = size - len; i < size; i++, j++) {
        msg |= (uint64_t)input[i] << ((len - i - 1) * size);
    }
    if (msg > key->modulus) {
        error_str(commands[command].str, "data greater than mod len");
        return (-1);
    }
    res = power_mod(msg, exp, mod);
    if (conf->hexdump && rsautl_hexdump(conf->io.out_fd, res, command) < 0) {
        error_file(commands[command].str, conf->io.out_file);
        return (-1);
    }
    else if (!conf->hexdump) {
        for (size_t i = 0; i < size; i++) {
            c = res >> ((8 - i - 1) * 8) & 0xFF;
            if (write(conf->io.out_fd, &c, 1) < 0) {
                error_file(commands[command].str, conf->io.out_file);
                return (-1);
            }
        }
    }
    return (0);
}

ssize_t rsautl_read(_s_rsautl_config *conf, unsigned char *dst, ssize_t len,
                e_command command)
{
    unsigned char buf[len * 2];
    ssize_t bytes_read;

    if (!conf || !dst) {
        error_errno(commands[command].str, "rsautl_read()", EINVAL);
        return (-1);
    }
    bytes_read = read_full_buffer(conf->io.in_fd, (char*)buf, len * 2);
    if (bytes_read < 0) {
        error_file(commands[command].str, conf->key_file);
        return (-1);
    }
    if (!bytes_read) {
        error_str(commands[command].str, "Error reading input Data");
        return (-1);
    }
    if (conf->cryptset && (bytes_read > len || (bytes_read < len && !conf->decrypt))) {
        error_str(commands[command].str, "RSA operation error");
    }
    if (conf->cryptset && !conf->decrypt && bytes_read < len) {
        error_str(commands[command].str, "data too small for key size");
        return (-1);
    }
    if (conf->cryptset && !conf->decrypt && bytes_read > len) {
        error_str(commands[command].str, "data too large for key size");
        return (-1);
    }
    if ((!conf->cryptset || conf->decrypt) && bytes_read > len) {
        error_str(commands[command].str, "data greater than mod len");
        return (-1);
    }
    ft_memcpy(dst, buf, len);

    return (bytes_read);
}

int parse_rsautl_options(int argc, char *argv[], _s_rsautl_config *config,
                         e_command command)
{
    s_ftarg_opt options[] = {{'i', 0,      "in", 1}, {'o', 0,     "out", 1},
                             {'k', 0,   "inkey", 1}, {'p', 0,   "pubin", 0},
                             {'e', 0, "encrypt", 0}, {'d', 0, "decrypt", 0},
                             {'h', 0, "hexdump", 0}};
    int optcount = sizeof(options) / sizeof((options)[0]);
    int opt;

    optind = 2;
    while ((opt = ftarg_getopt(argc, argv, options, optcount)) != -1)
    {
        if (opt == '?') {
            error_arg(commands[command].str, optarg, ARG_UNRECOGNIZED);
            return (-1);
        }
        if (optarg[1] == '=' && opt != 'i' && opt != 'o' && opt != 'k') {
            error_arg(commands[command].str, optarg, ARG_NO_VALUE);
            return (-1);
        }
        if (!optval && (opt == 'i' || opt == 'o' || opt == 'k')) {
            error_arg(commands[command].str, optarg, ARG_MISSING_VALUE);
            return (-1);
        }
        if (opt == 'i') {
            config->io.in_file = optval;
        }
        else if (opt == 'o') {
            config->io.out_file = optval;
        }
        else if (opt == 'k') {
            config->key_file = optval;
        }
        else if (opt == 'p') {
            config->pubin = 1;
        }
        else if (opt == 'e') {
            config->decrypt = 0;
            config->cryptset = 1;
        }
        else if (opt == 'd') {
            config->decrypt = 1;
            config->cryptset = 1;
        }
        else if (opt == 'h') {
            config->hexdump = 1;
        }
    }
    if (optind < argc) {
        error_arg(commands[command].str, NULL, ARG_EXTRA);
        return (-1);
    }
    return (optind);
}

int handle_rsautl(int argc, char *argv[], e_command command)
{
    _s_rsautl_config config = {{NULL, NULL, 0, 0}, NULL, 0, 0, 0, 0, 0};
    unsigned char msg[8] = {0};
    s_rsa_key key;
    ssize_t len;
    int ret;

    assert(command == rsautl);

    if (parse_rsautl_options(argc, argv, &config, command) < 0) {
        print_rsautl_usage(STDERR_FILENO, command);
        return (1);
    }
    if (config.decrypt && config.pubin) {
        error_str(commands[command].str,
                  "A private key is needed for this operation");
        return (1);
    }
    if (!config.key_file) {
        error_str(commands[command].str, "no keyfile specified");
        error_str(commands[command].str, config.pubin ? ERR_PUB_KEY : ERR_PRIV_KEY);
        return (1);
    }
    config.key_fd = open(config.key_file, O_RDONLY);
    if (config.key_fd < 0) {
        error_file(commands[command].str, config.key_file);
        return (1);
    }
    ret = rsa_get_key(config.key_fd, config.key_file, &key, config.pubin,
                      NULL, 0, command);
    if (close(config.key_fd) < 0) {
        error_file(commands[command].str, config.key_file);
        return (1);
    }
    if (ret < 0) {
        return (1);
    }
    if (set_fds(&config.io, commands[command].str) < 0) {
        return (1);
    }
    len = rsautl_read(&config, msg, sizeof(msg), command);
    if (len < 0) {
        close_fds(&config.io, commands[command].str);
        return (1);
    }
    ret = rsautl_print(&config, &key, msg, len, command);
    if (close_fds(&config.io, commands[command].str) < 0) {
        return (1);
    }
    return (ret < 0 ? 1 : 0);
}
