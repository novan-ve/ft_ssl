#include "rsa.h"
#include "libft.h"
#include "ftarg.h"
#include "fterror.h"

#include <assert.h>
#include <fcntl.h>

extern char **environ;

void print_rsa_usage(int fd, e_command command)
{
    ft_dprintf(fd, "usage: %s %s [options]\n", PROGRAM_NAME, commands[command].str);
    ft_dprintf(fd, "Valid options are:\n");
    ft_dprintf(fd, " %-18s%s\n", "-inform PEM", "Expect input key in PEM format");
    ft_dprintf(fd, " %-18s%s\n", "-outform PEM", "Output key in PEM format");
    ft_dprintf(fd, " %-18s%s\n", "-in file", "Input file");
    ft_dprintf(fd, " %-18s%s\n", "-passin arg", "Input file pass phrase source");
    ft_dprintf(fd, " %-18s%s\n", "-out file", "Output file");
    ft_dprintf(fd, " %-18s%s\n", "-passout arg", "Output file pass phrase source");
    ft_dprintf(fd, " %-18s%s\n", "-des", "Encrypt with des cipher");
    ft_dprintf(fd, " %-18s%s\n", "-text", "Print the key in text");
    ft_dprintf(fd, " %-18s%s\n", "-noout", "Don't print key out");
    ft_dprintf(fd, " %-18s%s\n", "-modulus", "Print the RSA key modulus");
    ft_dprintf(fd, " %-18s%s\n", "-check", "Verify key consistency");
    ft_dprintf(fd, " %-18s%s\n", "-pubin", "Expect a public key in input file");
    ft_dprintf(fd, " %-18s%s\n", "-pubout", "Output a public key");
}

int rsa_parse_pass_file(char *filename, int skip_line, char *dst,
                        size_t len, e_command command)
{
    ssize_t bytes_read;
    char buf[len];
    char *newline = NULL;
    char *newline2 = NULL;
    int fd;

    fd = open(filename, O_RDONLY);
    if (fd >= 0) {
        bytes_read = read(fd, buf, sizeof(buf) - 1);
        if (close(fd) < 0) {
            error_other(commands[command].str);
            return (-1);
        }
        if (bytes_read > 0) {
            buf[bytes_read] = '\0';
        }
    }
    if (fd < 0 || bytes_read < 0) {
        ft_dprintf(STDERR_FILENO, "Can't open file %s\n", filename);
        ft_dprintf(STDERR_FILENO, "Error getting passwords\n");
        return (-1);
    }
    if (bytes_read > 0) {
        newline = ft_strchr(buf, '\n');
        if (skip_line && newline && newline[1]) {
            newline2 = ft_strchr(newline + 1, '\n');
            if (!newline2) {
                ft_strlcpy(dst, newline + 1, bytes_read - (newline - buf));
            }
            else {
                ft_strlcpy(dst, newline + 1, newline2 - newline);
            }
            return (0);
        }
        else if (!skip_line) {
            if (newline) {
                ft_strlcpy(dst, buf, newline - buf + 1);
            }
            else {
                ft_strlcpy(dst, buf, bytes_read + 1);
            }
            return (0);
        }
    }
    ft_dprintf(STDERR_FILENO, "Error reading password from BIO\n");
    ft_dprintf(STDERR_FILENO, "Error getting passwords\n");
    return (-1);
}

int rsa_parse_pass_fd(int fd, char *buf, size_t len)
{
    ssize_t bytes_read;
    char *newline;

    bytes_read = read(fd, buf, len - 1);
    if (bytes_read <= 0) {
        ft_dprintf(STDERR_FILENO, "Error reading password from BIO\n");
        ft_dprintf(STDERR_FILENO, "Error getting passwords\n");
        return (-1);
    }
    buf[bytes_read] = '\0';
    newline = ft_strchr(buf, '\n');
    if (newline) {
        *newline = '\0';
    }
    return (0);
}

int rsa_parse_pass_env(char *id, char *buf, size_t len)
{
    char *delimiter = NULL;

    if (environ && id && *id) {
        for (int i = 0; environ[i]; i++) {
            delimiter = ft_strchr(environ[i], '=');
            if (!delimiter) {
                break;
            }
            if (ft_strlen(id) != (size_t)(delimiter - environ[i])) {
                continue;
            }
            if (!ft_strncmp(environ[i], id, delimiter - environ[i])) {
                ft_strlcpy(buf, delimiter + 1, len);
                return (0);
            }
        }
    }
    ft_dprintf(STDERR_FILENO, "Can't read environment variable %s\n", id);
    ft_dprintf(STDERR_FILENO, "Error getting passwords\n");
    return (-1);
}

int rsa_parse_pass(char *arg, char *pass_buf, size_t len, int skip_line,
                   e_command command)
{
    if (!arg || !pass_buf) {
        ft_dprintf(STDERR_FILENO, "Invalid arguments passed to rsa_parse_pass\n");
        return (-1);
    }

    char *delimiter = ft_strchr(arg, ':');
    if (delimiter) {
        char token[delimiter - arg + 1];
        char *value = delimiter + 1;

        ft_strlcpy(token, arg, sizeof(token));

        if (!ft_strcmp(token, "pass")) {
            ft_strlcpy(pass_buf, value, len);
            return (0);
        }
        else if (!ft_strcmp(token, "env")) {
            return(rsa_parse_pass_env(value, pass_buf, len));
        }
        else if (!ft_strcmp(token, "fd")) {
            return (rsa_parse_pass_fd(ft_atoi(value), pass_buf, len));
        }
        else if (!ft_strcmp(token, "file")) {
            return (rsa_parse_pass_file(value, skip_line, pass_buf, len, command));
        }
    }
    else if (!delimiter && !ft_strcmp(arg, "stdin")) {
        return (rsa_parse_pass_fd(STDIN_FILENO, pass_buf, len));
    }
    ft_dprintf(STDERR_FILENO, "Invalid password argument \"%s\"\n", arg);
    ft_dprintf(STDERR_FILENO, "Error getting passwords\n");
    return (-1);
}

int rsa_check_format_args(const char *inform, const char *outform,
                          e_command command)
{
    if (inform && ft_strcmp(inform, "PEM")) {
        ft_dprintf(
            STDERR_FILENO,
            "%s: %s: invalid format \"%s\" for -inform\n",
            PROGRAM_NAME, commands[command].str, inform
        );
        return (-1);
    }
    if (outform && ft_strcmp(outform, "PEM")) {
        ft_dprintf(
            STDERR_FILENO,
            "%s: %s: invalid format \"%s\" for -outform\n",
            PROGRAM_NAME, commands[command].str, outform
        );
        return (-1);
    }
    return (0);
}

int parse_rsa_options(int argc, char *argv[], _s_rsa_config *config,
                      e_command command)
{
    s_ftarg_opt options[] = {{'f', 0, "inform", 1}, {'g', 0, "outform", 1},
                             {'i', 0,     "in", 1}, {'o', 0,     "out", 1},
                             {'p', 0, "passin", 1}, {'q', 0, "passout", 1},
                             {'d', 0,    "des", 0}, {'t', 0,    "text", 0},
                             {'n', 0,  "noout", 0}, {'m', 0, "modulus", 0},
                             {'c', 0,  "check", 0}, {'r', 0,   "pubin", 0},
                             {'s', 0, "pubout", 0}};
    int optcount = sizeof(options) / sizeof((options)[0]);
    int opt;

    optind = 2;
    while ((opt = ftarg_getopt(argc, argv, options, optcount)) != -1)
    {
        if (opt == '?') {
            error_arg(commands[command].str, optarg, ARG_UNRECOGNIZED);
            return (-1);
        }
        if (optarg[1] == '=' && opt != 'f' && opt != 'g' && opt != 'i' &&
                                opt != 'o' && opt != 'p' && opt != 'q') {
            error_arg(commands[command].str, optarg, ARG_NO_VALUE);
            return (-1);
        }
        if (!optval && (opt == 'f' || opt == 'g' || opt == 'i' ||
                        opt == 'o' || opt == 'p' || opt == 'q')) {
            error_arg(commands[command].str, optarg, ARG_MISSING_VALUE);
            return (-1);
        }
        if (opt == 'f') {
            config->inform = optval;
        }
        else if (opt == 'g') {
            config->outform = optval;
        }
        else if (opt == 'i') {
            config->io.in_file = optval;
        }
        else if (opt == 'o') {
            config->io.out_file = optval;
        }
        else if (opt == 'p') {
            config->passin_arg = optval;
        }
        else if (opt == 'q') {
            config->passout_arg = optval;
        }
        else if (opt == 'd') {
            config->des = 1;
        }
        else if (opt == 't') {
            config->text = 1;
        }
        else if (opt == 'n') {
            config->noout = 1;
        }
        else if (opt == 'm') {
            config->modulus = 1;
        }
        else if (opt == 'c') {
            config->check = 1;
        }
        else if (opt == 'r') {
            config->pubin = 1;
        }
        else if (opt == 's') {
            config->pubout = 1;
        }
    }
    if (optind < argc) {
        error_arg(commands[command].str, NULL, ARG_EXTRA);
        return (-1);
    }
    return (optind);
}

int handle_rsa(int argc, char *argv[], e_command command)
{
    _s_rsa_config config = {NULL, NULL, {NULL, NULL, 0, 0}, NULL, NULL,
                            {0}, {0}, 0, 0, 0, 0, 0, 0, 0};
    s_rsa_key key;
    int matching = 0;
    int ret = 0;

    assert(command == rsa);

    if (parse_rsa_options(argc, argv, &config, command) < 0) {
        print_rsa_usage(STDERR_FILENO, command);
        return (1);
    }
    if (rsa_check_format_args(config.inform, config.outform, command) < 0) {
        return (1);
    }
    if (config.passin_arg &&
        rsa_parse_pass(config.passin_arg, config.passin,
                       sizeof(config.passin), 0, command) < 0) {
        return (1);
    }
    if (config.passout_arg) {
        matching = config.passin_arg && !ft_strcmp(config.passin_arg, config.passout_arg);
        if (rsa_parse_pass(config.passout_arg, config.passout,
                           sizeof(config.passout), matching, command) < 0) {
            return (1);
        }
    }
    if (config.pubin && config.check) {
        error_str(commands[command].str, ERR_PUB_CHECK);
        return (1);
    }
    if (set_in_fd(&config.io, commands[command].str) < 0) {
        return (-1);
    }
    if (rsa_get_key(config.io.in_fd, config.io.in_file, &key, config.pubin,
                    config.passin, config.passin_arg != NULL, command) < 0) {
        close_in_fd(&config.io, commands[command].str);
        return (1);
    }
    if (set_out_fd(&config.io, commands[command].str) < 0) {
        close_in_fd(&config.io, commands[command].str);
        return (-1);
    }
    if (config.text && rsa_print_text(config.io.out_fd, &key, command) < 0) {
        error_file(commands[command].str, config.io.out_file);
        close_fds(&config.io, commands[command].str);
        return (1);
    }
    if (config.modulus && ft_dprintf(config.io.out_fd, "Modulus=%X\n", key.modulus) < 0) {
        error_file(commands[command].str, config.io.out_file);
        close_fds(&config.io, commands[command].str);
        return (1);
    }
    if (config.check) {
        if (rsa_check_key(&key, command) < 0) {
            close_fds(&config.io, commands[command].str);
            return (1);
        }
        if (write(config.io.out_fd, "RSA key ok\n", 11) < 0) {
            close_fds(&config.io, commands[command].str);
            return (1);
        }
    }
    if (!config.noout) {
        ft_dprintf(STDERR_FILENO, "writing RSA key\n");
        if (key.type == PUBLIC || config.pubout) {
            ret = rsa_print_pub(config.io.out_fd, config.io.out_file, &key,
                                PEM, command);
        }
        else {
            if (config.des && config.passout_arg && !config.passout[0]) {
                ft_dprintf(STDERR_FILENO, "unable to write key\n");
                close_fds(&config.io, commands[command].str);
                return (1);
            }
            ret = rsa_print_priv(config.io.out_fd, config.io.out_file, &key, PEM,
                                 config.des, config.passout, command);
        }
        if (ret < 0) {
            ret = 1;
        }
    }
    if (close_fds(&config.io, commands[command].str) < 0) {
        return (1);
    }
    return (ret);
}
