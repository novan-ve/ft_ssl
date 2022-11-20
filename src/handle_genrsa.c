#include "rsa.h"
#include "libft.h"
#include "ftarg.h"
#include "fterror.h"
#include "ftmath.h"
#include "rand.h"

#include <unistd.h>
#include <fcntl.h>
#include <assert.h>

void print_genrsa_usage(int fd, e_command command)
{
    ft_dprintf(
        fd,
        "usage: %s %s [-i val] [-o outfile]\n",
        PROGRAM_NAME,
        commands[command].str
    );
}

int genrsa_io(_s_genrsa_config *config, e_command command)
{
    int fd;
    char c;

    if (config->out_file) {
        config->out_fd = open(config->out_file, O_WRONLY|O_CREAT|O_TRUNC,
                             S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
        if (config->out_fd < 0) {
            error_file(commands[command].str, config->out_file);
            return (0);
        }
    }
    if (config->rand_file) {
        fd = open(config->rand_file, O_RDONLY);

        if (fd < 0 || read(fd, &c, 1) < 0) {
            ft_dprintf(STDERR_FILENO, "%s: %s: Can't load %s into RNG\n",
                PROGRAM_NAME, commands[command].str, config->rand_file);

            if (fd != -1) {
                close(fd);
            }
            if (config->out_file) {
                close(config->out_fd);
            }
            return (0);
        }
        close(fd);
    }
    return (1);
}

int parse_genrsa_options(int argc, char *argv[], _s_genrsa_config *config,
                         e_command command)
{
    s_ftarg_opt options[] = {{'i', 'i', NULL, 1}, {'o', 'o', NULL, 1}};
    int optcount = sizeof(options) / sizeof((options)[0]);
    int opt;

    optind = 2;
    while ((opt = ftarg_getopt(argc, argv, options, optcount)) != -1)
    {
        if (opt == '?') {
            error_arg(commands[command].str, optarg, ARG_UNRECOGNIZED);
            return (-1);
        }
        if (!optval) {
            error_arg(commands[command].str, optarg, ARG_MISSING_VALUE);
            return (-1);
        }
        else if (opt == 'i') {
            config->rand_file = optval;
        }
        else if (opt == 'o') {
            config->out_file = optval;
        }
    }
    if (optind < argc) {
        error_arg(commands[command].str, NULL, ARG_EXTRA);
        return (-1);
    }
    return (optind);
}

int handle_genrsa(int argc, char *argv[], e_command command)
{
    _s_genrsa_config config = {NULL, NULL, STDOUT_FILENO};
    s_rsa_key priv;
    int ret = 0;

    assert(command == genrsa);

    if (parse_genrsa_options(argc, argv, &config, command) < 0) {
        print_genrsa_usage(STDERR_FILENO, command);
        return (1);
    }
    if (!genrsa_io(&config, command)) {
        return (1);
    }

    ft_dprintf(STDERR_FILENO, "Generating RSA private key, 64 bit long modulus\n");

    ret = rsa_create_priv(config.rand_file, &priv, command);
    if (ret >= 0) {
        ft_dprintf(STDERR_FILENO, "e is %u (0x%x)\n", priv.pub_exp, priv.pub_exp);
        ret = rsa_print_priv(config.out_fd, config.out_file, &priv, PEM, 0,
                             NULL, command);
    }
    if (config.out_file && close(config.out_fd) < 0) {
        return (1);
    }

    return (ret < 0 ? 1 : 0);
}
