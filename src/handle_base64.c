#include "base64.h"
#include "libft.h"
#include "ftarg.h"
#include "fterror.h"

#include <fcntl.h>
#include <assert.h>

void print_base64_usage(int fd)
{
    ft_dprintf(fd, "usage: ft_ssl base64 [-d] [-e] [-i infile] [-o outfile]\n");
}

int parse_base64_options(int argc, char *argv[], _s_base64_config *config)
{
    s_ftarg_opt options[] = {{'d', 'd', NULL, 0}, {'e', 'e', NULL, 0},
                             {'i', 'i', NULL, 1}, {'o', 'o', NULL, 1}};
    int optcount = sizeof(options) / sizeof((options)[0]);
    int opt;

    optind = 2;
    while ((opt = ftarg_getopt(argc, argv, options, optcount)) != -1)
    {
        if (opt == '?') {
            error_arg("base64", optarg, ARG_UNRECOGNIZED);
            return (-1);
        }
        if (opt != 'i' && opt != 'o' && optarg[1] == '=') {
            error_arg("base64", optarg, ARG_NO_VALUE);
            return (-1);
        }
        if ((opt == 'i' || opt == 'o') && !optval) {
            error_arg("base64", optarg, ARG_MISSING_VALUE);
            return (-1);
        }
        if (opt == 'd') {
            config->decode = 1;
        }
        else if (opt == 'e') {
            config->decode = 0;
        }
        else if (opt == 'i') {
            config->io.in_file = optval;
        }
        else if (opt == 'o') {
            config->io.out_file = optval;
        }
    }
    if (optind < argc) {
        error_arg("base64", NULL, ARG_EXTRA);
        return (-1);
    }
    return (optind);
}

int handle_base64(int argc, char *argv[], e_command command)
{
    _s_base64_config config = {0, {NULL, NULL, 0, 0}};
    int ret = 0;
    int index;

    assert(command == base64);

    index = parse_base64_options(argc, argv, &config);
    if (index < 0) {
        print_base64_usage(STDERR_FILENO);
        return (1);
    }
    if (set_fds(&config.io, "base64") < 0) {
        return (1);
    }
    ret = base64_io(config.io.in_fd, config.io.out_fd, config.decode);
    if (close_fds(&config.io, "base64") < 0) {
        return (1);
    }
    return (ret < 0 ? 1 : 0);
}
