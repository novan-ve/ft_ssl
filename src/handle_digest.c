#include "digest.h"
#include "libft.h"
#include "ftarg.h"
#include "fterror.h"
#include "md5.h"
#include "sha1.h"
#include "sha256.h"

#include <fcntl.h>
#include <assert.h>

const _s_digest_fn digest_fn[] = {
    [md5] = {md5_str, md5_fd},
    [sha1] = {sha1_str, sha1_fd},
    [sha256] = {sha256_str, sha256_fd}
};

void print_digest_usage(int fd, e_command command)
{
    ft_dprintf(
        fd,
        "usage: ft_ssl %s [-pqr] [-s text] [FILE]...\n",
        commands[command].str
    );
}

int digest_stdin(e_command command, _s_digest_config *config)
{
    char *hash = NULL;

    if (config->echo && !config->quiet) {
        ft_printf("(\"");
    }
    hash = digest_fn[command].digest_fd(STDIN_FILENO, config->echo, 1);
    if (!hash) {
        error_str(commands[command].str, ERR_MALLOC);
        return (1);
    }
    if (config->echo && !config->quiet) {
        ft_printf("\")= ");
    }
    if (!config->echo && !config->quiet) {
        ft_printf("(stdin)= ");
    }
    else if (config->echo && config->quiet) {
        ft_printf("\n");
    }
    ft_printf("%s\n", hash);
    free(hash);
    return (0);
}

int digest_str(char *str, e_command command, _s_digest_config *config)
{
    char *hash = digest_fn[command].digest_str(str, ft_strlen(str), 1);

    if (!hash) {
        error_str(commands[command].str, ERR_MALLOC);
        return (1);
    }
    if (!config->reverse && !config->quiet) {
        for (int i = 0; commands[command].str[i]; i++) {
            ft_printf("%c", ft_toupper(commands[command].str[i]));
        }
        ft_printf(" (\"%s\") = %s\n", str, hash);
    }
    else if (config->reverse && !config->quiet) {
        ft_printf("%s \"%s\"\n", hash, str);
    }
    else {
        ft_printf("%s\n", hash);
    }
    free(hash);
    return (0);
}

int digest_file(unsigned int fd, const char *filename,
                e_command command, _s_digest_config *config)
{
    char *hash = digest_fn[command].digest_fd(fd, 0, 1);

    if (!hash) {
        error_file(commands[command].str, filename);
        return (1);
    }
    if (!config->reverse && !config->quiet) {
        for (int i = 0; commands[command].str[i]; i++) {
            ft_printf("%c", ft_toupper(commands[command].str[i]));
        }
        ft_printf(" (%s) = %s\n", filename, hash);
    }
    else if (config->reverse && !config->quiet) {
        ft_printf("%s %s\n", hash, filename);
    }
    else {
        ft_printf("%s\n", hash);
    }
    free(hash);
    return (0);
}

int parse_digest_options(int argc, char *argv[],
                         e_command command, _s_digest_config *config)
{
    s_ftarg_opt options[] = {{'p', 'p', NULL, 0}, {'q', 'q', NULL, 0},
                             {'r', 'r', NULL, 0}, {'s', 's', NULL, 1}};
    int optcount = sizeof(options) / sizeof((options)[0]);
    const char *command_str = commands[command].str;
    int opt;

    optind = 2;
    while ((opt = ftarg_getopt(argc, argv, options, optcount)) != -1)
    {
        if (opt != '?' && opt != 's' && optarg[1] == '=') {
            error_arg(command_str, optarg, ARG_NO_VALUE);
            return (-1);
        }
        if (opt == 'p') {
            config->echo = 1;
        }
        else if (opt == 'q') {
            config->quiet = 1;
        }
        else if (opt == 'r') {
            config->reverse = 1;
        }
        else if (opt == 's') {
            if (!optval) {
                error_arg(command_str, optarg, ARG_MISSING_VALUE);
                return (-1);
            }
            config->str = optval;
            break;
        }
        else if (opt == '?') {
            error_arg(command_str, optarg, ARG_UNRECOGNIZED);
            return (-1);
        }
    }
    return (optind);
}

int handle_digest(int argc, char *argv[], e_command command)
{
    _s_digest_config config = {0, 0, 0, NULL};
    int index;
    int ret = 0;

    assert(command == md5 || command == sha1 || command == sha256);

    index = parse_digest_options(argc, argv, command, &config);
    if (index < 0) {
        print_digest_usage(STDERR_FILENO, command);
        return (1);
    }

    if (config.echo || (!config.str && index == argc)) {
        ret |= digest_stdin(command, &config);
    }
    if (config.str) {
        ret |= digest_str(config.str, command, &config);
    }
    for (; index < argc; index++) {
        int fd = open(argv[index], O_RDONLY);
        if (fd < 0) {
            error_file(commands[command].str, argv[index]);
            ret = 1;
            continue;
        }
        ret |= digest_file(fd, argv[index], command, &config);
        close(fd);
    }
    return (ret);
}