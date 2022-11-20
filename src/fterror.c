#include "fterror.h"
#include "libft.h"

#include <string.h>
#include <errno.h>

size_t key_len(const char *opt)
{
    size_t len = 0;

    if (opt) {
        while (opt[len] && opt[len] != '=') {
            len++;
        }
    }
    return (len);
}

void error_arg(const char *command, const char *opt, int error_code)
{
    size_t len = opt ? key_len(opt) + 1 : ft_strlen("(NULL)") + 1;
    char opt_key[len];

    if (opt) {
        ft_strlcpy(opt_key, opt, len);
    }
    else {
        ft_strlcpy(opt_key, "(NULL)", len);
    }
    ft_dprintf(STDERR_FILENO, "%s: %s: ", PROGRAM_NAME, command ? command : "?");

    switch (error_code) {
        case ARG_NO_VALUE:
            ft_dprintf(STDERR_FILENO, "Option -%s does not take a value\n",
                       opt_key);
            break;
        case ARG_MISSING_VALUE:
            ft_dprintf(STDERR_FILENO, "Option -%s needs a value\n", opt_key);
            break;
        case ARG_UNRECOGNIZED:
            ft_dprintf(STDERR_FILENO, "Unrecognized flag %s\n", opt_key);
            break;
        case ARG_EXTRA:
            ft_dprintf(STDERR_FILENO, "Extra arguments given\n");
            break;
        default:
            ft_dprintf(STDERR_FILENO, "Option -%s, unknown error\n", opt_key);
            break;
    }
}

void error_str(const char *command, const char *error_msg) {
    ft_dprintf(
        STDERR_FILENO,
        "%s: %s: %s\n",
        PROGRAM_NAME,
        command ? command : "?",
        error_msg ? error_msg : "?"
    );
}

void error_file(const char *command, const char *filename) {
    ft_dprintf(
        STDERR_FILENO,
        "%s: %s: %s: %s\n",
        PROGRAM_NAME,
        command ? command : "?",
        filename ? filename : "STDIN/STDOUT/STDERR",
        strerror(errno)
    );
}

void error_errno(const char *command, const char *error_msg, int errnum) {
    ft_dprintf(
        STDERR_FILENO,
        "%s: %s: %s: %s\n",
        PROGRAM_NAME,
        command ? command : "?",
        error_msg ? error_msg : "?",
        strerror(errnum)
    );
}

void error_other(const char *command) {
    ft_dprintf(
        STDERR_FILENO,
        "%s: %s: %s\n",
        PROGRAM_NAME,
        command ? command : "?",
        strerror(errno)
    );
}
