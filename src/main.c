#include "libft.h"
#include "commands.h"

void print_usage(int fd)
{
    ft_dprintf(fd,
        "Standard commands:\n"
        "genrsa\n"
        "rsa\n"
        "rsautl\n"
        "\n"
        "Message Digest commands:\n"
        "md5\n"
        "sha1\n"
        "sha256\n"
        "\n"
        "Cipher commands:\n"
        "base64\n"
        "des\n"
        "des-ecb\n"
        "des-cbc\n"
    );
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        ft_dprintf(STDERR_FILENO,
            "usage: ft_ssl command [flags] [file/string]\n");
        return (1);
    }
    for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
        if (!ft_strcmp(argv[1], commands[i].str)) {
            return (commands[i].handler(argc, argv, i));
        }
    }
    ft_dprintf(
        STDERR_FILENO,
        "ft_ssl: Error: '%s' is an invalid command.\n\n",
        argv[1]
    );
    print_usage(STDERR_FILENO);
    return (1);
}
