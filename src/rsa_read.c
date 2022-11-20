#include "rsa.h"
#include "libft.h"
#include "fterror.h"

#include <errno.h>

char *rsa_read_password_enc(e_command command)
{
    char *password = NULL;
    char tmp[RSA_MAX_PASS_LEN + 1];
    size_t size = 0;

    for (int i = 0; i < 2; i++) {
        if (i == 1) {
            ft_printf("Verifying - ");
        }
        ft_printf("Enter PEM pass phrase:");
        password = getpass("");
        if (!password) {
            error_str(commands[command].str, ERR_GETPASS);
            return (NULL);
        }
        size = ft_strlen(password);
        if (size < RSA_MIN_PASS_LEN || size > RSA_MAX_PASS_LEN) {
            ft_dprintf(
                STDERR_FILENO,
                "Result too %s, you must type in %u to %u characters\n",
                size < RSA_MIN_PASS_LEN ? "small" : "big",
                RSA_MIN_PASS_LEN, RSA_MAX_PASS_LEN
            );
            return (NULL);
        }
        if (i == 0) {
            ft_strlcpy(tmp, password, sizeof(tmp));
        }
    }
    if (ft_strcmp(password, tmp)) {
        ft_dprintf(STDERR_FILENO, "Verify failure\n");
        return (NULL);
    }
    return (password);
}

char *rsa_read_password_dec(const char *filename, e_command command)
{
    char *password = NULL;
    size_t size = 0;

    while (1) {
        if (filename) {
            ft_printf("Enter pass phrase for %s:", filename);
        }
        else {
            ft_printf("Enter pass phrase:");
        }
        password = getpass("");
        if (!password) {
            error_str(commands[command].str, ERR_GETPASS);
            return (NULL);
        }
        size = ft_strlen(password);
        if (size >= RSA_MIN_PASS_LEN && size <= RSA_MAX_PASS_LEN) {
            break;
        }
        ft_dprintf(
            STDERR_FILENO,
            "Result too %s, you must type in %u to %u characters\n",
            size < RSA_MIN_PASS_LEN ? "small" : "big",
            RSA_MIN_PASS_LEN, RSA_MAX_PASS_LEN
        );
    }
    return (password);
}

int rsa_extract_key(char *dst, char *src, size_t len, int public, e_command command)
{
    char *header = NULL;
    char *footer = NULL;
    char *start = NULL;

    if (!dst || !src) {
        error_errno(commands[command].str, "rsa_extract_key()", EINVAL);
        return (-1);
    }
    header = ft_strnstr(src, public ? RSA_PUB_HDR : RSA_PRIV_HDR, ft_strlen(src));
    if (header) {
        footer = ft_strnstr(header, public ? RSA_PUB_FTR : RSA_PRIV_FTR, ft_strlen(header));
    }
    if (!header || !footer || (header != src && *(header - 1) != '\n') || *(footer - 1) != '\n') {
        return (-1);
    }
    start = footer + ft_strlen(public ? RSA_PUB_FTR : RSA_PRIV_FTR);
    for (int i = 0; start[i] != '\n' && start[i] != '\0'; i++) {
        if (!ft_isspace(start[i])) {
            return (-1);
        }
    }
    start = header + ft_strlen(public ? RSA_PUB_HDR : RSA_PRIV_HDR);
    if (start > footer) {
        return (-1);
    }
    if ((size_t)(footer - start + 1) > len) {
        return (-1);
    }
    ft_memcpy(dst, start, footer - start);
    dst[footer - start] = '\0';

    return (0);
}

int rsa_read_key(int fd, char *data, size_t len, int public, e_command command)
{
    char tmp[RSA_BUFFER_SIZE + 1] = {0};
    char buf[RSA_BUFFER_SIZE + 1] = {0};
    char contents[RSA_BUFFER_SIZE * 2 + 1] = {0};
    char *header = NULL;
    ssize_t tmp_len = 0;
    ssize_t buf_len = 0;

    if (!data) {
        error_errno(commands[command].str, "rsa_read_key()", EINVAL);
        return (-1);
    }
    for (int i = 0; i < 5; i++) {
        buf_len = read_full_buffer(fd, buf, sizeof(buf));
        if (buf_len < 0) {
            error_other(commands[command].str);
            return (-1);
        }
        ft_memcpy(contents, tmp, tmp_len);
        ft_memcpy(contents + tmp_len, buf, buf_len + 1);
        if (buf_len < RSA_BUFFER_SIZE) {
            break;
        }
        header = ft_strnstr(contents, public ? RSA_PUB_HDR : RSA_PRIV_HDR, ft_strlen(contents));
        if (*tmp && header < contents + RSA_BUFFER_SIZE) {
            break;
        }
        ft_memcpy(tmp, buf, sizeof(buf));
        tmp_len = buf_len;
    }
    return (rsa_extract_key(data, contents, len, public, command));
}
