/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   libft.h                                            :+:    :+:            */
/*                                                     +:+                    */
/*   By: novan-ve <marvin@codam.nl>                   +#+                     */
/*                                                   +#+                      */
/*   Created: 2019/11/01 14:33:47 by novan-ve      #+#    #+#                 */
/*   Updated: 2022/09/28 13:43:19 by novan-ve      ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#ifndef LIBFT_H
# define LIBFT_H

# include <stdarg.h>
# include <stdlib.h>
# include <unistd.h>

typedef struct  s_print
{
    char        *format;
    va_list     args;
    int         i;
    int         fd;
    int         len;
    int         tmplen;
    char        *strtmp;
    char        hex[16];
    int         itmp;
    char        padchar;
    int         width;
    int         tmpwidth;
    char        just;
    int         minus;
    char        var;
    int         error;
    int         prec;
}               t_print;

int             ft_atoi(const char *str);
void            ft_bzero(void *s, size_t n);
void            *ft_calloc(size_t count, size_t size);
int             ft_isalnum(int c);
int             ft_isalpha(int c);
int             ft_isascii(int c);
int             ft_isdigit(int c);
int             ft_isprint(int c);
int             ft_isspace(int c);
void            *ft_memccpy(void *dst, const void *src, int c, size_t n);
void            *ft_memchr(const void *s, int c, size_t n);
int             ft_memcmp(const void *s1, const void *s2, size_t n);
void            *ft_memcpy(void *dst, const void *src, size_t n);
void            *ft_memmove(void *dst, const void *src, size_t len);
void            *ft_memset(void *b, int c, size_t len);
char            *ft_strchr(const char *s, int c);
char            *ft_strdup(const char *s1);
size_t          ft_strlcat(char *dst, const char *src, size_t dstsize);
size_t          ft_strlcpy(char *dst, const char *src, size_t dstsize);
size_t          ft_strlen(const char *s);
int             ft_strcmp(const char *s1, const char *s2);
int             ft_strncmp(const char *s1, const char *s2, size_t n);
char            *ft_strnstr \
                    (const char *haystack, const char *needle, size_t len);
char            *ft_strrchr(const char *s, int c);
int             ft_tolower(int c);
int             ft_toupper(int c);
char            *ft_substr(char const *s, unsigned int start, size_t len);
char            *ft_strjoin(char const *s1, char const *s2);
char            *ft_strtrim(char const *s1, char const *set);
char            **ft_split(char const *s, char c);
char            *ft_itoa(int n);
char            *ft_strmapi(char const *s, char (*f)(unsigned int, char));
void            ft_putchar_fd(char c, int fd);
void            ft_putstr_fd(char *s, int fd);
void            ft_putendl_fd(char *s, int fd);
void            ft_putnbr_fd(int n, int fd);
int	            ft_putulong_fd(unsigned long long n, int fd);

int             ft_printf(const char *format, ...);
int             ft_dprintf(int fd, const char *format, ...);
void            ft_resetlst(t_print *p, int i);
void            ft_uputnbr_fd(unsigned int n, int fd);
void            ft_dec_to_hex(t_print *p, unsigned long dec, int x, int len);
void            ft_dec_to_hex2(t_print *p, unsigned long dec, int x, int len);
int             ft_nbrleni(long nb, int x);
int             ft_nbrlenu(unsigned int nb);
void            ft_printc(t_print *p);
void            ft_format(t_print *p);
void            ft_format2(t_print *p);
void            ft_prints(t_print *p);
void            ft_prints2(t_print *p);
void            ft_prints3(t_print *p);
void            ft_prints4(t_print *p);
void            ft_prints5(t_print *p);
void            ft_printi(t_print *p);
int             ft_printi2(t_print *p, int j);
void            ft_printi3(t_print *p, int j, int k);
void            ft_printp(t_print *p);
void            ft_printp2(t_print *p);
void            ft_printu(t_print *p);
void            ft_printu2(t_print *p);
void            ft_printx(t_print *p, int x);
void            ft_printx2(t_print *p);
void            ft_printx3(t_print *p, int x);
void            ft_printper(t_print *p);
void            ft_calcwidth(t_print *p);
void            ft_calcwidth2(t_print *p, int x, int j);
void            ft_putprec_fd(char *s, int fd, int prec);

#endif
