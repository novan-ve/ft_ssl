#include "ftarg.h"

char *optarg = NULL;
char *optval = NULL;
int optind = 1;

char *ftarg_getvalue(const char *s)
{
    for (int i = 0; s[i]; i++) {
        if (s[i] == '=') {
            return ((char*)s + i + 1);
        }
    }
    return (NULL);
}

int ftarg_parse_letter(char letter,
                       const s_ftarg_opt *options, size_t optcount)
{
    for (size_t i = 0; i < optcount; i++) {
        if (letter == options[i].letter) {
            return (i);
        }
    }
    return (-1);
}

int ftarg_parse_name(const char *name,
                     const s_ftarg_opt *options, size_t optcount)
{
    char *optname;
    size_t i = 0;
    int cmp;

    for (size_t opt = 0; opt < optcount; opt++) {
        optname = (char*)options[opt].name;
        if (optname) {
            cmp = 0;
            for (i = 0; name[i] && name[i] != '=' && optname[i]; i++) {
                if (name[i] != optname[i]) {
                    cmp = 1;
                    break;
                }
            }
            if (!cmp && name[i] == '\0' && optname[i] == '\0') {
                return (opt);
            }
        }
    }
    return (-1);
}

int ftarg_parse_opt(int argc, char *const argv[],
                    const s_ftarg_opt *options, size_t optcount)
{
    int option;

    if (optarg[1] == '\0' || optarg[1] == '=') {
        option = ftarg_parse_letter(optarg[0], options, optcount);
        if (option == -1) {
            optind++;
            return ('?');
        }
    }
    else {
        option = ftarg_parse_name(optarg, options, optcount);
        if (option == -1) {
            optind++;
            return ('?');
        }
    }
    if (options[option].has_arg) {
        optval = ftarg_getvalue(optarg);
        if (!optval) {
            optind++;
            optval = (char*)argv[optind];
        }
    }
    if (optind < argc) {
        optind++;
    }
    return (options[option].id);
}

int ftarg_getopt(int argc, char *const argv[],
                 const s_ftarg_opt *options, size_t optcount)
{
    optarg = (char*)argv[optind];
    optval = NULL;

    if (!optarg || !optarg[0]) {
        return (-1);
    }
    if (optarg[0] != '-' || optarg[1] == '\0') {
        return (-1);
    }
    optarg++;
    if (optarg[0] == '-') {
        optarg++;
        if (optarg[0] == '\0') {
            optind++;
            return (-1);
        }
        if (optarg[0] == '-') {
            optind++;
            return ('?');
        }
    }
    return (ftarg_parse_opt(argc, argv, options, optcount));
}