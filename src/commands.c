#include "commands.h"
#include "digest.h"
#include "base64.h"
#include "des.h"
#include "rsa.h"

s_command commands[10] = {
    [md5] = {"md5", handle_digest},
    [sha1] = {"sha1", handle_digest},
    [sha256] = {"sha256", handle_digest},
    [base64] = {"base64", handle_base64},
    [des] = {"des", handle_des},
    [des_cbc] = {"des-cbc", handle_des},
    [des_ecb] = {"des-ecb", handle_des},
    [genrsa] = {"genrsa", handle_genrsa},
    [rsa] = {"rsa", handle_rsa},
    [rsautl] = {"rsautl", handle_rsautl}
};
