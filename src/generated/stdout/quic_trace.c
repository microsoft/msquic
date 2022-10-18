/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Helper functions for STDOUT tracing

--*/

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ARRAYSIZE(A) (sizeof(A) / sizeof((A)[0]))


void clog_stdout(const char * const format, ...)
{
    const char * repls[] = {"!CID!", "!ADDR!", "!VNL!", "!ALPN!"};
    char * reformat = strdup(format);

    for (size_t i = 0; i < ARRAYSIZE(repls); i++) {
        char * match = reformat;

        while (1) {
            // find next match
            match = strstr(match, repls[i]);

            // break if no match
            if (match == 0)
                break;

            // replace match with 's' and shift rest of string
            *match++ = 's';
            const size_t repl_len = strlen(repls[i]) - 1;
            const size_t match_len = strlen(match + repl_len);
            memmove(match, match + repl_len, match_len + 1);
        }
    }

    va_list ap;
    va_start(ap, format);
    vprintf(reformat, ap);
    va_end(ap);
    free(reformat);
}


char * hex2str(const uint8_t * const src,
               const size_t len_src,
               char * const dst,
               const size_t len_dst)
{
    static const char hex[] = "0123456789abcdef";

    size_t i;
    for (i = 0; i < len_src && i * 2 + 1 < len_dst; i++) {
        dst[i * 2] = hex[(src[i] >> 4) & 0x0f];
        dst[i * 2 + 1] = hex[src[i] & 0x0f];
    }

    if (i * 2 + 1 <= len_dst)
        dst[i * 2] = 0;
    else {
        size_t l = len_dst;
        if (l)
            dst[--l] = 0;
        if (l)
            dst[--l] = '.';
        if (l)
            dst[--l] = '.';
        if (l)
            dst[--l] = '.';
    }

    return dst;
}
