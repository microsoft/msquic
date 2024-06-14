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

#include <msquichelper.h>
#include <quic_platform.h>
#include <quic_trace.h>


void EncodeHexBuffer(_In_reads_(BufferLen) uint8_t * Buffer,
                     _In_ uint8_t BufferLen,
                     _Out_writes_bytes_(2 * BufferLen) char * HexString);


char * casted_clog_bytearray(const uint8_t * const data,
                             const size_t len,
                             struct clog_param ** head)
{
    struct clog_param * const param =
        CXPLAT_ALLOC_PAGED(sizeof(*param), QUIC_POOL_TMP_ALLOC);
    if (param == 0) {
        return 0;
    }

    // try to be clever about how to print this thing
    if (len == sizeof(QUIC_ADDR)) {
        // this seems to be a QUIC_ADDR, so print it nicely
        param->str =
            CXPLAT_ALLOC_PAGED(sizeof(QUIC_ADDR_STR), QUIC_POOL_TMP_ALLOC);
        if (param->str) {
            QuicAddrToString((const QUIC_ADDR *)data,
                             (QUIC_ADDR_STR *)param->str);
        }

    } else if (len) {
        // unsure what this is, just hexdump it
        param->str = CXPLAT_ALLOC_PAGED(len * 2 + 1, QUIC_POOL_TMP_ALLOC);
        if (param->str) {
            EncodeHexBuffer((uint8_t *)data, (uint8_t)len, param->str);
            param->str[len * 2] = 0;
        }

    } else {
        param->str = 0;
    }

    // record this param in the list
    param->next = *head ? *head : 0;
    *head = param;

    // return the string representation
    return param->str;
}


void clog_stdout(struct clog_param * head, const char * const format, ...)
{
    char * reformat;

    if (strstr(format, "%!") == 0) {
        // if there are no clog specifiers, just print
        reformat = (char *)format;
        goto JustPrint;
    }

    // replace clog specifiers in the format string
    const char * repls[] = {"!CID!", "!ADDR!", "!VNL!", "!ALPN!"};
    reformat = strdup(format);
    if (reformat == 0) {
        printf("[Could not reformat log entry: %s]\n", format);
        goto Exit;
    }

    for (size_t i = 0; i < ARRAYSIZE(repls); i++) {
        char * match = reformat;
        while (1) {
            // find next match
            match = strstr(match, repls[i]);

            // break if no match
            if (match == 0) {
                break;
            }

            // replace match with 's' and shift rest of string
            *match++ = 's';
            const size_t repl_len = strlen(repls[i]) - 1;
            const size_t match_len = strlen(match + repl_len);
            memmove(match, match + repl_len, match_len + 1);
        }
    }

JustPrint: ;
    // print the log line
    va_list ap;
    va_start(ap, format);
    vprintf(reformat, ap);
    va_end(ap);
    if (reformat != format) {
        free(reformat);
    }

Exit:
    // free the param structure
    while (head) {
        struct clog_param * const next = head->next;
        CXPLAT_FREE(head->str, QUIC_POOL_TMP_ALLOC);
        CXPLAT_FREE(head, QUIC_POOL_TMP_ALLOC);
        head = next;
    }
}
