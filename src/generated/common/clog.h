/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Main CLOG header file - this describes the primary macros that result in calling your desired trace libraries

Version:
    0.2.0

--*/

#pragma once

#ifndef LOG_ADDR_LEN
#define LOG_ADDR_LEN(x) sizeof(x)
#endif

#define CLOG_BYTEARRAY_HELPER(length, pointer) pointer, length
#define CLOG_BYTEARRAY(length, pointer) CLOG_BYTEARRAY_HELPER(length, pointer)

typedef const void * CLOG_PTR;
typedef const unsigned char CLOG_UINT8;
typedef const char CLOG_INT8;

typedef const unsigned int CLOG_UINT32;
typedef const int CLOG_INT32;

typedef unsigned long long CLOG_UINT64;
typedef const long long CLOG_INT64;

#ifndef CLOG_H
#define CLOG_H 1

#ifdef __cplusplus
extern "C" {
#endif

#define _clog_EXPAND(x) x
#define _clog_SELECT_ARGN_MACRO(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15, _16, _17, _18, _19, _20, _21, _22, _23, _24, _25, N, ...) N
#define _clog_ARGN_SELECTOR(...) \
    _clog_EXPAND(_clog_SELECT_ARGN_MACRO( \
        __VA_ARGS__, \
        _clog_26_ARGS_TRACE,\
        _clog_25_ARGS_TRACE,\
        _clog_24_ARGS_TRACE,\
        _clog_23_ARGS_TRACE,\
        _clog_22_ARGS_TRACE,\
        _clog_21_ARGS_TRACE,\
        _clog_20_ARGS_TRACE,\
        _clog_19_ARGS_TRACE,\
        _clog_18_ARGS_TRACE,\
        _clog_17_ARGS_TRACE,\
        _clog_16_ARGS_TRACE,\
        _clog_15_ARGS_TRACE,\
        _clog_14_ARGS_TRACE,\
        _clog_13_ARGS_TRACE,\
        _clog_12_ARGS_TRACE,\
        _clog_11_ARGS_TRACE,\
        _clog_10_ARGS_TRACE,\
        _clog_9_ARGS_TRACE, \
        _clog_8_ARGS_TRACE, \
        _clog_7_ARGS_TRACE, \
        _clog_6_ARGS_TRACE, \
        _clog_5_ARGS_TRACE, \
        _clog_4_ARGS_TRACE, \
        _clog_3_ARGS_TRACE, \
        _clog_2_ARGS_TRACE, \
        0))

#define _clog_CAT_HELPER(x, y) x ## y
#define _clog_CAT(x, y) _clog_CAT_HELPER(x, y)

#ifdef __cplusplus
}
#endif

#endif
