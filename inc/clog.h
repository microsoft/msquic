#ifndef CLOG_H
#define CLOG_H 1

//#include <evntrace.h>
//#include <evntprov.h>

#ifdef __cplusplus
extern "C" {
#endif


    
#define EXPAND(x) x
#define SELECT_ARGN_MACRO(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15, _16, _17, _18, N, ...) N
#define CLOG_ARGN_SELECTOR(...) \
    EXPAND(SELECT_ARGN_MACRO( \
        __VA_ARGS__,\
        CLOG_18_ARGS_TRACE,\
        CLOG_17_ARGS_TRACE,\
        CLOG_16_ARGS_TRACE,\
        CLOG_15_ARGS_TRACE,\
        CLOG_14_ARGS_TRACE,\
        CLOG_13_ARGS_TRACE,\
        CLOG_12_ARGS_TRACE,\
        CLOG_11_ARGS_TRACE,\
        CLOG_10_ARGS_TRACE,\
        CLOG_9_ARGS_TRACE,\
        CLOG_8_ARGS_TRACE,\
        CLOG_7_ARGS_TRACE,\
        CLOG_6_ARGS_TRACE,\
        CLOG_5_ARGS_TRACE,\
        CLOG_4_ARGS_TRACE,\
        CLOG_3_ARGS_TRACE,\
        CLOG_2_ARGS_TRACE,\
        CLOG_1_ARGS_TRACE,\
        0))


#define CLOG_CAT_HELPER(x, y) x ## y
#define CLOG_CAT(x, y) CLOG_CAT_HELPER(x, y)       



#ifdef __cplusplus
}
#endif

#endif
