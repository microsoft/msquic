/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file contains linux platform implementation.

Environment:

    Linux user mode

--*/

#ifndef _QUIC_PLATFORM_
#error "Must be included from quic_platform.h"
#endif

#ifndef QUIC_PLATFORM_LINUX
#error "Incorrectly including Linux Platform Header from non-Linux platfrom"
#endif

#ifndef _PLATFORM_LINUX_
#define _PLATFORM_LINUX_

#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>
#include <stddef.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <msquic_linux.h>
#include <stdbool.h>
#include <pthread.h>
#include <errno.h>
#include <sys/syscall.h>
#include <quic_sal_stub.h>

#if defined(__cplusplus)
extern "C" {
#endif

//
// Library Initialization routines.
//

void
QuicPlatformSystemLoad(
    void
    );

void
QuicPlatformSystemUnload(
    void
    );

QUIC_STATUS
QuicPlatformInitialize(
    void
    );

void
QuicPlatformUninitialize(
    void
    );


//
// Generic stuff.
//

#define INVALID_SOCKET_FD ((int)(-1))

#define SOCKET_ERROR (-1)

#define max(a,b) (((a) > (b)) ? (a) : (b))

#define min(a,b) (((a) < (b)) ? (a) : (b))

#define ARRAYSIZE(A) (sizeof(A)/sizeof((A)[0]))

#define UNREFERENCED_PARAMETER(P) (P)

#define QuicNetByteSwapShort(x) htons((x)

#define SIZEOF_STRUCT_MEMBER(StructType, StructMember) sizeof(((StructType *)0)->StructMember)
#define TYPEOF_STRUCT_MEMBER(StructType, StructMember) typeof(((StructType *)0)->StructMember)

//
// Interlocked implementations.
//

inline
LONG
InterlockedIncrement(
    _Inout_ _Interlocked_operand_ LONG volatile *Addend
    )
{
    return __sync_add_and_fetch(Addend, (LONG)1);
}

inline
LONG
InterlockedDecrement(
    _Inout_ _Interlocked_operand_ LONG volatile *Addend
    )
{
    return __sync_sub_and_fetch(Addend, (LONG)1);
}

inline
LONG64
InterlockedExchangeAdd64(
    _Inout_ _Interlocked_operand_ LONG64 volatile *Addend,
    _In_ LONG64 Value
    )
{
    return __sync_fetch_and_add(Addend, Value);
}

inline
SHORT
InterlockedCompareExchange16(
    _Inout_ _Interlocked_operand_ SHORT volatile *Destination,
    _In_ SHORT ExChange,
    _In_ SHORT Comperand
    )
{
    return __sync_val_compare_and_swap(Destination, Comperand, ExChange);
}

inline
SHORT
InterlockedIncrement16(
    _Inout_ _Interlocked_operand_ SHORT volatile *Addend
    )
{
    return __sync_add_and_fetch(Addend, (SHORT)1);
}

inline
SHORT
InterlockedDecrement16(
    _Inout_ _Interlocked_operand_ SHORT volatile *Addend
    )
{
    return __sync_sub_and_fetch(Addend, (SHORT)1);
}

inline
LONG64
InterlockedIncrement64(
    _Inout_ _Interlocked_operand_ LONG64 volatile *Addend
    )
{
    return __sync_add_and_fetch(Addend, (LONG64)1);
}

//
// String utils.
//

#define strcpy_s(dst, dst_len, src) strcpy(dst, src) // TODO - Better solution for Linux
int _strnicmp(const char * _Str1, const char * _Str2, size_t _MaxCount);

#define _vsnprintf_s(buf, size, flag, format, ...) \
    vsnprintf(buf, size, format, __VA_ARGS__)

//
// Assertion interfaces.
//

__attribute__((noinline))
void
quic_bugcheck(
    void
    );

void
QuicPlatformLogAssert(
    _In_z_ const char* File,
    _In_ int Line,
    _In_z_ const char* Func,
    _In_z_ const char* Expr
    );

#define QUIC_STATIC_ASSERT(X,Y) static_assert(X, Y);
#define QUIC_ANALYSIS_ASSERT(X)
#define QUIC_FRE_ASSERT(exp) ((exp) ? (void)0 : (QuicPlatformLogAssert(__FILE__, __LINE__, __func__, #exp), quic_bugcheck()));

//
// LINUX_TODO: Define DBG on debug build.
//

#define DBG 1
#ifdef DBG
#define QUIC_DBG_ASSERT(exp) QUIC_FRE_ASSERT(exp)
#define QUIC_DBG_ASSERTMSG(exp, msg) QUIC_FRE_ASSERT(exp)
#define QUIC_TEL_ASSERT(exp) QUIC_FRE_ASSERT(exp)
#define QUIC_TEL_ASSERTMSG(exp, Y) QUIC_FRE_ASSERT(exp)
#define QUIC_TEL_ASSERTMSG_ARGS(exp, _msg, _origin, _bucketArg1, _bucketArg2) QUIC_FRE_ASSERT(exp)
#define QUIC_FRE_ASSERTMSG(exp, Y) QUIC_FRE_ASSERT(exp)
#else
#define QUIC_DBG_ASSERT(exp)
#define QUIC_DBG_ASSERTMSG(exp, msg)
#define QUIC_TEL_ASSERT(exp)
#define QUIC_TEL_ASSERTMSG(exp, Y)
#define QUIC_TEL_ASSERTMSG_ARGS(exp, _msg, _origin, _bucketArg1, _bucketArg2)
#define QUIC_FRE_ASSERTMSG(exp, Y)
#endif

#define __assume(X) (void)0

//
// Debugger check.
//

#define QuicDebuggerPresent() FALSE

//
// Interrupt ReQuest Level.
//

#define QUIC_IRQL() 0
#define QUIC_PASSIVE_CODE()

//
// Memory management interfaces.
//

extern uint64_t QuicTotalMemory;

_Ret_maybenull_
void*
QuicAlloc(
    _In_ SIZE_T ByteCount
    );

void
QuicFree(
    __drv_freesMem(Mem) _Frees_ptr_opt_ void* Mem
    );

#define QUIC_ALLOC_PAGED(Size) QuicAlloc(Size)
#define QUIC_ALLOC_NONPAGED(Size) QuicAlloc(Size)
#define QUIC_FREE(Mem) QuicFree((void*)Mem)

//
// Represents a QUIC memory pool used for fixed sized allocations.
//

typedef struct _QUIC_POOL {

    //
    // List of free entries.
    //

    QUIC_SINGLE_LIST_ENTRY ListHead;

    //
    // Number of free entries in the list.
    //

    USHORT ListDepth;

    //
    // Lock to synchronize access to the List.
    // LINUX_TODO: Check how to make this lock free?
    //

    pthread_mutex_t Lock;

    //
    // Size of entries.
    //

    UINT32 Size;

    //
    // The memory tag to use for any allocation from this pool.
    //

    UINT32 MemTag;

} QUIC_POOL, *PQUIC_POOL;

#define QUIC_POOL_MAXIMUM_DEPTH   256 // Copied from EX_MAXIMUM_LOOKASIDE_DEPTH_BASE

void
QuicPoolInitialize(
    _In_ BOOLEAN IsPaged,
    _In_ uint32_t Size,
    _Inout_ PQUIC_POOL Pool
    );

void
QuicPoolUninitialize(
    _Inout_ PQUIC_POOL Pool
    );

void*
QuicPoolAlloc(
    _Inout_ PQUIC_POOL Pool
    );

void
QuicPoolFree(
    _Inout_ PQUIC_POOL Pool,
    _In_ void* Entry
    );

#define QuicZeroMemory(Destination, Length) memset((Destination), 0, (Length))
#define QuicCopyMemory(Destination, Source, Length) memcpy((Destination), (Source), (Length))
#define QuicMoveMemory(Destination, Source, Length) memmove((Destination), (Source), (Length))
#define QuicSecureZeroMemory QuicZeroMemory // TODO - Something better?

#define QuicByteSwapUint16(value) __builtin_bswap16((unsigned short)(value))
#define QuicByteSwapUint32(value) __builtin_bswap32((value))
#define QuicByteSwapUint64(value) __builtin_bswap64((value))

//
// Lock interfaces.
//

//
// Represents a QUIC lock.
//

typedef struct _QUIC_LOCK {

    pthread_mutex_t Mutex;

} QUIC_LOCK, *PQUIC_LOCK;

#define QuicLockInitialize(Lock) { \
    pthread_mutexattr_t Attr; \
    QUIC_FRE_ASSERT(pthread_mutexattr_init(&Attr) == 0); \
    QUIC_FRE_ASSERT(pthread_mutexattr_settype(&Attr, PTHREAD_MUTEX_RECURSIVE) == 0); \
    QUIC_FRE_ASSERT(pthread_mutex_init(&(Lock)->Mutex, &Attr) == 0); \
    QUIC_FRE_ASSERT(pthread_mutexattr_destroy(&Attr) == 0); \
}

#define QuicLockUninitialize(Lock) \
        QUIC_FRE_ASSERT(pthread_mutex_destroy(&(Lock)->Mutex) == 0);

#define QuicLockAcquire(Lock) \
    QUIC_FRE_ASSERT(pthread_mutex_lock(&(Lock)->Mutex) == 0);

#define QuicLockRelease(Lock) \
    QUIC_FRE_ASSERT(pthread_mutex_unlock(&(Lock)->Mutex) == 0);

typedef QUIC_LOCK QUIC_DISPATCH_LOCK, *PQUIC_DISPATCH_LOCK;

#define QuicDispatchLockInitialize QuicLockInitialize

#define QuicDispatchLockUninitialize QuicLockUninitialize

#define QuicDispatchLockAcquire QuicLockAcquire

#define QuicDispatchLockRelease QuicLockRelease

//
// Represents a QUIC RW lock.
//

typedef struct _QUIC_RW_LOCK {

    pthread_rwlock_t RwLock;

} QUIC_RW_LOCK, *PQUIC_RW_LOCK;

#define QuicRwLockInitialize(Lock) \
    QUIC_FRE_ASSERT(pthread_rwlock_init(&(Lock)->RwLock, NULL) == 0);

#define QuicRwLockUninitialize(Lock) \
    QUIC_FRE_ASSERT(pthread_rwlock_destroy(&(Lock)->RwLock) == 0);

#define QuicRwLockAcquireShared(Lock) \
    QUIC_FRE_ASSERT(pthread_rwlock_rdlock(&(Lock)->RwLock) == 0);

#define QuicRwLockAcquireExclusive(Lock) \
    QUIC_FRE_ASSERT(pthread_rwlock_wrlock(&(Lock)->RwLock) == 0);

#define QuicRwLockReleaseShared(Lock) \
    QUIC_FRE_ASSERT(pthread_rwlock_unlock(&(Lock)->RwLock) == 0);

#define QuicRwLockReleaseExclusive(Lock) \
    QUIC_FRE_ASSERT(pthread_rwlock_unlock(&(Lock)->RwLock) == 0);

typedef QUIC_RW_LOCK QUIC_DISPATCH_RW_LOCK, *PQUIC_DISPATCH_RW_LOCK;

#define QuicDispatchRwLockInitialize QuicRwLockInitialize

#define QuicDispatchRwLockUninitialize QuicRwLockUninitialize

#define QuicDispatchRwLockAcquireShared QuicRwLockAcquireShared

#define QuicDispatchRwLockAcquireExclusive QuicRwLockAcquireExclusive

#define QuicDispatchRwLockReleaseShared QuicRwLockReleaseShared

#define QuicDispatchRwLockReleaseExclusive QuicRwLockReleaseExclusive

//
// Reference Count Interface
//

typedef int64_t QUIC_REF_COUNT, *PQUIC_REF_COUNT;

void
QuicRefInitialize(
    _Inout_ PQUIC_REF_COUNT RefCount
    );

void
QuicRefIncrement(
    _Inout_ PQUIC_REF_COUNT RefCount
    );

BOOLEAN
QuicRefIncrementNonZero(
    _Inout_ volatile PQUIC_REF_COUNT RefCount
    );

BOOLEAN
QuicRefDecrement(
    _In_ PQUIC_REF_COUNT RefCount
    );

#define QuicRefUninitialize(RefCount)

//
// Event Interfaces
//

//
// QUIC event object.
//

typedef struct _QUIC_EVENT_OBJECT {

    //
    // Mutex and condition.
    //

    pthread_mutex_t Mutex;
    pthread_cond_t Cond;

    //
    // Denotes if the event object is in signaled state.
    //

    BOOLEAN Signaled;

    //
    // Denotes if the event object should be auto reset after it's signaled.
    //

    BOOLEAN AutoReset;

} QUIC_EVENT_OBJECT, *PQUIC_EVENT_OBJECT;

typedef PQUIC_EVENT_OBJECT QUIC_EVENT, *PQUIC_EVENT;

void
QuicEventInitialize(
    _Out_ PQUIC_EVENT Event,
    _In_ BOOLEAN ManualReset,
    _In_ BOOLEAN InitialState
    );

void
QuicEventUninitialize(
    _Inout_ QUIC_EVENT Event
    );

void
QuicEventSet(
    _Inout_ QUIC_EVENT Event
    );

void
QuicEventReset(
    _Inout_ QUIC_EVENT Event
    );

void
QuicEventWaitForever(
    _Inout_ QUIC_EVENT Event
    );

BOOLEAN
QuicEventWaitWithTimeout(
    _Inout_ QUIC_EVENT Event,
    _In_ ULONG timeoutMs
    );

//
// Time Measurement Interfaces
//

#define QUIC_NANOSEC_PER_MS       (1000000)
#define QUIC_NANOSEC_PER_MICROSEC (1000)
#define QUIC_NANOSEC_PER_SEC      (1000000000)
#define QUIC_MICROSEC_PER_MS      (1000)
#define QUIC_MICROSEC_PER_SEC     (1000000)
#define QUIC_MS_PER_SECOND        (1000)

uint64_t
QuicGetTimerResolution(
    void
    );

uint64_t
QuicTimeUs64(
    void
    );

void
QuicGetAbsoluteTime(
    _In_ unsigned long DeltaMs,
    _Out_ struct timespec *Time
    );

#define QuicTimeUs32() (uint32_t)QuicTimeUs64()
#define QuicTimeMs64()  (QuicTimeUs64() / QUIC_MICROSEC_PER_MS)
#define QuicTimeMs32() (uint32_t)QuicTimeMs64()
#define QuicTimeUs64ToPlat(x) (x)

inline
uint64_t
QuicTimeDiff64(
    _In_ uint64_t T1,
    _In_ uint64_t T2
    )
/*++

Routine Description:

    Returns the difference between two 64-bit timestamps.

Arguments:

    T1 - First time measured.

    T2 - Second time measured.

Return Value:

    Returns the difference.

--*/
{
    //
    // Assume no wrap around.
    //

    return T2 - T1;
}

inline
uint32_t
QuicTimeDiff32(
    _In_ uint32_t T1,     // First time measured
    _In_ uint32_t T2      // Second time measured
    )
/*++

Routine Description:

    Returns the difference between two 32-bit timestamps.

Arguments:

    T1 - First time measured.

    T2 - Second time measured.

Return Value:

    Returns the difference.

--*/

{
    if (T2 > T1) {
        return T2 - T1;
    } else { // Wrap around case.
        return T2 + (0xFFFFFFFF - T1) + 1;
    }
}

inline
BOOLEAN
QuicTimeAtOrBefore64(
    _In_ uint64_t T1,
    _In_ uint64_t T2
    )
/*++

Routine Description:

    Checks if T1 came before T2 (64-bit version).

Arguments:

    T1 - First time measured.

    T2 - Second time measured.

Return Value:

    Returns TRUE if T1 came before T2.

--*/
{
    //
    // Assume no wrap around.
    //

    return T1 <= T2;
}

inline
BOOLEAN
QuicTimeAtOrBefore32(
    _In_ uint32_t T1,
    _In_ uint32_t T2
    )
/*++

Routine Description:

    Checks if T1 came before T2 (32-bit version).

Arguments:

    T1 - First time measured.

    T2 - Second time measured.

Return Value:

    Returns TRUE if T1 came before T2.

--*/
{
    return (int32_t)(T1 - T2) <= 0;
}

void
QuicSleep(
    _In_ uint32_t DurationMs
    );


//
// Thread Interfaces.
//

//
// QUIC thread object.
//

typedef struct _QUIC_THREAD {

    pthread_t Thread;

} QUIC_THREAD, *PQUIC_THREAD;

#define QUIC_THREAD_CALLBACK(FuncName, CtxVarName) \
    void* \
    FuncName( \
        void* CtxVarName \
        )

#define QUIC_THREAD_RETURN(Status) return NULL;

typedef void* (* LPTHREAD_START_ROUTINE)(void *);

#define QUIC_THREAD_FLAG_SET_IDEAL_PROC     0x0001
#define QUIC_THREAD_FLAG_SET_AFFINITIZE     0x0002
#define QUIC_THREAD_FLAG_HIGH_PRIORITY      0x0004

typedef struct _QUIC_THREAD_CONFIG {
    uint16_t Flags;
    uint8_t IdealProcessor;
    _Field_z_ const char* Name;
    LPTHREAD_START_ROUTINE Callback;
    void* Context;
} QUIC_THREAD_CONFIG;

QUIC_STATUS
QuicThreadCreate(
    _In_ QUIC_THREAD_CONFIG* Config,
    _Out_ PQUIC_THREAD* Thread
    );

void
QuicThreadDelete(
    _Inout_ PQUIC_THREAD Thread
    );

void
QuicThreadWait(
    _Inout_ PQUIC_THREAD Thread
    );

uint32_t
QuicCurThreadID(
    void
    );

//
// Processor Count and Index.
//

uint32_t
QuicProcMaxCount(
    void
    );

uint32_t
QuicProcActiveCount(
    void
    );

uint32_t
QuicProcCurrentNumber(
    void
    );

//
// Rundown Protection Interfaces.
//

typedef struct _QUIC_RUNDOWN_REF {

    //
    // The ref counter.
    //

    QUIC_REF_COUNT RefCount;

    //
    // The completion event.
    //

    QUIC_EVENT RundownComplete;

} QUIC_RUNDOWN_REF, *PQUIC_RUNDOWN_REF;


void
QuicRundownInitialize(
    _Inout_ PQUIC_RUNDOWN_REF Rundown
    );

void
QuicRundownInitializeDisabled(
    _Inout_ PQUIC_RUNDOWN_REF Rundown
    );

void
QuicRundownReInitialize(
    _Inout_ PQUIC_RUNDOWN_REF Rundown
    );

void
QuicRundownUninitialize(
    _Inout_ PQUIC_RUNDOWN_REF Rundown
    );

BOOLEAN
QuicRundownAcquire(
    _Inout_ PQUIC_RUNDOWN_REF Rundown
    );

void
QuicRundownRelease(
    _Inout_ PQUIC_RUNDOWN_REF Rundown
    );

void
QuicRundownReleaseAndWait(
    _Inout_ PQUIC_RUNDOWN_REF Rundown
    );

//
// Crypto Interfaces
//

QUIC_STATUS
QuicRandom(
    _In_ UINT32 BufferLen,
    _Out_writes_bytes_(BufferLen) PUCHAR Buffer
    );

//
// Tracing stuff.
//

void
QuicConvertToMappedV6(
    _In_ const SOCKADDR_INET * InAddr,
    _Out_ SOCKADDR_INET * OutAddr
    );

void
QuicConvertFromMappedV6(
    _In_ const SOCKADDR_INET * InAddr,
    _Out_ SOCKADDR_INET * OutAddr
    );

//
// Test Interface for loading a self-signed certificate.
//

#ifdef QUIC_TEST_APIS

typedef struct QUIC_SEC_CONFIG_PARAMS {
    uint32_t Flags;
    void* Certificate;
    const char* Principal;
} QUIC_SEC_CONFIG_PARAMS;

typedef enum QUIC_SELF_SIGN_CERT_TYPE {
    QUIC_SELF_SIGN_CERT_USER,
    QUIC_SELF_SIGN_CERT_MACHINE
} QUIC_SELF_SIGN_CERT_TYPE;

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_SEC_CONFIG_PARAMS*
QuicPlatGetSelfSignedCert(
    _In_ QUIC_SELF_SIGN_CERT_TYPE Type
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPlatFreeSelfSignedCert(
    _In_ QUIC_SEC_CONFIG_PARAMS* Params
    );

#endif // QUIC_TEST_APIS

#if defined(__cplusplus)
}
#endif

#endif // _PLATFORM_LINUX_
