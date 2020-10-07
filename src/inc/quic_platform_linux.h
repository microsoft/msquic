/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file contains linux platform implementation.

Environment:

    Linux user mode

--*/

#pragma once

#ifndef QUIC_PLATFORM_TYPE
#error "Must be included from quic_platform.h"
#endif

#ifndef QUIC_PLATFORM_LINUX
#error "Incorrectly including Linux Platform Header from non-Linux platfrom"
#endif

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
#include <sys/time.h>
#include <quic_sal_stub.h>

#if defined(__cplusplus)
extern "C" {
#endif

#ifndef NDEBUG
#define DEBUG 1
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

#define UNREFERENCED_PARAMETER(P) (void)(P)

#define QuicNetByteSwapShort(x) htons((x))

#define SIZEOF_STRUCT_MEMBER(StructType, StructMember) sizeof(((StructType *)0)->StructMember)
#define TYPEOF_STRUCT_MEMBER(StructType, StructMember) typeof(((StructType *)0)->StructMember)

#if defined(__GNUC__) && __GNUC__ >= 7
#define __fallthrough __attribute__((fallthrough))
#else
#define __fallthrough // fall through
#endif /* __GNUC__ >= 7 */


//
// Interlocked implementations.
//

inline
long
InterlockedIncrement(
    _Inout_ _Interlocked_operand_ long volatile *Addend
    )
{
    return __sync_add_and_fetch(Addend, (long)1);
}

inline
long
InterlockedDecrement(
    _Inout_ _Interlocked_operand_ long volatile *Addend
    )
{
    return __sync_sub_and_fetch(Addend, (long)1);
}

inline
int64_t
InterlockedExchangeAdd64(
    _Inout_ _Interlocked_operand_ int64_t volatile *Addend,
    _In_ int64_t Value
    )
{
    return __sync_fetch_and_add(Addend, Value);
}

inline
short
InterlockedCompareExchange16(
    _Inout_ _Interlocked_operand_ short volatile *Destination,
    _In_ short ExChange,
    _In_ short Comperand
    )
{
    return __sync_val_compare_and_swap(Destination, Comperand, ExChange);
}

inline
short
InterlockedIncrement16(
    _Inout_ _Interlocked_operand_ short volatile *Addend
    )
{
    return __sync_add_and_fetch(Addend, (short)1);
}

inline
short
InterlockedDecrement16(
    _Inout_ _Interlocked_operand_ short volatile *Addend
    )
{
    return __sync_sub_and_fetch(Addend, (short)1);
}

inline
int64_t
InterlockedIncrement64(
    _Inout_ _Interlocked_operand_ int64_t volatile *Addend
    )
{
    return __sync_add_and_fetch(Addend, (int64_t)1);
}

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
    _In_z_ const char* Expr
    );

#define QUIC_STATIC_ASSERT(X,Y) static_assert(X, Y);
#define QUIC_ANALYSIS_ASSERT(X)
#define QUIC_ANALYSIS_ASSUME(X)
#define QUIC_FRE_ASSERT(exp) ((exp) ? (void)0 : (QuicPlatformLogAssert(__FILE__, __LINE__, #exp), quic_bugcheck()));

#ifdef DEBUG
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
    _In_ size_t ByteCount
    );

void
QuicFree(
    __drv_freesMem(Mem) _Frees_ptr_opt_ void* Mem
    );

#define QUIC_ALLOC_PAGED(Size) QuicAlloc(Size)
#define QUIC_ALLOC_NONPAGED(Size) QuicAlloc(Size)
#define QUIC_FREE(Mem) QuicFree((void*)Mem)
#define QUIC_FREE_TAG(Mem, Tag) QUIC_FREE(Mem)

//
// Represents a QUIC memory pool used for fixed sized allocations.
//

typedef struct QUIC_POOL {

    //
    // List of free entries.
    //

    QUIC_SINGLE_LIST_ENTRY ListHead;

    //
    // Number of free entries in the list.
    //

    uint16_t ListDepth;

    //
    // Lock to synchronize access to the List.
    // LINUX_TODO: Check how to make this lock free?
    //

    pthread_mutex_t Lock;

    //
    // Size of entries.
    //

    uint32_t Size;

    //
    // The memory tag to use for any allocation from this pool.
    //

    uint32_t MemTag;

} QUIC_POOL;

#define QUIC_POOL_MAXIMUM_DEPTH   256 // Copied from EX_MAXIMUM_LOOKASIDE_DEPTH_BASE

void
QuicPoolInitialize(
    _In_ BOOLEAN IsPaged,
    _In_ uint32_t Size,
    _In_ uint32_t Tag,
    _Inout_ QUIC_POOL* Pool
    );

void
QuicPoolUninitialize(
    _Inout_ QUIC_POOL* Pool
    );

void*
QuicPoolAlloc(
    _Inout_ QUIC_POOL* Pool
    );

void
QuicPoolFree(
    _Inout_ QUIC_POOL* Pool,
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

typedef struct QUIC_LOCK {

    pthread_mutex_t Mutex;

} QUIC_LOCK;

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

typedef QUIC_LOCK QUIC_DISPATCH_LOCK;

#define QuicDispatchLockInitialize QuicLockInitialize

#define QuicDispatchLockUninitialize QuicLockUninitialize

#define QuicDispatchLockAcquire QuicLockAcquire

#define QuicDispatchLockRelease QuicLockRelease

//
// Represents a QUIC RW lock.
//

typedef struct QUIC_RW_LOCK {

    pthread_rwlock_t RwLock;

} QUIC_RW_LOCK;

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

typedef QUIC_RW_LOCK QUIC_DISPATCH_RW_LOCK;

#define QuicDispatchRwLockInitialize QuicRwLockInitialize

#define QuicDispatchRwLockUninitialize QuicRwLockUninitialize

#define QuicDispatchRwLockAcquireShared QuicRwLockAcquireShared

#define QuicDispatchRwLockAcquireExclusive QuicRwLockAcquireExclusive

#define QuicDispatchRwLockReleaseShared QuicRwLockReleaseShared

#define QuicDispatchRwLockReleaseExclusive QuicRwLockReleaseExclusive

//
// Reference Count Interface
//

typedef int64_t QUIC_REF_COUNT;

void
QuicRefInitialize(
    _Inout_ QUIC_REF_COUNT* RefCount
    );

void
QuicRefIncrement(
    _Inout_ QUIC_REF_COUNT* RefCount
    );

BOOLEAN
QuicRefIncrementNonZero(
    _Inout_ volatile QUIC_REF_COUNT* RefCount
    );

BOOLEAN
QuicRefDecrement(
    _In_ QUIC_REF_COUNT* RefCount
    );

#define QuicRefUninitialize(RefCount)

//
// Event Interfaces
//

//
// QUIC event object.
//

typedef struct QUIC_EVENT_OBJECT {

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

} QUIC_EVENT_OBJECT;

typedef QUIC_EVENT_OBJECT* QUIC_EVENT;

void
QuicEventInitialize(
    _Out_ QUIC_EVENT* Event,
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
    _In_ uint32_t timeoutMs
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
int64_t
QuicTimeEpochMs64(
    void
    )
{
    struct timeval tv = { 0, 0 };
    gettimeofday(&tv, NULL);
    return S_TO_MS(tv.tv_sec) + US_TO_MS(tv.tv_usec);
}

inline
uint64_t
QuicTimeDiff64(
    _In_ uint64_t T1,
    _In_ uint64_t T2
    )
{
    //
    // Assume no wrap around.
    //

    return T2 - T1;
}

inline
uint32_t
QUIC_NO_SANITIZE("unsigned-integer-overflow")
QuicTimeDiff32(
    _In_ uint32_t T1,     // First time measured
    _In_ uint32_t T2      // Second time measured
    )
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
{
    //
    // Assume no wrap around.
    //

    return T1 <= T2;
}

inline
BOOLEAN
QUIC_NO_SANITIZE("unsigned-integer-overflow")
QuicTimeAtOrBefore32(
    _In_ uint32_t T1,
    _In_ uint32_t T2
    )
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

typedef pthread_t QUIC_THREAD;

#define QUIC_THREAD_CALLBACK(FuncName, CtxVarName) \
    void* \
    FuncName( \
        void* CtxVarName \
        )

#define QUIC_THREAD_RETURN(Status) return NULL;

typedef void* (* LPTHREAD_START_ROUTINE)(void *);

typedef struct QUIC_THREAD_CONFIG {
    uint16_t Flags;
    uint16_t IdealProcessor;
    _Field_z_ const char* Name;
    LPTHREAD_START_ROUTINE Callback;
    void* Context;
} QUIC_THREAD_CONFIG;

QUIC_STATUS
QuicThreadCreate(
    _In_ QUIC_THREAD_CONFIG* Config,
    _Out_ QUIC_THREAD* Thread
    );

void
QuicThreadDelete(
    _Inout_ QUIC_THREAD* Thread
    );

void
QuicThreadWait(
    _Inout_ QUIC_THREAD* Thread
    );

typedef uint32_t QUIC_THREAD_ID;

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

typedef struct QUIC_RUNDOWN_REF {

    //
    // The ref counter.
    //

    QUIC_REF_COUNT RefCount;

    //
    // The completion event.
    //

    QUIC_EVENT RundownComplete;

} QUIC_RUNDOWN_REF;


void
QuicRundownInitialize(
    _Inout_ QUIC_RUNDOWN_REF* Rundown
    );

void
QuicRundownInitializeDisabled(
    _Inout_ QUIC_RUNDOWN_REF* Rundown
    );

void
QuicRundownReInitialize(
    _Inout_ QUIC_RUNDOWN_REF* Rundown
    );

void
QuicRundownUninitialize(
    _Inout_ QUIC_RUNDOWN_REF* Rundown
    );

BOOLEAN
QuicRundownAcquire(
    _Inout_ QUIC_RUNDOWN_REF* Rundown
    );

void
QuicRundownRelease(
    _Inout_ QUIC_RUNDOWN_REF* Rundown
    );

void
QuicRundownReleaseAndWait(
    _Inout_ QUIC_RUNDOWN_REF* Rundown
    );

//
// Crypto Interfaces
//

QUIC_STATUS
QuicRandom(
    _In_ uint32_t BufferLen,
    _Out_writes_bytes_(BufferLen) void* Buffer
    );

//
// Tracing stuff.
//

void
QuicConvertToMappedV6(
    _In_ const QUIC_ADDR* InAddr,
    _Out_ QUIC_ADDR* OutAddr
    );

void
QuicConvertFromMappedV6(
    _In_ const QUIC_ADDR* InAddr,
    _Out_ QUIC_ADDR* OutAddr
    );

#define QuicSetCurrentThreadProcessorAffinity(ProcessorIndex) QUIC_STATUS_SUCCESS

#define QUIC_CPUID(FunctionId, eax, ebx, ecx, dx)

#if defined(__cplusplus)
}
#endif
