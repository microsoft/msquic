/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file contains linux platform implementation.

Environment:

    Linux user mode

--*/

#pragma once

#ifndef CX_PLATFORM_TYPE
#error "Must be included from quic_platform.h"
#endif

#ifndef CX_PLATFORM_LINUX
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
CxPlatSystemLoad(
    void
    );

void
CxPlatSystemUnload(
    void
    );

QUIC_STATUS
CxPlatInitialize(
    void
    );

void
CxPlatUninitialize(
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

__attribute__((noinline, noreturn))
void
quic_bugcheck(
    void
    );

void
CxPlatLogAssert(
    _In_z_ const char* File,
    _In_ int Line,
    _In_z_ const char* Expr
    );

#define CXPLAT_STATIC_ASSERT(X,Y) static_assert(X, Y);
#define CXPLAT_ANALYSIS_ASSERT(X)
#define CXPLAT_ANALYSIS_ASSUME(X)
#define CXPLAT_FRE_ASSERT(exp) ((exp) ? (void)0 : (CxPlatLogAssert(__FILE__, __LINE__, #exp), quic_bugcheck()));

#ifdef DEBUG
#define CXPLAT_DBG_ASSERT(exp) CXPLAT_FRE_ASSERT(exp)
#define CXPLAT_DBG_ASSERTMSG(exp, msg) CXPLAT_FRE_ASSERT(exp)
#define CXPLAT_TEL_ASSERT(exp) CXPLAT_FRE_ASSERT(exp)
#define CXPLAT_TEL_ASSERTMSG(exp, Y) CXPLAT_FRE_ASSERT(exp)
#define CXPLAT_TEL_ASSERTMSG_ARGS(exp, _msg, _origin, _bucketArg1, _bucketArg2) CXPLAT_FRE_ASSERT(exp)
#define CXPLAT_FRE_ASSERTMSG(exp, Y) CXPLAT_FRE_ASSERT(exp)
#else
#define CXPLAT_DBG_ASSERT(exp)
#define CXPLAT_DBG_ASSERTMSG(exp, msg)
#define CXPLAT_TEL_ASSERT(exp)
#define CXPLAT_TEL_ASSERTMSG(exp, Y)
#define CXPLAT_TEL_ASSERTMSG_ARGS(exp, _msg, _origin, _bucketArg1, _bucketArg2)
#define CXPLAT_FRE_ASSERTMSG(exp, Y)
#endif

#define __assume(X) (void)0

//
// Debugger check.
//

#define CxPlatDebuggerPresent() FALSE

//
// Interrupt ReQuest Level.
//

#define CXPLAT_IRQL() 0
#define CXPLAT_PASSIVE_CODE()

//
// Memory management interfaces.
//

extern uint64_t CxPlatTotalMemory;

_Ret_maybenull_
void*
CxPlatAlloc(
    _In_ size_t ByteCount,
    _In_ uint32_t Tag
    );

void
CxPlatFree(
    __drv_freesMem(Mem) _Frees_ptr_opt_ void* Mem,
    _In_ uint32_t Tag
    );

#define CXPLAT_ALLOC_PAGED(Size, Tag) CxPlatAlloc(Size, Tag)
#define CXPLAT_ALLOC_NONPAGED(Size, Tag) CxPlatAlloc(Size, Tag)
#define CXPLAT_FREE(Mem, Tag) CxPlatFree((void*)Mem, Tag)

//
// Represents a QUIC memory pool used for fixed sized allocations.
//

typedef struct CXPLAT_POOL {

    //
    // List of free entries.
    //

    CXPLAT_SLIST_ENTRY ListHead;

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

} CXPLAT_POOL;

#define QUIC_POOL_MAXIMUM_DEPTH   256 // Copied from EX_MAXIMUM_LOOKASIDE_DEPTH_BASE

void
CxPlatPoolInitialize(
    _In_ BOOLEAN IsPaged,
    _In_ uint32_t Size,
    _In_ uint32_t Tag,
    _Inout_ CXPLAT_POOL* Pool
    );

void
CxPlatPoolUninitialize(
    _Inout_ CXPLAT_POOL* Pool
    );

void*
CxPlatPoolAlloc(
    _Inout_ CXPLAT_POOL* Pool
    );

void
CxPlatPoolFree(
    _Inout_ CXPLAT_POOL* Pool,
    _In_ void* Entry
    );

#define CxPlatZeroMemory(Destination, Length) memset((Destination), 0, (Length))
#define CxPlatCopyMemory(Destination, Source, Length) memcpy((Destination), (Source), (Length))
#define CxPlatMoveMemory(Destination, Source, Length) memmove((Destination), (Source), (Length))
#define CxPlatSecureZeroMemory CxPlatZeroMemory // TODO - Something better?

#define CxPlatByteSwapUint16(value) __builtin_bswap16((unsigned short)(value))
#define CxPlatByteSwapUint32(value) __builtin_bswap32((value))
#define CxPlatByteSwapUint64(value) __builtin_bswap64((value))

//
// Lock interfaces.
//

//
// Represents a QUIC lock.
//

typedef struct CXPLAT_LOCK {

    pthread_mutex_t Mutex;

} CXPLAT_LOCK;

#define CxPlatLockInitialize(Lock) { \
    pthread_mutexattr_t Attr; \
    CXPLAT_FRE_ASSERT(pthread_mutexattr_init(&Attr) == 0); \
    CXPLAT_FRE_ASSERT(pthread_mutexattr_settype(&Attr, PTHREAD_MUTEX_RECURSIVE) == 0); \
    CXPLAT_FRE_ASSERT(pthread_mutex_init(&(Lock)->Mutex, &Attr) == 0); \
    CXPLAT_FRE_ASSERT(pthread_mutexattr_destroy(&Attr) == 0); \
}

#define CxPlatLockUninitialize(Lock) \
        CXPLAT_FRE_ASSERT(pthread_mutex_destroy(&(Lock)->Mutex) == 0);

#define CxPlatLockAcquire(Lock) \
    CXPLAT_FRE_ASSERT(pthread_mutex_lock(&(Lock)->Mutex) == 0);

#define CxPlatLockRelease(Lock) \
    CXPLAT_FRE_ASSERT(pthread_mutex_unlock(&(Lock)->Mutex) == 0);

typedef CXPLAT_LOCK CXPLAT_DISPATCH_LOCK;

#define CxPlatDispatchLockInitialize CxPlatLockInitialize

#define CxPlatDispatchLockUninitialize CxPlatLockUninitialize

#define CxPlatDispatchLockAcquire CxPlatLockAcquire

#define CxPlatDispatchLockRelease CxPlatLockRelease

//
// Represents a QUIC RW lock.
//

typedef struct CXPLAT_RW_LOCK {

    pthread_rwlock_t RwLock;

} CXPLAT_RW_LOCK;

#define CxPlatRwLockInitialize(Lock) \
    CXPLAT_FRE_ASSERT(pthread_rwlock_init(&(Lock)->RwLock, NULL) == 0);

#define CxPlatRwLockUninitialize(Lock) \
    CXPLAT_FRE_ASSERT(pthread_rwlock_destroy(&(Lock)->RwLock) == 0);

#define CxPlatRwLockAcquireShared(Lock) \
    CXPLAT_FRE_ASSERT(pthread_rwlock_rdlock(&(Lock)->RwLock) == 0);

#define CxPlatRwLockAcquireExclusive(Lock) \
    CXPLAT_FRE_ASSERT(pthread_rwlock_wrlock(&(Lock)->RwLock) == 0);

#define CxPlatRwLockReleaseShared(Lock) \
    CXPLAT_FRE_ASSERT(pthread_rwlock_unlock(&(Lock)->RwLock) == 0);

#define CxPlatRwLockReleaseExclusive(Lock) \
    CXPLAT_FRE_ASSERT(pthread_rwlock_unlock(&(Lock)->RwLock) == 0);

typedef CXPLAT_RW_LOCK CXPLAT_DISPATCH_RW_LOCK;

#define CxPlatDispatchRwLockInitialize CxPlatRwLockInitialize

#define CxPlatDispatchRwLockUninitialize CxPlatRwLockUninitialize

#define CxPlatDispatchRwLockAcquireShared CxPlatRwLockAcquireShared

#define CxPlatDispatchRwLockAcquireExclusive CxPlatRwLockAcquireExclusive

#define CxPlatDispatchRwLockReleaseShared CxPlatRwLockReleaseShared

#define CxPlatDispatchRwLockReleaseExclusive CxPlatRwLockReleaseExclusive

//
// Reference Count Interface
//

typedef int64_t CXPLAT_REF_COUNT;

void
CxPlatRefInitialize(
    _Inout_ CXPLAT_REF_COUNT* RefCount
    );

void
CxPlatRefIncrement(
    _Inout_ CXPLAT_REF_COUNT* RefCount
    );

BOOLEAN
CxPlatRefIncrementNonZero(
    _Inout_ volatile CXPLAT_REF_COUNT* RefCount
    );

BOOLEAN
CxPlatRefDecrement(
    _In_ CXPLAT_REF_COUNT* RefCount
    );

#define CxPlatRefUninitialize(RefCount)

//
// Event Interfaces
//

//
// QUIC event object.
//

typedef struct CXPLAT_EVENT_OBJECT {

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

} CXPLAT_EVENT_OBJECT;

typedef CXPLAT_EVENT_OBJECT* CXPLAT_EVENT;

void
CxPlatEventInitialize(
    _Out_ CXPLAT_EVENT* Event,
    _In_ BOOLEAN ManualReset,
    _In_ BOOLEAN InitialState
    );

void
CxPlatEventUninitialize(
    _Inout_ CXPLAT_EVENT Event
    );

void
CxPlatEventSet(
    _Inout_ CXPLAT_EVENT Event
    );

void
CxPlatEventReset(
    _Inout_ CXPLAT_EVENT Event
    );

void
CxPlatEventWaitForever(
    _Inout_ CXPLAT_EVENT Event
    );

BOOLEAN
CxPlatEventWaitWithTimeout(
    _Inout_ CXPLAT_EVENT Event,
    _In_ uint32_t timeoutMs
    );

//
// Time Measurement Interfaces
//

#define CXPLAT_NANOSEC_PER_MS       (1000000)
#define CXPLAT_NANOSEC_PER_MICROSEC (1000)
#define CXPLAT_NANOSEC_PER_SEC      (1000000000)
#define CXPLAT_MICROSEC_PER_MS      (1000)
#define CXPLAT_MICROSEC_PER_SEC     (1000000)
#define CXPLAT_MS_PER_SECOND        (1000)

uint64_t
CxPlatGetTimerResolution(
    void
    );

uint64_t
CxPlatTimeUs64(
    void
    );

void
CxPlatGetAbsoluteTime(
    _In_ unsigned long DeltaMs,
    _Out_ struct timespec *Time
    );

#define CxPlatTimeUs32() (uint32_t)CxPlatTimeUs64()
#define CxPlatTimeMs64()  (CxPlatTimeUs64() / CXPLAT_MICROSEC_PER_MS)
#define CxPlatTimeMs32() (uint32_t)CxPlatTimeMs64()
#define CxPlatTimeUs64ToPlat(x) (x)

inline
int64_t
CxPlatTimeEpochMs64(
    void
    )
{
    struct timeval tv = { 0, 0 };
    gettimeofday(&tv, NULL);
    return S_TO_MS(tv.tv_sec) + US_TO_MS(tv.tv_usec);
}

inline
uint64_t
CxPlatTimeDiff64(
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
CxPlatTimeDiff32(
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
CxPlatTimeAtOrBefore64(
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
CxPlatTimeAtOrBefore32(
    _In_ uint32_t T1,
    _In_ uint32_t T2
    )
{
    return (int32_t)(T1 - T2) <= 0;
}

void
CxPlatSleep(
    _In_ uint32_t DurationMs
    );


//
// Thread Interfaces.
//

//
// QUIC thread object.
//

typedef pthread_t CXPLAT_THREAD;

#define CXPLAT_THREAD_CALLBACK(FuncName, CtxVarName) \
    void* \
    FuncName( \
        void* CtxVarName \
        )

#define CXPLAT_THREAD_RETURN(Status) return NULL;

typedef void* (* LPTHREAD_START_ROUTINE)(void *);

typedef struct CXPLAT_THREAD_CONFIG {
    uint16_t Flags;
    uint16_t IdealProcessor;
    _Field_z_ const char* Name;
    LPTHREAD_START_ROUTINE Callback;
    void* Context;
} CXPLAT_THREAD_CONFIG;

#ifdef CXPLAT_USE_CUSTOM_THREAD_CONTEXT

//
// Extension point that allows additional platform specific logic to be executed
// for every thread created. The platform must define CXPLAT_USE_CUSTOM_THREAD_CONTEXT
// and implement the CxPlatThreadCustomStart function. CxPlatThreadCustomStart MUST
// call the Callback passed in. CxPlatThreadCustomStart MUST also free
// CustomContext (via CXPLAT_FREE(CustomContext, QUIC_POOL_CUSTOM_THREAD)) before
// returning.
//

typedef struct CXPLAT_THREAD_CUSTOM_CONTEXT {
    LPTHREAD_START_ROUTINE Callback;
    void* Context;
} CXPLAT_THREAD_CUSTOM_CONTEXT;

CXPLAT_THREAD_CALLBACK(CxPlatThreadCustomStart, CustomContext); // CXPLAT_THREAD_CUSTOM_CONTEXT* CustomContext

#endif // CXPLAT_USE_CUSTOM_THREAD_CONTEXT

QUIC_STATUS
CxPlatThreadCreate(
    _In_ CXPLAT_THREAD_CONFIG* Config,
    _Out_ CXPLAT_THREAD* Thread
    );

void
CxPlatThreadDelete(
    _Inout_ CXPLAT_THREAD* Thread
    );

void
CxPlatThreadWait(
    _Inout_ CXPLAT_THREAD* Thread
    );

typedef uint32_t CXPLAT_THREAD_ID;

uint32_t
CxPlatCurThreadID(
    void
    );

//
// Processor Count and Index.
//

uint32_t
CxPlatProcMaxCount(
    void
    );

uint32_t
CxPlatProcActiveCount(
    void
    );

uint32_t
CxPlatProcCurrentNumber(
    void
    );

//
// Rundown Protection Interfaces.
//

typedef struct CXPLAT_RUNDOWN_REF {

    //
    // The ref counter.
    //

    CXPLAT_REF_COUNT RefCount;

    //
    // The completion event.
    //

    CXPLAT_EVENT RundownComplete;

} CXPLAT_RUNDOWN_REF;


void
CxPlatRundownInitialize(
    _Inout_ CXPLAT_RUNDOWN_REF* Rundown
    );

void
CxPlatRundownInitializeDisabled(
    _Inout_ CXPLAT_RUNDOWN_REF* Rundown
    );

void
CxPlatRundownReInitialize(
    _Inout_ CXPLAT_RUNDOWN_REF* Rundown
    );

void
CxPlatRundownUninitialize(
    _Inout_ CXPLAT_RUNDOWN_REF* Rundown
    );

BOOLEAN
CxPlatRundownAcquire(
    _Inout_ CXPLAT_RUNDOWN_REF* Rundown
    );

void
CxPlatRundownRelease(
    _Inout_ CXPLAT_RUNDOWN_REF* Rundown
    );

void
CxPlatRundownReleaseAndWait(
    _Inout_ CXPLAT_RUNDOWN_REF* Rundown
    );

//
// Crypto Interfaces
//

QUIC_STATUS
CxPlatRandom(
    _In_ uint32_t BufferLen,
    _Out_writes_bytes_(BufferLen) void* Buffer
    );

//
// Tracing stuff.
//

void
CxPlatConvertToMappedV6(
    _In_ const QUIC_ADDR* InAddr,
    _Out_ QUIC_ADDR* OutAddr
    );

void
CxPlatConvertFromMappedV6(
    _In_ const QUIC_ADDR* InAddr,
    _Out_ QUIC_ADDR* OutAddr
    );

#define CxPlatSetCurrentThreadProcessorAffinity(ProcessorIndex) QUIC_STATUS_SUCCESS
#define CxPlatSetCurrentThreadGroupAffinity(ProcessorGroup) QUIC_STATUS_SUCCESS

#define CXPLAT_CPUID(FunctionId, eax, ebx, ecx, dx)

#if defined(__cplusplus)
}
#endif
