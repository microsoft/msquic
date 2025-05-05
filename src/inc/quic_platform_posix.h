/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file contains POSIX platform implementations of the
    QUIC Platform Interfaces.

Environment:

    POSIX user mode

--*/

#pragma once

#ifndef CX_PLATFORM_TYPE
#error "Must be included from quic_platform.h"
#endif

#if !defined(CX_PLATFORM_LINUX) && !defined(CX_PLATFORM_DARWIN)
#error "Incorrectly including Posix Platform Header from unsupported platfrom"
#endif

// For FreeBSD
#if defined(__FreeBSD__)
#include <sys/socket.h>
#include <netinet/in.h>
#define ETIME   ETIMEDOUT
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
#include <stdalign.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "msquic_posix.h"
#include <stdbool.h>
#include <pthread.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include "quic_sal_stub.h"

#if defined(__cplusplus)
extern "C" {
#endif

#ifndef NDEBUG
#define DEBUG 1
#endif

#define ALIGN_DOWN(length, type) \
    ((unsigned long)(length) & ~(sizeof(type) - 1))

#define ALIGN_UP(length, type) \
    (ALIGN_DOWN(((unsigned long)(length) + sizeof(type) - 1), type))

//
// Generic stuff.
//

#define INVALID_SOCKET ((int)(-1))

#define SOCKET_ERROR (-1)

#define ARRAYSIZE(A) (sizeof(A)/sizeof((A)[0]))

#define UNREFERENCED_PARAMETER(P) (void)(P)

#define QuicNetByteSwapShort(x) htons((x))

#define SIZEOF_STRUCT_MEMBER(StructType, StructMember) sizeof(((StructType *)0)->StructMember)
#define TYPEOF_STRUCT_MEMBER(StructType, StructMember) typeof(((StructType *)0)->StructMember)

#define SOCKET int

#if defined(__GNUC__) && __GNUC__ >= 7
#define __fallthrough __attribute__((fallthrough))
#else
#define __fallthrough // fall through
#endif /* __GNUC__ >= 7 */

//
// Interlocked implementations.
//

QUIC_INLINE
long
InterlockedIncrement(
    _Inout_ _Interlocked_operand_ long volatile *Addend
    )
{
    return __sync_add_and_fetch(Addend, (long)1);
}

QUIC_INLINE
long
InterlockedDecrement(
    _Inout_ _Interlocked_operand_ long volatile *Addend
    )
{
    return __sync_sub_and_fetch(Addend, (long)1);
}

QUIC_INLINE
long
InterlockedAnd(
    _Inout_ _Interlocked_operand_ long volatile *Destination,
    _In_ long Value
    )
{
    return __sync_and_and_fetch(Destination, Value);
}

QUIC_INLINE
long
InterlockedOr(
    _Inout_ _Interlocked_operand_ long volatile *Destination,
    _In_ long Value
    )
{
    return __sync_or_and_fetch(Destination, Value);
}

QUIC_INLINE
int64_t
InterlockedOr64(
    _Inout_ _Interlocked_operand_ int64_t volatile *Destination,
    _In_ int64_t Value
    )
{
    return __sync_fetch_and_or(Destination, Value);
}

QUIC_INLINE
int64_t
InterlockedExchange64(
    _Inout_ _Interlocked_operand_ int64_t volatile *Target,
    _In_ int64_t Value
    )
{
    return __sync_lock_test_and_set(Target, Value);
}

QUIC_INLINE
int64_t
InterlockedExchangeAdd64(
    _Inout_ _Interlocked_operand_ int64_t volatile *Addend,
    _In_ int64_t Value
    )
{
    return __sync_fetch_and_add(Addend, Value);
}

QUIC_INLINE
short
InterlockedCompareExchange16(
    _Inout_ _Interlocked_operand_ short volatile *Destination,
    _In_ short ExChange,
    _In_ short Comperand
    )
{
    return __sync_val_compare_and_swap(Destination, Comperand, ExChange);
}

QUIC_INLINE
short
InterlockedCompareExchange(
    _Inout_ _Interlocked_operand_ long volatile *Destination,
    _In_ long ExChange,
    _In_ long Comperand
    )
{
    return __sync_val_compare_and_swap(Destination, Comperand, ExChange);
}

QUIC_INLINE
int64_t
InterlockedCompareExchange64(
    _Inout_ _Interlocked_operand_ int64_t volatile *Destination,
    _In_ int64_t ExChange,
    _In_ int64_t Comperand
    )
{
    return __sync_val_compare_and_swap(Destination, Comperand, ExChange);
}

QUIC_INLINE
BOOLEAN
InterlockedFetchAndClearBoolean(
    _Inout_ _Interlocked_operand_ BOOLEAN volatile *Target
    )
{
    return __sync_fetch_and_and(Target, 0);
}

QUIC_INLINE
BOOLEAN
InterlockedFetchAndSetBoolean(
    _Inout_ _Interlocked_operand_ BOOLEAN volatile *Target
    )
{
    return __sync_fetch_and_or(Target, 1);
}

QUIC_INLINE
void*
InterlockedExchangePointer(
    _Inout_ _Interlocked_operand_ void* volatile *Target,
    _In_opt_ void* Value
    )
{
    return __sync_lock_test_and_set(Target, Value);
}

QUIC_INLINE
void*
InterlockedFetchAndClearPointer(
    _Inout_ _Interlocked_operand_ void* volatile *Target
    )
{
    return __sync_fetch_and_and(Target, 0);
}

QUIC_INLINE
short
InterlockedIncrement16(
    _Inout_ _Interlocked_operand_ short volatile *Addend
    )
{
    return __sync_add_and_fetch(Addend, (short)1);
}

QUIC_INLINE
short
InterlockedDecrement16(
    _Inout_ _Interlocked_operand_ short volatile *Addend
    )
{
    return __sync_sub_and_fetch(Addend, (short)1);
}

QUIC_INLINE
int64_t
InterlockedIncrement64(
    _Inout_ _Interlocked_operand_ int64_t volatile *Addend
    )
{
    return __sync_add_and_fetch(Addend, (int64_t)1);
}

QUIC_INLINE
int64_t
InterlockedDecrement64(
    _Inout_ _Interlocked_operand_ int64_t volatile *Addend
    )
{
    return __sync_sub_and_fetch(Addend, (int64_t)1);
}

#define QuicReadPtrNoFence(p) ((void*)(*p)) // TODO

//
// Assertion interfaces.
//

__attribute__((noinline, noreturn))
void
quic_bugcheck(
    _In_z_ const char* File,
    _In_ int Line,
    _In_z_ const char* Expr
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
#define CXPLAT_FRE_ASSERT(exp) ((exp) ? (void)0 : (CxPlatLogAssert(__FILE__, __LINE__, #exp), quic_bugcheck(__FILE__, __LINE__, #exp)));
#define CXPLAT_FRE_ASSERTMSG(exp, Y) CXPLAT_FRE_ASSERT(exp)

#ifdef DEBUG
#define CXPLAT_DBG_ASSERT(exp) CXPLAT_FRE_ASSERT(exp)
#define CXPLAT_DBG_ASSERTMSG(exp, msg) CXPLAT_FRE_ASSERT(exp)
#else
#define CXPLAT_DBG_ASSERT(exp)
#define CXPLAT_DBG_ASSERTMSG(exp, msg)
#endif

#if DEBUG // TODO - Do something with QUIC_TELEMETRY_ASSERTS
#define CXPLAT_TEL_ASSERT(exp) CXPLAT_FRE_ASSERT(exp)
#define CXPLAT_TEL_ASSERTMSG(exp, Y) CXPLAT_FRE_ASSERT(exp)
#define CXPLAT_TEL_ASSERTMSG_ARGS(exp, _msg, _origin, _bucketArg1, _bucketArg2) CXPLAT_FRE_ASSERT(exp)
#else
#define CXPLAT_TEL_ASSERT(exp)
#define CXPLAT_TEL_ASSERTMSG(exp, Y)
#define CXPLAT_TEL_ASSERTMSG_ARGS(exp, _msg, _origin, _bucketArg1, _bucketArg2)
#endif

//
// Debugger check.
//

#define CxPlatDebuggerPresent() FALSE

//
// Interrupt ReQuest Level.
//

#define CXPLAT_IRQL() 0
#define CXPLAT_PASSIVE_CODE()
#define CXPLAT_AT_DISPATCH() FALSE

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
    __drv_freesMem(Mem) _Frees_ptr_ void* Mem,
    _In_ uint32_t Tag
    );

#define CXPLAT_ALLOC_PAGED(Size, Tag) CxPlatAlloc(Size, Tag)
#define CXPLAT_ALLOC_NONPAGED(Size, Tag) CxPlatAlloc(Size, Tag)
#define CXPLAT_FREE(Mem, Tag) CxPlatFree((void*)Mem, Tag)

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

    alignas(16) pthread_mutex_t Mutex;

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

#define CxPlatDispatchRwLockAcquireShared(Lock, PrevIrql) CxPlatRwLockAcquireShared(Lock)

#define CxPlatDispatchRwLockAcquireExclusive(Lock, PrevIrql) CxPlatRwLockAcquireExclusive(Lock)

#define CxPlatDispatchRwLockReleaseShared(Lock, PrevIrql) CxPlatRwLockReleaseShared(Lock)

#define CxPlatDispatchRwLockReleaseExclusive(Lock, PrevIrql) CxPlatRwLockReleaseExclusive(Lock)

//
// Represents a QUIC memory pool used for fixed sized allocations.
// This must be below the lock definitions.
//

FORCEINLINE
void
CxPlatListPushEntry(
    _Inout_ CXPLAT_SLIST_ENTRY* ListHead,
    _Inout_ __drv_aliasesMem CXPLAT_SLIST_ENTRY* Entry
    );

FORCEINLINE
CXPLAT_SLIST_ENTRY*
CxPlatListPopEntry(
    _Inout_ CXPLAT_SLIST_ENTRY* ListHead
    );

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

    CXPLAT_LOCK Lock;

    //
    // Size of entries.
    //

    uint32_t Size;

    //
    // The memory tag to use for any allocation from this pool.
    //

    uint32_t Tag;

} CXPLAT_POOL;

typedef struct __attribute__((aligned(16))) CXPLAT_POOL_HEADER {
    union {
    CXPLAT_POOL* Owner;
    CXPLAT_SLIST_ENTRY Entry;
    };
#if DEBUG
    uint64_t SpecialFlag;
#endif
} CXPLAT_POOL_HEADER;

#define CXPLAT_POOL_FREE_FLAG   0xAAAAAAAAAAAAAAAAull
#define CXPLAT_POOL_ALLOC_FLAG  0xE9E9E9E9E9E9E9E9ull

#ifndef DISABLE_CXPLAT_POOL
#define CXPLAT_POOL_MAXIMUM_DEPTH   256 // Copied from EX_MAXIMUM_LOOKASIDE_DEPTH_BASE
#else
#define CXPLAT_POOL_MAXIMUM_DEPTH   0   // TODO - Optimize this scenario better
#endif

#if DEBUG
int32_t
CxPlatGetAllocFailDenominator(
    );
#endif

QUIC_INLINE
void
CxPlatPoolInitialize(
    _In_ BOOLEAN IsPaged,
    _In_ uint32_t Size,
    _In_ uint32_t Tag,
    _Inout_ CXPLAT_POOL* Pool
    )
{
    Pool->Size = Size + sizeof(CXPLAT_POOL_HEADER); // Add space for the pool header
    Pool->Tag = Tag;
    CxPlatLockInitialize(&Pool->Lock);
    Pool->ListDepth = 0;
    CxPlatZeroMemory(&Pool->ListHead, sizeof(Pool->ListHead));
    UNREFERENCED_PARAMETER(IsPaged);
}

QUIC_INLINE
void
CxPlatPoolUninitialize(
    _Inout_ CXPLAT_POOL* Pool
    )
{
    CXPLAT_POOL_HEADER* Entry;
    while ((Entry = (CXPLAT_POOL_HEADER*)CxPlatListPopEntry(&Pool->ListHead)) != NULL) {
        CXPLAT_DBG_ASSERT(Entry->SpecialFlag == CXPLAT_POOL_FREE_FLAG);
        CxPlatFree(Entry, Pool->Tag);
    }
    CxPlatLockUninitialize(&Pool->Lock);
}

QUIC_INLINE
void*
CxPlatPoolAlloc(
    _Inout_ CXPLAT_POOL* Pool
    )
{
    CxPlatLockAcquire(&Pool->Lock);
    CXPLAT_POOL_HEADER* Header =
    #if DEBUG
        CxPlatGetAllocFailDenominator() ? NULL : // No pool when using simulated alloc failures
    #endif
        (CXPLAT_POOL_HEADER*)CxPlatListPopEntry(&Pool->ListHead);
    if (Header != NULL) {
        CXPLAT_DBG_ASSERT(Pool->ListDepth > 0);
        CXPLAT_DBG_ASSERT(Header->SpecialFlag == CXPLAT_POOL_FREE_FLAG);
        Pool->ListDepth--;
    }
    CxPlatLockRelease(&Pool->Lock);
    if (Header == NULL) {
        Header = (CXPLAT_POOL_HEADER*)CxPlatAlloc(Pool->Size, Pool->Tag);
        if (Header == NULL) {
            return NULL;
        }
    }
#if DEBUG
    Header->SpecialFlag = CXPLAT_POOL_ALLOC_FLAG;
#endif
    Header->Owner = Pool;
    return (void*)((uint8_t*)Header + sizeof(CXPLAT_POOL_HEADER));
}

QUIC_INLINE
void
CxPlatPoolFree(
    _In_ void* Memory
    )
{
    CXPLAT_POOL_HEADER* Header = (CXPLAT_POOL_HEADER*)Memory - 1;
    CXPLAT_POOL* Pool = Header->Owner;
#if DEBUG
    CXPLAT_DBG_ASSERT(Header->SpecialFlag == CXPLAT_POOL_ALLOC_FLAG);
    if (CxPlatGetAllocFailDenominator()) {
        CxPlatFree(Header, Pool->Tag);
        return;
    }
    Header->SpecialFlag = CXPLAT_POOL_FREE_FLAG;
#endif
    if (Pool->ListDepth >= CXPLAT_POOL_MAXIMUM_DEPTH) {
        CxPlatFree(Header, Pool->Tag);
    } else {
        CxPlatLockAcquire(&Pool->Lock);
        CxPlatListPushEntry(&Pool->ListHead, &Header->Entry);
        Pool->ListDepth++;
        CxPlatLockRelease(&Pool->Lock);
    }
}

QUIC_INLINE
BOOLEAN
CxPlatPoolPrune(
    _Inout_ CXPLAT_POOL* Pool
    )
{
    CxPlatLockAcquire(&Pool->Lock);
    void* Entry = CxPlatListPopEntry(&Pool->ListHead);
    if (Entry != NULL) {
        CXPLAT_FRE_ASSERT(Pool->ListDepth > 0);
        Pool->ListDepth--;
    }
    CxPlatLockRelease(&Pool->Lock);
    if (Entry == NULL) {
        return FALSE;
    }
    CxPlatFree(Entry, Pool->Tag);
    return TRUE;
}

//
// Reference Count Interface
//

typedef int64_t CXPLAT_REF_COUNT;

void
CxPlatRefInitialize(
    _Inout_ CXPLAT_REF_COUNT* RefCount
    );

void
CxPlatRefInitializeEx(
    _Inout_ CXPLAT_REF_COUNT* RefCount,
    _In_ uint32_t Initial
    );

void
CxPlatRefIncrement(
    _Inout_ CXPLAT_REF_COUNT* RefCount
    );

BOOLEAN
CxPlatRefIncrementNonZero(
    _Inout_ volatile CXPLAT_REF_COUNT* RefCount,
    _In_ uint32_t Bias
    );

BOOLEAN
CxPlatRefDecrement(
    _In_ CXPLAT_REF_COUNT* RefCount
    );

#define CxPlatRefUninitialize(RefCount)

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

QUIC_INLINE
int64_t
CxPlatTimeEpochMs64(
    void
    )
{
    struct timeval tv;
    CxPlatZeroMemory(&tv, sizeof(tv));
    gettimeofday(&tv, NULL);
    return S_TO_MS(tv.tv_sec) + US_TO_MS(tv.tv_usec);
}

QUIC_INLINE
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

QUIC_INLINE
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

QUIC_INLINE
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

QUIC_INLINE
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

#define CxPlatSchedulerYield() sched_yield()

//
// Event Interfaces
//

//
// QUIC event object.
//

typedef struct CXPLAT_EVENT {

    //
    // Mutex and condition. The alignas is important, as the perf tanks
    // if the event is not aligned.
    //
    alignas(16) pthread_mutex_t Mutex;
    pthread_cond_t Cond;

    //
    // Denotes if the event object is in signaled state.
    //

    BOOLEAN Signaled;

    //
    // Denotes if the event object should be auto reset after it's signaled.
    //

    BOOLEAN AutoReset;

} CXPLAT_EVENT;

QUIC_INLINE
void
CxPlatEventInitialize(
    _Out_ CXPLAT_EVENT* Event,
    _In_ BOOLEAN ManualReset,
    _In_ BOOLEAN InitialState
    )
{
    pthread_condattr_t Attr;
    int Result;

    CxPlatZeroMemory(&Attr, sizeof(Attr));
    Event->AutoReset = !ManualReset;
    Event->Signaled = InitialState;

    Result = pthread_mutex_init(&Event->Mutex, NULL);
    CXPLAT_FRE_ASSERT(Result == 0);
    Result = pthread_condattr_init(&Attr);
    CXPLAT_FRE_ASSERT(Result == 0);
#if defined(CX_PLATFORM_LINUX)
    Result = pthread_condattr_setclock(&Attr, CLOCK_MONOTONIC);
    CXPLAT_FRE_ASSERT(Result == 0);
#endif // CX_PLATFORM_LINUX
    Result = pthread_cond_init(&Event->Cond, &Attr);
    CXPLAT_FRE_ASSERT(Result == 0);
    Result = pthread_condattr_destroy(&Attr);
    CXPLAT_FRE_ASSERT(Result == 0);
}

QUIC_INLINE
void
CxPlatInternalEventUninitialize(
    _Inout_ CXPLAT_EVENT* Event
    )
{
    int Result;

    Result = pthread_cond_destroy(&Event->Cond);
    CXPLAT_FRE_ASSERT(Result == 0);
    Result = pthread_mutex_destroy(&Event->Mutex);
    CXPLAT_FRE_ASSERT(Result == 0);
}

QUIC_INLINE
void
CxPlatInternalEventSet(
    _Inout_ CXPLAT_EVENT* Event
    )
{
    int Result;

    Result = pthread_mutex_lock(&Event->Mutex);
    CXPLAT_FRE_ASSERT(Result == 0);

    Event->Signaled = true;

    //
    // Signal the condition while holding the lock for predictable scheduling,
    // better performance and removing possibility of use after free for the
    // condition.
    //

    Result = pthread_cond_broadcast(&Event->Cond);
    CXPLAT_FRE_ASSERT(Result == 0);

    Result = pthread_mutex_unlock(&Event->Mutex);
    CXPLAT_FRE_ASSERT(Result == 0);
}

QUIC_INLINE
void
CxPlatInternalEventReset(
    _Inout_ CXPLAT_EVENT* Event
    )
{
    int Result;

    Result = pthread_mutex_lock(&Event->Mutex);
    CXPLAT_FRE_ASSERT(Result == 0);
    Event->Signaled = false;
    Result = pthread_mutex_unlock(&Event->Mutex);
    CXPLAT_FRE_ASSERT(Result == 0);
}

QUIC_INLINE
void
CxPlatInternalEventWaitForever(
    _Inout_ CXPLAT_EVENT* Event
    )
{
    int Result;

    Result = pthread_mutex_lock(&Event->Mutex);
    CXPLAT_FRE_ASSERT(Result == 0);

    //
    // Spurious wake ups from pthread_cond_wait can occur. So the function needs
    // to be called in a loop until the predicate 'Signalled' is satisfied.
    //

    while (!Event->Signaled) {
        Result = pthread_cond_wait(&Event->Cond, &Event->Mutex);
        CXPLAT_FRE_ASSERT(Result == 0);
    }

    if(Event->AutoReset) {
        Event->Signaled = false;
    }

    Result = pthread_mutex_unlock(&Event->Mutex);
    CXPLAT_FRE_ASSERT(Result == 0);
}

QUIC_INLINE
BOOLEAN
CxPlatInternalEventWaitWithTimeout(
    _Inout_ CXPLAT_EVENT* Event,
    _In_ uint32_t TimeoutMs
    )
{
    BOOLEAN WaitSatisfied = FALSE;
    struct timespec Ts = {0, 0};
    int Result;

    CXPLAT_DBG_ASSERT(TimeoutMs != UINT32_MAX);

    //
    // Get absolute time.
    //

    CxPlatGetAbsoluteTime(TimeoutMs, &Ts);

    Result = pthread_mutex_lock(&Event->Mutex);
    CXPLAT_FRE_ASSERT(Result == 0);

    while (!Event->Signaled) {

        Result = pthread_cond_timedwait(&Event->Cond, &Event->Mutex, &Ts);

        if (Result == ETIMEDOUT) {
            WaitSatisfied = FALSE;
            goto Exit;
        }

        CXPLAT_DBG_ASSERT(Result == 0);
        UNREFERENCED_PARAMETER(Result);
    }

    if (Event->AutoReset) {
        Event->Signaled = FALSE;
    }

    WaitSatisfied = TRUE;

Exit:

    Result = pthread_mutex_unlock(&Event->Mutex);
    CXPLAT_FRE_ASSERT(Result == 0);

    return WaitSatisfied;
}

#define CxPlatEventUninitialize(Event) CxPlatInternalEventUninitialize(&Event)
#define CxPlatEventSet(Event) CxPlatInternalEventSet(&Event)
#define CxPlatEventReset(Event) CxPlatInternalEventReset(&Event)
#define CxPlatEventWaitForever(Event) CxPlatInternalEventWaitForever(&Event)
#define CxPlatEventWaitWithTimeout(Event, TimeoutMs) CxPlatInternalEventWaitWithTimeout(&Event, TimeoutMs)

//
// Event Queue Interfaces
//

#if __linux__

#if CXPLAT_USE_IO_URING // liburing

#include <liburing.h>
typedef struct io_uring CXPLAT_EVENTQ;
typedef struct io_uring_cqe* CXPLAT_CQE;
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
void
(CXPLAT_EVENT_COMPLETION)(
    _In_ CXPLAT_CQE* Cqe
    );
typedef CXPLAT_EVENT_COMPLETION *CXPLAT_EVENT_COMPLETION_HANDLER;
typedef struct CXPLAT_SQE {
    CXPLAT_EVENT_COMPLETION_HANDLER Completion;
} CXPLAT_SQE;

QUIC_INLINE
BOOLEAN
CxPlatEventQInitialize(
    _Out_ CXPLAT_EVENTQ* queue
    )
{
    return 0 == io_uring_queue_init(256, queue, 0); // TODO - make size configurable
}

QUIC_INLINE
void
CxPlatEventQCleanup(
    _In_ CXPLAT_EVENTQ* queue
    )
{
    io_uring_queue_exit(queue);
}

QUIC_INLINE
BOOLEAN
CxPlatEventQEnqueue(
    _In_ CXPLAT_EVENTQ* queue,
    _In_ CXPLAT_SQE* sqe
    )
{
    struct io_uring_sqe *io_sqe = io_uring_get_sqe(queue);
    if (io_sqe == NULL) return FALSE; // OOM
    io_uring_prep_nop(io_sqe);
    io_uring_sqe_set_data(io_sqe, sqe);
    io_uring_submit(queue); // TODO - Extract to separate function?
    return TRUE;
}

QUIC_INLINE
uint32_t
CxPlatEventQDequeue(
    _In_ CXPLAT_EVENTQ* queue,
    _Out_ CXPLAT_CQE* events,
    _In_ uint32_t count,
    _In_ uint32_t wait_time // milliseconds
    )
{
    int result = io_uring_peek_batch_cqe(queue, events, count);
    if (result > 0 || wait_time == 0) return result;
    if (wait_time != UINT32_MAX) {
        struct __kernel_timespec timeout;
        timeout.tv_sec = (wait_time / 1000);
        timeout.tv_nsec = ((wait_time % 1000) * 1000000);
        (void)io_uring_wait_cqe_timeout(queue, events, &timeout);
    } else {
        (void)io_uring_wait_cqe(queue, events);
    }
    return io_uring_peek_batch_cqe(queue, events, count);
}

QUIC_INLINE
void
CxPlatEventQReturn(
    _In_ CXPLAT_EVENTQ* queue,
    _In_ uint32_t count
    )
{
    io_uring_cq_advance(queue, count);
}

QUIC_INLINE
BOOLEAN
CxPlatSqeInitialize(
    _In_ CXPLAT_EVENTQ* queue,
    _In_ CXPLAT_EVENT_COMPLETION completion,
    _Out_ CXPLAT_SQE* sqe
    )
{
    UNREFERENCED_PARAMETER(queue);
    sqe->Completion = completion;
    return TRUE;
}

QUIC_INLINE
void
CxPlatSqeCleanup(
    _In_ CXPLAT_EVENTQ* queue,
    _In_ CXPLAT_SQE* sqe
    )
{
    UNREFERENCED_PARAMETER(queue);
    UNREFERENCED_PARAMETER(sqe);
}

QUIC_INLINE
CXPLAT_SQE*
CxPlatCqeGetSqe(
    _In_ const CXPLAT_CQE* cqe
    )
{
    return (CXPLAT_SQE*)(uintptr_t)cqe->user_data;
}

#else // epoll

#include <sys/epoll.h>
#include <sys/eventfd.h>

typedef int CXPLAT_EVENTQ;
typedef struct epoll_event CXPLAT_CQE;
typedef
void
(CXPLAT_EVENT_COMPLETION)(
    _In_ CXPLAT_CQE* Cqe
    );
typedef CXPLAT_EVENT_COMPLETION *CXPLAT_EVENT_COMPLETION_HANDLER;
typedef struct CXPLAT_SQE {
    int fd;
    CXPLAT_EVENT_COMPLETION_HANDLER Completion;
} CXPLAT_SQE;

QUIC_INLINE
BOOLEAN
CxPlatEventQInitialize(
    _Out_ CXPLAT_EVENTQ* queue
    )
{
    return (*queue = epoll_create1(EPOLL_CLOEXEC)) != -1;
}

QUIC_INLINE
void
CxPlatEventQCleanup(
    _In_ CXPLAT_EVENTQ* queue
    )
{
    close(*queue);
}

QUIC_INLINE
BOOLEAN
CxPlatEventQEnqueue(
    _In_ CXPLAT_EVENTQ* queue,
    _In_ CXPLAT_SQE* sqe
    )
{
    UNREFERENCED_PARAMETER(queue);
    return eventfd_write(sqe->fd, 1) == 0;
}

QUIC_INLINE
uint32_t
CxPlatEventQDequeue(
    _In_ CXPLAT_EVENTQ* queue,
    _Out_ CXPLAT_CQE* events,
    _In_ uint32_t count,
    _In_ uint32_t wait_time // milliseconds
    )
{
    const int timeout = wait_time == UINT32_MAX ? -1 : (int)wait_time;
    int result;
    do {
        result = epoll_wait(*queue, events, count, timeout);
    } while ((result == -1L) && (errno == EINTR));
    return (uint32_t)result;
}

QUIC_INLINE
void
CxPlatEventQReturn(
    _In_ CXPLAT_EVENTQ* queue,
    _In_ uint32_t count
    )
{
    UNREFERENCED_PARAMETER(queue);
    UNREFERENCED_PARAMETER(count);
}

QUIC_INLINE
BOOLEAN
CxPlatSqeInitialize(
    _In_ CXPLAT_EVENTQ* queue,
    _In_ CXPLAT_EVENT_COMPLETION completion,
    _Out_ CXPLAT_SQE* sqe
    )
{
    struct epoll_event event = { .events = EPOLLIN | EPOLLET, .data = { .ptr = sqe } };
    sqe->Completion = completion;
    if ((sqe->fd = eventfd(0, EFD_CLOEXEC)) == -1) return FALSE;
    if (epoll_ctl(*queue, EPOLL_CTL_ADD, sqe->fd, &event) != 0) { close(sqe->fd); return FALSE; }
    return TRUE;
}

QUIC_INLINE
void
CxPlatSqeCleanup(
    _In_ CXPLAT_EVENTQ* queue,
    _In_ CXPLAT_SQE* sqe
    )
{
    epoll_ctl(*queue, EPOLL_CTL_DEL, sqe->fd, NULL);
    close(sqe->fd);
}

QUIC_INLINE
CXPLAT_SQE*
CxPlatCqeGetSqe(
    _In_ const CXPLAT_CQE* cqe
    )
{
    return (CXPLAT_SQE*)cqe->data.ptr;
}

#endif

#elif __APPLE__ || __FreeBSD__ // kqueue

#include <sys/event.h>
#include <fcntl.h>

typedef int CXPLAT_EVENTQ;
typedef struct kevent CXPLAT_CQE;
typedef
void
(CXPLAT_EVENT_COMPLETION)(
    _In_ CXPLAT_CQE* Cqe
    );
typedef CXPLAT_EVENT_COMPLETION *CXPLAT_EVENT_COMPLETION_HANDLER;
typedef struct CXPLAT_SQE {
    uintptr_t Handle;
    CXPLAT_EVENT_COMPLETION_HANDLER Completion;
} CXPLAT_SQE;

QUIC_INLINE
BOOLEAN
CxPlatEventQInitialize(
    _Out_ CXPLAT_EVENTQ* queue
    )
{
    return (*queue = kqueue()) != -1;
}

QUIC_INLINE
void
CxPlatEventQCleanup(
    _In_ CXPLAT_EVENTQ* queue
    )
{
    close(*queue);
}

QUIC_INLINE
BOOLEAN
CxPlatEventQEnqueue(
    _In_ CXPLAT_EVENTQ* queue,
    _In_ CXPLAT_SQE* sqe
    )
{
    // TODO - Should ident simply use the pointer value of sqe?
    struct kevent event = {.ident = sqe->Handle, .filter = EVFILT_USER, .flags = EV_ADD | EV_ONESHOT, .fflags = NOTE_TRIGGER, .data = 0, .udata = sqe};
    return kevent(*queue, &event, 1, NULL, 0, NULL) == 0;
}

QUIC_INLINE
BOOLEAN
CxPlatEventQEnqueueEx(
    _In_ CXPLAT_EVENTQ* queue,
    _In_ CXPLAT_SQE* sqe,
    _In_ short filter,
    _In_ unsigned short flags
    )
{
    struct kevent event = {.ident = sqe->Handle, .filter = filter, .flags = flags, .fflags = 0, .data = 0, .udata = sqe};
    return kevent(*queue, &event, 1, NULL, 0, NULL) == 0;
}

QUIC_INLINE
uint32_t
CxPlatEventQDequeue(
    _In_ CXPLAT_EVENTQ* queue,
    _Out_ CXPLAT_CQE* events,
    _In_ uint32_t count,
    _In_ uint32_t wait_time // milliseconds
    )
{
    struct timespec timeout = {0, 0};
    if (wait_time != UINT32_MAX) {
        timeout.tv_sec = (wait_time / 1000);
        timeout.tv_nsec = ((wait_time % 1000) * 1000000);
    }
    int result;
    do {
        result = kevent(*queue, NULL, 0, events, count, wait_time == UINT32_MAX ? NULL : &timeout);
    } while ((result == -1L) && (errno == EINTR));
    return (uint32_t)result;
}

QUIC_INLINE
void
CxPlatEventQReturn(
    _In_ CXPLAT_EVENTQ* queue,
    _In_ uint32_t count
    )
{
    UNREFERENCED_PARAMETER(queue);
    UNREFERENCED_PARAMETER(count);
}

extern uintptr_t CxPlatCurrentSqe;

QUIC_INLINE
BOOLEAN
CxPlatSqeInitialize(
    _In_ CXPLAT_EVENTQ* queue,
    _In_ CXPLAT_EVENT_COMPLETION completion,
    _Out_ CXPLAT_SQE* sqe
    )
{
    UNREFERENCED_PARAMETER(queue);
    sqe->Handle = __sync_add_and_fetch(&CxPlatCurrentSqe, 1);
    sqe->Completion = completion;
    return TRUE;
}

QUIC_INLINE
void
CxPlatSqeInitializeEx(
    _In_ CXPLAT_EVENTQ* queue,
    _In_ uintptr_t handle,
    _In_ CXPLAT_EVENT_COMPLETION completion,
    _Out_ CXPLAT_SQE* sqe
    )
{
    UNREFERENCED_PARAMETER(queue);
    sqe->Handle = handle;
    sqe->Completion = completion;
}

QUIC_INLINE
void
CxPlatSqeCleanup(
    _In_ CXPLAT_EVENTQ* queue,
    _In_ CXPLAT_SQE* sqe
    )
{
    UNREFERENCED_PARAMETER(queue);
    UNREFERENCED_PARAMETER(sqe);
}

QUIC_INLINE
CXPLAT_SQE*
CxPlatCqeGetSqe(
    _In_ const CXPLAT_CQE* cqe
    )
{
    return (CXPLAT_SQE*)cqe->udata;
}

#else

#error "Unsupported platform"

#endif

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

CXPLAT_THREAD_ID
CxPlatCurThreadID(
    void
    );

//
// Processor Count and Index.
//

extern uint32_t CxPlatProcessorCount;
#define CxPlatProcCount() CxPlatProcessorCount

uint32_t
CxPlatProcCurrentNumber(
    void
    );

//
// Rundown Protection Interfaces.
//

typedef struct CXPLAT_RUNDOWN_REF {

    //
    // The completion event.
    //

    CXPLAT_EVENT RundownComplete;

    //
    // The ref counter.
    //

    CXPLAT_REF_COUNT RefCount;


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

#define CXPLAT_CPUID(FunctionId, eax, ebx, ecx, dx)

#if defined(__cplusplus)
}
#endif
