/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file contains Windows User Mode implementations of the
    QUIC Platform Interfaces.

Environment:

    Windows user mode

--*/

#pragma once

#ifndef CX_PLATFORM_TYPE
#error "Must be included from quic_platform.h"
#endif

#ifdef _KERNEL_MODE
#error "Incorrectly including Windows User Platform Header"
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN 1
#endif

#pragma warning(push) // Don't care about OACR warnings in publics
#pragma warning(disable:26036)
#pragma warning(disable:28251)
#pragma warning(disable:28252)
#pragma warning(disable:28253)
#pragma warning(disable:28301)
#pragma warning(disable:6553) // Bad SAL annotation in public header
#pragma warning(disable:5105) // The conformant preprocessor along with the newest SDK throws this warning for a macro.
#include <windows.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <bcrypt.h>
#include <stdlib.h>
#include <winternl.h>
#include "msquic_winuser.h"
#ifdef _M_X64
#pragma warning(disable:28251) // Inconsistent annotation for function
#include <intrin.h>
#endif
#pragma warning(pop)
#pragma warning(disable:4201)  // nonstandard extension used: nameless struct/union
#pragma warning(disable:4324)  // 'CXPLAT_POOL': structure was padded due to alignment specifier

#if defined(__cplusplus)
extern "C" {
#endif

#ifndef NDEBUG
#define DBG 1
#define DEBUG 1
#endif

#if _WIN64
#define QUIC_64BIT 1
#else
#define QUIC_32BIT 1
#endif

#define INITCODE
#define PAGEDX

#define QUIC_CACHEALIGN DECLSPEC_CACHEALIGN

#define ALIGN_DOWN(length, type) \
    ((ULONG)(length) & ~(sizeof(type) - 1))

#define ALIGN_UP(length, type) \
    (ALIGN_DOWN(((ULONG)(length) + sizeof(type) - 1), type))

#define INIT_NO_SAL(X) // No-op since Windows supports SAL

#ifdef QUIC_RESTRICTED_BUILD
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

_When_(Status < 0, _Out_range_(>, 0))
_When_(Status >= 0, _Out_range_(==, 0))
ULONG
NTAPI
RtlNtStatusToDosError (
   NTSTATUS Status
   );
#endif

//
// Static Analysis Interfaces
//

#define QUIC_NO_SANITIZE(X)

#if defined(_PREFAST_)
// _Analysis_assume_ will never result in any code generation for _exp,
// so using it will not have runtime impact, even if _exp has side effects.
#define CXPLAT_ANALYSIS_ASSUME(_exp) _Analysis_assume_(_exp)
#else // _PREFAST_
// CXPLAT_ANALYSIS_ASSUME ensures that _exp is parsed in non-analysis compile.
// On DEBUG, it's guaranteed to be parsed as part of the normal compile, but
// with non-DEBUG, use __noop to ensure _exp is parseable but without code
// generation.
#if DEBUG
#define CXPLAT_ANALYSIS_ASSUME(_exp) ((void) 0)
#else // DEBUG
#define CXPLAT_ANALYSIS_ASSUME(_exp) __noop(_exp)
#endif // DEBUG
#endif // _PREFAST_

#ifdef __clang__
#define CXPLAT_STATIC_ASSERT(X,Y) _Static_assert(X,Y)
#else
#define CXPLAT_STATIC_ASSERT(X,Y) static_assert(X,Y)
#endif

#define CXPLAT_ANALYSIS_ASSERT(X) __analysis_assert(X)

//
// Assertion Interfaces

_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatLogAssert(
    _In_z_ const char* File,
    _In_ int Line,
    _In_z_ const char* Expr
    );

#define CXPLAT_WIDE_STRING(_str) L##_str

#define CXPLAT_ASSERT_NOOP(_exp, _msg) \
    (CXPLAT_ANALYSIS_ASSUME(_exp), 0)

#define CXPLAT_ASSERT_LOG(_exp, _msg) \
    (CXPLAT_ANALYSIS_ASSUME(_exp), \
    ((!(_exp)) ? (CxPlatLogAssert(__FILE__, __LINE__, #_exp), FALSE) : TRUE))

#define CXPLAT_ASSERT_CRASH(_exp, _msg) \
    (CXPLAT_ANALYSIS_ASSUME(_exp), \
    ((!(_exp)) ? \
        (CxPlatLogAssert(__FILE__, __LINE__, #_exp), \
         __annotation(L"Debug", L"AssertFail", _msg), \
         DbgRaiseAssertionFailure(), FALSE) : \
        TRUE))

//
// MsQuic uses three types of asserts:
//
//  CXPLAT_DBG_ASSERT - Asserts that are too expensive to evaluate all the time.
//  CXPLAT_TEL_ASSERT - Asserts that are acceptable to always evaluate, but not
//                      always crash the system.
//  CXPLAT_FRE_ASSERT - Asserts that must always crash the system.
//

#if DEBUG
#define CXPLAT_DBG_ASSERT(_exp)          CXPLAT_ASSERT_CRASH(_exp, CXPLAT_WIDE_STRING(#_exp))
#define CXPLAT_DBG_ASSERTMSG(_exp, _msg) CXPLAT_ASSERT_CRASH(_exp, CXPLAT_WIDE_STRING(_msg))
#else
#define CXPLAT_DBG_ASSERT(_exp)          CXPLAT_ASSERT_NOOP(_exp, CXPLAT_WIDE_STRING(#_exp))
#define CXPLAT_DBG_ASSERTMSG(_exp, _msg) CXPLAT_ASSERT_NOOP(_exp, CXPLAT_WIDE_STRING(_msg))
#endif

#if DEBUG
#define CXPLAT_TEL_ASSERT(_exp)          CXPLAT_ASSERT_CRASH(_exp, CXPLAT_WIDE_STRING(#_exp))
#define CXPLAT_TEL_ASSERTMSG(_exp, _msg) CXPLAT_ASSERT_CRASH(_exp, CXPLAT_WIDE_STRING(_msg))
#define CXPLAT_TEL_ASSERTMSG_ARGS(_exp, _msg, _origin, _bucketArg1, _bucketArg2) \
                                         CXPLAT_ASSERT_CRASH(_exp, CXPLAT_WIDE_STRING(_msg))
#elif QUIC_TELEMETRY_ASSERTS
#define CXPLAT_TEL_ASSERT(_exp)          CXPLAT_ASSERT_LOG(_exp, CXPLAT_WIDE_STRING(#_exp))
#define CXPLAT_TEL_ASSERTMSG(_exp, _msg) CXPLAT_ASSERT_LOG(_exp, CXPLAT_WIDE_STRING(_msg))
#define CXPLAT_TEL_ASSERTMSG_ARGS(_exp, _msg, _origin, _bucketArg1, _bucketArg2) \
                                         CXPLAT_ASSERT_LOG(_exp, CXPLAT_WIDE_STRING(_msg))
#else
#define CXPLAT_TEL_ASSERT(_exp)          CXPLAT_ASSERT_NOOP(_exp, CXPLAT_WIDE_STRING(#_exp))
#define CXPLAT_TEL_ASSERTMSG(_exp, _msg) CXPLAT_ASSERT_NOOP(_exp, CXPLAT_WIDE_STRING(_msg))
#define CXPLAT_TEL_ASSERTMSG_ARGS(_exp, _msg, _origin, _bucketArg1, _bucketArg2) \
                                         CXPLAT_ASSERT_NOOP(_exp, CXPLAT_WIDE_STRING(_msg))
#endif

#define CXPLAT_FRE_ASSERT(_exp)          CXPLAT_ASSERT_CRASH(_exp, CXPLAT_WIDE_STRING(#_exp))
#define CXPLAT_FRE_ASSERTMSG(_exp, _msg) CXPLAT_ASSERT_CRASH(_exp, CXPLAT_WIDE_STRING(_msg))

#ifdef QUIC_UWP_BUILD
WINBASEAPI
_When_(lpModuleName == NULL,_Ret_notnull_)
_When_(lpModuleName != NULL,_Ret_maybenull_)
HMODULE
WINAPI
GetModuleHandleW(
    _In_opt_ LPCWSTR lpModuleName
    );
#endif

//
// Verifier is enabled.
//
#define CxPlatVerifierEnabled(Flags) \
    (GetModuleHandleW(L"verifier.dll") != NULL && \
     GetModuleHandleW(L"vrfcore.dll") != NULL), \
    Flags = 0

//
// Debugger check.
//
#define CxPlatDebuggerPresent() IsDebuggerPresent()

//
// Interrupt ReQuest Level
//

#define CXPLAT_IRQL() PASSIVE_LEVEL

#define CXPLAT_PASSIVE_CODE() CXPLAT_DBG_ASSERT(CXPLAT_IRQL() == PASSIVE_LEVEL)
#define CXPLAT_AT_DISPATCH() FALSE

//
// Wrapper functions
//

QUIC_INLINE
void*
InterlockedFetchAndClearPointer(
    _Inout_ _Interlocked_operand_ void* volatile *Target
    )
{
    return InterlockedExchangePointer(Target, NULL);
}

QUIC_INLINE
BOOLEAN
InterlockedFetchAndClearBoolean(
    _Inout_ _Interlocked_operand_ BOOLEAN volatile *Target
    )
{
    return (BOOLEAN)InterlockedAnd8((char*)Target, 0);
}

QUIC_INLINE
BOOLEAN
InterlockedFetchAndSetBoolean(
    _Inout_ _Interlocked_operand_ BOOLEAN volatile *Target
    )
{
    return (BOOLEAN)InterlockedOr8((char*)Target, 1);
}

//
// CloseHandle has an incorrect SAL annotation, so call through a wrapper.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_INLINE
void
CxPlatCloseHandle(_Pre_notnull_ HANDLE Handle) {
    CloseHandle(Handle);
}

//
// Allocation/Memory Interfaces
//

extern uint64_t CxPlatTotalMemory;

_Ret_maybenull_
_Post_writable_byte_size_(ByteCount)
DECLSPEC_ALLOCATOR
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

typedef struct CXPLAT_POOL CXPLAT_POOL;

typedef struct DECLSPEC_ALIGN(MEMORY_ALLOCATION_ALIGNMENT) CXPLAT_POOL_HEADER {
    union {
    CXPLAT_POOL* Owner;
    CXPLAT_SLIST_ENTRY Entry;
    };
#if DEBUG
    uint64_t SpecialFlag;
#endif
} CXPLAT_POOL_HEADER;

#define CXPLAT_POOL_FREE_FLAG   0xAAAAAAAAAAAAAAAAui64
#define CXPLAT_POOL_ALLOC_FLAG  0xE9E9E9E9E9E9E9E9ui64

typedef
CXPLAT_POOL_HEADER*
(*CXPLAT_POOL_ALLOC_FN)(
    _In_ uint32_t Size,
    _In_ uint32_t Tag,
    _Inout_ CXPLAT_POOL* Pool
    );

typedef
void
(*CXPLAT_POOL_FREE_FN)(
    _In_ CXPLAT_POOL_HEADER* Entry,
    _In_ uint32_t Tag,
    _Inout_ CXPLAT_POOL* Pool
    );

typedef struct CXPLAT_POOL {
    SLIST_HEADER ListHead;
    uint32_t Size;
    uint32_t Tag;
    uint32_t MaxDepth;
    CXPLAT_POOL_ALLOC_FN Allocate;
    CXPLAT_POOL_FREE_FN Free;
} CXPLAT_POOL;

#ifndef DISABLE_CXPLAT_POOL
#define CXPLAT_POOL_MAXIMUM_DEPTH       0x4000  // 16384
#define CXPLAT_POOL_DEFAULT_MAX_DEPTH   256     // Copied from EX_MAXIMUM_LOOKASIDE_DEPTH_BASE
#else
#define CXPLAT_POOL_MAXIMUM_DEPTH       0       // TODO - Optimize this scenario better
#define CXPLAT_POOL_DEFAULT_MAX_DEPTH   0
#endif

#if DEBUG
int32_t
CxPlatGetAllocFailDenominator(
    );
#endif

QUIC_INLINE
CXPLAT_POOL_HEADER*
CxPlatPoolGenericAlloc(
    _In_ uint32_t Size,
    _In_ uint32_t Tag,
    _Inout_ CXPLAT_POOL* Pool
    )
{
    UNREFERENCED_PARAMETER(Pool);
    return (CXPLAT_POOL_HEADER*)CxPlatAlloc(Size, Tag);
}

QUIC_INLINE
void
CxPlatPoolGenericFree(
    _In_ CXPLAT_POOL_HEADER* Entry,
    _In_ uint32_t Tag,
    _Inout_ CXPLAT_POOL* Pool
    )
{
    UNREFERENCED_PARAMETER(Pool);
    CxPlatFree(Entry, Tag);
}

QUIC_INLINE
void
CxPlatPoolInitialize(
    _In_ BOOLEAN IsPaged,
    _In_ uint32_t Size,
    _In_ uint32_t Tag,
    _Inout_ CXPLAT_POOL* Pool
    )
{
    Pool->Size = Size + sizeof(CXPLAT_POOL_HEADER); // Add space for the object header
    Pool->Tag = Tag;
    Pool->MaxDepth = CXPLAT_POOL_DEFAULT_MAX_DEPTH;
    Pool->Allocate = CxPlatPoolGenericAlloc;
    Pool->Free = CxPlatPoolGenericFree;
    InitializeSListHead(&(Pool)->ListHead);
    UNREFERENCED_PARAMETER(IsPaged);
}

QUIC_INLINE
void
CxPlatPoolInitializeEx(
    _In_ BOOLEAN IsPaged,
    _In_ uint32_t Size,
    _In_ uint32_t Tag,
    _In_ uint32_t MaxDepth,
    _In_opt_ CXPLAT_POOL_ALLOC_FN Allocate,
    _In_opt_ CXPLAT_POOL_FREE_FN Free,
    _Inout_ CXPLAT_POOL* Pool
    )
{
    Pool->Size = Size + sizeof(CXPLAT_POOL_HEADER); // Add space for the object header
    Pool->Tag = Tag;
    Pool->Allocate = Allocate ? Allocate : CxPlatPoolGenericAlloc;
    Pool->Free = Free ? Free : CxPlatPoolGenericFree;
    InitializeSListHead(&(Pool)->ListHead);
    UNREFERENCED_PARAMETER(IsPaged);
    if (MaxDepth != 0) {
        Pool->MaxDepth = CXPLAT_MIN(MaxDepth, CXPLAT_POOL_MAXIMUM_DEPTH);
    } else {
        Pool->MaxDepth = CXPLAT_POOL_DEFAULT_MAX_DEPTH;
    }
}

QUIC_INLINE
void
CxPlatPoolUninitialize(
    _Inout_ CXPLAT_POOL* Pool
    )
{
    CXPLAT_POOL_HEADER* Entry;
    while ((Entry = (CXPLAT_POOL_HEADER*)InterlockedPopEntrySList(&Pool->ListHead)) != NULL) {
#if DEBUG
        CXPLAT_DBG_ASSERT(Entry->SpecialFlag == CXPLAT_POOL_FREE_FLAG);
#endif
        Pool->Free(Entry, Pool->Tag, Pool);
    }
}

QUIC_INLINE
void*
CxPlatPoolAlloc(
    _Inout_ CXPLAT_POOL* Pool
    )
{
    CXPLAT_POOL_HEADER* Header =
#if DEBUG
        CxPlatGetAllocFailDenominator() ? NULL : // No pool when using simulated alloc failures
#endif
        (CXPLAT_POOL_HEADER*)InterlockedPopEntrySList(&Pool->ListHead);
    if (Header == NULL) {
        Header = Pool->Allocate(Pool->Size, Pool->Tag, Pool);
        if (Header == NULL) {
            return NULL;
        }
    }
#if DEBUG
    else {
        CXPLAT_DBG_ASSERT(Header->SpecialFlag == CXPLAT_POOL_FREE_FLAG);
    }
    Header->SpecialFlag = CXPLAT_POOL_ALLOC_FLAG;
#endif
    Header->Owner = Pool;
    return (void*)(Header + 1);
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
        Pool->Free(Header, Pool->Tag, Pool);
        return;
    }
    Header->SpecialFlag = CXPLAT_POOL_FREE_FLAG;
#endif
    if (QueryDepthSList(&Pool->ListHead) >= Pool->MaxDepth) {
        Pool->Free(Header, Pool->Tag, Pool);
    } else {
        InterlockedPushEntrySList(&Pool->ListHead, (PSLIST_ENTRY)Header);
    }
}

QUIC_INLINE
BOOLEAN
CxPlatPoolPrune(
    _Inout_ CXPLAT_POOL* Pool
    )
{
    CXPLAT_POOL_HEADER* Entry =
        (CXPLAT_POOL_HEADER*)InterlockedPopEntrySList(&Pool->ListHead);
    if (Entry == NULL) {
        return FALSE;
    }
#if DEBUG
    CXPLAT_DBG_ASSERT(Entry->SpecialFlag == CXPLAT_POOL_FREE_FLAG);
#endif
    Pool->Free(Entry, Pool->Tag, Pool);
    return TRUE;
}

#define CxPlatZeroMemory RtlZeroMemory
#define CxPlatCopyMemory RtlCopyMemory
#define CxPlatMoveMemory RtlMoveMemory
#define CxPlatSecureZeroMemory RtlSecureZeroMemory

#define CxPlatByteSwapUint16 _byteswap_ushort
#define CxPlatByteSwapUint32 _byteswap_ulong
#define CxPlatByteSwapUint64 _byteswap_uint64

//
// Locking Interfaces
//

typedef CRITICAL_SECTION CXPLAT_LOCK;

#define CxPlatLockInitialize(Lock) InitializeCriticalSection(Lock)
#define CxPlatLockUninitialize(Lock) DeleteCriticalSection(Lock)
#define CxPlatLockAcquire(Lock) EnterCriticalSection(Lock)
#define CxPlatLockRelease(Lock) LeaveCriticalSection(Lock)

typedef CRITICAL_SECTION CXPLAT_DISPATCH_LOCK;

#define CxPlatDispatchLockInitialize(Lock) InitializeCriticalSection(Lock)
#define CxPlatDispatchLockUninitialize(Lock) DeleteCriticalSection(Lock)
#define CxPlatDispatchLockAcquire(Lock) EnterCriticalSection(Lock)
#define CxPlatDispatchLockRelease(Lock) LeaveCriticalSection(Lock)

typedef SRWLOCK CXPLAT_RW_LOCK;

#define CxPlatRwLockInitialize(Lock) InitializeSRWLock(Lock)
#define CxPlatRwLockUninitialize(Lock)
#define CxPlatRwLockAcquireShared(Lock) AcquireSRWLockShared(Lock)
#define CxPlatRwLockAcquireExclusive(Lock) AcquireSRWLockExclusive(Lock)
#define CxPlatRwLockReleaseShared(Lock) ReleaseSRWLockShared(Lock)
#define CxPlatRwLockReleaseExclusive(Lock) ReleaseSRWLockExclusive(Lock)

typedef SRWLOCK CXPLAT_DISPATCH_RW_LOCK;

#define CxPlatDispatchRwLockInitialize(Lock) InitializeSRWLock(Lock)
#define CxPlatDispatchRwLockUninitialize(Lock)
#define CxPlatDispatchRwLockAcquireShared(Lock, PrevIrql) AcquireSRWLockShared(Lock)
#define CxPlatDispatchRwLockAcquireExclusive(Lock, PrevIrql) AcquireSRWLockExclusive(Lock)
#define CxPlatDispatchRwLockReleaseShared(Lock, PrevIrql) ReleaseSRWLockShared(Lock)
#define CxPlatDispatchRwLockReleaseExclusive(Lock, PrevIrql) ReleaseSRWLockExclusive(Lock)

//
// Reference Count Interface
//

#if defined(_X86_) || defined(_AMD64_)
#define QuicBarrierAfterInterlock()
#elif defined(_ARM64_)
#define QuicBarrierAfterInterlock()  __dmb(_ARM64_BARRIER_ISH)
#elif defined(_ARM_)
#define QuicBarrierAfterInterlock()  __dmb(_ARM_BARRIER_ISH)
#else
#error Unsupported architecture.
#endif

#if defined (_WIN64)

#define QuicIncrementLongPtrNoFence InterlockedIncrementNoFence64
#define QuicDecrementLongPtrRelease InterlockedDecrementRelease64
#define QuicCompareExchangeLongPtrNoFence InterlockedCompareExchangeNoFence64

#ifdef QUIC_RESTRICTED_BUILD
#define QuicReadLongPtrNoFence(p) ((LONG64)(*p))
#else
#define QuicReadLongPtrNoFence ReadNoFence64
#endif

#else

#define QuicIncrementLongPtrNoFence InterlockedIncrementNoFence
#define QuicDecrementLongPtrRelease InterlockedDecrementRelease
#define QuicCompareExchangeLongPtrNoFence InterlockedCompareExchangeNoFence

#ifdef QUIC_RESTRICTED_BUILD
#define QuicReadLongPtrNoFence(p) ((LONG)(*p))
#else
#define QuicReadLongPtrNoFence ReadNoFence
#endif

#endif

#ifdef QUIC_RESTRICTED_BUILD
#define QuicReadPtrNoFence(p) ((void*)(*p))
#else
#define QuicReadPtrNoFence ReadPointerNoFence
#endif

typedef LONG_PTR CXPLAT_REF_COUNT;

QUIC_INLINE
void
CxPlatRefInitialize(
    _Out_ CXPLAT_REF_COUNT* RefCount
    )
{
    *RefCount = 1;
}

QUIC_INLINE
void
CxPlatRefInitializeEx(
    _Out_ CXPLAT_REF_COUNT* RefCount,
    _In_ uint32_t Initial
    )
{
    *RefCount = (LONG_PTR)Initial;
}

#define CxPlatRefUninitialize(RefCount)

QUIC_INLINE
void
CxPlatRefIncrement(
    _Inout_ CXPLAT_REF_COUNT* RefCount
    )
{
    if (QuicIncrementLongPtrNoFence(RefCount) > 1) {
        return;
    }

    __fastfail(FAST_FAIL_INVALID_REFERENCE_COUNT);
}

QUIC_INLINE
BOOLEAN
CxPlatRefIncrementNonZero(
    _Inout_ volatile CXPLAT_REF_COUNT *RefCount,
    _In_ ULONG Bias
    )
{
    CXPLAT_REF_COUNT NewValue;
    CXPLAT_REF_COUNT OldValue;

    PrefetchForWrite(RefCount);
    OldValue = QuicReadLongPtrNoFence(RefCount);
    for (;;) {
        NewValue = OldValue + Bias;
        if ((ULONG_PTR)NewValue > Bias) {
            NewValue = QuicCompareExchangeLongPtrNoFence(RefCount,
                                                         NewValue,
                                                         OldValue);
            if (NewValue == OldValue) {
                return TRUE;
            }

            OldValue = NewValue;

        } else if ((ULONG_PTR)NewValue == Bias) {
            return FALSE;

        } else {
            __fastfail(FAST_FAIL_INVALID_REFERENCE_COUNT);
            return FALSE;
        }
    }
}

QUIC_INLINE
BOOLEAN
CxPlatRefDecrement(
    _Inout_ CXPLAT_REF_COUNT* RefCount
    )
{
    CXPLAT_REF_COUNT NewValue;

    //
    // A release fence is required to ensure all guarded memory accesses are
    // complete before any thread can begin destroying the object.
    //

    NewValue = QuicDecrementLongPtrRelease(RefCount);
    if (NewValue > 0) {
        return FALSE;

    } else if (NewValue == 0) {

        //
        // An acquire fence is required before object destruction to ensure
        // that the destructor cannot observe values changing on other threads.
        //

        QuicBarrierAfterInterlock();
        return TRUE;
    }

    __fastfail(FAST_FAIL_INVALID_REFERENCE_COUNT);
    return FALSE;
}

//
// Event Interfaces
//

typedef HANDLE CXPLAT_EVENT;

#define CxPlatEventInitialize(Event, ManualReset, InitialState)     \
    *(Event) = CreateEvent(NULL, ManualReset, InitialState, NULL);  \
    CXPLAT_DBG_ASSERT(*Event != NULL)
#define CxPlatEventUninitialize(Event) CxPlatCloseHandle(Event)
#define CxPlatEventSet(Event) SetEvent(Event)
#define CxPlatEventReset(Event) ResetEvent(Event)
#define CxPlatEventWaitForever(Event) WaitForSingleObject(Event, INFINITE)
QUIC_INLINE
BOOLEAN
CxPlatEventWaitWithTimeout(
    _In_ CXPLAT_EVENT Event,
    _In_ uint32_t TimeoutMs
    )
{
    CXPLAT_DBG_ASSERT(TimeoutMs != UINT32_MAX);
    return WAIT_OBJECT_0 == WaitForSingleObject(Event, TimeoutMs);
}

//
// Event Queue Interfaces
//

typedef HANDLE CXPLAT_EVENTQ;
typedef OVERLAPPED_ENTRY CXPLAT_CQE;
typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
void
(CXPLAT_EVENT_COMPLETION)(
    _In_ CXPLAT_CQE* Cqe
    );
typedef CXPLAT_EVENT_COMPLETION *CXPLAT_EVENT_COMPLETION_HANDLER;
typedef struct CXPLAT_SQE {
    OVERLAPPED Overlapped;
    CXPLAT_EVENT_COMPLETION_HANDLER Completion;
#if DEBUG
    BOOLEAN IsQueued; // Debug flag to catch double queueing.
#endif
} CXPLAT_SQE;

QUIC_INLINE
BOOLEAN
CxPlatEventQInitialize(
    _Out_ CXPLAT_EVENTQ* queue
    )
{
    return (*queue = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1)) != NULL;
}

QUIC_INLINE
void
CxPlatEventQCleanup(
    _In_ CXPLAT_EVENTQ* queue
    )
{
    CloseHandle(*queue);
}

QUIC_INLINE
BOOLEAN
CxPlatEventQAssociateHandle(
    _In_ CXPLAT_EVENTQ* queue,
    _In_ HANDLE fileHandle
    )
{
    return *queue == CreateIoCompletionPort(fileHandle, *queue, 0, 0);
}

QUIC_INLINE
BOOLEAN
CxPlatEventQEnqueue(
    _In_ CXPLAT_EVENTQ* queue,
    _In_ CXPLAT_SQE* sqe
    )
{
#if DEBUG
    CXPLAT_DBG_ASSERT(!sqe->IsQueued);
    sqe->IsQueued;
#endif
    CxPlatZeroMemory(&sqe->Overlapped, sizeof(sqe->Overlapped));
    return PostQueuedCompletionStatus(*queue, 0, 0, &sqe->Overlapped) != 0;
}

QUIC_INLINE
BOOLEAN
CxPlatEventQEnqueueEx( // Windows specific extension
    _In_ CXPLAT_EVENTQ* queue,
    _In_ CXPLAT_SQE* sqe,
    _In_ uint32_t num_bytes
    )
{
#if DEBUG
    CXPLAT_DBG_ASSERT(!sqe->IsQueued);
    sqe->IsQueued;
#endif
    CxPlatZeroMemory(&sqe->Overlapped, sizeof(sqe->Overlapped));
    return PostQueuedCompletionStatus(*queue, num_bytes, 0, &sqe->Overlapped) != 0;
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
    ULONG out_count = 0;
    if (!GetQueuedCompletionStatusEx(*queue, events, count, &out_count, wait_time, FALSE)) return 0;
    CXPLAT_DBG_ASSERT(out_count != 0);
    CXPLAT_DBG_ASSERT(events[0].lpOverlapped != NULL || out_count == 1);
#if DEBUG
    if (events[0].lpOverlapped) {
        for (uint32_t i = 0; i < (uint32_t)out_count; ++i) {
            CXPLAT_CONTAINING_RECORD(events[i].lpOverlapped, CXPLAT_SQE, Overlapped)->IsQueued = FALSE;
        }
    }
#endif
    return events[0].lpOverlapped == NULL ? 0 : (uint32_t)out_count;
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
    UNREFERENCED_PARAMETER(queue);
    CxPlatZeroMemory(sqe, sizeof(*sqe));
    sqe->Completion = completion;
    return TRUE;
}

QUIC_INLINE
void
CxPlatSqeInitializeEx(
    _In_ CXPLAT_EVENT_COMPLETION_HANDLER completion,
    _Out_ CXPLAT_SQE* sqe
    )
{
    sqe->Completion = completion;
    CxPlatZeroMemory(&sqe->Overlapped, sizeof(sqe->Overlapped));
#if DEBUG
    sqe->IsQueued = FALSE;
#endif
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
    return CONTAINING_RECORD(cqe->lpOverlapped, CXPLAT_SQE, Overlapped);
}

//
// Time Measurement Interfaces
//

#ifdef QUIC_UWP_BUILD
WINBASEAPI
_Success_(return != FALSE)
BOOL
WINAPI
GetSystemTimeAdjustment(
    _Out_ PDWORD lpTimeAdjustment,
    _Out_ PDWORD lpTimeIncrement,
    _Out_ PBOOL lpTimeAdjustmentDisabled
    );
#endif

//
// Returns the worst-case system timer resolution (in us).
//
QUIC_INLINE
uint64_t
CxPlatGetTimerResolution()
{
    DWORD Adjustment, Increment;
    BOOL AdjustmentDisabled;
    GetSystemTimeAdjustment(&Adjustment, &Increment, &AdjustmentDisabled);
    return NS100_TO_US(Increment);
}

//
// Performance counter frequency.
//
extern uint64_t CxPlatPerfFreq;

//
// Returns the current time in platform specific time units.
//
QUIC_INLINE
uint64_t
QuicTimePlat(
    void
    )
{
    uint64_t Count;
    QueryPerformanceCounter((LARGE_INTEGER*)&Count);
    return Count;
}

//
// Converts platform time to microseconds.
//
QUIC_INLINE
uint64_t
QuicTimePlatToUs64(
    uint64_t Count
    )
{
    //
    // Multiply by a big number (1000000, to convert seconds to microseconds)
    // and divide by a big number (CxPlatPerfFreq, to convert counts to secs).
    //
    // Avoid overflow with separate multiplication/division of the high and low
    // bits. Taken from TcpConvertPerformanceCounterToMicroseconds.
    //
    uint64_t High = (Count >> 32) * 1000000;
    uint64_t Low = (Count & 0xFFFFFFFF) * 1000000;
    return
        ((High / CxPlatPerfFreq) << 32) +
        ((Low + ((High % CxPlatPerfFreq) << 32)) / CxPlatPerfFreq);
}

//
// Converts microseconds to platform time.
//
QUIC_INLINE
uint64_t
CxPlatTimeUs64ToPlat(
    uint64_t TimeUs
    )
{
    uint64_t High = (TimeUs >> 32) * CxPlatPerfFreq;
    uint64_t Low = (TimeUs & 0xFFFFFFFF) * CxPlatPerfFreq;
    return
        ((High / 1000000) << 32) +
        ((Low + ((High % 1000000) << 32)) / CxPlatPerfFreq);
}

#define CxPlatTimeUs64() QuicTimePlatToUs64(QuicTimePlat())
#define CxPlatTimeUs32() (uint32_t)CxPlatTimeUs64()
#define CxPlatTimeMs64() US_TO_MS(CxPlatTimeUs64())
#define CxPlatTimeMs32() (uint32_t)CxPlatTimeMs64()

#define UNIX_EPOCH_AS_FILE_TIME 0x19db1ded53e8000ll

QUIC_INLINE
int64_t
CxPlatTimeEpochMs64(
    )
{
    LARGE_INTEGER FileTime;
    GetSystemTimeAsFileTime((FILETIME*) &FileTime);
    return NS100_TO_MS(FileTime.QuadPart - UNIX_EPOCH_AS_FILE_TIME);
}

//
// Returns the difference between two timestamps.
//
QUIC_INLINE
uint64_t
CxPlatTimeDiff64(
    _In_ uint64_t T1,     // First time measured
    _In_ uint64_t T2      // Second time measured
    )
{
    //
    // Assume no wrap around.
    //
    return T2 - T1;
}

//
// Returns the difference between two timestamps.
//
QUIC_INLINE
uint32_t
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

//
// Returns TRUE if T1 came before T2.
//
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

//
// Returns TRUE if T1 came before T2.
//
QUIC_INLINE
BOOLEAN
CxPlatTimeAtOrBefore32(
    _In_ uint32_t T1,
    _In_ uint32_t T2
    )
{
    return (int32_t)(T1 - T2) <= 0;
}

#define CxPlatSleep(ms) Sleep(ms)

#define CxPlatSchedulerYield() Sleep(0)

//
// Processor Count and Index
//

typedef struct CXPLAT_PROCESSOR_INFO {
    uint16_t Group;  // The group number this processor is a part of
    uint8_t Index;   // Index in the current group
    uint8_t PADDING; // Here to align with PROCESSOR_NUMBER struct
} CXPLAT_PROCESSOR_INFO;

CXPLAT_STATIC_ASSERT(sizeof(CXPLAT_PROCESSOR_INFO) == sizeof(PROCESSOR_NUMBER), "Size check");

typedef struct CXPLAT_PROCESSOR_GROUP_INFO {
    KAFFINITY Mask;  // Bit mask of active processors in the group
    uint32_t Count;  // Count of active processors in the group
    uint32_t Offset; // Base process index offset this group starts at
} CXPLAT_PROCESSOR_GROUP_INFO;

extern CXPLAT_PROCESSOR_INFO* CxPlatProcessorInfo;
extern CXPLAT_PROCESSOR_GROUP_INFO* CxPlatProcessorGroupInfo;

extern uint32_t CxPlatProcessorCount;
#define CxPlatProcCount() CxPlatProcessorCount

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_INLINE
uint32_t
CxPlatProcNumberToIndex(
    PROCESSOR_NUMBER* ProcNumber
    )
{
    const CXPLAT_PROCESSOR_GROUP_INFO* Group = &CxPlatProcessorGroupInfo[ProcNumber->Group];
    return Group->Offset + (ProcNumber->Number % Group->Count);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_INLINE
uint32_t
CxPlatProcCurrentNumber(
    void
    ) {
    PROCESSOR_NUMBER ProcNumber;
    GetCurrentProcessorNumberEx(&ProcNumber);
    return CxPlatProcNumberToIndex(&ProcNumber);
}


//
// Create Thread Interfaces
//

//
// This is the undocumented interface for setting a thread's name. This is
// essentially what SetThreadDescription does, but that is not available in
// older versions of Windows. These API's are suffixed _PRIVATE in order
// to not colide with the built in windows definitions, which are not gated
// behind any preprocessor macros
//
#if !defined(QUIC_RESTRICTED_BUILD)
#define ThreadNameInformationPrivate ((THREADINFOCLASS)38)

typedef struct _THREAD_NAME_INFORMATION_PRIVATE {
    UNICODE_STRING ThreadName;
} THREAD_NAME_INFORMATION_PRIVATE, *PTHREAD_NAME_INFORMATION_PRIVATE;

__kernel_entry
NTSTATUS
NTAPI
NtSetInformationThread(
    _In_ HANDLE ThreadHandle,
    _In_ THREADINFOCLASS ThreadInformationClass,
    _In_reads_bytes_(ThreadInformationLength) PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength
    );
#endif

#ifdef QUIC_UWP_BUILD
WINBASEAPI
BOOL
WINAPI
SetThreadGroupAffinity(
    _In_ HANDLE hThread,
    _In_ CONST GROUP_AFFINITY* GroupAffinity,
    _Out_opt_ PGROUP_AFFINITY PreviousGroupAffinity
    );
#endif

typedef struct CXPLAT_THREAD_CONFIG {
    uint16_t Flags;
    uint16_t IdealProcessor;
    _Field_z_ const char* Name;
    LPTHREAD_START_ROUTINE Callback;
    void* Context;
} CXPLAT_THREAD_CONFIG;

typedef HANDLE CXPLAT_THREAD;
#define CXPLAT_THREAD_CALLBACK(FuncName, CtxVarName)  \
    DWORD                                           \
    WINAPI                                          \
    FuncName(                                       \
      _In_ void* CtxVarName                         \
      )

#define CXPLAT_THREAD_RETURN(Status) return (DWORD)(Status)

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
#define CxPlatThreadDelete(Thread) CxPlatCloseHandle(*(Thread))
#define CxPlatThreadWait(Thread) WaitForSingleObject(*(Thread), INFINITE)
typedef uint32_t CXPLAT_THREAD_ID;
#define CxPlatCurThreadID() GetCurrentThreadId()

//
// Rundown Protection Interfaces
//

typedef struct CXPLAT_RUNDOWN_REF {

    //
    // The ref counter.
    //
    CXPLAT_REF_COUNT RefCount;

    //
    // The completion event.
    //
    HANDLE RundownComplete;

} CXPLAT_RUNDOWN_REF;

#define CxPlatRundownInitialize(Rundown)                                \
    CxPlatRefInitialize(&(Rundown)->RefCount);                          \
    (Rundown)->RundownComplete = CreateEvent(NULL, FALSE, FALSE, NULL); \
    CXPLAT_DBG_ASSERT((Rundown)->RundownComplete != NULL)
#define CxPlatRundownInitializeDisabled(Rundown)                        \
    (Rundown)->RefCount = 0;                                            \
    (Rundown)->RundownComplete = CreateEvent(NULL, FALSE, FALSE, NULL); \
    CXPLAT_DBG_ASSERT((Rundown)->RundownComplete != NULL)
#define CxPlatRundownReInitialize(Rundown) (Rundown)->RefCount = 1
#define CxPlatRundownUninitialize(Rundown) CxPlatCloseHandle((Rundown)->RundownComplete)
#define CxPlatRundownAcquire(Rundown) CxPlatRefIncrementNonZero(&(Rundown)->RefCount, 1)
#define CxPlatRundownRelease(Rundown) \
    if (CxPlatRefDecrement(&(Rundown)->RefCount)) { \
        SetEvent((Rundown)->RundownComplete); \
    }
#define CxPlatRundownReleaseAndWait(Rundown) \
    if (!CxPlatRefDecrement(&(Rundown)->RefCount)) { \
        WaitForSingleObject((Rundown)->RundownComplete, INFINITE); \
    }

//
// Crypto Interfaces
//

//
// Returns cryptographically random bytes.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
CxPlatRandom(
    _In_ uint32_t BufferLen,
    _Out_writes_bytes_(BufferLen) void* Buffer
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatUtf8ToWideChar(
    _In_z_ const char* const Input,
    _In_ uint32_t Tag,
    _Outptr_result_z_ PWSTR* Output
    );

//
// Network Compartment ID interfaces
//

#if !defined(QUIC_RESTRICTED_BUILD)

#define QUIC_COMPARTMENT_ID NET_IF_COMPARTMENT_ID

#define QUIC_UNSPECIFIED_COMPARTMENT_ID NET_IF_COMPARTMENT_ID_UNSPECIFIED
#define QUIC_DEFAULT_COMPARTMENT_ID     NET_IF_COMPARTMENT_ID_PRIMARY

#define QuicCompartmentIdGetCurrent() GetCurrentThreadCompartmentId()
#define QuicCompartmentIdSetCurrent(CompartmentId) \
    HRESULT_FROM_WIN32(SetCurrentThreadCompartmentId(CompartmentId))

#endif

#ifdef _M_X64
#define CXPLAT_CPUID(FunctionId, eax, ebx, ecx, edx) \
    int CpuInfo[4]; \
    CpuInfo[0] = eax; \
    CpuInfo[1] = ebx; \
    CpuInfo[2] = ecx; \
    CpuInfo[3] = edx; \
    __cpuid(CpuInfo, FunctionId);
#else
#define CXPLAT_CPUID(FunctionId, eax, ebx, ecx, dx)
#endif

#if defined(__cplusplus)
}
#endif
