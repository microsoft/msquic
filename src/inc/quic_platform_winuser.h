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

#if defined(DEBUG) || defined(_DEBUG)
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

//
// Wrapper functions
//

inline
void*
InterlockedFetchAndClearPointer(
    _Inout_ _Interlocked_operand_ void* volatile *Target
    )
{
    return InterlockedExchangePointer(Target, NULL);
}

//
// CloseHandle has an incorrect SAL annotation, so call through a wrapper.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
inline
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

typedef struct CXPLAT_POOL {
    SLIST_HEADER ListHead;
    uint32_t Size;
    uint32_t Tag;
} CXPLAT_POOL;

#define CXPLAT_POOL_MAXIMUM_DEPTH   256 // Copied from EX_MAXIMUM_LOOKASIDE_DEPTH_BASE

#if DEBUG
typedef struct CXPLAT_POOL_ENTRY {
    SLIST_ENTRY ListHead;
    uint64_t SpecialFlag;
} CXPLAT_POOL_ENTRY;
#define CXPLAT_POOL_SPECIAL_FLAG    0xAAAAAAAAAAAAAAAAui64

int32_t
CxPlatGetAllocFailDenominator(
    );
#endif

inline
void
CxPlatPoolInitialize(
    _In_ BOOLEAN IsPaged,
    _In_ uint32_t Size,
    _In_ uint32_t Tag,
    _Inout_ CXPLAT_POOL* Pool
    )
{
#if DEBUG
    CXPLAT_DBG_ASSERT(Size >= sizeof(CXPLAT_POOL_ENTRY));
#endif
    Pool->Size = Size;
    Pool->Tag = Tag;
    InitializeSListHead(&(Pool)->ListHead);
    UNREFERENCED_PARAMETER(IsPaged);
}

inline
void
CxPlatPoolUninitialize(
    _Inout_ CXPLAT_POOL* Pool
    )
{
    void* Entry;
    while ((Entry = InterlockedPopEntrySList(&Pool->ListHead)) != NULL) {
        CxPlatFree(Entry, Pool->Tag);
    }
}

inline
void*
CxPlatPoolAlloc(
    _Inout_ CXPLAT_POOL* Pool
    )
{
#if DEBUG
    if (CxPlatGetAllocFailDenominator()) {
        return CxPlatAlloc(Pool->Size, Pool->Tag);
    }
#endif
    void* Entry = InterlockedPopEntrySList(&Pool->ListHead);
    if (Entry == NULL) {
        Entry = CxPlatAlloc(Pool->Size, Pool->Tag);
    }
#if DEBUG
    if (Entry != NULL) {
        ((CXPLAT_POOL_ENTRY*)Entry)->SpecialFlag = 0;
    }
#endif
    return Entry;
}

inline
void
CxPlatPoolFree(
    _Inout_ CXPLAT_POOL* Pool,
    _In_ void* Entry
    )
{
#if DEBUG
    if (CxPlatGetAllocFailDenominator()) {
        CxPlatFree(Entry, Pool->Tag);
        return;
    }
    CXPLAT_DBG_ASSERT(((CXPLAT_POOL_ENTRY*)Entry)->SpecialFlag != CXPLAT_POOL_SPECIAL_FLAG);
    ((CXPLAT_POOL_ENTRY*)Entry)->SpecialFlag = CXPLAT_POOL_SPECIAL_FLAG;
#endif
    if (QueryDepthSList(&Pool->ListHead) >= CXPLAT_POOL_MAXIMUM_DEPTH) {
        CxPlatFree(Entry, Pool->Tag);
    } else {
        InterlockedPushEntrySList(&Pool->ListHead, (PSLIST_ENTRY)Entry);
    }
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
#define CxPlatDispatchRwLockAcquireShared(Lock) AcquireSRWLockShared(Lock)
#define CxPlatDispatchRwLockAcquireExclusive(Lock) AcquireSRWLockExclusive(Lock)
#define CxPlatDispatchRwLockReleaseShared(Lock) ReleaseSRWLockShared(Lock)
#define CxPlatDispatchRwLockReleaseExclusive(Lock) ReleaseSRWLockExclusive(Lock)

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

inline
void
CxPlatRefInitialize(
    _Out_ CXPLAT_REF_COUNT* RefCount
    )
{
    *RefCount = 1;
}

#define CxPlatRefUninitialize(RefCount)

inline
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

inline
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

inline
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
#define CxPlatEventWaitWithTimeout(Event, timeoutMs) \
    (WAIT_OBJECT_0 == WaitForSingleObject(Event, timeoutMs))

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
inline
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
inline
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
inline
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
inline
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

inline
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
inline
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
inline
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

//
// Returns TRUE if T1 came before T2.
//
inline
BOOLEAN
CxPlatTimeAtOrBefore32(
    _In_ uint32_t T1,
    _In_ uint32_t T2
    )
{
    return (int32_t)(T1 - T2) <= 0;
}

#define CxPlatSleep(ms) Sleep(ms)

//
// Processor Count and Index
//

typedef struct {

    uint16_t Group;
    uint32_t Index; // In Group;
    uint32_t NumaNode;
    uint64_t MaskInGroup;

} CXPLAT_PROCESSOR_INFO;

extern CXPLAT_PROCESSOR_INFO* CxPlatProcessorInfo;
extern uint64_t* CxPlatNumaMasks;
extern uint32_t* CxPlatProcessorGroupOffsets;

#if defined(QUIC_RESTRICTED_BUILD)
DWORD CxPlatProcMaxCount();
DWORD CxPlatProcActiveCount();
#else
#define CxPlatProcMaxCount() GetMaximumProcessorCount(ALL_PROCESSOR_GROUPS)
#define CxPlatProcActiveCount() GetActiveProcessorCount(ALL_PROCESSOR_GROUPS)
#endif

_IRQL_requires_max_(DISPATCH_LEVEL)
inline
uint32_t
CxPlatProcCurrentNumber(
    void
    ) {
    PROCESSOR_NUMBER ProcNumber;
    GetCurrentProcessorNumberEx(&ProcNumber);
    return CxPlatProcessorGroupOffsets[ProcNumber.Group] + ProcNumber.Number;
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

inline
QUIC_STATUS
CxPlatThreadCreate(
    _In_ CXPLAT_THREAD_CONFIG* Config,
    _Out_ CXPLAT_THREAD* Thread
    )
{
#ifdef CXPLAT_USE_CUSTOM_THREAD_CONTEXT
    CXPLAT_THREAD_CUSTOM_CONTEXT* CustomContext =
        CXPLAT_ALLOC_NONPAGED(sizeof(CXPLAT_THREAD_CUSTOM_CONTEXT), QUIC_POOL_CUSTOM_THREAD);
    if (CustomContext == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "Custom thread context",
            sizeof(CXPLAT_THREAD_CUSTOM_CONTEXT));
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    CustomContext->Callback = Config->Callback;
    CustomContext->Context = Config->Context;
    *Thread =
        CreateThread(
            NULL,
            0,
            CxPlatThreadCustomStart,
            CustomContext,
            0,
            NULL);
    if (*Thread == NULL) {
        CXPLAT_FREE(CustomContext, QUIC_POOL_CUSTOM_THREAD);
        return GetLastError();
    }
#else // CXPLAT_USE_CUSTOM_THREAD_CONTEXT
    *Thread =
        CreateThread(
            NULL,
            0,
            Config->Callback,
            Config->Context,
            0,
            NULL);
    if (*Thread == NULL) {
        return GetLastError();
    }
#endif // CXPLAT_USE_CUSTOM_THREAD_CONTEXT
    const CXPLAT_PROCESSOR_INFO* ProcInfo = &CxPlatProcessorInfo[Config->IdealProcessor];
    GROUP_AFFINITY Group = {0};
    if (Config->Flags & CXPLAT_THREAD_FLAG_SET_AFFINITIZE) {
        Group.Mask = (KAFFINITY)(1ull << ProcInfo->Index);          // Fixed processor
    } else {
        Group.Mask = (KAFFINITY)CxPlatNumaMasks[ProcInfo->NumaNode];  // Fixed NUMA node
    }
    Group.Group = ProcInfo->Group;
    SetThreadGroupAffinity(*Thread, &Group, NULL);
    if (Config->Flags & CXPLAT_THREAD_FLAG_SET_IDEAL_PROC) {
        SetThreadIdealProcessor(*Thread, ProcInfo->Index);
    }
    if (Config->Flags & CXPLAT_THREAD_FLAG_HIGH_PRIORITY) {
        SetThreadPriority(*Thread, THREAD_PRIORITY_HIGHEST);
    }
    if (Config->Name) {
        WCHAR WideName[64] = L"";
        size_t WideNameLength;
        mbstowcs_s(
            &WideNameLength,
            WideName,
            ARRAYSIZE(WideName) - 1,
            Config->Name,
            _TRUNCATE);
#if defined(QUIC_RESTRICTED_BUILD)
        SetThreadDescription(*Thread, WideName);
#else
        THREAD_NAME_INFORMATION_PRIVATE ThreadNameInfo;
        RtlInitUnicodeString(&ThreadNameInfo.ThreadName, WideName);
        NtSetInformationThread(
            *Thread,
            ThreadNameInformationPrivate,
            &ThreadNameInfo,
            sizeof(ThreadNameInfo));
#endif
    }
    return QUIC_STATUS_SUCCESS;
}
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

inline
QUIC_STATUS
CxPlatSetCurrentThreadProcessorAffinity(
    _In_ uint16_t ProcessorIndex
    )
{
    const CXPLAT_PROCESSOR_INFO* ProcInfo = &CxPlatProcessorInfo[ProcessorIndex];
    GROUP_AFFINITY Group = {0};
    Group.Mask = (KAFFINITY)(1ull << ProcInfo->Index);
    Group.Group = ProcInfo->Group;
    if (SetThreadGroupAffinity(GetCurrentThread(), &Group, NULL)) {
        return QUIC_STATUS_SUCCESS;
    }
    return HRESULT_FROM_WIN32(GetLastError());
}

#define QuicCompartmentIdGetCurrent() GetCurrentThreadCompartmentId()
#define QuicCompartmentIdSetCurrent(CompartmentId) \
    HRESULT_FROM_WIN32(SetCurrentThreadCompartmentId(CompartmentId))

inline
QUIC_STATUS
CxPlatSetCurrentThreadGroupAffinity(
    _In_ uint16_t ProcessorGroup
    )
{
    GROUP_AFFINITY Group = {0};
    GROUP_AFFINITY ExistingGroup = {0};
    if (!GetThreadGroupAffinity(GetCurrentThread(), &ExistingGroup)) {
        return HRESULT_FROM_WIN32(GetLastError());
    }
    Group.Mask = ExistingGroup.Mask;
    Group.Group = ProcessorGroup;
    if (SetThreadGroupAffinity(GetCurrentThread(), &Group, NULL)) {
        return QUIC_STATUS_SUCCESS;
    }
    return HRESULT_FROM_WIN32(GetLastError());
}

#else

inline
QUIC_STATUS
CxPlatSetCurrentThreadProcessorAffinity(
    _In_ uint16_t ProcessorIndex
    )
{
    UNREFERENCED_PARAMETER(ProcessorIndex);
    return QUIC_STATUS_SUCCESS;
}

inline
QUIC_STATUS
CxPlatSetCurrentThreadGroupAffinity(
    _In_ uint16_t ProcessorGroup
    )
{
    UNREFERENCED_PARAMETER(ProcessorGroup);
    return QUIC_STATUS_SUCCESS;
}

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
