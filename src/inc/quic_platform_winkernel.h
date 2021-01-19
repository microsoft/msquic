/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file contains Windows Kernel Mode implementations of the
    QUIC Platform Interfaces.

Environment:

    Windows kernel mode

--*/

#pragma once

#ifndef CX_PLATFORM_TYPE
#error "Must be included from quic_platform.h"
#endif

#ifndef _KERNEL_MODE
#error "Incorrectly including Windows Kernel Platform Header"
#endif

#pragma warning(push) // Don't care about OACR warnings in publics
#pragma warning(disable:26036)
#pragma warning(disable:26061)
#pragma warning(disable:26071)
#pragma warning(disable:28118)
#pragma warning(disable:28196)
#pragma warning(disable:28252)
#pragma warning(disable:28253)
#pragma warning(disable:28309)
#include <ntifs.h>
#include <ntverp.h>
#include <ntstrsafe.h>
#include <wdf.h>
#include <netioapi.h>
#include <wsk.h>
#include <bcrypt.h>
#include <intrin.h>
#ifdef QUIC_TELEMETRY_ASSERTS
#include <telemetry\MicrosoftTelemetryAssertKM.h>
#endif
#include <msquic_winkernel.h>
#pragma warning(pop)

#if defined(__cplusplus)
extern "C" {
#endif

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwClose(
    _In_ HANDLE Handle
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSYSAPI
NTSTATUS
NTAPI
ZwQueryInformationThread (
    _In_ HANDLE ThreadHandle,
    _In_ THREADINFOCLASS ThreadInformationClass,
    _In_ PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

#if DBG
#define DEBUG 1
#endif

#if _WIN64
#define QUIC_64BIT 1
#else
#define QUIC_32BIT 1
#endif

#ifndef KRTL_INIT_SEGMENT
#define KRTL_INIT_SEGMENT "INIT"
#endif
#ifndef KRTL_PAGE_SEGMENT
#define KRTL_PAGE_SEGMENT "PAGE"
#endif
#ifndef KRTL_NONPAGED_SEGMENT
#define KRTL_NONPAGED_SEGMENT ".text"
#endif

// Use on code in the INIT segment. (Code is discarded after DriverEntry returns.)
#define INITCODE __declspec(code_seg(KRTL_INIT_SEGMENT))

// Use on pageable functions.
#define PAGEDX __declspec(code_seg(KRTL_PAGE_SEGMENT))

#define QUIC_CACHEALIGN DECLSPEC_CACHEALIGN

//
// Library Initialization
//

//
// Called in DLLMain or DriverEntry.
//
INITCODE
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatSystemLoad(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

//
// Called in DLLMain or DriverUnload.
//
PAGEDX
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatSystemUnload(
    void
    );

//
// Initializes the PAL library. Calls to this and
// CxPlatformUninitialize must be serialized and cannot overlap.
//
PAGEDX
_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatInitialize(
    void
    );

//
// Uninitializes the PAL library. Calls to this and
// CxPlatformInitialize must be serialized and cannot overlap.
//
PAGEDX
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatUninitialize(
    void
    );

//
// Assertion Interfaces
//

#define CXPLAT_STATIC_ASSERT(X,Y) static_assert(X,Y)

#define CXPLAT_ANALYSIS_ASSERT(X) __analysis_assert(X)

//
// Logs the assertion failure to ETW.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
CxPlatLogAssert(
    _In_z_ const char* File,
    _In_ int Line,
    _In_z_ const char* Expr
    );

#define QUIC_WIDE_STRING(_str) L##_str

#define QUIC_ASSERT_ACTION(_exp) \
    ((!(_exp)) ? \
        (CxPlatLogAssert(__FILE__, __LINE__, #_exp), \
         __annotation(L"Debug", L"AssertFail", QUIC_WIDE_STRING(#_exp)), \
         DbgRaiseAssertionFailure(), FALSE) : \
        TRUE)

#define QUIC_ASSERTMSG_ACTION(_msg, _exp) \
    ((!(_exp)) ? \
        (CxPlatLogAssert(__FILE__, __LINE__, #_exp), \
         __annotation(L"Debug", L"AssertFail", L##_msg), \
         DbgRaiseAssertionFailure(), FALSE) : \
        TRUE)

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

//
// MsQuic uses three types of asserts:
//
//  CXPLAT_DBG_ASSERT - Asserts that are too expensive to evaluate all the time.
//  CXPLAT_TEL_ASSERT - Asserts that are acceptable to always evaluate, but not
//                    always crash the system.
//  CXPLAT_FRE_ASSERT - Asserts that must always crash the system.
//

#if DEBUG
#define CXPLAT_DBG_ASSERT(_exp)          (CXPLAT_ANALYSIS_ASSUME(_exp), QUIC_ASSERT_ACTION(_exp))
#define CXPLAT_DBG_ASSERTMSG(_exp, _msg) (CXPLAT_ANALYSIS_ASSUME(_exp), QUIC_ASSERTMSG_ACTION(_msg, _exp))
#else
#define CXPLAT_DBG_ASSERT(_exp)          (CXPLAT_ANALYSIS_ASSUME(_exp), 0)
#define CXPLAT_DBG_ASSERTMSG(_exp, _msg) (CXPLAT_ANALYSIS_ASSUME(_exp), 0)
#endif

#if DEBUG
#define CXPLAT_TEL_ASSERT(_exp)          (CXPLAT_ANALYSIS_ASSUME(_exp), QUIC_ASSERT_ACTION(_exp))
#define CXPLAT_TEL_ASSERTMSG(_exp, _msg) (CXPLAT_ANALYSIS_ASSUME(_exp), QUIC_ASSERTMSG_ACTION(_msg, _exp))
#define CXPLAT_TEL_ASSERTMSG_ARGS(_exp, _msg, _origin, _bucketArg1, _bucketArg2) \
     (CXPLAT_ANALYSIS_ASSUME(_exp), QUIC_ASSERTMSG_ACTION(_msg, _exp))
#else
#ifdef MICROSOFT_TELEMETRY_ASSERT
#define CXPLAT_TEL_ASSERT(_exp)          (CXPLAT_ANALYSIS_ASSUME(_exp), MICROSOFT_TELEMETRY_ASSERT_KM(_exp))
#define CXPLAT_TEL_ASSERTMSG(_exp, _msg) (CXPLAT_ANALYSIS_ASSUME(_exp), MICROSOFT_TELEMETRY_ASSERT_MSG_KM(_exp, _msg))
#define CXPLAT_TEL_ASSERTMSG_ARGS(_exp, _msg, _origin, _bucketArg1, _bucketArg2) \
    (CXPLAT_ANALYSIS_ASSUME(_exp), MICROSOFT_TELEMETRY_ASSERT_MSG_WITH_ARGS_KM(_exp, _msg, _origin, _bucketArg1, _bucketArg2))
#else
#define CXPLAT_TEL_ASSERT(_exp)          (CXPLAT_ANALYSIS_ASSUME(_exp), 0)
#define CXPLAT_TEL_ASSERTMSG(_exp, _msg) (CXPLAT_ANALYSIS_ASSUME(_exp), 0)
#define CXPLAT_TEL_ASSERTMSG_ARGS(_exp, _msg, _origin, _bucketArg1, _bucketArg2) \
    (CXPLAT_ANALYSIS_ASSUME(_exp), 0)
#endif
#endif

#define CXPLAT_FRE_ASSERT(_exp)          (CXPLAT_ANALYSIS_ASSUME(_exp), QUIC_ASSERT_ACTION(_exp))
#define CXPLAT_FRE_ASSERTMSG(_exp, _msg) (CXPLAT_ANALYSIS_ASSUME(_exp), QUIC_ASSERTMSG_ACTION(_msg, _exp))

//
// Verifier is enabled.
//
#define QuicVerifierEnabled(Flags) NT_SUCCESS(MmIsVerifierEnabled((PULONG)&Flags))
#define QuicVerifierEnabledByAddr(Address) MmIsDriverVerifyingByAddress(Address)

//
// Debugger check.
//
#define CxPlatDebuggerPresent() KD_DEBUGGER_ENABLED

//
// Interrupt ReQuest Level
//

#define CXPLAT_IRQL() KeGetCurrentIrql()

#define CXPLAT_PASSIVE_CODE() CXPLAT_DBG_ASSERT(CXPLAT_IRQL() == PASSIVE_LEVEL)

//
// Allocation/Memory Interfaces
//

extern uint64_t CxPlatTotalMemory;

#define CXPLAT_ALLOC_PAGED(Size, Tag) ExAllocatePool2(POOL_FLAG_PAGED | POOL_FLAG_UNINITIALIZED, Size, Tag)
#define CXPLAT_ALLOC_NONPAGED(Size, Tag) ExAllocatePool2(POOL_FLAG_NON_PAGED | POOL_FLAG_UNINITIALIZED, Size, Tag)
#define CXPLAT_FREE(Mem, Tag) ExFreePoolWithTag((void*)Mem, Tag)

typedef LOOKASIDE_LIST_EX CXPLAT_POOL;

#define CxPlatPoolInitialize(IsPaged, Size, Tag, Pool) \
    ExInitializeLookasideListEx( \
        Pool, \
        NULL, \
        NULL, \
        (IsPaged) ? PagedPool : NonPagedPoolNx, \
        0, \
        Size, \
        Tag, \
        0)

#define CxPlatPoolUninitialize(Pool) ExDeleteLookasideListEx(Pool)
#define CxPlatPoolAlloc(Pool) ExAllocateFromLookasideListEx(Pool)
#define CxPlatPoolFree(Pool, Entry) ExFreeToLookasideListEx(Pool, Entry)

#define CxPlatZeroMemory RtlZeroMemory
#define CxPlatCopyMemory RtlCopyMemory
#define CxPlatMoveMemory RtlMoveMemory
#define CxPlatSecureZeroMemory RtlSecureZeroMemory

#define CxPlatByteSwapUint16 RtlUshortByteSwap
#define CxPlatByteSwapUint32 RtlUlongByteSwap
#define CxPlatByteSwapUint64 RtlUlonglongByteSwap

//
// Locking Interfaces
//

//
// The following declares several currently unpublished shared locking
// functions from Windows.
//

__drv_maxIRQL(APC_LEVEL)
__drv_mustHoldCriticalRegion
NTKERNELAPI
VOID
FASTCALL
ExfAcquirePushLockExclusive(
    __inout __deref __drv_acquiresExclusiveResource(ExPushLockType)
    PEX_PUSH_LOCK PushLock
    );

__drv_maxIRQL(APC_LEVEL)
__drv_mustHoldCriticalRegion
NTKERNELAPI
VOID
FASTCALL
ExfAcquirePushLockShared(
    __inout __deref __drv_acquiresExclusiveResource(ExPushLockType)
    PEX_PUSH_LOCK PushLock
    );

__drv_maxIRQL(DISPATCH_LEVEL)
__drv_mustHoldCriticalRegion
NTKERNELAPI
VOID
FASTCALL
ExfReleasePushLockExclusive(
    __inout __deref __drv_releasesExclusiveResource(ExPushLockType)
    PEX_PUSH_LOCK PushLock
    );

__drv_maxIRQL(DISPATCH_LEVEL)
__drv_mustHoldCriticalRegion
NTKERNELAPI
VOID
FASTCALL
ExfReleasePushLockShared(
    __inout __deref __drv_releasesExclusiveResource(ExPushLockType)
    PEX_PUSH_LOCK PushLock
    );

typedef EX_PUSH_LOCK CXPLAT_LOCK;

#define CxPlatLockInitialize(Lock) ExInitializePushLock(Lock)
#define CxPlatLockUninitialize(Lock)
#define CxPlatLockAcquire(Lock) KeEnterCriticalRegion(); ExfAcquirePushLockExclusive(Lock)
#define CxPlatLockRelease(Lock) ExfReleasePushLockExclusive(Lock); KeLeaveCriticalRegion()

typedef struct CXPLAT_DISPATCH_LOCK {
    KSPIN_LOCK SpinLock;
    KIRQL PrevIrql;
} CXPLAT_DISPATCH_LOCK;

#define CxPlatDispatchLockInitialize(Lock) KeInitializeSpinLock(&(Lock)->SpinLock)
#define CxPlatDispatchLockUninitialize(Lock)
#if defined(_AMD64_) || defined(_ARM64_)
#define CxPlatDispatchLockAcquire(Lock) (Lock)->PrevIrql = KeAcquireSpinLockRaiseToDpc(&(Lock)->SpinLock)
#else
#define CxPlatDispatchLockAcquire(Lock) KeAcquireSpinLock(&(Lock)->SpinLock, &(Lock)->PrevIrql)
#endif
#define CxPlatDispatchLockRelease(Lock) KeReleaseSpinLock(&(Lock)->SpinLock, (Lock)->PrevIrql)

typedef EX_PUSH_LOCK CXPLAT_RW_LOCK;

#define CxPlatRwLockInitialize(Lock) ExInitializePushLock(Lock)
#define CxPlatRwLockUninitialize(Lock)
#define CxPlatRwLockAcquireShared(Lock) KeEnterCriticalRegion(); ExfAcquirePushLockShared(Lock)
#define CxPlatRwLockAcquireExclusive(Lock) KeEnterCriticalRegion(); ExfAcquirePushLockExclusive(Lock)
#define CxPlatRwLockReleaseShared(Lock) ExfReleasePushLockShared(Lock); KeLeaveCriticalRegion()
#define CxPlatRwLockReleaseExclusive(Lock) ExfReleasePushLockExclusive(Lock); KeLeaveCriticalRegion()

typedef struct CXPLAT_DISPATCH_RW_LOCK {
    EX_SPIN_LOCK SpinLock;
    KIRQL PrevIrql;
} CXPLAT_DISPATCH_RW_LOCK;

#define CxPlatDispatchRwLockInitialize(Lock) (Lock)->SpinLock = 0
#define CxPlatDispatchRwLockUninitialize(Lock)
#define CxPlatDispatchRwLockAcquireShared(Lock) (Lock)->PrevIrql = ExAcquireSpinLockShared(&(Lock)->SpinLock)
#define CxPlatDispatchRwLockAcquireExclusive(Lock) (Lock)->PrevIrql = ExAcquireSpinLockExclusive(&(Lock)->SpinLock)
#define CxPlatDispatchRwLockReleaseShared(Lock) ExReleaseSpinLockShared(&(Lock)->SpinLock, (Lock)->PrevIrql)
#define CxPlatDispatchRwLockReleaseExclusive(Lock) ExReleaseSpinLockExclusive(&(Lock)->SpinLock, (Lock)->PrevIrql)

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
#define QuicReadLongPtrNoFence ReadNoFence64
#else
#define QuicIncrementLongPtrNoFence InterlockedIncrementNoFence
#define QuicDecrementLongPtrRelease InterlockedDecrementRelease
#define QuicCompareExchangeLongPtrNoFence InterlockedCompareExchangeNoFence
#define QuicReadLongPtrNoFence ReadNoFence
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

typedef KEVENT CXPLAT_EVENT;
#define CxPlatEventInitialize(Event, ManualReset, InitialState) \
    KeInitializeEvent(Event, ManualReset ? NotificationEvent : SynchronizationEvent, InitialState)
#define CxPlatEventUninitialize(Event) UNREFERENCED_PARAMETER(Event)
#define CxPlatEventSet(Event) KeSetEvent(&(Event), IO_NO_INCREMENT, FALSE)
#define CxPlatEventReset(Event) KeResetEvent(&(Event))
#define CxPlatEventWaitForever(Event) \
    KeWaitForSingleObject(&(Event), Executive, KernelMode, FALSE, NULL)
inline
NTSTATUS
_CxPlatEventWaitWithTimeout(
    _In_ CXPLAT_EVENT* Event,
    _In_ uint32_t TimeoutMs
    )
{
    LARGE_INTEGER Timeout100Ns;
    Timeout100Ns.QuadPart = Int32x32To64(TimeoutMs, -10000);
    return KeWaitForSingleObject(Event, Executive, KernelMode, FALSE, &Timeout100Ns);
}
#define CxPlatEventWaitWithTimeout(Event, TimeoutMs) \
    (STATUS_SUCCESS == _CxPlatEventWaitWithTimeout(&Event, TimeoutMs))

//
// Time Measurement Interfaces
//

//
// Returns the worst-case system timer resolution (in us).
//
inline
uint64_t
CxPlatGetTimerResolution()
{
    ULONG MaximumTime, MinimumTime, CurrentTime;
    ExQueryTimerResolution(&MaximumTime, &MinimumTime, &CurrentTime);
    return NS100_TO_US(MaximumTime);
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
    return (uint64_t)KeQueryPerformanceCounter(NULL).QuadPart;
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
        ((Low + ((High % 1000000) << 32)) / 1000000);
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
    LARGE_INTEGER SystemTime;
    KeQuerySystemTime(&SystemTime);
    return NS100_TO_MS(SystemTime.QuadPart - UNIX_EPOCH_AS_FILE_TIME);
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

_IRQL_requires_max_(PASSIVE_LEVEL)
inline
void
CxPlatSleep(
    _In_ uint32_t DurationMs
    )
{
    CXPLAT_DBG_ASSERT(DurationMs != (uint32_t)-1);

    KTIMER SleepTimer;
    LARGE_INTEGER TimerValue;

    KeInitializeTimerEx(&SleepTimer, SynchronizationTimer);
    TimerValue.QuadPart = Int32x32To64(DurationMs, -10000);
    KeSetTimer(&SleepTimer, TimerValue, NULL);

    KeWaitForSingleObject(&SleepTimer, Executive, KernelMode, FALSE, NULL);
}

//
// Create Thread Interfaces
//

typedef struct CXPLAT_THREAD_CONFIG {
    uint16_t Flags;
    uint16_t IdealProcessor;
    _Field_z_ const char* Name;
    KSTART_ROUTINE* Callback;
    void* Context;
} CXPLAT_THREAD_CONFIG;

typedef struct _ETHREAD *CXPLAT_THREAD;
#define CXPLAT_THREAD_CALLBACK(FuncName, CtxVarName)  \
    _Function_class_(KSTART_ROUTINE)                \
    _IRQL_requires_same_                            \
    void                                            \
    FuncName(                                       \
      _In_ void* CtxVarName                         \
      )

#define CXPLAT_THREAD_RETURN(Status) PsTerminateSystemThread(Status)

inline
QUIC_STATUS
CxPlatThreadCreate(
    _In_ CXPLAT_THREAD_CONFIG* Config,
    _Out_ CXPLAT_THREAD* Thread
    )
{
    QUIC_STATUS Status;
    HANDLE ThreadHandle;
    Status =
        PsCreateSystemThread(
            &ThreadHandle,
            THREAD_ALL_ACCESS,
            NULL,
            NULL,
            NULL,
            Config->Callback,
            Config->Context);
    CXPLAT_DBG_ASSERT(QUIC_SUCCEEDED(Status));
    if (QUIC_FAILED(Status)) {
        *Thread = NULL;
        goto Error;
    }
    Status =
        ObReferenceObjectByHandle(
            ThreadHandle,
            THREAD_ALL_ACCESS,
            *PsThreadType,
            KernelMode,
            (void**)Thread,
            NULL);
    CXPLAT_DBG_ASSERT(QUIC_SUCCEEDED(Status));
    if (QUIC_FAILED(Status)) {
        *Thread = NULL;
        goto Cleanup;
    }
    PROCESSOR_NUMBER Processor, IdealProcessor;
    Status =
        KeGetProcessorNumberFromIndex(
            Config->IdealProcessor,
            &Processor);
    CXPLAT_DBG_ASSERT(QUIC_SUCCEEDED(Status));
    if (QUIC_FAILED(Status)) {
        goto Cleanup;
    }
    IdealProcessor = Processor;
    if (Config->Flags & CXPLAT_THREAD_FLAG_SET_AFFINITIZE) {
        GROUP_AFFINITY Affinity;
        CxPlatZeroMemory(&Affinity, sizeof(Affinity));
        Affinity.Group = Processor.Group;
        Affinity.Mask = (1ull << Processor.Number);
        Status =
            ZwSetInformationThread(
                ThreadHandle,
                ThreadGroupInformation,
                &Affinity,
                sizeof(Affinity));
        CXPLAT_DBG_ASSERT(QUIC_SUCCEEDED(Status));
        if (QUIC_FAILED(Status)) {
            goto Cleanup;
        }
    } else { // NUMA Node Affinity
        SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX Info;
        ULONG InfoLength = sizeof(Info);
        Status =
            KeQueryLogicalProcessorRelationship(
                &Processor,
                RelationNumaNode,
                &Info,
                &InfoLength);
        CXPLAT_DBG_ASSERT(QUIC_SUCCEEDED(Status));
        if (QUIC_FAILED(Status)) {
            goto Cleanup;
        }
        Status =
            ZwSetInformationThread(
                ThreadHandle,
                ThreadGroupInformation,
                &Info.NumaNode.GroupMask,
                sizeof(GROUP_AFFINITY));
        CXPLAT_DBG_ASSERT(QUIC_SUCCEEDED(Status));
        if (QUIC_FAILED(Status)) {
            goto Cleanup;
        }
    }
    if (Config->Flags & CXPLAT_THREAD_FLAG_SET_IDEAL_PROC) {
        Status =
            ZwSetInformationThread(
                ThreadHandle,
                ThreadIdealProcessorEx,
                &IdealProcessor, // Don't pass in Processor because this overwrites on output.
                sizeof(IdealProcessor));
        CXPLAT_DBG_ASSERT(QUIC_SUCCEEDED(Status));
        if (QUIC_FAILED(Status)) {
            goto Cleanup;
        }
    }
    if (Config->Flags & CXPLAT_THREAD_FLAG_HIGH_PRIORITY) {
        KeSetBasePriorityThread(
            (PKTHREAD)(*Thread),
            IO_NETWORK_INCREMENT + 1);
    }
    if (Config->Name) {
        DECLARE_UNICODE_STRING_SIZE(UnicodeName, 64);
        ULONG UnicodeNameLength = 0;
        Status =
            RtlUTF8ToUnicodeN(
                UnicodeName.Buffer,
                UnicodeName.MaximumLength,
                &UnicodeNameLength,
                Config->Name,
                (ULONG)strnlen(Config->Name, 64));
        CXPLAT_DBG_ASSERT(QUIC_SUCCEEDED(Status));
        UnicodeName.Length = (USHORT)UnicodeNameLength;
#define ThreadNameInformation ((THREADINFOCLASS)38)
        Status =
            ZwSetInformationThread(
                ThreadHandle,
                ThreadNameInformation,
                &UnicodeName,
                sizeof(UNICODE_STRING));
        CXPLAT_DBG_ASSERT(QUIC_SUCCEEDED(Status));
        Status = QUIC_STATUS_SUCCESS;
    }
Cleanup:
    ZwClose(ThreadHandle);
Error:
    return Status;
}
#define CxPlatThreadDelete(Thread) ObDereferenceObject(*(Thread))
#define CxPlatThreadWait(Thread) \
    KeWaitForSingleObject( \
        *(Thread), \
        Executive, \
        KernelMode, \
        FALSE, \
        NULL)
typedef ULONG_PTR CXPLAT_THREAD_ID;
#define CxPlatCurThreadID() ((CXPLAT_THREAD_ID)PsGetCurrentThreadId())

//
// Processor Count and Index
//

#define CxPlatProcMaxCount() KeQueryMaximumProcessorCountEx(ALL_PROCESSOR_GROUPS)
#define CxPlatProcActiveCount() KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS)
#define CxPlatProcCurrentNumber() KeGetCurrentProcessorIndex()

//
// Rundown Protection Interfaces
//

typedef EX_RUNDOWN_REF CXPLAT_RUNDOWN_REF;
#define CxPlatRundownInitialize(Rundown) ExInitializeRundownProtection(Rundown)
#define CxPlatRundownInitializeDisabled(Rundown) (Rundown)->Count = EX_RUNDOWN_ACTIVE
#define CxPlatRundownReInitialize(Rundown) ExReInitializeRundownProtection(Rundown)
#define CxPlatRundownUninitialize(Rundown)
#define CxPlatRundownAcquire(Rundown) ExAcquireRundownProtection(Rundown)
#define CxPlatRundownRelease(Rundown) ExReleaseRundownProtection(Rundown)
#define CxPlatRundownReleaseAndWait(Rundown) ExWaitForRundownProtectionRelease(Rundown)

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

//
// Silo interfaces
//

#define QUIC_SILO PESILO
#define QUIC_SILO_INVALID ((PESILO)(void*)(LONG_PTR)-1)

#define QuicSiloGetCurrentServer() PsGetCurrentServerSilo()
#define QuicSiloAddRef(Silo) if (Silo != NULL) { ObReferenceObjectWithTag(Silo, QUIC_POOL_SILO); }
#define QuicSiloRelease(Silo) if (Silo != NULL) { ObDereferenceObjectWithTag(Silo, QUIC_POOL_SILO); }
#define QuicSiloAttach(Silo) PsAttachSiloToCurrentThread(Silo)
#define QuicSiloDetatch(PrevSilo) PsDetachSiloFromCurrentThread(PrevSilo)

//
// Network Compartment ID interfaces
//

#define QUIC_COMPARTMENT_ID COMPARTMENT_ID

#define QUIC_UNSPECIFIED_COMPARTMENT_ID UNSPECIFIED_COMPARTMENT_ID
#define QUIC_DEFAULT_COMPARTMENT_ID     DEFAULT_COMPARTMENT_ID

COMPARTMENT_ID
NdisGetThreadObjectCompartmentId(
    IN PETHREAD ThreadObject
    );

NTSTATUS
NdisSetThreadObjectCompartmentId(
    IN PETHREAD ThreadObject,
    IN NET_IF_COMPARTMENT_ID CompartmentId
    );

inline
QUIC_STATUS
CxPlatSetCurrentThreadProcessorAffinity(
    _In_ uint16_t ProcessorIndex
    )
{
    PROCESSOR_NUMBER ProcInfo;
    QUIC_STATUS Status =
        KeGetProcessorNumberFromIndex(
            ProcessorIndex,
            &ProcInfo);
    if (QUIC_FAILED(Status)) {
        return Status;
    }
    GROUP_AFFINITY Affinity = {0};
    Affinity.Mask = (KAFFINITY)(1ull << ProcInfo.Number);
    Affinity.Group = ProcInfo.Group;
    return
        ZwSetInformationThread(
            ZwCurrentThread(),
            ThreadGroupInformation,
            &Affinity,
            sizeof(Affinity));
}

inline
QUIC_STATUS
CxPlatSetCurrentThreadGroupAffinity(
    _In_ uint16_t ProcessorGroup
    )
{
    GROUP_AFFINITY Affinity = {0};
    GROUP_AFFINITY ExistingAffinity = {0};
    QUIC_STATUS Status;
    if (QUIC_FAILED(
        Status =
            ZwQueryInformationThread(
                ZwCurrentThread(),
                ThreadGroupInformation,
                &ExistingAffinity,
                sizeof(ExistingAffinity),
                NULL))) {
        return Status;
    }

    Affinity.Mask = ExistingAffinity.Mask;
    Affinity.Group = ProcessorGroup;
    return
        ZwSetInformationThread(
            ZwCurrentThread(),
            ThreadGroupInformation,
            &Affinity,
            sizeof(Affinity));
}

#define QuicCompartmentIdGetCurrent() NdisGetThreadObjectCompartmentId(PsGetCurrentThread())
#define QuicCompartmentIdSetCurrent(CompartmentId) \
    NdisSetThreadObjectCompartmentId(PsGetCurrentThread(), CompartmentId)

#define CXPLAT_CPUID(FunctionId, eax, ebx, ecx, dx)

#if defined(__cplusplus)
}
#endif
