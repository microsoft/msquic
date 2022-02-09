/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    External definition of C99 inline functions.
    See "Clang" / "Language Compatibility" / "C99 inline functions"
    ( https://clang.llvm.org/compatibility.html#inline .)
    It seems that C99 standard requires that every inline function defined
    in a header have a corresponding non-inline definition in a C source file.
    Observed behavior is that Clang is enforcing this, but not MSVC.
    Until an alternative solution is found, this file is required for Clang.

--*/

#include "platform_internal.h"
#ifdef QUIC_CLOG
#include "inline.c.clog.h"
#endif

uint16_t
MaxUdpPayloadSizeFromMTU(
    _In_ uint16_t Mtu
    );

uint16_t
MaxUdpPayloadSizeForFamily(
    _In_ QUIC_ADDRESS_FAMILY Family,
    _In_ uint16_t Mtu
    );

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

void
CxPlatListInitializeHead(
    _Out_ CXPLAT_LIST_ENTRY* ListHead
    );

_Must_inspect_result_
BOOLEAN
CxPlatListIsEmpty(
    _In_ const CXPLAT_LIST_ENTRY* ListHead
    );

_Must_inspect_result_
BOOLEAN
CxPlatListIsEmptyNoFence(
    _In_ const CXPLAT_LIST_ENTRY* ListHead
    );

void
CxPlatListInsertHead(
    _Inout_ CXPLAT_LIST_ENTRY* ListHead,
    _Inout_ __drv_aliasesMem CXPLAT_LIST_ENTRY* Entry
    );

void
CxPlatListInsertTail(
    _Inout_ CXPLAT_LIST_ENTRY* ListHead,
    _Inout_ __drv_aliasesMem CXPLAT_LIST_ENTRY* Entry
    );

CXPLAT_LIST_ENTRY*
CxPlatListRemoveHead(
    _Inout_ CXPLAT_LIST_ENTRY* ListHead
    );

BOOLEAN
CxPlatListEntryRemove(
    _In_ CXPLAT_LIST_ENTRY* Entry
    );

void
CxPlatListMoveItems(
    _In_ CXPLAT_LIST_ENTRY* Source,
    _Out_ CXPLAT_LIST_ENTRY* Destination
    );

void
CxPlatListPushEntry(
    _Inout_ CXPLAT_SLIST_ENTRY* ListHead,
    _Inout_ __drv_aliasesMem CXPLAT_SLIST_ENTRY* Entry
    );

CXPLAT_SLIST_ENTRY*
CxPlatListPopEntry(
    _Inout_ CXPLAT_SLIST_ENTRY* ListHead
    );

long
InterlockedIncrement(
    _Inout_ _Interlocked_operand_ long volatile *Addend
    );

long
InterlockedDecrement(
    _Inout_ _Interlocked_operand_ long volatile *Addend
    );

long
InterlockedAnd(
    _Inout_ _Interlocked_operand_ long volatile *Destination,
    _In_ long Value
    );

long
InterlockedOr(
    _Inout_ _Interlocked_operand_ long volatile *Destination,
    _In_ long Value
    );

int64_t
InterlockedExchangeAdd64(
    _Inout_ _Interlocked_operand_ int64_t volatile *Addend,
    _In_ int64_t Value
    );

short
InterlockedCompareExchange16(
    _Inout_ _Interlocked_operand_ short volatile *Destination,
    _In_ short ExChange,
    _In_ short Comperand
    );

short
InterlockedCompareExchange(
    _Inout_ _Interlocked_operand_ long volatile *Destination,
    _In_ long ExChange,
    _In_ long Comperand
    );

int64_t
InterlockedCompareExchange64(
    _Inout_ _Interlocked_operand_ int64_t volatile *Destination,
    _In_ int64_t ExChange,
    _In_ int64_t Comperand
    );

void*
InterlockedFetchAndClearPointer(
    _Inout_ _Interlocked_operand_ void* volatile *Target
    );

short
InterlockedIncrement16(
    _Inout_ _Interlocked_operand_ short volatile *Addend
    );

short
InterlockedDecrement16(
    _Inout_ _Interlocked_operand_ short volatile *Addend
    );

int64_t
InterlockedIncrement64(
    _Inout_ _Interlocked_operand_ int64_t volatile *Addend
    );

_Must_inspect_result_
_Success_(return != 0)
BOOLEAN
CxPlatHashtableInitializeEx(
    _Inout_ CXPLAT_HASHTABLE* HashTable,
    _In_ uint32_t InitialSize
    );

uint32_t
CxPlatHashSimple(
    _In_ uint16_t Length,
    _In_reads_(Length) const uint8_t* Buffer
    );

uint16_t
CxPlatHashLength(
    CXPLAT_HASH_TYPE Type
    );

uint16_t
CxPlatKeyLength(
    CXPLAT_AEAD_TYPE Type
    );

uint64_t
CxPlatTimeDiff64(
    _In_ uint64_t T1,
    _In_ uint64_t T2
    );

uint32_t
CxPlatTimeDiff32(
    _In_ uint32_t T1,
    _In_ uint32_t T2
    );

BOOLEAN
CxPlatTimeAtOrBefore64(
    _In_ uint64_t T1,
    _In_ uint64_t T2
    );

BOOLEAN
CxPlatTimeAtOrBefore32(
    _In_ uint32_t T1,
    _In_ uint32_t T2
    );

void
QuicTraceEventStubVarArgs(
    _In_ const void* Fmt,
    ...
    );

void
QuicTraceStubVarArgs(
    _In_ const void* Fmt,
    ...
    );

const uint8_t*
CxPlatTlsAlpnFindInList(
    _In_ uint16_t AlpnListLength,
    _In_reads_(AlpnListLength)
        const uint8_t* AlpnList,
    _In_ uint8_t FindAlpnLength,
    _In_reads_(FindAlpnLength)
        const uint8_t* FindAlpn
    );

BOOLEAN
QuicAddrFamilyIsValid(
    _In_ QUIC_ADDRESS_FAMILY Family
    );

BOOLEAN
QuicAddrIsValid(
    _In_ const QUIC_ADDR* const Addr
    );

BOOLEAN
QuicAddrCompareIp(
    _In_ const QUIC_ADDR* const Addr1,
    _In_ const QUIC_ADDR* const Addr2
    );

BOOLEAN
QuicAddrCompare(
    _In_ const QUIC_ADDR* const Addr1,
    _In_ const QUIC_ADDR* const Addr2
    );

QUIC_ADDRESS_FAMILY
QuicAddrGetFamily(
    _In_ const QUIC_ADDR* const Addr
    );

void
QuicAddrSetFamily(
    _In_ QUIC_ADDR* Addr,
    _In_ QUIC_ADDRESS_FAMILY Family
    );

uint16_t
QuicAddrGetPort(
    _In_ const QUIC_ADDR* const Addr
    );

void
QuicAddrSetPort(
    _Out_ QUIC_ADDR* Addr,
    _In_ uint16_t Port
    );

void
QuicAddrIncrement(
    _Inout_ QUIC_ADDR* Addr
    );

void
QuicAddrSetToLoopback(
    _Inout_ QUIC_ADDR* Addr
    );

uint32_t
QuicAddrHash(
    _In_ const QUIC_ADDR* Addr
    );

BOOLEAN
QuicAddrIsWildCard(
    _In_ const QUIC_ADDR* const Addr
    );

BOOLEAN
QuicAddr4FromString(
    _In_z_ const char* AddrStr,
    _Out_ QUIC_ADDR* Addr
    );

BOOLEAN
QuicAddr6FromString(
    _In_z_ const char* AddrStr,
    _Out_ QUIC_ADDR* Addr
    );

BOOLEAN
QuicAddrFromString(
    _In_z_ const char* AddrStr,
    _In_ uint16_t Port, // Host byte order
    _Out_ QUIC_ADDR* Addr
    );

BOOLEAN
QuicAddrToString(
    _In_ const QUIC_ADDR* Addr,
    _Out_ QUIC_ADDR_STR* AddrStr
    );

void
CxPlatEventInitialize(
    _Out_ CXPLAT_EVENT* Event,
    _In_ BOOLEAN ManualReset,
    _In_ BOOLEAN InitialState
    );

void
CxPlatInternalEventUninitialize(
    _Inout_ CXPLAT_EVENT* Event
    );

void
CxPlatInternalEventSet(
    _Inout_ CXPLAT_EVENT* Event
    );

void
CxPlatInternalEventReset(
    _Inout_ CXPLAT_EVENT* Event
    );

void
CxPlatInternalEventWaitForever(
    _Inout_ CXPLAT_EVENT* Event
    );

BOOLEAN
CxPlatInternalEventWaitWithTimeout(
    _Inout_ CXPLAT_EVENT* Event,
    _In_ uint32_t TimeoutMs
    );

void
CxPlatToeplitzHashComputeAddr(
    _In_ const CXPLAT_TOEPLITZ_HASH* Toeplitz,
    _In_ const QUIC_ADDR* Addr,
    _Inout_ uint32_t* Key,
    _Out_ uint32_t* Offset
    );
