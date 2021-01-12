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
CxPlatListInitializeHead(
    _Out_ QUIC_LIST_ENTRY* ListHead
    );

_Must_inspect_result_
BOOLEAN
CxPlatListIsEmpty(
    _In_ const QUIC_LIST_ENTRY* ListHead
    );

void
CxPlatListInsertHead(
    _Inout_ QUIC_LIST_ENTRY* ListHead,
    _Inout_ __drv_aliasesMem QUIC_LIST_ENTRY* Entry
    );

void
CxPlatListInsertTail(
    _Inout_ QUIC_LIST_ENTRY* ListHead,
    _Inout_ __drv_aliasesMem QUIC_LIST_ENTRY* Entry
    );

QUIC_LIST_ENTRY*
CxPlatListRemoveHead(
    _Inout_ QUIC_LIST_ENTRY* ListHead
    );

BOOLEAN
CxPlatListEntryRemove(
    _In_ QUIC_LIST_ENTRY* Entry
    );

void
CxPlatListMoveItems(
    _In_ QUIC_LIST_ENTRY* Source,
    _Out_ QUIC_LIST_ENTRY* Destination
    );

void
CxPlatListPushEntry(
    _Inout_ QUIC_SINGLE_LIST_ENTRY* ListHead,
    _Inout_ __drv_aliasesMem QUIC_SINGLE_LIST_ENTRY* Entry
    );

QUIC_SINGLE_LIST_ENTRY*
CxPlatListPopEntry(
    _Inout_ QUIC_SINGLE_LIST_ENTRY* ListHead
    );

long
InterlockedIncrement(
    _Inout_ _Interlocked_operand_ long volatile *Addend
    );

long
InterlockedDecrement(
    _Inout_ _Interlocked_operand_ long volatile *Addend
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
    _Inout_ QUIC_HASHTABLE* HashTable,
    _In_ uint32_t InitialSize
    );

uint32_t
CxPlatHashSimple(
    _In_ uint16_t Length,
    _In_reads_(Length) const uint8_t* Buffer
    );

uint16_t
CxPlatHashLength(
    QUIC_HASH_TYPE Type
    );

uint16_t
CxPlatKeyLength(
    QUIC_AEAD_TYPE Type
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
CxPlatTraceStubVarArgs(
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
CxPlatAddrFamilyIsValid(
    _In_ QUIC_ADDRESS_FAMILY Family
    );

BOOLEAN
CxPlatAddrIsValid(
    _In_ const QUIC_ADDR* const Addr
    );

BOOLEAN
CxPlatAddrCompareIp(
    _In_ const QUIC_ADDR* const Addr1,
    _In_ const QUIC_ADDR* const Addr2
    );

BOOLEAN
CxPlatAddrCompare(
    _In_ const QUIC_ADDR* const Addr1,
    _In_ const QUIC_ADDR* const Addr2
    );

uint16_t
CxPlatAddrGetFamily(
    _In_ const QUIC_ADDR* const Addr
    );

void
CxPlatAddrSetFamily(
    _In_ QUIC_ADDR* Addr,
    _In_ uint16_t Family
    );

uint16_t
CxPlatAddrGetPort(
    _In_ const QUIC_ADDR* const Addr
    );

void
CxPlatAddrSetPort(
    _Out_ QUIC_ADDR* Addr,
    _In_ uint16_t Port
    );

void
CxPlatAddrIncrement(
    _Inout_ QUIC_ADDR* Addr
    );

void
CxPlatAddrSetToLoopback(
    _Inout_ QUIC_ADDR* Addr
    );

uint32_t
CxPlatAddrHash(
    _In_ const QUIC_ADDR* Addr
    );

BOOLEAN
CxPlatAddrIsWildCard(
    _In_ const QUIC_ADDR* const Addr
    );

BOOLEAN
CxPlatAddr4FromString(
    _In_z_ const char* AddrStr,
    _Out_ QUIC_ADDR* Addr
    );

BOOLEAN
CxPlatAddr6FromString(
    _In_z_ const char* AddrStr,
    _Out_ QUIC_ADDR* Addr
    );

BOOLEAN
CxPlatAddrFromString(
    _In_z_ const char* AddrStr,
    _In_ uint16_t Port, // Host byte order
    _Out_ QUIC_ADDR* Addr
    );

BOOLEAN
CxPlatAddrToString(
    _In_ const QUIC_ADDR* Addr,
    _Out_ QUIC_ADDR_STR* AddrStr
    );
