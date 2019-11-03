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
QuicListInitializeHead(
    _Out_ QUIC_LIST_ENTRY* ListHead
    );

_Must_inspect_result_
BOOLEAN
QuicListIsEmpty(
    _In_ const QUIC_LIST_ENTRY* ListHead
    );

void
QuicListInsertHead(
    _Inout_ QUIC_LIST_ENTRY* ListHead,
    _Inout_ __drv_aliasesMem QUIC_LIST_ENTRY* Entry
    );

void
QuicListInsertTail(
    _Inout_ QUIC_LIST_ENTRY* ListHead,
    _Inout_ __drv_aliasesMem QUIC_LIST_ENTRY* Entry
    );

QUIC_LIST_ENTRY*
QuicListRemoveHead(
    _Inout_ QUIC_LIST_ENTRY* ListHead
    );

BOOLEAN
QuicListEntryRemove(
    _In_ QUIC_LIST_ENTRY* Entry
    );

void
QuicListMoveItems(
    _In_ QUIC_LIST_ENTRY* Source,
    _Out_ QUIC_LIST_ENTRY* Destination
    );

void
QuicListPushEntry(
    _Inout_ QUIC_SINGLE_LIST_ENTRY* ListHead,
    _Inout_ __drv_aliasesMem QUIC_SINGLE_LIST_ENTRY* Entry
    );

QUIC_SINGLE_LIST_ENTRY*
QuicListPopEntry(
    _Inout_ QUIC_SINGLE_LIST_ENTRY* ListHead
    );

LONG
InterlockedIncrement(
    _Inout_ _Interlocked_operand_ LONG volatile *Addend
    );

LONG
InterlockedDecrement(
    _Inout_ _Interlocked_operand_ LONG volatile *Addend
    );

LONG64
InterlockedExchangeAdd64(
    _Inout_ _Interlocked_operand_ LONG64 volatile *Addend,
    _In_ LONG64 Value
    );

SHORT
InterlockedCompareExchange16(
    _Inout_ _Interlocked_operand_ SHORT volatile *Destination,
    _In_ SHORT ExChange,
    _In_ SHORT Comperand
    );

SHORT
InterlockedIncrement16(
    _Inout_ _Interlocked_operand_ SHORT volatile *Addend
    );

SHORT
InterlockedDecrement16(
    _Inout_ _Interlocked_operand_ SHORT volatile *Addend
    );

LONG64
InterlockedIncrement64(
    _Inout_ _Interlocked_operand_ LONG64 volatile *Addend
    );

uint32_t
QuicHashtableGetTotalEntryCount(
    _In_ const QUIC_HASHTABLE* Table
    );

_Must_inspect_result_
_Success_(return != 0)
BOOLEAN
QuicHashtableInitializeEx(
    _Inout_ QUIC_HASHTABLE* HashTable,
    _In_ uint32_t InitialSize
    );

uint32_t
QuicHashSimple(
    _In_ uint16_t Length,
    _In_reads_(Length) const uint8_t* Buffer
    );

uint64_t
QuicTimeDiff64(
    _In_ uint64_t T1,
    _In_ uint64_t T2
    );

uint32_t
QuicTimeDiff32(
    _In_ uint32_t T1,
    _In_ uint32_t T2
    );

BOOLEAN
QuicTimeAtOrBefore64(
    _In_ uint64_t T1,
    _In_ uint64_t T2
    );

BOOLEAN
QuicTimeAtOrBefore32(
    _In_ uint32_t T1,
    _In_ uint32_t T2
    );
