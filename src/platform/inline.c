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
QuicHashtableInitializeEx(
    _Inout_ QUIC_HASHTABLE* HashTable,
    _In_ uint32_t InitialSize
    );

uint32_t
QuicHashSimple(
    _In_ uint16_t Length,
    _In_reads_(Length) const uint8_t* Buffer
    );

uint16_t
QuicHashLength(
    QUIC_HASH_TYPE Type
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
