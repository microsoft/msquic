/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file contains the platform specific definitions for MsQuic structures
    and error codes.

Environment:

    Windows Kernel mode

--*/

#pragma once

#ifndef _MSQUIC_WINKERNEL_
#define _MSQUIC_WINKERNEL_

#include <ws2def.h>
#include <ws2ipdef.h>
#include <minwindef.h>
#include <ntstatus.h>
#include <basetsd.h>

typedef INT8 int8_t;
typedef INT16 int16_t;
typedef INT32 int32_t;
typedef INT64 int64_t;

typedef UINT8 uint8_t;
typedef UINT16 uint16_t;
typedef UINT32 uint32_t;
typedef UINT64 uint64_t;

#define UINT8_MAX   0xffui8
#define UINT16_MAX  0xffffui16
#define UINT32_MAX  0xffffffffui32
#define UINT64_MAX  0xffffffffffffffffui64

#ifndef STATUS_QUIC_HANDSHAKE_FAILURE
#define STATUS_QUIC_HANDSHAKE_FAILURE    ((NTSTATUS)0xC0240000L)
#endif

#ifndef STATUS_QUIC_VER_NEG_FAILURE
#define STATUS_QUIC_VER_NEG_FAILURE      ((NTSTATUS)0xC0240001L)
#endif

#ifndef STATUS_QUIC_USER_CANCELED
#define STATUS_QUIC_USER_CANCELED        ((NTSTATUS)0xC0240002L)
#endif

#ifndef STATUS_QUIC_INTERNAL_ERROR
#define STATUS_QUIC_INTERNAL_ERROR       ((NTSTATUS)0xC0240003L)
#endif

#ifndef STATUS_QUIC_PROTOCOL_VIOLATION
#define STATUS_QUIC_PROTOCOL_VIOLATION   ((NTSTATUS)0xC0240004L)
#endif

#ifndef STATUS_QUIC_CONNECTION_IDLE
#define STATUS_QUIC_CONNECTION_IDLE      ((NTSTATUS)0xC0240005L)
#endif

#ifndef STATUS_QUIC_CONNECTION_TIMEOUT
#define STATUS_QUIC_CONNECTION_TIMEOUT   ((NTSTATUS)0xC0240006L)
#endif

#ifndef STATUS_QUIC_ALPN_NEG_FAILURE
#define STATUS_QUIC_ALPN_NEG_FAILURE     ((NTSTATUS)0xC0240007L)
#endif

#define QUIC_API                        NTAPI
#define QUIC_STATUS                     NTSTATUS
#define QUIC_FAILED(X)                  (!NT_SUCCESS(X))
#define QUIC_SUCCEEDED(X)               NT_SUCCESS(X)

#define QUIC_STATUS_SUCCESS             STATUS_SUCCESS
#define QUIC_STATUS_PENDING             STATUS_PENDING
#define QUIC_STATUS_CONTINUE            STATUS_REPARSE
#define QUIC_STATUS_OUT_OF_MEMORY       STATUS_NO_MEMORY
#define QUIC_STATUS_INVALID_PARAMETER   STATUS_INVALID_PARAMETER
#define QUIC_STATUS_INVALID_STATE       STATUS_INVALID_DEVICE_STATE
#define QUIC_STATUS_NOT_SUPPORTED       STATUS_NOT_SUPPORTED
#define QUIC_STATUS_NOT_FOUND           STATUS_NOT_FOUND
#define QUIC_STATUS_BUFFER_TOO_SMALL    STATUS_BUFFER_TOO_SMALL
#define QUIC_STATUS_HANDSHAKE_FAILURE   STATUS_QUIC_HANDSHAKE_FAILURE
#define QUIC_STATUS_ABORTED             STATUS_CANCELLED
#define QUIC_STATUS_ADDRESS_IN_USE      STATUS_ADDRESS_ALREADY_EXISTS
#define QUIC_STATUS_CONNECTION_TIMEOUT  STATUS_QUIC_CONNECTION_TIMEOUT
#define QUIC_STATUS_CONNECTION_IDLE     STATUS_QUIC_CONNECTION_IDLE
#define QUIC_STATUS_UNREACHABLE         STATUS_HOST_UNREACHABLE
#define QUIC_STATUS_INTERNAL_ERROR      STATUS_QUIC_INTERNAL_ERROR
#define QUIC_STATUS_CONNECTION_REFUSED  STATUS_CONNECTION_REFUSED
#define QUIC_STATUS_PROTOCOL_ERROR      STATUS_QUIC_PROTOCOL_VIOLATION
#define QUIC_STATUS_VER_NEG_ERROR       STATUS_QUIC_VER_NEG_FAILURE
#define QUIC_STATUS_USER_CANCELED       STATUS_QUIC_USER_CANCELED
#define QUIC_STATUS_ALPN_NEG_FAILURE    STATUS_QUIC_ALPN_NEG_FAILURE

//
// Swaps byte orders between host and network endianness.
//
#ifdef RtlUshortByteSwap
#define QuicNetByteSwapShort(x) RtlUshortByteSwap(x)
#else
#define QuicNetByteSwapShort(x) ((uint16_t)((((x) & 0x00ff) << 8) | (((x) & 0xff00) >> 8)))
#endif

//
// IP Address Abstraction Helpers
//

typedef ADDRESS_FAMILY QUIC_ADDRESS_FAMILY;
typedef SOCKADDR_INET QUIC_ADDR;

#define QUIC_ADDR_V4_PORT_OFFSET        FIELD_OFFSET(SOCKADDR_IN, sin_port)
#define QUIC_ADDR_V4_IP_OFFSET          FIELD_OFFSET(SOCKADDR_IN, sin_addr)

#define QUIC_ADDR_V6_PORT_OFFSET        FIELD_OFFSET(SOCKADDR_IN6, sin6_port)
#define QUIC_ADDR_V6_IP_OFFSET          FIELD_OFFSET(SOCKADDR_IN6, sin6_addr)

inline
BOOLEAN
QuicAddrIsValid(
    _In_ const QUIC_ADDR * const Addr
    )
{
    return
        Addr->si_family == AF_UNSPEC ||
        Addr->si_family == AF_INET ||
        Addr->si_family == AF_INET6;
}

inline
BOOLEAN
QuicAddrCompareIp(
    _In_ const QUIC_ADDR * const Addr1,
    _In_ const QUIC_ADDR * const Addr2
    )
{
    if (Addr1->si_family == AF_INET) {
        return memcmp(&Addr1->Ipv4.sin_addr, &Addr2->Ipv4.sin_addr, sizeof(IN_ADDR)) == 0;
    } else {
        return memcmp(&Addr1->Ipv6.sin6_addr, &Addr2->Ipv6.sin6_addr, sizeof(IN6_ADDR)) == 0;
    }
}

inline
BOOLEAN
QuicAddrCompare(
    _In_ const QUIC_ADDR * const Addr1,
    _In_ const QUIC_ADDR * const Addr2
    )
{
    if (Addr1->si_family != Addr2->si_family ||
        Addr1->Ipv4.sin_port != Addr2->Ipv4.sin_port) {
        return FALSE;
    }
    return QuicAddrCompareIp(Addr1, Addr2);
}

inline
BOOLEAN
QuicAddrIsWildCard(
    _In_ const QUIC_ADDR * const Addr
    )
{
    if (Addr->si_family == AF_UNSPEC) {
        return TRUE;
    } else if (Addr->si_family == AF_INET) {
        const IN_ADDR ZeroAddr = {0};
        return memcmp(&Addr->Ipv4.sin_addr, &ZeroAddr, sizeof(IN_ADDR)) == 0;
    } else {
        const IN6_ADDR ZeroAddr = {0};
        return memcmp(&Addr->Ipv6.sin6_addr, &ZeroAddr, sizeof(IN6_ADDR)) == 0;
    }
}

inline
uint16_t
QuicAddrGetFamily(
    _In_ const QUIC_ADDR * const Addr
    )
{
    return Addr->si_family;
}

inline
void
QuicAddrSetFamily(
    _Inout_ QUIC_ADDR * Addr,
    _In_ uint16_t Family
    )
{
    Addr->si_family = Family;
}

inline
uint16_t // Returns in host byte order.
QuicAddrGetPort(
    _In_ const QUIC_ADDR * const Addr
    )
{
    return QuicNetByteSwapShort(Addr->Ipv4.sin_port);
}

inline
void
QuicAddrSetPort(
    _Inout_ QUIC_ADDR * Addr,
    _In_ uint16_t Port // Host byte order
    )
{
    Addr->Ipv4.sin_port = QuicNetByteSwapShort(Port);
}

inline
BOOLEAN
QuicAddrIsBoundExplicitly(
    _In_ const QUIC_ADDR * const Addr
    )
{
    //
    // Scope ID of zero indicates we are sending from a connected binding.
    //
    return Addr->Ipv6.sin6_scope_id == 0;
}

inline
void
QuicAddrSetToLoopback(
    _Inout_ QUIC_ADDR * Addr
    )
{
    if (Addr->si_family == AF_INET) {
        Addr->Ipv4.sin_addr.S_un.S_un_b.s_b1 = 127;
        Addr->Ipv4.sin_addr.S_un.S_un_b.s_b4 = 1;
    } else {
        Addr->Ipv6.sin6_addr.u.Byte[15] = 1;
    }
}

//
// Test only API to increment the IP address value.
//
inline
void
QuicAddrIncrement(
    _Inout_ QUIC_ADDR * Addr
    )
{
    if (Addr->si_family == AF_INET) {
        Addr->Ipv4.sin_addr.S_un.S_un_b.s_b4++;
    } else {
        Addr->Ipv6.sin6_addr.u.Byte[15]++;
    }
}

inline
uint32_t
QuicAddrHash(
    _In_ const QUIC_ADDR * Addr
    )
{
    uint32_t Hash = 5387; // A random prime number.
#define UPDATE_HASH(byte) Hash = ((Hash << 5) - Hash) + (byte)
    if (Addr->si_family == AF_INET) {
        UPDATE_HASH(Addr->Ipv4.sin_port & 0xFF);
        UPDATE_HASH(Addr->Ipv4.sin_port >> 8);
        for (uint8_t i = 0; i < sizeof(Addr->Ipv4.sin_addr); ++i) {
            UPDATE_HASH(((uint8_t*)&Addr->Ipv4.sin_addr)[i]);
        }
    } else {
        UPDATE_HASH(Addr->Ipv6.sin6_port & 0xFF);
        UPDATE_HASH(Addr->Ipv6.sin6_port >> 8);
        for (uint8_t i = 0; i < sizeof(Addr->Ipv6.sin6_addr); ++i) {
            UPDATE_HASH(((uint8_t*)&Addr->Ipv6.sin6_addr)[i]);
        }
    }
    return Hash;
}

#define QUIC_LOCALHOST_FOR_AF(Af) "localhost"

inline
BOOLEAN
QuicAddrFromString(
    _In_z_ const char* AddrStr,
    _In_ uint16_t Port, // Host byte order
    _Out_ QUIC_ADDR* Addr
    )
{
    Addr->Ipv4.sin_port = QuicNetByteSwapShort(Port);
    if (RtlIpv4StringToAddressExA(AddrStr, FALSE, &Addr->Ipv4.sin_addr, &Addr->Ipv4.sin_port) == STATUS_SUCCESS) {
        Addr->si_family = AF_INET;
    } else if (RtlIpv6StringToAddressExA(AddrStr, &Addr->Ipv6.sin6_addr, &Addr->Ipv6.sin6_scope_id, &Addr->Ipv6.sin6_port) == STATUS_SUCCESS) {
        Addr->si_family = AF_INET6;
    } else {
        return FALSE;
    }
    return TRUE;
}

//
// Represents an IP address and (optionally) port number as a string.
//
typedef struct QUIC_ADDR_STR {
    char Address[64];
} QUIC_ADDR_STR;

inline
BOOLEAN
QuicAddrToString(
    _In_ const QUIC_ADDR* Addr,
    _Out_ QUIC_ADDR_STR* AddrStr
    )
{
    LONG Status;
    ULONG AddrStrLen = ARRAYSIZE(AddrStr->Address);
    if (Addr->si_family == AF_INET) {
        Status =
            RtlIpv4AddressToStringExA(
                &Addr->Ipv4.sin_addr,
                Addr->Ipv4.sin_port,
                AddrStr->Address,
                &AddrStrLen);
    } else {
        Status =
            RtlIpv6AddressToStringExA(
                &Addr->Ipv6.sin6_addr,
                0,
                Addr->Ipv6.sin6_port,
                AddrStr->Address,
                &AddrStrLen);
    }
    return Status == STATUS_SUCCESS;
}

#endif // _MSQUIC_WINKERNEL_
