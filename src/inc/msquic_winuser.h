/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file contains the platform specific definitions for MsQuic structures
    and error codes.

Environment:

    Windows User mode

--*/

#pragma once

#ifndef _MSQUIC_WINUSER_
#define _MSQUIC_WINUSER_

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <ws2def.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <stdint.h>

#define SUCCESS_HRESULT_FROM_WIN32(x) \
    ((HRESULT)(((x) & 0x0000FFFF) | (FACILITY_WIN32 << 16)))

#ifndef ERROR_QUIC_HANDSHAKE_FAILURE
#define ERROR_QUIC_HANDSHAKE_FAILURE    _HRESULT_TYPEDEF_(0x80410000L)
#endif

#ifndef ERROR_QUIC_VER_NEG_FAILURE
#define ERROR_QUIC_VER_NEG_FAILURE      _HRESULT_TYPEDEF_(0x80410001L)
#endif

#ifndef ERROR_QUIC_USER_CANCELED
#define ERROR_QUIC_USER_CANCELED        _HRESULT_TYPEDEF_(0x80410002L)
#endif

#ifndef ERROR_QUIC_INTERNAL_ERROR
#define ERROR_QUIC_INTERNAL_ERROR       _HRESULT_TYPEDEF_(0x80410003L)
#endif

#ifndef ERROR_QUIC_PROTOCOL_VIOLATION
#define ERROR_QUIC_PROTOCOL_VIOLATION   _HRESULT_TYPEDEF_(0x80410004L)
#endif

#ifndef ERROR_QUIC_CONNECTION_IDLE
#define ERROR_QUIC_CONNECTION_IDLE      _HRESULT_TYPEDEF_(0x80410005L)
#endif

#ifndef ERROR_QUIC_CONNECTION_TIMEOUT
#define ERROR_QUIC_CONNECTION_TIMEOUT   _HRESULT_TYPEDEF_(0x80410006L)
#endif

#ifndef ERROR_QUIC_ALPN_NEG_FAILURE
#define ERROR_QUIC_ALPN_NEG_FAILURE     _HRESULT_TYPEDEF_(0x80410007L)
#endif

#define QUIC_API                        __cdecl
#define QUIC_MAIN_EXPORT                __cdecl
#define QUIC_STATUS                     HRESULT
#define QUIC_FAILED(X)                  FAILED(X)
#define QUIC_SUCCEEDED(X)               SUCCEEDED(X)

#define QUIC_STATUS_SUCCESS             S_OK
#define QUIC_STATUS_PENDING             SUCCESS_HRESULT_FROM_WIN32(ERROR_IO_PENDING)
#define QUIC_STATUS_CONTINUE            SUCCESS_HRESULT_FROM_WIN32(ERROR_CONTINUE)
#define QUIC_STATUS_OUT_OF_MEMORY       E_OUTOFMEMORY
#define QUIC_STATUS_INVALID_PARAMETER   E_INVALIDARG
#define QUIC_STATUS_INVALID_STATE       E_NOT_VALID_STATE
#define QUIC_STATUS_NOT_SUPPORTED       E_NOINTERFACE
#define QUIC_STATUS_NOT_FOUND           HRESULT_FROM_WIN32(ERROR_NOT_FOUND)
#define QUIC_STATUS_BUFFER_TOO_SMALL    E_NOT_SUFFICIENT_BUFFER
#define QUIC_STATUS_HANDSHAKE_FAILURE   ERROR_QUIC_HANDSHAKE_FAILURE
#define QUIC_STATUS_ABORTED             E_ABORT
#define QUIC_STATUS_ADDRESS_IN_USE      HRESULT_FROM_WIN32(WSAEADDRINUSE)
#define QUIC_STATUS_CONNECTION_TIMEOUT  ERROR_QUIC_CONNECTION_TIMEOUT
#define QUIC_STATUS_CONNECTION_IDLE     ERROR_QUIC_CONNECTION_IDLE
#define QUIC_STATUS_UNREACHABLE         HRESULT_FROM_WIN32(ERROR_HOST_UNREACHABLE)
#define QUIC_STATUS_INTERNAL_ERROR      ERROR_QUIC_INTERNAL_ERROR
#define QUIC_STATUS_CONNECTION_REFUSED  HRESULT_FROM_WIN32(ERROR_CONNECTION_REFUSED)
#define QUIC_STATUS_PROTOCOL_ERROR      ERROR_QUIC_PROTOCOL_VIOLATION
#define QUIC_STATUS_VER_NEG_ERROR       ERROR_QUIC_VER_NEG_FAILURE
#define QUIC_STATUS_TLS_ERROR           HRESULT_FROM_WIN32(WSA_SECURE_HOST_NOT_FOUND)
#define QUIC_STATUS_USER_CANCELED       ERROR_QUIC_USER_CANCELED
#define QUIC_STATUS_ALPN_NEG_FAILURE    ERROR_QUIC_ALPN_NEG_FAILURE

//
// Swaps byte orders between host and network endianness.
//
#ifdef htons
#define QuicNetByteSwapShort(x) htons(x)
#else
#define QuicNetByteSwapShort(x) ((uint16_t)((((x) & 0x00ff) << 8) | (((x) & 0xff00) >> 8)))
#endif

//
// IP Address Abstraction Helpers
//

typedef enum QUIC_ADDRESS_FAMILY {
    QUIC_ADDRESS_FAMILY_UNSPEC = AF_UNSPEC,
    QUIC_ADDRESS_FAMILY_INET = AF_INET,
    QUIC_ADDRESS_FAMILY_INET6 = AF_INET6
} QUIC_ADDRESS_FAMILY;

typedef struct _QUIC_ADDR {
    QUIC_ADDRESS_FAMILY Family;
    uint16_t Port;
    uint32_t ScopeId;
    union {
        uint8_t Ipv4Addr[4];
        uint8_t Ipv6Addr[16];
    };
} QUIC_ADDR;

#define QUIC_ADDR_V4_PORT_OFFSET        FIELD_OFFSET(QUIC_ADDR, Port)
#define QUIC_ADDR_V4_IP_OFFSET          FIELD_OFFSET(QUIC_ADDR, Ipv4Addr)

#define QUIC_ADDR_V6_PORT_OFFSET        FIELD_OFFSET(QUIC_ADDR, Port)
#define QUIC_ADDR_V6_IP_OFFSET          FIELD_OFFSET(QUIC_ADDR, Ipv6Addr)

inline
BOOLEAN
QuicAddrIsValid(
    _In_ const QUIC_ADDR * const Addr
    )
{
    return
        Addr->Family == QUIC_ADDRESS_FAMILY_UNSPEC ||
        Addr->Family == QUIC_ADDRESS_FAMILY_INET ||
        Addr->Family == QUIC_ADDRESS_FAMILY_INET6;
}

inline
BOOLEAN
QuicAddrCompareIp(
    _In_ const QUIC_ADDR * const Addr1,
    _In_ const QUIC_ADDR * const Addr2
    )
{
    if (Addr1->Family == QUIC_ADDRESS_FAMILY_INET) {
        return memcmp(&Addr1->Ipv4Addr, &Addr2->Ipv4Addr, sizeof(Addr1->Ipv4Addr)) == 0;
    } else {
        return memcmp(&Addr1->Ipv6Addr, &Addr2->Ipv6Addr, sizeof(Addr1->Ipv6Addr)) == 0;
    }
}

inline
BOOLEAN
QuicAddrCompare(
    _In_ const QUIC_ADDR * const Addr1,
    _In_ const QUIC_ADDR * const Addr2
    )
{
    if (Addr1->Family != Addr2->Family ||
        Addr1->Port != Addr2->Port) {
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
    if (Addr->Family == QUIC_ADDRESS_FAMILY_UNSPEC) {
        return TRUE;
    } else if (Addr->Family == QUIC_ADDRESS_FAMILY_INET) {
        const uint8_t Zeros[4];
        QuicZeroMemory(&Zeros, sizeof(Zeros));
        return memcmp(&Addr->Ipv4Addr, &Zeros, sizeof(Zeros)) == 0;
    } else {
        const uint8_t Zeros[16];
        QuicZeroMemory(&Zeros, sizeof(Zeros));
        return memcmp(&Addr->Ipv6Addr, &Zeros, sizeof(Zeros)) == 0;
    }
}

inline
QUIC_ADDRESS_FAMILY
QuicAddrGetFamily(
    _In_ const QUIC_ADDR * const Addr
    )
{
    return (QUIC_ADDRESS_FAMILY)Addr->Family;
}

inline
void
QuicAddrSetFamily(
    _Inout_ QUIC_ADDR * Addr,
    _In_ QUIC_ADDRESS_FAMILY Family
    )
{
    Addr->Family = (ADDRESS_FAMILY)Family;
}

inline
uint16_t // Returns in host byte order.
QuicAddrGetPort(
    _In_ const QUIC_ADDR * const Addr
    )
{
    return QuicNetByteSwapShort(Addr->Port);
}

inline
void
QuicAddrSetPort(
    _Out_ QUIC_ADDR * Addr,
    _In_ uint16_t Port // Host byte order
    )
{
    Addr->Port = QuicNetByteSwapShort(Port);
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
    return Addr->ScopeId == 0;
}

inline
void
QuicAddrSetToLoopback(
    _Inout_ QUIC_ADDR * Addr
    )
{
    if (Addr->Family == QUIC_ADDRESS_FAMILY_UNSPEC) {
        Addr->Ipv4Addr[0] = 127;
        Addr->Ipv4Addr[3] = 1;
    } else {
        Addr->Ipv6Addr[15] = 1;
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
    if (Addr->Family == QUIC_ADDRESS_FAMILY_INET) {
        Addr->Ipv4Addr[3]++;
    } else {
        Addr->Ipv6Addr[15]++;
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
    if (Addr->Family == QUIC_ADDRESS_FAMILY_INET) {
        UPDATE_HASH(Addr->Port & 0xFF);
        UPDATE_HASH(Addr->Port >> 8);
        for (uint8_t i = 0; i < sizeof(Addr->Ipv4Addr); ++i) {
            UPDATE_HASH(Addr->Ipv4Addr[i]);
        }
    } else {
        UPDATE_HASH(Addr->Port & 0xFF);
        UPDATE_HASH(Addr->Port >> 8);
        for (uint8_t i = 0; i < sizeof(Addr->Ipv6Addr); ++i) {
            UPDATE_HASH(Addr->Ipv6Addr[i]);
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
    Addr->Port = QuicNetByteSwapShort(Port);
    struct in_addr ipv4In;
    struct in6_addr ipv6In;
    if (RtlIpv4StringToAddressExA(AddrStr, FALSE, &ipv4In, &Addr->Port) == NO_ERROR) {
        QuicCopyMemory(&Addr->Ipv4Addr, &ipv4In.S_un.S_addr, sizeof(ipv4In.S_un.S_addr));
        Addr->Family = QUIC_ADDRESS_FAMILY_INET;
    } else if (RtlIpv6StringToAddressExA(AddrStr, &ipv6In, &Addr->ScopeId, &Addr->Port) == NO_ERROR) {
        QuicCopyMemory(&Addr->Ipv6Addr, &ipv6In.u.Byte, sizeof(Addr->Ipv6Addr));
        Addr->Family = QUIC_ADDRESS_FAMILY_INET6;
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
    if (Addr->Family == QUIC_ADDRESS_FAMILY_INET) {
        struct in_addr ipv4In;
        QuicCopyMemory(&ipv4In.S_un.S_addr, &Addr->Ipv4Addr, sizeof(ipv4In.S_un.S_addr));
        Status =
            RtlIpv4AddressToStringExA(
                &ipv4In,
                Addr->Port,
                AddrStr->Address,
                &AddrStrLen);
    } else {
        struct in6_addr ipv6In;
        QuicCopyMemory(&ipv6In.u.Byte, &Addr->Ipv6Addr, sizeof(Addr->Ipv6Addr));
        Status =
            RtlIpv6AddressToStringExA(
                &ipv6In,
                0,
                Addr->Port,
                AddrStr->Address,
                &AddrStrLen);
    }
    return Status == NO_ERROR;
}

#endif // _MSQUIC_WINUSER_
