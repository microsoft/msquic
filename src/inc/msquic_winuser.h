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

#pragma warning(push)
#pragma warning(disable:6553) // Annotation does not apply to value type.
#include <windows.h>
#pragma warning(pop)
#include <winsock2.h>
#include <ws2ipdef.h>
#pragma warning(push)
#pragma warning(disable:6385) // Invalid data: accessing [buffer-name], the readable size is size1 bytes but size2 bytes may be read
#pragma warning(disable:6101) // Returning uninitialized memory
#include <ws2tcpip.h>
#include <mstcpip.h>
#pragma warning(pop)

#include <stdint.h>

#define QUIC_INLINE inline

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

#ifndef ERROR_QUIC_STREAM_LIMIT_REACHED
#define ERROR_QUIC_STREAM_LIMIT_REACHED _HRESULT_TYPEDEF_(0x80410008L)
#endif

#ifndef ERROR_QUIC_ALPN_IN_USE
#define ERROR_QUIC_ALPN_IN_USE          _HRESULT_TYPEDEF_(0x80410009L)
#endif

#ifndef QUIC_TLS_ALERT_HRESULT_PREFIX
#define QUIC_TLS_ALERT_HRESULT_PREFIX   _HRESULT_TYPEDEF_(0x80410100L)
#endif

#define QUIC_API                            __cdecl
#define QUIC_MAIN_EXPORT                    __cdecl
#define QUIC_STATUS                         HRESULT
#define QUIC_FAILED(X)                      FAILED(X)
#define QUIC_SUCCEEDED(X)                   SUCCEEDED(X)

#define QUIC_STATUS_SUCCESS                 S_OK                                            // 0x0
#define QUIC_STATUS_PENDING                 SUCCESS_HRESULT_FROM_WIN32(ERROR_IO_PENDING)    // 0x703e5
#define QUIC_STATUS_CONTINUE                SUCCESS_HRESULT_FROM_WIN32(ERROR_CONTINUE)      // 0x704de
#define QUIC_STATUS_OUT_OF_MEMORY           E_OUTOFMEMORY                                   // 0x8007000e
#define QUIC_STATUS_INVALID_PARAMETER       E_INVALIDARG                                    // 0x80070057
#define QUIC_STATUS_INVALID_STATE           E_NOT_VALID_STATE                               // 0x8007139f
#define QUIC_STATUS_NOT_SUPPORTED           E_NOINTERFACE                                   // 0x80004002
#define QUIC_STATUS_NOT_FOUND               HRESULT_FROM_WIN32(ERROR_NOT_FOUND)             // 0x80070490
#define QUIC_STATUS_FILE_NOT_FOUND          HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)        // 0x80070002
#define QUIC_STATUS_BUFFER_TOO_SMALL        E_NOT_SUFFICIENT_BUFFER                         // 0x8007007a
#define QUIC_STATUS_HANDSHAKE_FAILURE       ERROR_QUIC_HANDSHAKE_FAILURE                    // 0x80410000
#define QUIC_STATUS_ABORTED                 E_ABORT                                         // 0x80004004
#define QUIC_STATUS_ADDRESS_IN_USE          HRESULT_FROM_WIN32(WSAEADDRINUSE)               // 0x80072740
#define QUIC_STATUS_INVALID_ADDRESS         HRESULT_FROM_WIN32(WSAEADDRNOTAVAIL)            // 0x80072741
#define QUIC_STATUS_CONNECTION_TIMEOUT      ERROR_QUIC_CONNECTION_TIMEOUT                   // 0x80410006
#define QUIC_STATUS_CONNECTION_IDLE         ERROR_QUIC_CONNECTION_IDLE                      // 0x80410005
#define QUIC_STATUS_UNREACHABLE             HRESULT_FROM_WIN32(ERROR_HOST_UNREACHABLE)      // 0x800704d0
#define QUIC_STATUS_INTERNAL_ERROR          ERROR_QUIC_INTERNAL_ERROR                       // 0x80410003
#define QUIC_STATUS_CONNECTION_REFUSED      HRESULT_FROM_WIN32(ERROR_CONNECTION_REFUSED)    // 0x800704c9
#define QUIC_STATUS_PROTOCOL_ERROR          ERROR_QUIC_PROTOCOL_VIOLATION                   // 0x80410004
#define QUIC_STATUS_VER_NEG_ERROR           ERROR_QUIC_VER_NEG_FAILURE                      // 0x80410001
#define QUIC_STATUS_TLS_ERROR               HRESULT_FROM_WIN32(WSA_SECURE_HOST_NOT_FOUND)   // 0x80072b18
#define QUIC_STATUS_USER_CANCELED           ERROR_QUIC_USER_CANCELED                        // 0x80410002
#define QUIC_STATUS_ALPN_NEG_FAILURE        ERROR_QUIC_ALPN_NEG_FAILURE                     // 0x80410007
#define QUIC_STATUS_STREAM_LIMIT_REACHED    ERROR_QUIC_STREAM_LIMIT_REACHED                 // 0x80410008
#define QUIC_STATUS_ALPN_IN_USE             ERROR_QUIC_ALPN_IN_USE                          // 0x80410009

#define QUIC_STATUS_TLS_ALERT(Alert)        (QUIC_TLS_ALERT_HRESULT_PREFIX | (0xff & Alert))

#define QUIC_STATUS_CLOSE_NOTIFY            QUIC_STATUS_TLS_ALERT(0)    // Close notify
#define QUIC_STATUS_BAD_CERTIFICATE         QUIC_STATUS_TLS_ALERT(42)   // Bad Certificate
#define QUIC_STATUS_UNSUPPORTED_CERTIFICATE QUIC_STATUS_TLS_ALERT(43)   // Unsupported Certficiate
#define QUIC_STATUS_REVOKED_CERTIFICATE     QUIC_STATUS_TLS_ALERT(44)   // Revoked Certificate
#define QUIC_STATUS_EXPIRED_CERTIFICATE     QUIC_STATUS_TLS_ALERT(45)   // Expired Certificate
#define QUIC_STATUS_UNKNOWN_CERTIFICATE     QUIC_STATUS_TLS_ALERT(46)   // Unknown Certificate
#define QUIC_STATUS_REQUIRED_CERTIFICATE    QUIC_STATUS_TLS_ALERT(116)  // Required Certificate

#define QUIC_STATUS_CERT_EXPIRED            CERT_E_EXPIRED
#define QUIC_STATUS_CERT_UNTRUSTED_ROOT     CERT_E_UNTRUSTEDROOT
#define QUIC_STATUS_CERT_NO_CERT            SEC_E_NO_CREDENTIALS

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

typedef ADDRESS_FAMILY QUIC_ADDRESS_FAMILY;
typedef SOCKADDR_INET QUIC_ADDR;

#define QUIC_ADDR_V4_PORT_OFFSET        FIELD_OFFSET(SOCKADDR_IN, sin_port)
#define QUIC_ADDR_V4_IP_OFFSET          FIELD_OFFSET(SOCKADDR_IN, sin_addr)

#define QUIC_ADDR_V6_PORT_OFFSET        FIELD_OFFSET(SOCKADDR_IN6, sin6_port)
#define QUIC_ADDR_V6_IP_OFFSET          FIELD_OFFSET(SOCKADDR_IN6, sin6_addr)

#define QUIC_ADDRESS_FAMILY_UNSPEC AF_UNSPEC
#define QUIC_ADDRESS_FAMILY_INET AF_INET
#define QUIC_ADDRESS_FAMILY_INET6 AF_INET6

QUIC_INLINE
BOOLEAN
QuicAddrIsValid(
    _In_ const QUIC_ADDR* const Addr
    )
{
    return
        Addr->si_family == QUIC_ADDRESS_FAMILY_UNSPEC ||
        Addr->si_family == QUIC_ADDRESS_FAMILY_INET ||
        Addr->si_family == QUIC_ADDRESS_FAMILY_INET6;
}

QUIC_INLINE
BOOLEAN
QuicAddrCompareIp(
    _In_ const QUIC_ADDR* const Addr1,
    _In_ const QUIC_ADDR* const Addr2
    )
{
    if (Addr1->si_family == QUIC_ADDRESS_FAMILY_INET) {
        return memcmp(&Addr1->Ipv4.sin_addr, &Addr2->Ipv4.sin_addr, sizeof(IN_ADDR)) == 0;
    } else {
        return memcmp(&Addr1->Ipv6.sin6_addr, &Addr2->Ipv6.sin6_addr, sizeof(IN6_ADDR)) == 0;
    }
}

QUIC_INLINE
BOOLEAN
QuicAddrCompare(
    _In_ const QUIC_ADDR* const Addr1,
    _In_ const QUIC_ADDR* const Addr2
    )
{
    if (Addr1->si_family != Addr2->si_family ||
        Addr1->Ipv4.sin_port != Addr2->Ipv4.sin_port) {
        return FALSE;
    }
    return QuicAddrCompareIp(Addr1, Addr2);
}

QUIC_INLINE
BOOLEAN
QuicAddrIsWildCard(
    _In_ const QUIC_ADDR* const Addr
    )
{
    if (Addr->si_family == QUIC_ADDRESS_FAMILY_UNSPEC) {
        return TRUE;
    } else if (Addr->si_family == QUIC_ADDRESS_FAMILY_INET) {
        const IN_ADDR ZeroAddr = {0};
        return memcmp(&Addr->Ipv4.sin_addr, &ZeroAddr, sizeof(IN_ADDR)) == 0;
    } else {
        const IN6_ADDR ZeroAddr = {0};
        return memcmp(&Addr->Ipv6.sin6_addr, &ZeroAddr, sizeof(IN6_ADDR)) == 0;
    }
}

QUIC_INLINE
QUIC_ADDRESS_FAMILY
QuicAddrGetFamily(
    _In_ const QUIC_ADDR* const Addr
    )
{
    return (QUIC_ADDRESS_FAMILY)Addr->si_family;
}

QUIC_INLINE
void
QuicAddrSetFamily(
    _Inout_ QUIC_ADDR* Addr,
    _In_ QUIC_ADDRESS_FAMILY Family
    )
{
    Addr->si_family = (ADDRESS_FAMILY)Family;
}

QUIC_INLINE
uint16_t // Returns in host byte order.
QuicAddrGetPort(
    _In_ const QUIC_ADDR* const Addr
    )
{
    return QuicNetByteSwapShort(Addr->Ipv4.sin_port);
}

QUIC_INLINE
void
QuicAddrSetPort(
    _Out_ QUIC_ADDR* Addr,
    _In_ uint16_t Port // Host byte order
    )
{
    Addr->Ipv4.sin_port = QuicNetByteSwapShort(Port);
}

QUIC_INLINE
void
QuicAddrSetToLoopback(
    _Inout_ QUIC_ADDR* Addr
    )
{
    if (Addr->si_family == QUIC_ADDRESS_FAMILY_INET) {
        Addr->Ipv4.sin_addr.s_addr = 0UL;
        Addr->Ipv4.sin_addr.S_un.S_un_b.s_b1 = 127;
        Addr->Ipv4.sin_addr.S_un.S_un_b.s_b4 = 1;
    } else {
        memset(&Addr->Ipv6.sin6_addr, 0, sizeof(Addr->Ipv6.sin6_addr));
        Addr->Ipv6.sin6_addr.u.Byte[15] = 1;
    }
}

//
// Test only API to increment the IP address value.
//
QUIC_INLINE
void
QuicAddrIncrement(
    _Inout_ QUIC_ADDR* Addr
    )
{
    if (Addr->si_family == QUIC_ADDRESS_FAMILY_INET) {
        Addr->Ipv4.sin_addr.S_un.S_un_b.s_b4++;
    } else {
        Addr->Ipv6.sin6_addr.u.Byte[15]++;
    }
}

QUIC_INLINE
uint32_t
QuicAddrHash(
    _In_ const QUIC_ADDR* Addr
    )
{
    uint32_t Hash = 5387; // A random prime number.
#define UPDATE_HASH(byte) Hash = ((Hash << 5) - Hash) + (byte)
    if (Addr->si_family == QUIC_ADDRESS_FAMILY_INET) {
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

//
// Rtl String API's are not allowed in gamecore
//
#if WINAPI_FAMILY != WINAPI_FAMILY_GAMES

QUIC_INLINE
_Success_(return != FALSE)
BOOLEAN
QuicAddrFromString(
    _In_z_ const char* AddrStr,
    _In_ uint16_t Port, // Host byte order
    _Out_ QUIC_ADDR* Addr
    )
{
    if (RtlIpv4StringToAddressExA(AddrStr, FALSE, &Addr->Ipv4.sin_addr, &Addr->Ipv4.sin_port) == NO_ERROR) {
        Addr->si_family = QUIC_ADDRESS_FAMILY_INET;
    } else if (RtlIpv6StringToAddressExA(AddrStr, &Addr->Ipv6.sin6_addr, &Addr->Ipv6.sin6_scope_id, &Addr->Ipv6.sin6_port) == NO_ERROR) {
        Addr->si_family = QUIC_ADDRESS_FAMILY_INET6;
    } else {
        return FALSE;
    }
    if (Addr->Ipv4.sin_port == 0) {
        Addr->Ipv4.sin_port = QuicNetByteSwapShort(Port);
    }
    return TRUE;
}

//
// Represents an IP address and (optionally) port number as a string.
//
typedef struct QUIC_ADDR_STR {
    char Address[64];
} QUIC_ADDR_STR;

QUIC_INLINE
_Success_(return != FALSE)
BOOLEAN
QuicAddrToString(
    _In_ const QUIC_ADDR* Addr,
    _Out_ QUIC_ADDR_STR* AddrStr
    )
{
    LONG Status;
    ULONG AddrStrLen = ARRAYSIZE(AddrStr->Address);
    if (Addr->si_family == QUIC_ADDRESS_FAMILY_INET) {
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
    return Status == NO_ERROR;
}

#endif // WINAPI_FAMILY != WINAPI_FAMILY_GAMES

//
// Event Queue Abstraction
//

typedef HANDLE QUIC_EVENTQ;

typedef OVERLAPPED_ENTRY QUIC_CQE;

typedef
_IRQL_requires_max_(PASSIVE_LEVEL)
void
(QUIC_EVENT_COMPLETION)(
    _In_ QUIC_CQE* Cqe
    );
typedef QUIC_EVENT_COMPLETION *QUIC_EVENT_COMPLETION_HANDLER;

typedef struct QUIC_SQE {
    OVERLAPPED Overlapped;
    QUIC_EVENT_COMPLETION_HANDLER Completion;
#if DEBUG
    BOOLEAN IsQueued; // Debug flag to catch double queueing.
#endif
} QUIC_SQE;

#endif // _MSQUIC_WINUSER_
