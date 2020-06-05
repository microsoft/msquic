/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file contains the platform specific definitions for MsQuic structures
    and error codes.

Environment:

    Linux

--*/

#pragma once

#ifndef _MSQUIC_LINUX_
#define _MSQUIC_LINUX_

#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>
#include <stddef.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <quic_sal_stub.h>

#ifdef __cplusplus
extern "C++" {
template <size_t S> struct _ENUM_FLAG_INTEGER_FOR_SIZE;
template <> struct _ENUM_FLAG_INTEGER_FOR_SIZE<1> {
    typedef uint8_t type;
};
template <> struct _ENUM_FLAG_INTEGER_FOR_SIZE<2> {
    typedef uint16_t type;
};
template <> struct _ENUM_FLAG_INTEGER_FOR_SIZE<4> {
    typedef uint32_t type;
};
template <> struct _ENUM_FLAG_INTEGER_FOR_SIZE<8> {
    typedef uint64_t type;
};

// used as an approximation of std::underlying_type<T>
template <class T> struct _ENUM_FLAG_SIZED_INTEGER
{
    typedef typename _ENUM_FLAG_INTEGER_FOR_SIZE<sizeof(T)>::type type;
};
}

#define DEFINE_ENUM_FLAG_OPERATORS(ENUMTYPE) \
extern "C++" { \
inline ENUMTYPE operator | (ENUMTYPE a, ENUMTYPE b) throw() { return ENUMTYPE(((_ENUM_FLAG_SIZED_INTEGER<ENUMTYPE>::type)a) | ((_ENUM_FLAG_SIZED_INTEGER<ENUMTYPE>::type)b)); } \
inline ENUMTYPE &operator |= (ENUMTYPE &a, ENUMTYPE b) throw() { return (ENUMTYPE &)(((_ENUM_FLAG_SIZED_INTEGER<ENUMTYPE>::type &)a) |= ((_ENUM_FLAG_SIZED_INTEGER<ENUMTYPE>::type)b)); } \
inline ENUMTYPE operator & (ENUMTYPE a, ENUMTYPE b) throw() { return ENUMTYPE(((_ENUM_FLAG_SIZED_INTEGER<ENUMTYPE>::type)a) & ((_ENUM_FLAG_SIZED_INTEGER<ENUMTYPE>::type)b)); } \
inline ENUMTYPE &operator &= (ENUMTYPE &a, ENUMTYPE b) throw() { return (ENUMTYPE &)(((_ENUM_FLAG_SIZED_INTEGER<ENUMTYPE>::type &)a) &= ((_ENUM_FLAG_SIZED_INTEGER<ENUMTYPE>::type)b)); } \
inline ENUMTYPE operator ~ (ENUMTYPE a) throw() { return ENUMTYPE(~((_ENUM_FLAG_SIZED_INTEGER<ENUMTYPE>::type)a)); } \
inline ENUMTYPE operator ^ (ENUMTYPE a, ENUMTYPE b) throw() { return ENUMTYPE(((_ENUM_FLAG_SIZED_INTEGER<ENUMTYPE>::type)a) ^ ((_ENUM_FLAG_SIZED_INTEGER<ENUMTYPE>::type)b)); } \
inline ENUMTYPE &operator ^= (ENUMTYPE &a, ENUMTYPE b) throw() { return (ENUMTYPE &)(((_ENUM_FLAG_SIZED_INTEGER<ENUMTYPE>::type &)a) ^= ((_ENUM_FLAG_SIZED_INTEGER<ENUMTYPE>::type)b)); } \
}
#else
#define DEFINE_ENUM_FLAG_OPERATORS(ENUMTYPE) // NOP, C allows these operators.
#endif

#define QUIC_API
#define QUIC_MAIN_EXPORT
#define QUIC_STATUS                     unsigned int
#define QUIC_FAILED(X)                  ((int)(X) > 0)
#define QUIC_SUCCEEDED(X)               ((int)(X) <= 0)

//
// The type of an error code generated by the system is mostly 'int'.
// In many situations, we use the value of a system-generated error code
// as the value of QUIC_STATUS.
// In some situations, we use a custom value for QUIC_STATUS.
// In order to ensure that custom values don't conflict with system-generated values,
// the custom values are all kept outside the range of any possible 'int' value.
// There are static asserts to ensure that QUIC_STATUS type is large enough for
// this purpose. Below, all "ERROR_*" names represent custom error codes.
// All "E*" (that are not "ERROR_*") names are system error codes.
//

#define NO_ERROR                         0
#define ERROR_SUCCESS                    0
#define ERROR_CONTINUE                   -1
#define ERROR_NOT_READY                  -2
#define ERROR_BASE                       200000000
#define ERROR_NOT_ENOUGH_MEMORY          1 + ERROR_BASE
#define ERROR_INVALID_STATE              2 + ERROR_BASE
#define ERROR_INVALID_PARAMETER          3 + ERROR_BASE
#define ERROR_NOT_SUPPORTED              4 + ERROR_BASE
#define ERROR_NOT_FOUND                  5 + ERROR_BASE
#define ERROR_BUFFER_OVERFLOW            6 + ERROR_BASE
#define ERROR_CONNECTION_REFUSED         7 + ERROR_BASE
#define ERROR_OPERATION_ABORTED          8 + ERROR_BASE
#define ERROR_CONNECTION_UNAVAIL         9 + ERROR_BASE
#define ERROR_NETWORK_UNREACHABLE        10 + ERROR_BASE
#define ERROR_CONNECTION_ABORTED         11 + ERROR_BASE
#define ERROR_INTERNAL_ERROR             12 + ERROR_BASE
#define ERROR_CONNECTION_INVALID         13 + ERROR_BASE
#define ERROR_VERSION_PARSE_ERROR        14 + ERROR_BASE
#define ERROR_EPOLL_ERROR                15 + ERROR_BASE
#define ERROR_DNS_RESOLUTION_ERROR       16 + ERROR_BASE
#define ERROR_SOCKET_ERROR               17 + ERROR_BASE
#define ERROR_SSL_ERROR                  18 + ERROR_BASE
#define ERROR_USER_CANCELED              19 + ERROR_BASE

#define QUIC_STATUS_SUCCESS             ((QUIC_STATUS)ERROR_SUCCESS)
#define QUIC_STATUS_PENDING             ((QUIC_STATUS)ERROR_NOT_READY)
#define QUIC_STATUS_CONTINUE            ((QUIC_STATUS)ERROR_CONTINUE)
#define QUIC_STATUS_OUT_OF_MEMORY       ((QUIC_STATUS)ENOMEM)
#define QUIC_STATUS_INVALID_PARAMETER   ((QUIC_STATUS)EINVAL)
#define QUIC_STATUS_INVALID_STATE       ((QUIC_STATUS)ERROR_INVALID_STATE)
#define QUIC_STATUS_NOT_SUPPORTED       ((QUIC_STATUS)EOPNOTSUPP)
#define QUIC_STATUS_NOT_FOUND           ((QUIC_STATUS)ENOENT)
#define QUIC_STATUS_BUFFER_TOO_SMALL    ((QUIC_STATUS)EOVERFLOW)
#define QUIC_STATUS_HANDSHAKE_FAILURE   ((QUIC_STATUS)ERROR_CONNECTION_UNAVAIL)
#define QUIC_STATUS_ABORTED             ((QUIC_STATUS)ERROR_OPERATION_ABORTED)
#define QUIC_STATUS_ADDRESS_IN_USE      ((QUIC_STATUS)EADDRINUSE)
#define QUIC_STATUS_CONNECTION_TIMEOUT  ((QUIC_STATUS)ETIMEDOUT)
#define QUIC_STATUS_CONNECTION_IDLE     ((QUIC_STATUS)ERROR_CONNECTION_ABORTED)
#define QUIC_STATUS_INTERNAL_ERROR      ((QUIC_STATUS)ERROR_INTERNAL_ERROR)
#define QUIC_STATUS_SERVER_BUSY         ((QUIC_STATUS)ERROR_CONNECTION_REFUSED)
#define QUIC_STATUS_PROTOCOL_ERROR      ((QUIC_STATUS)ERROR_CONNECTION_INVALID)
#define QUIC_STATUS_VER_NEG_ERROR       ((QUIC_STATUS)ERROR_VERSION_PARSE_ERROR)
#define QUIC_STATUS_UNREACHABLE         ((QUIC_STATUS)EHOSTUNREACH)
#define QUIC_STATUS_PERMISSION_DENIED   ((QUIC_STATUS)EPERM)
#define QUIC_STATUS_EPOLL_ERROR         ((QUIC_STATUS)ERROR_EPOLL_ERROR)
#define QUIC_STATUS_DNS_RESOLUTION_ERROR ((QUIC_STATUS)ERROR_DNS_RESOLUTION_ERROR)
#define QUIC_STATUS_SOCKET_ERROR        ((QUIC_STATUS)ERROR_SOCKET_ERROR)
#define QUIC_STATUS_TLS_ERROR           ((QUIC_STATUS)ERROR_SSL_ERROR)
#define QUIC_STATUS_USER_CANCELED       ((QUIC_STATUS)ERROR_USER_CANCELED)

typedef unsigned char BOOLEAN;
typedef struct in_addr IN_ADDR;
typedef struct in6_addr IN6_ADDR;
typedef struct addrinfo ADDRINFO;
typedef sa_family_t QUIC_ADDRESS_FAMILY;

typedef union QUIC_ADDR {
    struct sockaddr_in Ipv4;
    struct sockaddr_in6 Ipv6;
    sa_family_t si_family;
} QUIC_ADDR;

#define FIELD_OFFSET(type, field)       ((uint32_t)(size_t)&(((type *)0)->field))

#define QUIC_ADDR_V4_PORT_OFFSET        FIELD_OFFSET(struct sockaddr_in, sin_port)
#define QUIC_ADDR_V4_IP_OFFSET          FIELD_OFFSET(struct sockaddr_in, sin_addr)

#define QUIC_ADDR_V6_PORT_OFFSET        FIELD_OFFSET(struct sockaddr_in6, sin6_port)
#define QUIC_ADDR_V6_IP_OFFSET          FIELD_OFFSET(struct sockaddr_in6, sin6_addr)

#ifndef FALSE
#define FALSE 0
#define TRUE 1
#endif

#define INITCODE
#define PAGEDX
#define QUIC_CACHEALIGN

#if defined(__cplusplus)
extern "C" {
#endif

#define QUIC_LOCALHOST_FOR_AF(Af) ((Af == AF_INET) ? "localhost" : "ip6-localhost")

#define QUIC_CERTIFICATE_FLAG_IGNORE_REVOCATION                 0x00000080
#define QUIC_CERTIFICATE_FLAG_IGNORE_UNKNOWN_CA                 0x00000100
#define QUIC_CERTIFICATE_FLAG_IGNORE_WRONG_USAGE                0x00000200
#define QUIC_CERTIFICATE_FLAG_IGNORE_CERTIFICATE_CN_INVALID     0x00001000 // bad common name in X509 Cert.
#define QUIC_CERTIFICATE_FLAG_IGNORE_CERTIFICATE_DATE_INVALID   0x00002000 // expired X509 Cert.
#define QUIC_CERTIFICATE_FLAG_IGNORE_WEAK_SIGNATURE             0x00010000

//
// Hack to pass in a client trusted cert from APP layer to the TAL layer.
//

extern char *QuicOpenSslClientTrustedCert;


//
// IP Address Abstraction Helpers
//

inline
BOOLEAN
QuicAddrFamilyIsValid(
    _In_ QUIC_ADDRESS_FAMILY Family
    )
{
    return Family == AF_INET || Family == AF_INET6 || Family == AF_UNSPEC;
}

inline
BOOLEAN
QuicAddrIsValid(
    _In_ const QUIC_ADDR* const Addr
    )
{
    return QuicAddrFamilyIsValid(Addr->si_family);
}

inline
BOOLEAN
QuicAddrCompareIp(
    _In_ const QUIC_ADDR* const Addr1,
    _In_ const QUIC_ADDR* const Addr2
    )
{
    if (AF_INET == Addr1->si_family) {
        return memcmp(&Addr1->Ipv4.sin_addr, &Addr2->Ipv4.sin_addr, sizeof(IN_ADDR)) == 0;
    } else {
        return memcmp(&Addr1->Ipv6.sin6_addr, &Addr2->Ipv6.sin6_addr, sizeof(IN6_ADDR)) == 0;
    }
}

inline
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

    if (AF_INET == Addr1->si_family) {
        return memcmp(&Addr1->Ipv4.sin_addr, &Addr2->Ipv4.sin_addr, sizeof(IN_ADDR)) == 0;
    } else {
        return memcmp(&Addr1->Ipv6.sin6_addr, &Addr2->Ipv6.sin6_addr, sizeof(IN6_ADDR)) == 0;
    }
}

inline
uint16_t
QuicAddrGetFamily(
    _In_ const QUIC_ADDR* const Addr
    )
{
    return Addr->si_family;
}

inline
void
QuicAddrSetFamily(
    _In_ QUIC_ADDR* Addr,
    _In_ uint16_t Family
    )
{
    Addr->si_family = Family;
}

inline
uint16_t
QuicAddrGetPort(
    _In_ const QUIC_ADDR* const Addr
    )
{
    if (AF_INET == Addr->si_family) {
        return ntohs(Addr->Ipv4.sin_port);
    } else {
        return ntohs(Addr->Ipv6.sin6_port);
    }
}

inline
void
QuicAddrSetPort(
    _Out_ QUIC_ADDR* Addr,
    _In_ uint16_t Port
    )
{
    if (AF_INET == Addr->si_family) {
        Addr->Ipv4.sin_port = htons(Port);
    } else {
        Addr->Ipv6.sin6_port = htons(Port);
    }
}

inline
BOOLEAN
QuicAddrIsBoundExplicitly(
    _In_ const QUIC_ADDR* const Addr
    )
{
    // LINUX_TODO: How to handle IPv4? Windows just does the below.

    //
    // Scope ID of zero indicates we are sending from a connected binding.
    //

    return Addr->Ipv6.sin6_scope_id == 0;
}

inline
void
QuicAddrSetToLoopback(
    _Inout_ QUIC_ADDR* Addr
    )
{
    if (Addr->si_family == AF_INET) {
        Addr->Ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    } else {
        Addr->Ipv6.sin6_addr = in6addr_loopback;
    }
}

inline
uint32_t
QuicAddrHash(
    _In_ const QUIC_ADDR* Addr
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

inline
BOOLEAN
QuicAddrIsWildCard(
    _In_ const QUIC_ADDR* const Addr
    )
{
    if (Addr->si_family == AF_UNSPEC) {
        return TRUE;
    } else if (Addr->si_family == AF_INET) {
        const IN_ADDR ZeroAddr = {0};
        return memcmp(&Addr->Ipv4.sin_addr.s_addr, &ZeroAddr, sizeof(IN_ADDR)) == 0;
    } else {
        const IN6_ADDR ZeroAddr = {0};
        return memcmp(&Addr->Ipv6.sin6_addr, &ZeroAddr, sizeof(IN6_ADDR)) == 0;
    }
}

inline
BOOLEAN
QuicAddr4FromString(
    _In_z_ const char* AddrStr,
    _Out_ QUIC_ADDR* Addr
    )
{
    if (AddrStr[0] == '[') {
        return FALSE;
    }

    const char* PortStart = strchr(AddrStr, ':');
    if (PortStart != NULL) {
        if (strchr(PortStart+1, ':') != NULL) {
            return FALSE;
        }

        char TmpAddrStr[16];
        size_t AddrLength = PortStart - AddrStr;
        if (AddrLength >= sizeof(TmpAddrStr)) {
            return FALSE;
        }
        memcpy(TmpAddrStr, AddrStr, AddrLength);
        TmpAddrStr[AddrLength] = '\0';

        if (inet_pton(AF_INET, TmpAddrStr, &Addr->Ipv4.sin_addr) != 1) {
            return FALSE;
        }
        Addr->Ipv4.sin_port = htons(atoi(PortStart+1));
    } else {
        if (inet_pton(AF_INET, AddrStr, &Addr->Ipv4.sin_addr) != 1) {
            return FALSE;
        }
    }
    Addr->si_family = AF_INET;
    return TRUE;
}

inline
BOOLEAN
QuicAddr6FromString(
    _In_z_ const char* AddrStr,
    _Out_ QUIC_ADDR* Addr
    )
{
    if (AddrStr[0] == '[') {
        const char* BracketEnd = strchr(AddrStr, ']');
        if (BracketEnd == NULL || *(BracketEnd+1) != ':') {
            return FALSE;
        }
        
        char TmpAddrStr[64];
        size_t AddrLength = BracketEnd - AddrStr;
        if (AddrLength >= sizeof(TmpAddrStr)) {
            return FALSE;
        }
        memcpy(TmpAddrStr, AddrStr, AddrLength);
        TmpAddrStr[AddrLength] = '\0';

        if (inet_pton(AF_INET6, TmpAddrStr, &Addr->Ipv6.sin6_addr) != 1) {
            return FALSE;
        }
        Addr->Ipv6.sin6_port = htons(atoi(BracketEnd+2));
    } else {
        if (inet_pton(AF_INET6, AddrStr, &Addr->Ipv6.sin6_addr) != 1) {
            return FALSE;
        }
    }
    Addr->si_family = AF_INET6;
    return TRUE;
}

inline
BOOLEAN
QuicAddrFromString(
    _In_z_ const char* AddrStr,
    _In_ uint16_t Port, // Host byte order
    _Out_ QUIC_ADDR* Addr
    )
{
    Addr->Ipv4.sin_port = htons(Port);
    return
        QuicAddr4FromString(AddrStr, Addr) ||
        QuicAddr6FromString(AddrStr, Addr);
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
    char* Address = AddrStr->Address;
    if (Addr->si_family == AF_INET6 && Addr->Ipv6.sin6_port != 0) {
        Address[0] = '[';
        Address++;
    }
    if (inet_ntop(
            Addr->si_family,
            &Addr->Ipv4.sin_addr,
            Address,
            sizeof(QUIC_ADDR_STR)) != 0) {
        return FALSE;
    }
    if (Addr->Ipv4.sin_port != 0) {
        Address += strlen(Address);
        if (Addr->si_family == AF_INET6) {
            Address[0] = ']';
            Address++;
        }
        sprintf(Address, ":%hu", ntohs(Addr->Ipv4.sin_port));
    }
    return TRUE;
}

#if defined(__cplusplus)
}
#endif

#endif
