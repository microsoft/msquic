/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file contains helpers for using MsQuic.

Environment:

    user mode or kernel mode

--*/

#ifndef _MSQUICHELPER_
#define _MSQUICHELPER_

#if _MSC_VER > 1000
#pragma once
#endif

#include <msquic.h>
#include <msquicp.h>
#include <stdio.h>
#include <stdlib.h>

#define ALPN_HTTP_OVER_QUIC_D23 "hq-23"
#define ALPN_HTTP_OVER_QUIC     ALPN_HTTP_OVER_QUIC_D23

//
// Converts the QUIC Status Code to a string for console output.
//
inline
_Null_terminated_
const char*
QuicStatusToString(
    _In_ QUIC_STATUS Status
    )
{
    switch (Status) {
    case QUIC_STATUS_SUCCESS:                   return "SUCCESS";
    case QUIC_STATUS_OUT_OF_MEMORY:             return "OUT_OF_MEMORY";
    case QUIC_STATUS_INVALID_PARAMETER:         return "INVALID_PARAMETER";
    case QUIC_STATUS_INVALID_STATE:             return "INVALID_STATE";
    case QUIC_STATUS_NOT_SUPPORTED:             return "NOT_SUPPORTED";
    case QUIC_STATUS_NOT_FOUND:                 return "NOT_FOUND";
    case QUIC_STATUS_BUFFER_TOO_SMALL:          return "BUFFER_TOO_SMALL";
    case QUIC_STATUS_HANDSHAKE_FAILURE:         return "HANDSHAKE_FAILURE";
    case QUIC_STATUS_ABORTED:                   return "ABORTED";
    case QUIC_STATUS_ADDRESS_IN_USE:            return "ADDRESS_IN_USE";
    case QUIC_STATUS_CONNECTION_TIMEOUT:        return "CONNECTION_TIMEOUT";
    case QUIC_STATUS_CONNECTION_IDLE:           return "CONNECTION_IDLE";
    case QUIC_STATUS_UNREACHABLE:               return "UNREACHABLE";
    case QUIC_STATUS_INTERNAL_ERROR:            return "INTERNAL_ERROR";
    case QUIC_STATUS_SERVER_BUSY:               return "SERVER_BUSY";
    case QUIC_STATUS_PROTOCOL_ERROR:            return "PROTOCOL_ERROR";
    case QUIC_STATUS_VER_NEG_ERROR:             return "VER_NEG_ERROR";
    }

    return "UNKNOWN";
}

//
// Helper function to get the RTT (in microseconds) from a MsQuic Connection or Stream handle.
//
inline
uint32_t
GetConnRtt(
    _In_ const QUIC_API_V1* MsQuic,
    _In_ HQUIC Handle
    )
{
    QUIC_STATISTICS Value;
    uint32_t ValueSize = sizeof(Value);
    MsQuic->GetParam(
        Handle,
        QUIC_PARAM_LEVEL_CONNECTION,
        QUIC_PARAM_CONN_STATISTICS,
        &ValueSize,
        &Value);
    return Value.Rtt;
}

//
// Helper function to get the Stream ID from a MsQuic Stream handle.
//
inline
uint64_t
GetStreamID(
    _In_ const QUIC_API_V1* MsQuic,
    _In_ HQUIC Handle
    )
{
    uint64_t ID = (uint32_t)(-1);
    uint32_t IDLen = sizeof(ID);
    MsQuic->GetParam(
        Handle,
        QUIC_PARAM_LEVEL_STREAM,
        QUIC_PARAM_STREAM_ID,
        &IDLen,
        &ID);
    return ID;
}

//
// Helper function to get the remote IP address (as a string) from a MsQuic
// Connection or Stream handle.
//
inline
QUIC_ADDR_STR
GetRemoteAddr(
    _In_ const QUIC_API_V1* MsQuic,
    _In_ HQUIC Handle
    )
{
    QUIC_ADDR addr;
    uint32_t addrLen = sizeof(addr);
    QUIC_ADDR_STR addrStr = { 0 };
    QUIC_STATUS status =
        MsQuic->GetParam(
            Handle,
            QUIC_PARAM_LEVEL_CONNECTION,
            QUIC_PARAM_CONN_REMOTE_ADDRESS,
            &addrLen,
            &addr);
    if (QUIC_SUCCEEDED(status)) {
        QuicAddrToString(&addr, &addrStr);
    }
    return addrStr;
}

inline
QUIC_STATUS
QuicForceRetry(
    _In_ const QUIC_API_V1* MsQuic,
    _In_ HQUIC Handle,
    _In_ BOOLEAN Enabled
    )
{
    uint16_t value = Enabled ? 0 : 65;
    return
        MsQuic->SetParam(
            Handle,
            QUIC_PARAM_LEVEL_REGISTRATION,
            QUIC_PARAM_REGISTRATION_RETRY_MEMORY_PERCENT,
            sizeof(value),
            &value);
}

//
// Converts an input command line arg string and port to a socket address.
// Supports IPv4, IPv6 or '*' input strings.
//
inline
BOOLEAN
ConvertArgToAddress(
    _In_z_ const char* Arg,
    _In_ uint16_t Port,   // Host Byte Order
    _Out_ QUIC_ADDR* Address
    )
{
    if (strcmp("*", Arg) == 0) {
        QuicAddrSetFamily(Address, AF_UNSPEC);
        QuicAddrSetPort(Address, Port);
        return TRUE;
    }
    return QuicAddrFromString(Arg, Port, Address);
}

inline uint8_t DecodeHexChar(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    return 0;
}

inline
uint32_t
DecodeHexBuffer(
    _In_z_ const char* HexBuffer,
    _In_ uint32_t OutBufferLen,
    _Out_writes_to_(OutBufferLen, return)
        uint8_t* OutBuffer
    )
{
    uint32_t HexBufferLen = (uint32_t)strlen(HexBuffer) / 2;
    if (HexBufferLen > OutBufferLen) {
        return 0;
    }

    for (uint32_t i = 0; i < HexBufferLen; i++) {
        OutBuffer[i] =
            (DecodeHexChar(HexBuffer[i * 2]) << 4) |
            DecodeHexChar(HexBuffer[i * 2 + 1]);
    }

    return HexBufferLen;
}

//
// Helper function to take a hex encoded byte string for the resumption state.
//
inline
BOOLEAN
SetResumptionState(
    _In_ const QUIC_API_V1* MsQuic,
    _In_ HQUIC Handle,
    _In_z_ const char* SerializedState
    )
{
    uint8_t State[2048];
    uint32_t StateLen =
        DecodeHexBuffer(SerializedState, sizeof(State), State);

    if (StateLen == 0) {
        return FALSE;
    }

    return
        QUIC_SUCCEEDED(
            MsQuic->SetParam(
                Handle,
                QUIC_PARAM_LEVEL_SESSION,
                QUIC_PARAM_SESSION_ADD_RESUMPTION_STATE,
                StateLen,
                State));
}

#if defined(__cplusplus)

#ifdef _WIN32

inline
QUIC_SEC_CONFIG*
GetNullSecConfig(
    _In_ const QUIC_API_V1* MsQuic,
    _In_ HQUIC Registration
    )
{
    struct CreateSecConfigHelper {
        HANDLE Complete;
        QUIC_STATUS Status;
        QUIC_SEC_CONFIG* SecurityConfig;

        _Function_class_(QUIC_SEC_CONFIG_CREATE_COMPLETE)
        static void
        QUIC_API
        GetSecConfigComplete(
            _In_opt_ void* Context,
            _In_ QUIC_STATUS Status,
            _In_opt_ QUIC_SEC_CONFIG* SecurityConfig
            )
        {
            _Analysis_assume_(Context);
            CreateSecConfigHelper* HelperContext = (CreateSecConfigHelper*)Context;
            HelperContext->Status = Status;
            HelperContext->SecurityConfig = SecurityConfig;
            SetEvent(HelperContext->Complete);
        }
    };

    CreateSecConfigHelper HelperContext = { CreateEvent(NULL, FALSE, FALSE, NULL), 0, NULL };
    if (HelperContext.Complete == NULL) {
        return FALSE;
    }
    if (QUIC_SUCCEEDED(
        MsQuic->SecConfigCreate(
            Registration,
            QUIC_SEC_CONFIG_FLAG_CERTIFICATE_NULL,
            nullptr,
            nullptr,
            &HelperContext,
            CreateSecConfigHelper::GetSecConfigComplete))) {
        WaitForSingleObject(HelperContext.Complete, INFINITE);
    }
    CloseHandle(HelperContext.Complete);
    return HelperContext.SecurityConfig;
}

inline
QUIC_SEC_CONFIG*
GetSecConfigForCertContext(
    _In_ const QUIC_API_V1* MsQuic,
    _In_ HQUIC Registration,
    _In_ void* CertContext
    )
{
    struct CreateSecConfigHelper {
        HANDLE Complete;
        QUIC_STATUS Status;
        QUIC_SEC_CONFIG* SecurityConfig;

        _Function_class_(QUIC_SEC_CONFIG_CREATE_COMPLETE)
        static void
        QUIC_API
        GetSecConfigComplete(
            _In_opt_ void* Context,
            _In_ QUIC_STATUS Status,
            _In_opt_ QUIC_SEC_CONFIG* SecurityConfig
            )
        {
            _Analysis_assume_(Context);
            CreateSecConfigHelper* HelperContext = (CreateSecConfigHelper*)Context;
            HelperContext->Status = Status;
            HelperContext->SecurityConfig = SecurityConfig;
            SetEvent(HelperContext->Complete);
        }
    };

    CreateSecConfigHelper HelperContext = { CreateEvent(NULL, FALSE, FALSE, NULL), 0, NULL };
    if (HelperContext.Complete == NULL) {
        return FALSE;
    }
    if (QUIC_SUCCEEDED(
        MsQuic->SecConfigCreate(
            Registration,
            QUIC_SEC_CONFIG_FLAG_CERTIFICATE_CONTEXT,
            CertContext,
            nullptr,
            &HelperContext,
            CreateSecConfigHelper::GetSecConfigComplete))) {
        WaitForSingleObject(HelperContext.Complete, INFINITE);
    }
    CloseHandle(HelperContext.Complete);
    return HelperContext.SecurityConfig;
}

inline
QUIC_SEC_CONFIG*
GetSecConfigForSNI(
    _In_ const QUIC_API_V1* MsQuic,
    _In_ HQUIC Registration,
    _In_z_ const char* ServerName
    )
{
    struct CreateSecConfigHelper {
        HANDLE Complete;
        QUIC_STATUS Status;
        QUIC_SEC_CONFIG* SecurityConfig;

        _Function_class_(QUIC_SEC_CONFIG_CREATE_COMPLETE)
        static void
        QUIC_API
        GetSecConfigComplete(
            _In_opt_ void* Context,
            _In_ QUIC_STATUS Status,
            _In_opt_ QUIC_SEC_CONFIG* SecurityConfig
            )
        {
            _Analysis_assume_(Context);
            CreateSecConfigHelper* HelperContext = (CreateSecConfigHelper*)Context;
            HelperContext->Status = Status;
            HelperContext->SecurityConfig = SecurityConfig;
            SetEvent(HelperContext->Complete);
        }
    };

    CreateSecConfigHelper HelperContext = { CreateEvent(NULL, FALSE, FALSE, NULL), 0, NULL };
    if (HelperContext.Complete == NULL) {
        return FALSE;
    }
    if (QUIC_SUCCEEDED(
        MsQuic->SecConfigCreate(
            Registration,
            QUIC_SEC_CONFIG_FLAG_NONE,
            nullptr,
            ServerName,
            &HelperContext,
            CreateSecConfigHelper::GetSecConfigComplete))) {
        WaitForSingleObject(HelperContext.Complete, INFINITE);
    }
    CloseHandle(HelperContext.Complete);
    return HelperContext.SecurityConfig;
}

inline
QUIC_SEC_CONFIG*
GetSecConfigForThumbprint(
    _In_ const QUIC_API_V1* MsQuic,
    _In_ HQUIC Registration,
    _In_z_ const char* Thumbprint
    )
{
    struct CreateSecConfigHelper {
        HANDLE Complete;
        QUIC_STATUS Status;
        QUIC_SEC_CONFIG* SecurityConfig;

        _Function_class_(QUIC_SEC_CONFIG_CREATE_COMPLETE)
        static void
        QUIC_API
        GetSecConfigComplete(
            _In_opt_ void* Context,
            _In_ QUIC_STATUS Status,
            _In_opt_ QUIC_SEC_CONFIG* SecurityConfig
            )
        {
            _Analysis_assume_(Context);
            CreateSecConfigHelper* HelperContext = (CreateSecConfigHelper*)Context;
            HelperContext->Status = Status;
            HelperContext->SecurityConfig = SecurityConfig;
            SetEvent(HelperContext->Complete);
        }
    };

    QUIC_CERTIFICATE_HASH CertHash;
    uint32_t CertHashLen =
        DecodeHexBuffer(
            Thumbprint,
            sizeof(CertHash.ShaHash),
            CertHash.ShaHash);
    if (CertHashLen != sizeof(CertHash.ShaHash)) {
        return FALSE;
    }

    CreateSecConfigHelper HelperContext = { CreateEvent(NULL, FALSE, FALSE, NULL), 0, NULL };
    if (HelperContext.Complete == NULL) {
        return FALSE;
    }
    if (QUIC_SUCCEEDED(
        MsQuic->SecConfigCreate(
            Registration,
            QUIC_SEC_CONFIG_FLAG_CERTIFICATE_HASH,
            &CertHash,
            nullptr,
            &HelperContext,
            CreateSecConfigHelper::GetSecConfigComplete))) {
        WaitForSingleObject(HelperContext.Complete, INFINITE);
    }
    CloseHandle(HelperContext.Complete);
    return HelperContext.SecurityConfig;
}

#endif // _WIN32

//
// Arg Value Parsers
//

//
// Helper function that searches the list of args for a given
// parameter name, insensitive to case.
//
inline
_Ret_maybenull_ _Null_terminated_ const char*
GetValue(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_z_ const char* name
    )
{
    const size_t nameLen = strlen(name);
    for (int i = 1; i < argc; i++) {
        if (_strnicmp(argv[i] + 1, name, nameLen) == 0) {
            return argv[i] + 1 + nameLen + 1;
        }
    }
    return nullptr;
}

inline
_Success_(return != false)
bool
TryGetValue(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_z_ const char* name,
    _Out_ _Null_terminated_ const char** pValue
    )
{
    auto value = GetValue(argc, argv, name);
    if (!value) return false;
    *pValue = value;
    return true;
}

inline
_Success_(return != false)
bool
TryGetValue(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_z_ const char* name,
    _Out_ uint8_t* pValue
    )
{
    auto value = GetValue(argc, argv, name);
    if (!value) return false;
    *pValue = (uint8_t)atoi(value);
    return true;
}

inline
_Success_(return != false)
bool
TryGetValue(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_z_ const char* name,
    _Out_ uint16_t* pValue
    )
{
    auto value = GetValue(argc, argv, name);
    if (!value) return false;
    *pValue = (uint16_t)atoi(value);
    return true;
}

inline
_Success_(return != false)
bool
TryGetValue(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_z_ const char* name,
    _Out_ uint32_t* pValue
    )
{
    auto value = GetValue(argc, argv, name);
    if (!value) return false;
    *pValue = (uint32_t)atoi(value);
    return true;
}

inline
_Success_(return != false)
bool
TryGetValue(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_z_ const char* name,
    _Out_ uint64_t* pValue
    )
{
    auto value = GetValue(argc, argv, name);
    if (!value) return false;
    char* End;
#ifdef _WIN32
    *pValue = _strtoui64(value, &End, 10);
#else
    *pValue = strtoull(value, &End, 10);
#endif
    return true;
}

#endif

#endif // _MSQUICHELPER_
