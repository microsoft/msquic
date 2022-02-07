/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file contains helpers for using MsQuic.

Environment:

    user mode or kernel mode

--*/

#pragma once

#include "quic_platform.h"
#include "msquic.h"
#include "msquicp.h"
#include <stdio.h>
#include <stdlib.h>

typedef struct QUIC_CREDENTIAL_CONFIG_HELPER {
    QUIC_CREDENTIAL_CONFIG CredConfig;
    union {
        QUIC_CERTIFICATE_HASH CertHash;
        QUIC_CERTIFICATE_HASH_STORE CertHashStore;
        QUIC_CERTIFICATE_FILE CertFile;
    };
} QUIC_CREDENTIAL_CONFIG_HELPER;

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
    case QUIC_STATUS_PENDING:                   return "PENDING";
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
    case QUIC_STATUS_CONNECTION_REFUSED:        return "CONNECTION_REFUSED";
    case QUIC_STATUS_PROTOCOL_ERROR:            return "PROTOCOL_ERROR";
    case QUIC_STATUS_VER_NEG_ERROR:             return "VER_NEG_ERROR";
    case QUIC_STATUS_USER_CANCELED:             return "USER_CANCELED";
    case QUIC_STATUS_ALPN_NEG_FAILURE:          return "ALPN_NEG_FAILURE";
    case QUIC_STATUS_STREAM_LIMIT_REACHED:      return "STREAM_LIMIT_REACHED";
    }

    return "UNKNOWN";
}

//
// Helper function to get the RTT (in microseconds) from a MsQuic Connection or Stream handle.
//
inline
uint32_t
GetConnRtt(
    _In_ const QUIC_API_TABLE* MsQuicTable,
    _In_ HQUIC Handle
    )
{
    QUIC_STATISTICS Value;
    uint32_t ValueSize = sizeof(Value);
    MsQuicTable->GetParam(
        Handle,
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
    _In_ const QUIC_API_TABLE* MsQuicTable,
    _In_ HQUIC Handle
    )
{
    uint64_t ID = (uint32_t)(-1);
    uint32_t IDLen = sizeof(ID);
    MsQuicTable->GetParam(
        Handle,
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
    _In_ const QUIC_API_TABLE* MsQuicTable,
    _In_ HQUIC Handle
    )
{
    QUIC_ADDR addr;
    uint32_t addrLen = sizeof(addr);
    QUIC_ADDR_STR addrStr = { 0 };
    QUIC_STATUS status =
        MsQuicTable->GetParam(
            Handle,
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
    _In_ const QUIC_API_TABLE* MsQuicTable,
    _In_ BOOLEAN Enabled
    )
{
    uint16_t value = Enabled ? 0 : 65;
    return
        MsQuicTable->SetParam(
            NULL,
            QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT,
            sizeof(value),
            &value);
}

inline
void
DumpMsQuicPerfCounters(
    _In_ const QUIC_API_TABLE* MsQuicTable
    )
{
    uint64_t Counters[QUIC_PERF_COUNTER_MAX] = {0};
    uint32_t Lenth = sizeof(Counters);
    MsQuicTable->GetParam(
        NULL,
        QUIC_PARAM_GLOBAL_PERF_COUNTERS,
        &Lenth,
        &Counters);
    printf("Perf Counters:\n");
    printf("  CONN_CREATED:          %llu\n", (unsigned long long)Counters[QUIC_PERF_COUNTER_CONN_CREATED]);
    printf("  CONN_HANDSHAKE_FAIL:   %llu\n", (unsigned long long)Counters[QUIC_PERF_COUNTER_CONN_HANDSHAKE_FAIL]);
    printf("  CONN_APP_REJECT:       %llu\n", (unsigned long long)Counters[QUIC_PERF_COUNTER_CONN_APP_REJECT]);
    printf("  CONN_ACTIVE:           %llu\n", (unsigned long long)Counters[QUIC_PERF_COUNTER_CONN_ACTIVE]);
    printf("  CONN_CONNECTED:        %llu\n", (unsigned long long)Counters[QUIC_PERF_COUNTER_CONN_CONNECTED]);
    printf("  CONN_PROTOCOL_ERRORS:  %llu\n", (unsigned long long)Counters[QUIC_PERF_COUNTER_CONN_PROTOCOL_ERRORS]);
    printf("  CONN_NO_ALPN:          %llu\n", (unsigned long long)Counters[QUIC_PERF_COUNTER_CONN_NO_ALPN]);
    printf("  STRM_ACTIVE:           %llu\n", (unsigned long long)Counters[QUIC_PERF_COUNTER_STRM_ACTIVE]);
    printf("  PKTS_SUSPECTED_LOST:   %llu\n", (unsigned long long)Counters[QUIC_PERF_COUNTER_PKTS_SUSPECTED_LOST]);
    printf("  PKTS_DROPPED:          %llu\n", (unsigned long long)Counters[QUIC_PERF_COUNTER_PKTS_DROPPED]);
    printf("  PKTS_DECRYPTION_FAIL:  %llu\n", (unsigned long long)Counters[QUIC_PERF_COUNTER_PKTS_DECRYPTION_FAIL]);
    printf("  UDP_RECV:              %llu\n", (unsigned long long)Counters[QUIC_PERF_COUNTER_UDP_RECV]);
    printf("  UDP_SEND:              %llu\n", (unsigned long long)Counters[QUIC_PERF_COUNTER_UDP_SEND]);
    printf("  UDP_RECV_BYTES:        %llu\n", (unsigned long long)Counters[QUIC_PERF_COUNTER_UDP_RECV_BYTES]);
    printf("  UDP_SEND_BYTES:        %llu\n", (unsigned long long)Counters[QUIC_PERF_COUNTER_UDP_SEND_BYTES]);
    printf("  UDP_RECV_EVENTS:       %llu\n", (unsigned long long)Counters[QUIC_PERF_COUNTER_UDP_RECV_EVENTS]);
    printf("  UDP_SEND_CALLS:        %llu\n", (unsigned long long)Counters[QUIC_PERF_COUNTER_UDP_SEND_CALLS]);
    printf("  APP_SEND_BYTES:        %llu\n", (unsigned long long)Counters[QUIC_PERF_COUNTER_APP_SEND_BYTES]);
    printf("  APP_RECV_BYTES:        %llu\n", (unsigned long long)Counters[QUIC_PERF_COUNTER_APP_RECV_BYTES]);
    printf("  CONN_QUEUE_DEPTH:      %llu\n", (unsigned long long)Counters[QUIC_PERF_COUNTER_CONN_QUEUE_DEPTH]);
    printf("  CONN_OPER_QUEUE_DEPTH: %llu\n", (unsigned long long)Counters[QUIC_PERF_COUNTER_CONN_OPER_QUEUE_DEPTH]);
    printf("  CONN_OPER_QUEUED:      %llu\n", (unsigned long long)Counters[QUIC_PERF_COUNTER_CONN_OPER_QUEUED]);
    printf("  CONN_OPER_COMPLETED:   %llu\n", (unsigned long long)Counters[QUIC_PERF_COUNTER_CONN_OPER_COMPLETED]);
    printf("  WORK_OPER_QUEUE_DEPTH: %llu\n", (unsigned long long)Counters[QUIC_PERF_COUNTER_WORK_OPER_QUEUE_DEPTH]);
    printf("  WORK_OPER_QUEUED:      %llu\n", (unsigned long long)Counters[QUIC_PERF_COUNTER_WORK_OPER_QUEUED]);
    printf("  WORK_OPER_COMPLETED:   %llu\n", (unsigned long long)Counters[QUIC_PERF_COUNTER_WORK_OPER_COMPLETED]);
    printf("  PATH_VALIDATED:        %llu\n", (unsigned long long)Counters[QUIC_PERF_COUNTER_PATH_VALIDATED]);
    printf("  PATH_FAILURE:          %llu\n", (unsigned long long)Counters[QUIC_PERF_COUNTER_PATH_FAILURE]);
    printf("  SEND_STATELESS_RESET:  %llu\n", (unsigned long long)Counters[QUIC_PERF_COUNTER_SEND_STATELESS_RESET]);
    printf("  SEND_STATELESS_RETRY:  %llu\n", (unsigned long long)Counters[QUIC_PERF_COUNTER_SEND_STATELESS_RETRY]);
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
        //
        // Explicitly zero, otherwise kernel mode errors
        //
        CxPlatZeroMemory(Address, sizeof(*Address));
        QuicAddrSetFamily(Address, QUIC_ADDRESS_FAMILY_UNSPEC);
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

inline
void
EncodeHexBuffer(
    _In_reads_(BufferLen) uint8_t* Buffer,
    _In_ uint8_t BufferLen,
    _Out_writes_bytes_(2*BufferLen) char* HexString
    )
{
    #define HEX_TO_CHAR(x) ((x) > 9 ? ('a' + ((x) - 10)) : '0' + (x))
    for (uint8_t i = 0; i < BufferLen; i++) {
        HexString[i*2]     = HEX_TO_CHAR(Buffer[i] >> 4);
        HexString[i*2 + 1] = HEX_TO_CHAR(Buffer[i] & 0xf);
    }
}

#if defined(__cplusplus)

//
// Arg Value Parsers
//

inline
bool
IsArg(
    _In_z_ const char* Arg,
    _In_z_ const char* toTestAgainst
    )
{
    return Arg[0] && (_strnicmp(Arg + 1, toTestAgainst, strlen(toTestAgainst)) == 0);
}

inline
bool
IsValue(
    _In_z_ const char* name,
    _In_z_ const char* toTestAgainst
    )
{
    return _strnicmp(name, toTestAgainst, CXPLAT_MIN(strlen(name), strlen(toTestAgainst))) == 0;
}

inline
bool
GetFlag(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_z_ const char* name
    )
{
    const size_t nameLen = strlen(name);
    for (int i = 0; i < argc; i++) {
        if (_strnicmp(argv[i] + 1, name, nameLen) == 0
            && strlen(argv[i]) == nameLen + 1) {
            return true;
        }
    }
    return false;
}

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
    for (int i = 0; i < argc; i++) {
        if (_strnicmp(argv[i] + 1, name, nameLen) == 0
            && strlen(argv[i]) > 1 + nameLen + 1
            && *(argv[i] + 1 + nameLen) == ':') {
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
    char* End;
#ifdef _WIN32
    *pValue = (uint32_t)_strtoui64(value, &End, 10);
#else
    *pValue = (uint32_t)strtoull(value, &End, 10);
#endif
    return true;
}

inline
_Success_(return != false)
bool
TryGetValue(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_z_ const char* name,
    _Out_ int32_t* pValue
    )
{
    auto value = GetValue(argc, argv, name);
    if (!value) return false;
    *pValue = (int32_t)atoi(value);
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

inline
_Success_(return != false)
HQUIC
GetServerConfigurationFromArgs(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_ const QUIC_API_TABLE* MsQuicTable,
    _In_ HQUIC Registration,
    _In_reads_(AlpnBufferCount) _Pre_defensive_
        const QUIC_BUFFER* const AlpnBuffers,
    _In_range_(>, 0) uint32_t AlpnBufferCount,
    _In_reads_bytes_opt_(SettingsSize)
        const QUIC_SETTINGS* Settings,
    _In_ uint32_t SettingsSize
    )
{
    QUIC_CREDENTIAL_CONFIG_HELPER Helper;
    CxPlatZeroMemory(&Helper, sizeof(Helper));
    const QUIC_CREDENTIAL_CONFIG* Config = &Helper.CredConfig;
    Helper.CredConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;

    const char* Cert;
    const char* KeyFile;

    if (((Cert = GetValue(argc, argv, "thumbprint")) != nullptr) ||
        ((Cert = GetValue(argc, argv, "cert_hash")) != nullptr) ||
        ((Cert = GetValue(argc, argv, "hash")) != nullptr)) {
        uint32_t CertHashLen =
            DecodeHexBuffer(
                Cert,
                sizeof(Helper.CertHashStore.ShaHash),
                Helper.CertHashStore.ShaHash);
        if (CertHashLen != sizeof(Helper.CertHashStore.ShaHash)) {
            return nullptr;
        }
        Helper.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE;
        Helper.CredConfig.CertificateHashStore = &Helper.CertHashStore;
        memcpy(Helper.CertHashStore.StoreName, "My", sizeof("My"));
        Helper.CertHashStore.Flags =
            GetValue(argc, argv, "machine") ?
                QUIC_CERTIFICATE_HASH_STORE_FLAG_MACHINE_STORE :
                QUIC_CERTIFICATE_HASH_STORE_FLAG_NONE;

    } else if (
        (((Cert = GetValue(argc, argv, "file")) != nullptr) &&
         ((KeyFile = GetValue(argc, argv, "key")) != nullptr)) ||
        (((Cert = GetValue(argc, argv, "cert_file")) != nullptr) &&
         ((KeyFile = GetValue(argc, argv, "cert_key")) != nullptr))) {
        Helper.CertFile.CertificateFile = (char*)Cert;
        Helper.CertFile.PrivateKeyFile = (char*)KeyFile;
        Helper.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
        Helper.CredConfig.CertificateFile = &Helper.CertFile;

#ifdef QUIC_TEST_APIS
    } else if (GetValue(argc, argv, "selfsign")) {
        Config = CxPlatGetSelfSignedCert(CXPLAT_SELF_SIGN_CERT_USER, FALSE);
        if (!Config) {
            return nullptr;
        }
#endif

    } else {
        return nullptr;
    }

#ifdef QUIC_TEST_APIS
    void* Context = (Config != &Helper.CredConfig) ? (void*)Config : nullptr;
#else
    void* Context = nullptr;
#endif

    HQUIC Configuration = nullptr;
    if (QUIC_SUCCEEDED(
        MsQuicTable->ConfigurationOpen(
            Registration,
            AlpnBuffers,
            AlpnBufferCount,
            Settings,
            SettingsSize,
            Context,
            &Configuration)) &&
        QUIC_FAILED(
        MsQuicTable->ConfigurationLoadCredential(
            Configuration,
            Config))) {
        MsQuicTable->ConfigurationClose(Configuration);
        Configuration = nullptr;
    }

#ifdef QUIC_TEST_APIS
    if (!Configuration && Config != &Helper.CredConfig) {
        CxPlatFreeSelfSignedCert(Config);
    }
#endif

    return Configuration;
}

inline
void
FreeServerConfiguration(
    _In_ const QUIC_API_TABLE* MsQuicTable,
    _In_ HQUIC Configuration
    )
{
#ifdef QUIC_TEST_APIS
    auto SelfSignedConfig = (const QUIC_CREDENTIAL_CONFIG*)MsQuicTable->GetContext(Configuration);
    if (SelfSignedConfig) {
        CxPlatFreeSelfSignedCert(SelfSignedConfig);
    }
#endif
    MsQuicTable->ConfigurationClose(Configuration);
}

inline
void
WriteSslKeyLogFile(
    _In_z_ const char* FileName,
    _In_ QUIC_TLS_SECRETS& TlsSecrets
    )
{
    FILE* File = nullptr;
#ifdef _WIN32
    if (fopen_s(&File, FileName, "ab")) {
        printf("Failed to open sslkeylogfile %s\n", FileName);
        return;
    }
#else
    File = fopen(FileName, "ab");
#endif

    if (File == nullptr) {
        printf("Failed to open sslkeylogfile %s\n", FileName);
        return;
    }
    if (fseek(File, 0, SEEK_END) == 0 && ftell(File) == 0) {
        fprintf(File, "# TLS 1.3 secrets log file, generated by quicinterop\n");
    }
    char ClientRandomBuffer[(2 * sizeof(QUIC_TLS_SECRETS::ClientRandom)) + 1] = {0};
    char TempHexBuffer[(2 * QUIC_TLS_SECRETS_MAX_SECRET_LEN) + 1] = {0};
    if (TlsSecrets.IsSet.ClientRandom) {
        EncodeHexBuffer(
            TlsSecrets.ClientRandom,
            (uint8_t)sizeof(TlsSecrets.ClientRandom),
            ClientRandomBuffer);
    }

    if (TlsSecrets.IsSet.ClientEarlyTrafficSecret) {
        EncodeHexBuffer(
            TlsSecrets.ClientEarlyTrafficSecret,
            TlsSecrets.SecretLength,
            TempHexBuffer);
        fprintf(
            File,
            "CLIENT_EARLY_TRAFFIC_SECRET %s %s\n",
            ClientRandomBuffer,
            TempHexBuffer);
    }

    if (TlsSecrets.IsSet.ClientHandshakeTrafficSecret) {
        EncodeHexBuffer(
            TlsSecrets.ClientHandshakeTrafficSecret,
            TlsSecrets.SecretLength,
            TempHexBuffer);
        fprintf(
            File,
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET %s %s\n",
            ClientRandomBuffer,
            TempHexBuffer);
    }

    if (TlsSecrets.IsSet.ServerHandshakeTrafficSecret) {
        EncodeHexBuffer(
            TlsSecrets.ServerHandshakeTrafficSecret,
            TlsSecrets.SecretLength,
            TempHexBuffer);
        fprintf(
            File,
            "SERVER_HANDSHAKE_TRAFFIC_SECRET %s %s\n",
            ClientRandomBuffer,
            TempHexBuffer);
    }

    if (TlsSecrets.IsSet.ClientTrafficSecret0) {
        EncodeHexBuffer(
            TlsSecrets.ClientTrafficSecret0,
            TlsSecrets.SecretLength,
            TempHexBuffer);
        fprintf(
            File,
            "CLIENT_TRAFFIC_SECRET_0 %s %s\n",
            ClientRandomBuffer,
            TempHexBuffer);
    }

    if (TlsSecrets.IsSet.ServerTrafficSecret0) {
        EncodeHexBuffer(
            TlsSecrets.ServerTrafficSecret0,
            TlsSecrets.SecretLength,
            TempHexBuffer);
        fprintf(
            File,
            "SERVER_TRAFFIC_SECRET_0 %s %s\n",
            ClientRandomBuffer,
            TempHexBuffer);
    }

    fflush(File);
    fclose(File);
}

#endif // defined(__cplusplus)
