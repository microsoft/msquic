/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Implements the certificate functions by calling OpenSSL (via miPKI helper).

    NOTE - Currently out of date.

--*/

#include "platform_internal.h"
#ifdef QUIC_CLOG
#include "cert_openssl.c.clog.h"
#endif

#include <mitlsffi.h>
#include <mipki.h>

typedef mipki_state* (MITLS_CALLCONV *Fn_mipki_init)(const mipki_config_entry config[], size_t config_len, password_callback pcb, int *erridx);
typedef void (MITLS_CALLCONV *Fn_mipki_free)(mipki_state *st);
typedef int (MITLS_CALLCONV *Fn_mipki_add_root_file_or_path)(mipki_state *st, const char *ca_file);
typedef mipki_chain(MITLS_CALLCONV *Fn_mipki_select_certificate)(mipki_state *st, const char *sni, size_t sni_len, const mipki_signature *algs, size_t algs_len, mipki_signature *selected);
typedef int (MITLS_CALLCONV *Fn_mipki_sign_verify)(mipki_state *st, mipki_chain cert_ptr, const mipki_signature sigalg, const char *tbs, size_t tbs_len, char *sig, size_t *sig_len, mipki_mode m);
typedef mipki_chain(MITLS_CALLCONV *Fn_mipki_parse_chain)(mipki_state *st, const char *chain, size_t chain_len);
typedef size_t(MITLS_CALLCONV *Fn_mipki_format_chain)(mipki_state *st, mipki_chain chain, char *buffer, size_t buffer_len);
typedef int (MITLS_CALLCONV *Fn_mipki_validate_chain)(mipki_state *st, mipki_chain chain, const char *host);
typedef void (MITLS_CALLCONV *Fn_mipki_free_chain)(mipki_state *st, mipki_chain chain);

#define DECLARE_FUNC(Func) Fn_ ## Func Func

typedef struct QUIC_MIPKI_LIBRARY {

    HMODULE Libmipki;

    DECLARE_FUNC(mipki_init);
    DECLARE_FUNC(mipki_free);
    DECLARE_FUNC(mipki_add_root_file_or_path);
    DECLARE_FUNC(mipki_select_certificate);
    DECLARE_FUNC(mipki_sign_verify);
    DECLARE_FUNC(mipki_parse_chain);
    DECLARE_FUNC(mipki_format_chain);
    DECLARE_FUNC(mipki_validate_chain);
    DECLARE_FUNC(mipki_free_chain);

    QUIC_LOCK Lock;
    mipki_state *State;

} QUIC_MIPKI_LIBRARY;

QUIC_MIPKI_LIBRARY miPKI = { 0 };

static
inline
void
LogGetProcAddressFailure(
    _In_ const char* FuncName,
    _In_ DWORD Error
    )
{
    QuicTraceLogVerbose(
        CertOpenSslGetProcessAddressFailure,
        "[cert] GetProcAddress failed for %s, 0x%x",
        FuncName,
        Error);
}

QUIC_STATUS
QuicCertLibraryInitialize(
    void
    )
{
    QUIC_STATUS Status;

    if (miPKI.Libmipki) {
        Status = QUIC_STATUS_SUCCESS;
        goto Error;
    }

    //
    // First see if we can load the DLL.
    //
    miPKI.Libmipki = LoadLibrary("libmipki.dll");
    if (miPKI.Libmipki == NULL) {
        Status = GetLastError();
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "Failed to Load libmipki.dll");
        goto Error;
    }

#define GetFunc(Lib, Func) \
    miPKI.Func = (Fn_ ## Func)GetProcAddress(miPKI.Lib, #Func); \
    if (miPKI.Func == NULL) { \
        Status = GetLastError(); \
        LogGetProcAddressFailure(#Func, Status); \
        goto Error; \
    }

    //
    // Load the libmitls functions.
    //
    GetFunc(Libmipki, mipki_init);
    GetFunc(Libmipki, mipki_free);
    GetFunc(Libmipki, mipki_add_root_file_or_path);
    GetFunc(Libmipki, mipki_select_certificate);
    GetFunc(Libmipki, mipki_sign_verify);
    GetFunc(Libmipki, mipki_parse_chain);
    GetFunc(Libmipki, mipki_format_chain);
    GetFunc(Libmipki, mipki_validate_chain);
    GetFunc(Libmipki, mipki_free_chain);

    mipki_config_entry pki_config = {
        .cert_file = "server.crt",
        .key_file = "server.key",
        .is_universal = 1 // ignore SNI
    };

    int erridx;
    miPKI.State = miPKI.mipki_init(&pki_config, 1, NULL, &erridx);

    if (!miPKI.State) {
        Status = QUIC_STATUS_INVALID_STATE;
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            erridx,
            "mipki_init failed");
        goto Error;
    }

    if (!miPKI.mipki_add_root_file_or_path(miPKI.State, "CAFile.pem")) {
        Status = QUIC_STATUS_INVALID_STATE;
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "mipki_add_root_file_or_path failed");
        goto Error;
    }

    QuicLockInitialize(&miPKI.Lock);

    Status = QUIC_STATUS_SUCCESS;

Error:

    if (QUIC_FAILED(Status)) {
        if (miPKI.State) {
            miPKI.mipki_free(miPKI.State);
            miPKI.State = NULL;
        }
        if (miPKI.Libmipki) {
            FreeLibrary(miPKI.Libmipki);
            miPKI.Libmipki = NULL;
        }
    }

    return Status;
}

void
QuicCertLibraryUninitialize(
    void
    )
{
    if (miPKI.Libmipki != NULL) {
        QuicLockUninitialize(&miPKI.Lock);
        miPKI.mipki_free(miPKI.State);
        FreeLibrary(miPKI.Libmipki);
        miPKI.Libmipki = NULL;
    }
}

_Success_(return != NULL)
QUIC_CERT*
QuicCertSelect(
    _In_reads_opt_(ServerNameIndiciationLength)
        const char* ServerNameIndiciation,
    size_t ServerNameIndiciationLength,
    _In_reads_(SignatureAlgorithmsLength)
        const UINT16 *SignatureAlgorithms,
    _In_ size_t SignatureAlgorithmsLength,
    _Out_ UINT16 *SelectedSignature
    )
{
    QuicLockAcquire(&miPKI.Lock);

    mipki_chain Certificate =
        miPKI.mipki_select_certificate(
            miPKI.State,
            ServerNameIndiciation,
            ServerNameIndiciationLength,
            SignatureAlgorithms,
            SignatureAlgorithmsLength,
            SelectedSignature);

    QuicLockRelease(&miPKI.Lock);

    return (QUIC_CERT*)Certificate;
}

_Success_(return != NULL)
QUIC_CERT*
QuicCertParseChain(
    _In_ size_t ChainBufferLength,
    _In_reads_(ChainBufferLength) const BYTE *ChainBuffer
    )
{
    QuicLockAcquire(&miPKI.Lock);

    mipki_chain Certificate =
        miPKI.mipki_parse_chain(
            miPKI.State,
            (const char*)ChainBuffer,
            ChainBufferLength);

    QuicLockRelease(&miPKI.Lock);

    return (QUIC_CERT*)Certificate;
}

_Success_(return != 0)
size_t
QuicCertFormat(
    _In_ QUIC_CERT* Certificate,
    _In_ size_t BufferLength,
    _Out_writes_to_(BufferLength, return)
        BYTE* Buffer
    )
{
    QuicLockAcquire(&miPKI.Lock);

    size_t Result =
        miPKI.mipki_format_chain(
            miPKI.State,
            (mipki_chain)Certificate,
            (char*)Buffer,
            BufferLength);

    QuicLockRelease(&miPKI.Lock);

    return Result;
}

_Success_(return != FALSE)
BOOLEAN
QuicCertValidateChain(
    _In_ QUIC_CERT* Certificate,
    _In_opt_z_ const char* Host,
    _In_ uint32_t IgnoreFlags
    )
{
    UNREFERENCED_PARAMETER(IgnoreFlags);

    QuicLockAcquire(&miPKI.Lock);

    int Result =
        miPKI.mipki_validate_chain(
            miPKI.State,
            (mipki_chain)Certificate,
            Host);

    QuicLockRelease(&miPKI.Lock);

    return Result == 0 ? FALSE : TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicCertSign(
    _In_ QUIC_CERT* Certificate,
    _In_ const UINT16 SignatureAlgorithm,
    _In_reads_(CertListToBeSignedLength)
        const BYTE *CertListToBeSigned,
    _In_ size_t CertListToBeSignedLength,
    _Out_writes_to_(*SignatureLength, *SignatureLength)
        BYTE *Signature,
    _Inout_ size_t *SignatureLength
    )
{
    QuicLockAcquire(&miPKI.Lock);

    int Result =
        miPKI.mipki_sign_verify(
            miPKI.State,
            (mipki_chain)Certificate,
            SignatureAlgorithm,
            (const char*)CertListToBeSigned,
            CertListToBeSignedLength,
            (char*)Signature,
            SignatureLength,
            MIPKI_SIGN);

    QuicLockRelease(&miPKI.Lock);

    return Result == 0 ? FALSE : TRUE;
}

_Success_(return != FALSE)
BOOLEAN
QuicCertVerify(
    _In_ QUIC_CERT* Certificate,
    _In_ const UINT16 SignatureAlgorithm,
    _In_reads_(CertListToBeSignedLength)
        const BYTE *CertListToBeSigned,
    _In_ size_t CertListToBeSignedLength,
    _In_reads_(SignatureLength)
        const BYTE *Signature,
    _In_ size_t SignatureLength
    )
{
    QuicLockAcquire(&miPKI.Lock);

    int Result =
        miPKI.mipki_sign_verify(
            miPKI.State,
            (mipki_chain)Certificate,
            SignatureAlgorithm,
            (const char*)CertListToBeSigned,
            CertListToBeSignedLength,
            (char*)Signature,
            &SignatureLength,
            MIPKI_VERIFY);

    miPKI.mipki_free_chain(miPKI.State, Certificate);

    QuicLockRelease(&miPKI.Lock);

    return Result == 0 ? FALSE : TRUE;
}
