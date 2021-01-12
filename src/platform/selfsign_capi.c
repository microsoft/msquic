/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    CAPI implementation for generating the self-signed certificate.

--*/

#define QUIC_TEST_APIS 1

#include "platform_internal.h"
#ifdef QUIC_CLOG
#include "selfsign_capi.c.clog.h"
#endif

#include <wincrypt.h>
#include <msquic.h>

#define CXPLAT_CERT_CREATION_EVENT_NAME       L"MsQuicCertEvent"
#define CXPLAT_CERT_CREATION_EVENT_WAIT       10000
#define CXPLAT_CERTIFICATE_TEST_FRIENDLY_NAME L"MsQuicTestCert2"
#define CXPLAT_KEY_CONTAINER_NAME             L"MsQuicSelfSignKey2"
#define CXPLAT_KEY_SIZE                       2048

void
CleanTestCertificatesFromStore(BOOLEAN UserStore)
{
    PCCERT_CONTEXT Cert = NULL;
    DWORD FriendlyNamePropId = CERT_FRIENDLY_NAME_PROP_ID;
    int Found = 0;
    int Deleted = 0;

    HCERTSTORE CertStore =
        CertOpenStore(
            CERT_STORE_PROV_SYSTEM_A,
            0,
            0,
            UserStore ? CERT_SYSTEM_STORE_CURRENT_USER : CERT_SYSTEM_STORE_LOCAL_MACHINE,
            "MY");
    if (CertStore == NULL) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            GetLastError(),
            "CertOpenStore failed");
        return;
    }

    while (NULL !=
        (Cert = CertFindCertificateInStore(
            CertStore,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_PROPERTY,
            &FriendlyNamePropId,
            Cert))) {

        BYTE FriendlyName[sizeof(CXPLAT_CERTIFICATE_TEST_FRIENDLY_NAME)+sizeof(WCHAR)];
        DWORD NameSize = sizeof(FriendlyName);

        if (!CertGetCertificateContextProperty(Cert, CERT_FRIENDLY_NAME_PROP_ID, FriendlyName, &NameSize) ||
            wcscmp((wchar_t*)FriendlyName, CXPLAT_CERTIFICATE_TEST_FRIENDLY_NAME) != 0) {
            ++Found;
            continue;
        }
        //
        // Increment the ref count on the certificate before deleting it to
        // allow the iteration to continue.
        //
        CertDeleteCertificateFromStore(CertDuplicateCertificateContext(Cert));
        ++Deleted;
    }
    QuicTraceLogInfo(
        CertCleanTestCerts,
        "[cert] %d test certificates found, and %d deleted",
        Found,
        Deleted);

    CertCloseStore(CertStore, 0);
}

void
FreeEncodedObject(
    _In_ PCRYPT_DATA_BLOB CryptDataBlob
    )
{
    if (NULL != CryptDataBlob) {
        if (CryptDataBlob->pbData != NULL) {
            HeapFree(GetProcessHeap(), 0, CryptDataBlob->pbData);
            CryptDataBlob->pbData = NULL;
        }
        CryptDataBlob->cbData = 0;
    }
}

HRESULT
AllocateAndEncodeObject(
    _Out_ PCRYPT_DATA_BLOB CryptDataBlob,
    _In_ PCSTR StructType,
    _In_ const void* StructInfo
    )
{
    HRESULT hr = S_OK;

    ZeroMemory(CryptDataBlob, sizeof(*CryptDataBlob));

    //
    // Determine how much space is required for the encoded data.
    //
    if (!CryptEncodeObject(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            StructType,
            StructInfo,
            NULL,
            &CryptDataBlob->cbData)) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            hr,
            "CryptEncodeObject failed");
        goto Cleanup;
    }

    //
    // Allocate the space that is required.
    //
    CryptDataBlob->pbData =
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, CryptDataBlob->cbData);
    hr = CryptDataBlob->pbData ? S_OK : E_OUTOFMEMORY;
    if (FAILED(hr)) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CryptDataBlob",
            CryptDataBlob->cbData);
        goto Cleanup;
    }

    //
    // Space has been allocated. Now encode the data.
    //
    if (!CryptEncodeObject(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            StructType,
            StructInfo,
            CryptDataBlob->pbData,
            &CryptDataBlob->cbData)) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            hr,
            "CryptEncodeObject failed");
        goto Cleanup;
    }

Cleanup:
    if (FAILED(hr)) {
        FreeEncodedObject(CryptDataBlob);
        CryptDataBlob = NULL;
    }

    return hr;
}

HRESULT
CreateEnhancedKeyUsageCertExtension(
    _Out_ PCERT_EXTENSION CertExtension
    )
{
    LPSTR EnhKeyUsageIds[1] = { szOID_PKIX_KP_SERVER_AUTH };
    CERT_ENHKEY_USAGE CertEnhKeyUsage;
    CertEnhKeyUsage.cUsageIdentifier = 1;
    CertEnhKeyUsage.rgpszUsageIdentifier = EnhKeyUsageIds;

    ZeroMemory(CertExtension, sizeof(*CertExtension));
    CertExtension->fCritical = FALSE;
    CertExtension->pszObjId = szOID_ENHANCED_KEY_USAGE;

    HRESULT hr =
        AllocateAndEncodeObject(
            &CertExtension->Value,
            X509_ENHANCED_KEY_USAGE,
            &CertEnhKeyUsage);
    if (FAILED(hr)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            hr,
            "AllocateAndEncodeObject X509_ENHANCED_KEY_USAGE failed");
        goto Cleanup;
    }

Cleanup:
    return hr;
}

HRESULT
CreateKeyUsageCertExtension(
    _Out_ PCERT_EXTENSION CertExtension
    )
{
    BYTE KeyUsage = CERT_DIGITAL_SIGNATURE_KEY_USAGE;
    CRYPT_BIT_BLOB KeyUsageBlob;
    KeyUsageBlob.cbData = sizeof(KeyUsage);
    KeyUsageBlob.pbData = &KeyUsage;
    KeyUsageBlob.cUnusedBits = 0;

    ZeroMemory(CertExtension, sizeof(*CertExtension));
    CertExtension->fCritical = FALSE;
    CertExtension->pszObjId = szOID_KEY_USAGE;

    HRESULT hr =
        AllocateAndEncodeObject(
            &CertExtension->Value,
            X509_KEY_USAGE,
            &KeyUsageBlob);
    if (FAILED(hr)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            hr,
            "AllocateAndEncodeObject X509_KEY_USAGE failed");
        goto Cleanup;
    }

    hr = S_OK;

Cleanup:
    return hr;
}

HRESULT
CreateSubjAltNameExtension(
    _Out_ PCERT_EXTENSION CertExtension
    )
{
    CERT_ALT_NAME_ENTRY AltName = { CERT_ALT_NAME_DNS_NAME };
    AltName.pwszDNSName = L"localhost";
    CERT_ALT_NAME_INFO NameInfo;
    NameInfo.cAltEntry = 1;
    NameInfo.rgAltEntry = &AltName;

    ZeroMemory(CertExtension, sizeof(*CertExtension));
    CertExtension->fCritical = FALSE;
    CertExtension->pszObjId = szOID_SUBJECT_ALT_NAME;

    HRESULT hr =
        AllocateAndEncodeObject(
            &CertExtension->Value,
            szOID_SUBJECT_ALT_NAME,
            &NameInfo);
    if (FAILED(hr)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            hr,
            "AllocateAndEncodeObject szOID_SUBJECT_ALT_NAME failed");
        goto Cleanup;
    }

 Cleanup:
    return hr;
}

HRESULT
CreateSubjectNameBlob(
    _In_ LPCWSTR SubjectName,
    _Out_ CERT_NAME_BLOB* SubjectNameBlob
    )
{
    HRESULT hr = S_OK;

    PBYTE Buffer = NULL;
    DWORD BufferLength = 0;

    //
    // Encode the certificate name
    //
    if (!CertStrToNameW(
            X509_ASN_ENCODING,
            SubjectName,
            CERT_X500_NAME_STR,
            NULL,
            NULL,
            &BufferLength,
            NULL)) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            hr,
            "CreateSubjectNameBlob failed");
        goto Cleanup;
    }

    Buffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, BufferLength);
    hr = Buffer ? S_OK : E_OUTOFMEMORY;
    if (FAILED(hr)) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "SubjectNameBlob",
            BufferLength);
        goto Cleanup;
    }

    if (!CertStrToNameW(
            X509_ASN_ENCODING,
            SubjectName,
            CERT_X500_NAME_STR,
            NULL,
            Buffer,
            &BufferLength,
            NULL)) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            hr,
            "CreateSubjectNameBlob failed");
        goto Cleanup;
    }

    SubjectNameBlob->cbData = BufferLength;
    SubjectNameBlob->pbData = Buffer;

Cleanup:

    if (FAILED(hr)) {
        if (NULL != Buffer) {
            HeapFree(GetProcessHeap(), 0, Buffer);
        }
    }

    return hr;
}

void
ClearCertificateExtensions(
    _In_ CERT_EXTENSIONS* CertExtensions
    )
{
    if ((NULL != CertExtensions) && (NULL != CertExtensions->rgExtension)) {
        for (DWORD i = 0; i < CertExtensions->cExtension; i++) {
            if (CertExtensions->rgExtension[i].Value.pbData) {
                HeapFree(GetProcessHeap(), 0, CertExtensions->rgExtension[i].Value.pbData);
                CertExtensions->rgExtension[i].Value.pbData = NULL;
                CertExtensions->rgExtension[i].Value.cbData = 0;
            }
        }

        HeapFree(GetProcessHeap(), 0, CertExtensions->rgExtension);
        CertExtensions->rgExtension = NULL;
        CertExtensions->cExtension = 0;
    }
}

HRESULT
CreateCertificateExtensions(
    _Out_ CERT_EXTENSIONS* CertExtensions
    )
{
    HRESULT hr = S_OK;

    PCERT_EXTENSION TmpCertExtensions = NULL;
    const DWORD cTmpCertExtension = 3;

    CertExtensions->cExtension = 0;
    CertExtensions->rgExtension = NULL;

    //
    // Allocate the memory for the extensions.
    //
    TmpCertExtensions =
        (PCERT_EXTENSION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CERT_EXTENSION) * cTmpCertExtension);
    hr = TmpCertExtensions ? S_OK : E_OUTOFMEMORY;
    if (FAILED(hr)) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "TmpCertExtensions",
            sizeof(CERT_EXTENSION) * cTmpCertExtension);
        goto Cleanup;
    }

    CertExtensions->rgExtension = TmpCertExtensions;
    CertExtensions->cExtension = cTmpCertExtension;

    //
    // Set up the enhanced key usage extension that will specify the key is
    // intended for server authentication.
    //
    hr = CreateEnhancedKeyUsageCertExtension(&TmpCertExtensions[0]);
    if (FAILED(hr)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            hr,
            "CreateEnhancedKeyUsageCertExtension failed");
        goto Cleanup;
    }

    //
    // Set up the key usage and specify that the key is intended to be used
    // for key exchange and digital signatures.
    //
    hr = CreateKeyUsageCertExtension(&TmpCertExtensions[1]);
    if (FAILED(hr)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            hr,
            "CreateKeyUsageCertExtension failed");
        goto Cleanup;
    }

    //
    // Set up the Subject Alt Name extension.
    //
    hr = CreateSubjAltNameExtension(&TmpCertExtensions[2]);
    if (FAILED(hr)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            hr,
            "CreateSubjAltNameExtension failed");
        goto Cleanup;
    }

Cleanup:
    if (FAILED(hr)) {
        ClearCertificateExtensions(CertExtensions);
    }

    return hr;
}

HRESULT
GetPrivateRsaKey(
    _Out_ NCRYPT_KEY_HANDLE* Key
    )
{
    HRESULT hr = S_OK;

    PCERT_PUBLIC_KEY_INFO CertPubKeyInfo = NULL;
    DWORD KeyUsageProperty = NCRYPT_ALLOW_SIGNING_FLAG;
    DWORD ExportPolicyProperty = NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
    NCRYPT_PROV_HANDLE Provider = (NCRYPT_PROV_HANDLE)NULL;
    DWORD KeySize = CXPLAT_KEY_SIZE;

    *Key = (NCRYPT_KEY_HANDLE)NULL;

    if (FAILED(hr = NCryptOpenStorageProvider(
            &Provider,
            MS_KEY_STORAGE_PROVIDER,
            0))) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            hr,
            "NCryptOpenStorageProvider failed");
        goto Cleanup;
    }

ReadKey:

    //
    // Try to open the key.
    //
    hr =
        NCryptOpenKey(
            Provider,
            Key,
            CXPLAT_KEY_CONTAINER_NAME,
            0,
            NCRYPT_SILENT_FLAG);
    if (hr == ERROR_SUCCESS) {
        QuicTraceLogInfo(
            CertOpenRsaKeySuccess,
            "[cert] Successfully opened RSA key");
        goto Cleanup;
    } else if (hr != NTE_BAD_KEYSET) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            hr,
            "NCryptOpenKey failed");
        goto Cleanup;
    }

    //
    // Key couldn't be open so try to create it.
    //
    hr =
        NCryptCreatePersistedKey(
            Provider,
            Key,
            NCRYPT_RSA_ALGORITHM,
            CXPLAT_KEY_CONTAINER_NAME,
            0,
            0);
    if (hr == NTE_EXISTS) {
        goto ReadKey; // Key already created, in other thread/process.
    } else if (FAILED(hr)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            hr,
            "NCryptCreatePersistedKey failed");
        goto Cleanup;
    }

    if (FAILED(hr = NCryptSetProperty(
            *Key,
            NCRYPT_LENGTH_PROPERTY,
            (PBYTE)&KeySize,
            sizeof(KeySize),
            0))) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            hr,
            "NCryptSetProperty NCRYPT_LENGTH_PROPERTY failed");
        goto Cleanup;
    }

    if (FAILED(hr = NCryptSetProperty(
            *Key,
            NCRYPT_KEY_USAGE_PROPERTY,
            (PBYTE)&KeyUsageProperty,
            sizeof(KeyUsageProperty),
            0))) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            hr,
            "NCryptSetProperty NCRYPT_KEY_USAGE_PROPERTY failed");
        goto Cleanup;
    }

    if (FAILED(hr = NCryptSetProperty(
            *Key,
            NCRYPT_EXPORT_POLICY_PROPERTY,
            (PBYTE)&ExportPolicyProperty,
            sizeof(ExportPolicyProperty),
            0))) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            hr,
            "NCryptSetProperty NCRYPT_EXPORT_POLICY_PROPERTY failed");
        goto Cleanup;
    }

    if (FAILED(hr = NCryptFinalizeKey(*Key, 0))) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            hr,
            "NCryptFinalizeKey failed");
        goto Cleanup;
    }

    QuicTraceLogInfo(
        CertCreateRsaKeySuccess,
        "[cert] Successfully created key");

Cleanup:

    if (FAILED(hr)) {
        if ((NCRYPT_KEY_HANDLE)NULL != *Key) {
            NCryptDeleteKey(*Key, 0);
            *Key = (NCRYPT_KEY_HANDLE)NULL;
        }
        if (NULL != CertPubKeyInfo) {
            HeapFree(GetProcessHeap(), 0, CertPubKeyInfo);
        }
    }

    if ((NCRYPT_PROV_HANDLE)NULL != Provider) {
        NCryptFreeObject(Provider);
    }

    return hr;
}

HRESULT
CreateSelfSignedCertificate(
    _In_ LPCWSTR SubjectName,
    _Out_ PCCERT_CONTEXT* NewCertContext
    )
{
    HRESULT hr = S_OK;

    CRYPT_KEY_PROV_INFO KeyProvInfo = {0};
    PCCERT_CONTEXT CertContext = NULL;
    CERT_NAME_BLOB SubjectNameBlob = {0};
    NCRYPT_KEY_HANDLE Key = (NCRYPT_KEY_HANDLE)NULL;
    CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm = { szOID_RSA_SHA256RSA };
    SYSTEMTIME Now, Expiration;
    BOOLEAN CleanupExtensions = FALSE;

    //
    // First we have to convert the subject name into an ASN.1 (DER) blob.
    //
    hr = CreateSubjectNameBlob(SubjectName, &SubjectNameBlob);
    if (FAILED(hr)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            hr,
            "CreateSubjectNameBlob failed");
        goto Cleanup;
    }

    //
    // Now we get the private key.
    // This generates the key if not already present.
    //
    hr = GetPrivateRsaKey(&Key);
    if (FAILED(hr)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            hr,
            "GetPrivateRsaKey failed");
        goto Cleanup;
    }

    //
    // Create certificate extensions.
    //
    CERT_EXTENSIONS extensions;
    ZeroMemory(&extensions, sizeof(CERT_EXTENSIONS));
    hr = CreateCertificateExtensions(&extensions);
    if (FAILED(hr)) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            hr,
            "CreateCertificateExtensions failed");
        goto Cleanup;
    }
    CleanupExtensions = TRUE;

    //
    // Calculate SYSTEMTIME for the start time of the certificate (now)
    // and expiration time of the certificate (five years from now).
    //
    GetSystemTime(&Now);
    FILETIME ExpiredFileTime;
    if (!SystemTimeToFileTime(&Now, &ExpiredFileTime)) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            hr,
            "SystemTimeToFileTime failed");
        goto Cleanup;
    }
    ULARGE_INTEGER FiveYearsFromNowLargeInt;
    FiveYearsFromNowLargeInt.LowPart = ExpiredFileTime.dwLowDateTime;
    FiveYearsFromNowLargeInt.HighPart = ExpiredFileTime.dwHighDateTime;

    FiveYearsFromNowLargeInt.QuadPart += (5ll * 365ll * 24ll * 60ll * 60ll * 10000000ll);

    ExpiredFileTime.dwLowDateTime = FiveYearsFromNowLargeInt.LowPart;
    ExpiredFileTime.dwHighDateTime = FiveYearsFromNowLargeInt.HighPart;
    if (!FileTimeToSystemTime(&ExpiredFileTime, &Expiration)) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            hr,
            "FileTimeToSystemTime failed");
        goto Cleanup;
    }

    //
    // Create the certificate
    //
    KeyProvInfo.pwszContainerName   = CXPLAT_KEY_CONTAINER_NAME;
    KeyProvInfo.pwszProvName        = MS_KEY_STORAGE_PROVIDER;
    KeyProvInfo.dwProvType          = 0;
    KeyProvInfo.dwFlags             = NCRYPT_SILENT_FLAG;
    KeyProvInfo.cProvParam          = 0;
    KeyProvInfo.rgProvParam         = NULL;
    KeyProvInfo.dwKeySpec           = AT_KEYEXCHANGE;

#pragma prefast(suppress: __WARNING_33088, "Test Only Usage of Self-Signed Certs.")
    CertContext =
        CertCreateSelfSignCertificate(
            Key,
            &SubjectNameBlob,
            0,
            &KeyProvInfo,
            &SignatureAlgorithm,
            &Now, &Expiration,
            &extensions);
    if (NULL == CertContext) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            hr,
            "CertCreateSelfSignCertificate failed");
        goto Cleanup;
    }

    CRYPT_DATA_BLOB FriendlyNameBlob;
    FriendlyNameBlob.cbData = sizeof(CXPLAT_CERTIFICATE_TEST_FRIENDLY_NAME);
    FriendlyNameBlob.pbData = (BYTE*) CXPLAT_CERTIFICATE_TEST_FRIENDLY_NAME;

    if (!CertSetCertificateContextProperty(
            CertContext,
            CERT_FRIENDLY_NAME_PROP_ID,
            0,
            &FriendlyNameBlob)) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            hr,
            "CertSetCertificateContextProperty failed");
        CertFreeCertificateContext(CertContext);
        goto Cleanup;
    }

    *NewCertContext = CertContext;

Cleanup:

    if (CleanupExtensions) {
        ClearCertificateExtensions(&extensions);
    }

    if (NULL != SubjectNameBlob.pbData) {
        HeapFree(GetProcessHeap(), 0, SubjectNameBlob.pbData);
    }

    if ((NCRYPT_KEY_HANDLE)NULL != Key) {
        NCryptFreeObject(Key);
    }

    return hr;
}

void*
CreateServerCertificate(
    )
{
    PCCERT_CONTEXT CertContext;
    if (FAILED(CreateSelfSignedCertificate(L"CN=localhost", &CertContext))) {
        return NULL;
    }

#if 0
    //
    // Save the certificate to the store for debugging purposes.
    //
    HCERTSTORE CertStore =
        CertOpenStore(
            CERT_STORE_PROV_SYSTEM_A,
            0,
            0,
            CERT_SYSTEM_STORE_CURRENT_USER,
            "MY");
    if (CertStore != NULL) {
        if (!CertAddCertificateContextToStore(
                CertStore,
                CertContext,
                CERT_STORE_ADD_NEW,
                NULL)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                GetLastError(),
                "CertAddCertificateContextToStore failed");
        }
        CertCloseStore(CertStore, 0);
    }
#endif

    return (void*)CertContext;
}

void
FreeServerCertificate(
    void* CertCtx
    )
{
    CertFreeCertificateContext((PCCERT_CONTEXT)CertCtx);
}

/*
    Find the first MsQuic test certificate that is valid, or create one.
*/
_Success_(return != NULL)
void*
FindOrCreateCertificate(
    _In_ BOOLEAN UserStore,
    _Out_writes_all_(20) uint8_t* CertHash
    )
{
    PCCERT_CONTEXT Cert = NULL;
    DWORD FriendlyNamePropId = CERT_FRIENDLY_NAME_PROP_ID;

    BOOLEAN First = FALSE;
    HANDLE Event = CreateEventW(NULL, TRUE, FALSE, CXPLAT_CERT_CREATION_EVENT_NAME);
    if (Event == NULL) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "CreateEvent failed");
        return NULL;
    }

    //
    // Any process/thread that calls CreateEvent with a given name and isn't
    // the first process, behaves as if OpenHandle was called with the given
    // name.
    // The way to tell if that's the case is checking GetLastError for
    // ERROR_ALREADY_EXISTS. In this case, each process waits for the first
    // process to finish and set the event, and then search for the certificate.
    // If, for some reason, the first process takes longer than 10 seconds,
    // continue anyway.
    //
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        QuicTraceLogInfo(
            CertCreationEventAlreadyCreated,
            "[test] CreateEvent opened existing event");
        DWORD WaitResult = WaitForSingleObject(Event, CXPLAT_CERT_CREATION_EVENT_WAIT);
        if (WaitResult != WAIT_OBJECT_0) {
            QuicTraceLogWarning(
                CertWaitForCreationEvent,
                "[test] WaitForSingleObject returned 0x%x, proceeding without caution... (GLE: 0x%x)",
                WaitResult,
                GetLastError());
        }
    } else {
        First = TRUE;
    }

    HCERTSTORE CertStore =
        CertOpenStore(
            CERT_STORE_PROV_SYSTEM_A,
            0,
            0,
            UserStore ? CERT_SYSTEM_STORE_CURRENT_USER : CERT_SYSTEM_STORE_LOCAL_MACHINE,
            "MY");
    if (CertStore == NULL) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            GetLastError(),
            "CertOpenStore failed");
        goto Done;
    }

    while (NULL !=
        (Cert = CertFindCertificateInStore(
            CertStore,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_PROPERTY,
            &FriendlyNamePropId,
            Cert))) {

        BYTE FriendlyName[sizeof(CXPLAT_CERTIFICATE_TEST_FRIENDLY_NAME)+sizeof(WCHAR)];
        DWORD NameSize = sizeof(FriendlyName);

        if (!CertGetCertificateContextProperty(Cert, CERT_FRIENDLY_NAME_PROP_ID, FriendlyName, &NameSize) ||
            wcscmp((wchar_t*)FriendlyName, CXPLAT_CERTIFICATE_TEST_FRIENDLY_NAME) != 0) {
            continue;
        }

        //
        // Check if the certificate is valid.
        //
        FILETIME Now;
        GetSystemTimeAsFileTime(&Now);
        if (CertVerifyTimeValidity(&Now, Cert->pCertInfo) == 0) {
            goto Done;
        }
    }

    //
    // Getting this far means that no certificates were found. Create one!
    //
    Cert = (PCCERT_CONTEXT) CreateServerCertificate();
    if (Cert == NULL) {
        goto Done;
    }

    if (!CertAddCertificateContextToStore(
            CertStore,
            Cert,
            CERT_STORE_ADD_ALWAYS,
            NULL)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            GetLastError(),
            "CertAddCertificateContextToStore failed");
        CertFreeCertificateContext(Cert);
        Cert = NULL;
    }

Done:
    if (Cert != NULL) {
        DWORD CertHashLength = 20;
        if (!CertGetCertificateContextProperty(
                Cert,
                CERT_HASH_PROP_ID,
                CertHash,
                &CertHashLength)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                GetLastError(),
                "CertGetCertificateContextProperty failed");
            CertFreeCertificateContext(Cert);
            Cert = NULL;
        }
    }
    if (CertStore != NULL) {
        CertCloseStore(CertStore, 0);
    }
    if (First) {
        SetEvent(Event);
    }
    return (void*) Cert;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
const QUIC_CREDENTIAL_CONFIG*
CxPlatPlatGetSelfSignedCert(
    _In_ CXPLAT_SELF_SIGN_CERT_TYPE Type
    )
{
    QUIC_CREDENTIAL_CONFIG* Params =
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(QUIC_CREDENTIAL_CONFIG) + sizeof(QUIC_CERTIFICATE_HASH));
    if (Params == NULL) {
        return NULL;
    }

    Params->Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT;
    Params->Flags = QUIC_CREDENTIAL_FLAG_NONE;
    Params->CertificateContext =
        FindOrCreateCertificate(
            Type == CXPLAT_SELF_SIGN_CERT_USER,
            (uint8_t*)(Params + 1));
    if (Params->CertificateContext == NULL) {
        HeapFree(GetProcessHeap(), 0, Params);
        return NULL;
    }

    return Params;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatPlatFreeSelfSignedCert(
    _In_ const QUIC_CREDENTIAL_CONFIG* Params
    )
{
    FreeServerCertificate(Params->CertificateContext);
    HeapFree(GetProcessHeap(), 0, (void*)Params);
}
