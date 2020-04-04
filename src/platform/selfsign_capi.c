/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    CAPI implementation for generating the self-signed certificate.

--*/

#define QUIC_TEST_APIS 1

#include "platform_internal.h"
#include "selfsign_capi.c.clog.h"

#include <wincrypt.h>
#include <msquic.h>

#define QUIC_CERT_CREATION_EVENT_NAME       L"MsQuicCertEvent"
#define QUIC_CERT_CREATION_EVENT_WAIT       10000
#define QUIC_CERTIFICATE_TEST_FRIENDLY_NAME L"MsQuicTestCert"
#define QUIC_KEY_CONTAINER_NAME             L"MsQuicSelfSignKey"
#define QUIC_KEY_SIZE                       2048

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
        QuicTraceLogWarning(FN_selfsign_capi0ea0bfe55114d53864b583880e28febd, "[cert] CertOpenStore failed, 0x%x.", GetLastError());
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

        BYTE FriendlyName[sizeof(QUIC_CERTIFICATE_TEST_FRIENDLY_NAME)+sizeof(WCHAR)];
        DWORD NameSize = sizeof(FriendlyName);

        if (!CertGetCertificateContextProperty(Cert, CERT_FRIENDLY_NAME_PROP_ID, FriendlyName, &NameSize) ||
            wcscmp((wchar_t*)FriendlyName, QUIC_CERTIFICATE_TEST_FRIENDLY_NAME) != 0) {
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
    QuicTraceLogInfo(FN_selfsign_capicb36dc033ac9877463b0859504450655, "[cert] %d test certificates found, and %d deleted", Found, Deleted);

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
        QuicTraceLogError(FN_selfsign_capi8650607e99507e1eb44a84f5cb4faff4, "[cert] CryptEncodeObject failed, 0x%x", hr);
        goto Cleanup;
    }

    //
    // Allocate the space that is required.
    //
    CryptDataBlob->pbData =
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, CryptDataBlob->cbData);
    hr = CryptDataBlob->pbData ? S_OK : E_OUTOFMEMORY;
    if (FAILED(hr)) {
        QuicTraceLogError(FN_selfsign_capi9389d4c9e8922de376eb5fe3d0b2ec6e, "[cert] malloc cbData(%d) Failed", CryptDataBlob->cbData);
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
        QuicTraceLogError(FN_selfsign_capi8650607e99507e1eb44a84f5cb4faff4, "[cert] CryptEncodeObject failed, 0x%x", hr);
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
        QuicTraceLogError(FN_selfsign_capib4167274625f54f8d7dae77b1badfa37, "[cert] AllocateAndEncodeObject X509_ENHANCED_KEY_USAGE failed, 0x%x", hr);
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
        QuicTraceLogError(FN_selfsign_capib54384b48c8de0ef32831df01792b822, "[cert] AllocateAndEncodeObject X509_KEY_USAGE failed, 0x%x", hr);
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
        QuicTraceLogError(FN_selfsign_capif612c254501084f860a4d65f1d00f458, "[cert] AllocateAndEncodeObject(szOID_SUBJECT_ALT_NAME) Failed, 0x%x", hr);
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
        QuicTraceLogError(FN_selfsign_capi12b6d068a1a9391246c76011697121e0, "[cert] CreateSubjectNameBlob failed, 0x%x", hr);
        goto Cleanup;
    }

    Buffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, BufferLength);
    hr = Buffer ? S_OK : E_OUTOFMEMORY;
    if (FAILED(hr)) {
        QuicTraceLogError(FN_selfsign_capi0dde9310da399e50c6c40f7aa5805fe9, "[cert] Failed to allocate memory for the encoded name., 0x%x", hr);
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
        QuicTraceLogError(FN_selfsign_capi12b6d068a1a9391246c76011697121e0, "[cert] CreateSubjectNameBlob failed, 0x%x", hr);
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
        QuicTraceLogError(FN_selfsign_capi78ec506566adfde5beacd100ed342b0a, "[cert] malloc TmpCertExtensions Failed, 0x%x", hr);
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
        QuicTraceLogError(FN_selfsign_capi7224c0d1a17ab3a6ac156ed43aef923b, "[cert] CreateEnhancedKeyUsageCertExtension failed, 0x%x", hr);
        goto Cleanup;
    }

    //
    // Set up the key usage and specify that the key is intended to be used
    // for key exchange and digital signatures.
    //
    hr = CreateKeyUsageCertExtension(&TmpCertExtensions[1]);
    if (FAILED(hr)) {
        QuicTraceLogError(FN_selfsign_capi2005562022de62909c3f0c7285426014, "[cert] CreateKeyUsageCertExtension failed, 0x%x", hr);
        goto Cleanup;
    }

    //
    // Set up the Subject Alt Name extension.
    //
    hr = CreateSubjAltNameExtension(&TmpCertExtensions[2]);
    if (FAILED(hr)) {
        QuicTraceLogError(FN_selfsign_capi577a364e6a706037a4d5314ede005085, "[cert] CreateSubjAltNameExtension failed, 0x%x", hr);
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
    NCRYPT_PROV_HANDLE Provider = (NCRYPT_PROV_HANDLE)NULL;
    DWORD KeySize = QUIC_KEY_SIZE;

    *Key = (NCRYPT_KEY_HANDLE)NULL;

    if (FAILED(hr = NCryptOpenStorageProvider(
            &Provider,
            MS_KEY_STORAGE_PROVIDER,
            0))) {
        QuicTraceLogError(FN_selfsign_capibeb3d36073e270808487b7ad4e94759c, "[cert] NCryptOpenStorageProvider failed, 0x%x", hr);
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
            QUIC_KEY_CONTAINER_NAME,
            0,
            NCRYPT_SILENT_FLAG);
    if (hr == ERROR_SUCCESS) {
        QuicTraceLogInfo(FN_selfsign_capi35f78be05fa1f09f40401bab17eb322e, "[cert] Successfully opened key");
        goto Cleanup;
    } else if (hr != NTE_BAD_KEYSET) {
        QuicTraceLogError(FN_selfsign_capi50b9de74542ef82946afc0f3d0db3ed9, "[cert] NCryptCreatePersistedKey failed, 0x%x", hr);
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
            QUIC_KEY_CONTAINER_NAME,
            0,
            0);
    if (hr == NTE_EXISTS) {
        goto ReadKey; // Key already created, in other thread/process.
    } else if (FAILED(hr)) {
        QuicTraceLogError(FN_selfsign_capi50b9de74542ef82946afc0f3d0db3ed9, "[cert] NCryptCreatePersistedKey failed, 0x%x", hr);
        goto Cleanup;
    }

    if (FAILED(hr = NCryptSetProperty(
            *Key,
            NCRYPT_LENGTH_PROPERTY,
            (PBYTE)&KeySize,
            sizeof(KeySize),
            0))) {
        QuicTraceLogError(FN_selfsign_capifcdde10fcd730b6d052d07c926b4176a, "[cert] NCryptSetProperty NCRYPT_LENGTH_PROPERTY failed, 0x%x", hr);
        goto Cleanup;
    }

    if (FAILED(hr = NCryptSetProperty(
            *Key,
            NCRYPT_KEY_USAGE_PROPERTY,
            (PBYTE)&KeyUsageProperty,
            sizeof(KeyUsageProperty),
            0))) {
        QuicTraceLogError(FN_selfsign_capi7ef9c5e5ef97f389821078e31a11d45e, "[cert] NCryptSetProperty NCRYPT_KEY_USAGE_PROPERTY failed, 0x%x", hr);
        goto Cleanup;
    }

    if (FAILED(hr = NCryptFinalizeKey(*Key, 0))) {
        QuicTraceLogError(FN_selfsign_capieb8ac18220159f03a2fc2869b2bfd275, "[cert] NCryptFinalizeKey failed, 0x%x", hr);
        goto Cleanup;
    }

    QuicTraceLogInfo(FN_selfsign_capi7d9d27fd867edffa90d14735abcef13b, "[cert] Successfully created key");

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
        QuicTraceLogError(FN_selfsign_capi12b6d068a1a9391246c76011697121e0, "[cert] CreateSubjectNameBlob failed, 0x%x", hr);
        goto Cleanup;
    }

    //
    // Now we get the private key.
    // This generates the key if not already present.
    //
    hr = GetPrivateRsaKey(&Key);
    if (FAILED(hr)) {
        QuicTraceLogError(FN_selfsign_capi19a45b31070a77d6fccf2496fd8af96b, "[cert] GetPrivateRsaKey failed, 0x%x", hr);
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
        QuicTraceLogError(FN_selfsign_capi3039c7954db54dd771a7e5cf2a2e8543, "[cert] CreateCertificateExtensions failed, 0x%x", hr);
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
        QuicTraceLogError(FN_selfsign_capibb2e66d5c0fa329c33511153548609b9, "[cert] SystemTimeToFileTime failed, 0x%x", hr);
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
        QuicTraceLogError(FN_selfsign_capib7f937400a87b8cc12ab6d021b98d0da, "[cert] FileTimeToSystemTime failed, 0x%x", hr);
        goto Cleanup;
    }

    //
    // Create the certificate
    //
    KeyProvInfo.pwszContainerName   = QUIC_KEY_CONTAINER_NAME;
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
        QuicTraceLogError(FN_selfsign_capib3aab84f6a61d0f06607e50d73e64728, "[cert] CertCreateSelfSignCertificate failed, 0x%x", hr);
        goto Cleanup;
    }

    CRYPT_DATA_BLOB FriendlyNameBlob;
    FriendlyNameBlob.cbData = sizeof(QUIC_CERTIFICATE_TEST_FRIENDLY_NAME);
    FriendlyNameBlob.pbData = (BYTE*) QUIC_CERTIFICATE_TEST_FRIENDLY_NAME;

    if (!CertSetCertificateContextProperty(
            CertContext,
            CERT_FRIENDLY_NAME_PROP_ID,
            0,
            &FriendlyNameBlob)) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        QuicTraceLogError(FN_selfsign_capi9777e92b55d10041e8c1879083583602, "[cert] CertSetCertificateContextProperty failed, 0x%x", hr);
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
            QuicTraceLogError(FN_selfsign_capi24fca425cd878eb28a4a89014d353835, "[cert] CertAddCertificateContextToStore failed, 0x%x", GetLastError());
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
    HANDLE Event = CreateEventW(NULL, TRUE, FALSE, QUIC_CERT_CREATION_EVENT_NAME);
    if (Event == NULL) {
        QuicTraceLogError(FN_selfsign_capi35d3b0c70fdf4ee038769a9a60d87ee8, "[test] CreateEvent failed, 0x%x", GetLastError());
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
        QuicTraceLogInfo(FN_selfsign_capi760f4991b08a42d6e34243caf688f6db, "[test] CreateEvent opened existing event");
        DWORD WaitResult = WaitForSingleObject(Event, QUIC_CERT_CREATION_EVENT_WAIT);
        if (WaitResult != WAIT_OBJECT_0) {
            QuicTraceLogWarning(FN_selfsign_capib987d46256da02f01ee442873c55fc3a, "[test] WaitForSingleObject returned 0x%x, proceeding without caution... (GLE: 0x%x)", 
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
        QuicTraceLogError(FN_selfsign_capi1b6739defef24561b3846cb5127a3644, "[test] CertOpenStore failed, 0x%x.", GetLastError());
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

        BYTE FriendlyName[sizeof(QUIC_CERTIFICATE_TEST_FRIENDLY_NAME)+sizeof(WCHAR)];
        DWORD NameSize = sizeof(FriendlyName);

        if (!CertGetCertificateContextProperty(Cert, CERT_FRIENDLY_NAME_PROP_ID, FriendlyName, &NameSize) ||
            wcscmp((wchar_t*)FriendlyName, QUIC_CERTIFICATE_TEST_FRIENDLY_NAME) != 0) {
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
        QuicTraceLogError(FN_selfsign_capi30cfec4d6480dd6e2ccca715e08c306a, "[test] CertAddCertificateContextToStore failed, 0x%x.", GetLastError());
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
            QuicTraceLogError(FN_selfsign_capi47e693d98dffdb601a27fda197f23007, "[test] CertGetCertificateContextProperty failed, 0x%x.", GetLastError());
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
QUIC_SEC_CONFIG_PARAMS*
QuicPlatGetSelfSignedCert(
    _In_ QUIC_SELF_SIGN_CERT_TYPE Type
    )
{
    QUIC_SEC_CONFIG_PARAMS* Params =
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(QUIC_SEC_CONFIG_PARAMS));
    if (Params == NULL) {
        return NULL;
    }

    Params->Flags = QUIC_SEC_CONFIG_FLAG_CERTIFICATE_CONTEXT;
    Params->Certificate =
        FindOrCreateCertificate(
            Type == QUIC_SELF_SIGN_CERT_USER,
            Params->Thumbprint);
    if (Params->Certificate == NULL) {
        HeapFree(GetProcessHeap(), 0, Params);
        return NULL;
    }

    return Params;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPlatFreeSelfSignedCert(
    _In_ QUIC_SEC_CONFIG_PARAMS* Params
    )
{
    FreeServerCertificate(Params->Certificate);
    HeapFree(GetProcessHeap(), 0, Params);
}
