/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#define QUIC_TEST_APIS 1

#include "quic_platform.h"
#include <winioctl.h>

// TODO - Enable this: #define QUIC_COMPARTMENT_TESTS 1
#ifdef QUIC_COMPARTMENT_TESTS
#include <nsi.h>
#include <ntddndis.h>
#include <ndisnsi.h>
#include <netioapi.h>
#include <rpc.h>
#endif // QUIC_COMPARTMENT_TESTS

#include "MsQuicTests.h"
#include "MsQuicp.h"
#include "msquichelper.h"
#include "quic_trace.h"

#define LOG_ONLY_FAILURES
#define INLINE_TEST_METHOD_MARKUP
#include <wextestclass.h>
#include <logcontroller.h>

using namespace WEX;
using namespace WEX::Common;
using namespace WEX::Logging;
using namespace WEX::TestExecution;

const UINT TestCompartmentID = 2;

struct CompartmentHelper
{
    static bool CreateCompartment(uint32_t id) {
#ifdef QUIC_COMPARTMENT_TESTS
        NDIS_NSI_COMPARTMENT_RW Rw = { 0 };
        Rw.Header.Type = NDIS_OBJECT_TYPE_NSI_COMPARTMENT_RW_STRUCT;
        Rw.Header.Revision = NDIS_NSI_COMPARTMENT_RW_REVISION_1;
        Rw.Header.Size = sizeof(NDIS_NSI_COMPARTMENT_RW);

        UuidCreate(&Rw.CompartmentGuid);
        return
            NETIO_SUCCESS(
            NsiSetAllParameters(
                NsiActive,
                NsiSetCreateOnly,
                &NPI_MS_NDIS_MODULEID,
                NdisNsiObjectCompartment,
                &id, sizeof(id),
                &Rw, sizeof(Rw)));
#else
        UNREFERENCED_PARAMETER(id);
        return true;
#endif
    }

    static void DeleteCompartment(uint32_t id) {
#ifdef QUIC_COMPARTMENT_TESTS
        NsiSetAllParameters(
            NsiActive,
            NsiSetDelete,
            &NPI_MS_NDIS_MODULEID,
            NdisNsiObjectCompartment,
            &id, sizeof(id),
            NULL, 0);
#else
        UNREFERENCED_PARAMETER(id);
#endif
    }
};

struct CompartmentIdScope {
    UINT32 newCompartmentID;
    UINT32 previousCompartmentID;
    CompartmentIdScope() : newCompartmentID(0), previousCompartmentID(0) {
#if QUIC_COMPARTMENT_TESTS
        VERIFY_SUCCEEDED(WEX::TestExecution::TestData::TryGetValue(L"CompartmentID", newCompartmentID));
        previousCompartmentID = GetCurrentThreadCompartmentId();
        if (previousCompartmentID != newCompartmentID) {
            VERIFY_ARE_EQUAL((NETIO_STATUS)NO_ERROR, SetCurrentThreadCompartmentId(newCompartmentID));
        }
#endif
    }
    ~CompartmentIdScope() {
#if QUIC_COMPARTMENT_TESTS
        if (previousCompartmentID != newCompartmentID) {
            SetCurrentThreadCompartmentId(previousCompartmentID);
        }
#endif
    }
};

class QuicTestDriver {
    SC_HANDLE ScmHandle;
    SC_HANDLE ServiceHandle;
public:
    QuicTestDriver() :
        ScmHandle(nullptr),
        ServiceHandle(nullptr) {
    }
    ~QuicTestDriver() {
    }
    DWORD Initialize();
    void
    Uninitialize() {
        if (ServiceHandle != nullptr) {
            CloseServiceHandle(ServiceHandle);
        }
        if (ScmHandle != nullptr) {
            CloseServiceHandle(ScmHandle);
        }
    }
    DWORD Start();
};

class QuicTestClient {
    HANDLE DeviceHandle;
    bool Initialized;
public:
    QuicTestClient() :
        DeviceHandle(INVALID_HANDLE_VALUE),
        Initialized(false) {
    }
    bool IsInitialized() const {
        return Initialized;
    }
    DWORD
    Initialize(
        _In_ QUIC_CERTIFICATE_HASH* ServerCertHash
        );
    void
    Uninitialize() {
        if (DeviceHandle != INVALID_HANDLE_VALUE) {
            CloseHandle(DeviceHandle);
        }
    }
    DWORD
    SendIOCTL(
        _In_ DWORD IoControlCode,
        _In_reads_bytes_opt_(InBufferSize)
            LPVOID InBuffer,
        _In_ DWORD InBufferSize,
        _In_ DWORD TimeoutMs = 30000
        );
    DWORD
    SendIOCTL(
        _In_ DWORD IoControlCode,
        _In_ DWORD TimeoutMs = 30000
        ) {
        return SendIOCTL(IoControlCode, nullptr, 0, TimeoutMs);
    }
    template<class T>
    DWORD
    SendIOCTL(
        _In_ DWORD IoControlCode,
        _In_ const T& Data,
        _In_ DWORD TimeoutMs = 30000
        ) {
        return SendIOCTL(IoControlCode, (void*)&Data, sizeof(Data), TimeoutMs);
    }
};

