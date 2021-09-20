/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "quic_platform.h"
#include "quic_hashtable.h"
#include "msquic.hpp"
#include "quic_0rtt.h"

#define QUIC_0RTT_ID_LIFETIME_US (60 * 1000 * 1000)

MsQuicConnectionCallback Quic0RttServiceConnCallback;
QUIC_STREAM_CALLBACK Quic0RttServiceStreamCallback;

typedef struct QUIC_0RTT_ID_ENTRY {
    CXPLAT_HASHTABLE_ENTRY Hash;
    CXPLAT_LIST_ENTRY List;
    uint64_t ExpireTimeStamp;
} QUIC_0RTT_ID_ENTRY;

typedef struct QUIC_0RTT_ID_TABLE {
    CxPlatLock Lock;
    HashTable IdentifierTable;
    CXPLAT_LIST_ENTRY IdentifierList;
    CxPlatPool Pool {sizeof(QUIC_0RTT_ID_ENTRY)};
    QUIC_0RTT_ID_TABLE() { CxPlatListInitializeHead(&IdentifierList); }
    ~QUIC_0RTT_ID_TABLE() {
        while (!CxPlatListIsEmpty(&IdentifierList)) {
            Pool.Free(CXPLAT_CONTAINING_RECORD(CxPlatListRemoveHead(&IdentifierList), QUIC_0RTT_ID_ENTRY, List));
        }
    }
    bool ValidateIdentifier(uint64_t Identifier) {
        bool Result = false;
        auto NewEntry = (QUIC_0RTT_ID_ENTRY*)Pool.Alloc();
        if (NewEntry) {
            Lock.Acquire();
            auto TimeStamp = CxPlatTimeUs64();
            auto ExpireTimeStamp = TimeStamp + QUIC_0RTT_ID_LIFETIME_US;
            while (!CxPlatListIsEmpty(&IdentifierList)) {
                auto Entry = CXPLAT_CONTAINING_RECORD(IdentifierList.Flink, QUIC_0RTT_ID_ENTRY, List);
                if (Entry->ExpireTimeStamp < TimeStamp) {
                    break;
                }
                IdentifierTable.Remove(&Entry->Hash);
                CxPlatListRemoveHead(&IdentifierList);
                Pool.Free(Entry);
            }
            auto OldEntry = IdentifierTable.Lookup(Identifier);
            if (!OldEntry) {
                NewEntry->Hash.Signature = Identifier;
                NewEntry->ExpireTimeStamp = ExpireTimeStamp;
                IdentifierTable.Insert(&NewEntry->Hash);
                CxPlatListInsertTail(&IdentifierList, &NewEntry->List);
                Result = true;
            }
            Lock.Release();
            if (OldEntry) {
                Pool.Free(NewEntry);
            }
        }
        return Result;
    }
};

typedef struct QUIC_0RTT_SERVICE {
    QUIC_0RTT_ID_TABLE Table;
    MsQuicRegistration Registration {true};
    MsQuicCertificateHash CertificateHash;
    MsQuicCredentialConfig CredentialConfig {
        QUIC_CREDENTIAL_FLAG_NONE,
        &CertificateHash};
    MsQuicConfiguration Configuration {
        Registration,
        MsQuicAlpn(QUIC_0RTT_ALPN),
        MsQuicSettings().SetPeerBidiStreamCount(100),
        CredentialConfig};
    MsQuicAutoAcceptListener Listener {
        Registration,
        Configuration,
        Quic0RttServiceConnCallback,
        this};
    QUIC_0RTT_SERVICE(_In_reads_(20) const uint8_t* Thumbprint) : CertificateHash(Thumbprint) { }
    bool IsValid() const { return Listener.IsValid(); }
    bool Start() {
        QuicAddr ListenAddr(QUIC_ADDRESS_FAMILY_UNSPEC, (uint16_t)QUIC_0RTT_PORT);
        return Listener.Start(MsQuicAlpn(QUIC_0RTT_ALPN), &ListenAddr.SockAddr);
    }
    bool ValidateIdentifier(uint64_t Identifier) { return Table.ValidateIdentifier(Identifier); }
} QUIC_0RTT_SERVICE;

extern "C"
QUIC_0RTT_SERVICE*
Quic0RttServiceStart(
    _In_reads_(20)
        const uint8_t* CertificateThumbprint
    )
{
    auto Service = new(std::nothrow) QUIC_0RTT_SERVICE(CertificateThumbprint);
    if (Service) {
        if (!Service->IsValid() || !Service->Start()) {
            delete Service;
            Service = nullptr;
        }
    }
    return Service;
}

extern "C"
void
Quic0RttServiceStop(
    _In_ QUIC_0RTT_SERVICE* Service
    )
{
    delete Service;
}

QUIC_STATUS
Quic0RttServiceConnCallback(
    _In_ MsQuicConnection* Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    ) noexcept {
    if (Event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED) {
        MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)Quic0RttServiceStreamCallback, Context);
    }
    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS
QUIC_API
Quic0RttServiceStreamCallback(
    _In_ HQUIC Stream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    auto Service = (QUIC_0RTT_SERVICE*)Context;
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_RECEIVE:
        if (Event->RECEIVE.AbsoluteOffset == 0 &&
            Event->RECEIVE.TotalBufferLength == sizeof(QUIC_0RTT_IDENTIFIER) &&
            Event->RECEIVE.BufferCount == 1 &&
            Service->ValidateIdentifier(((const QUIC_0RTT_IDENTIFIER*)Event->RECEIVE.Buffers[0].Buffer)->Index)) {
            MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
        } else {
            MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        }
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
    case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED:
        MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        MsQuic->StreamClose(Stream);
        break;
    }
}
