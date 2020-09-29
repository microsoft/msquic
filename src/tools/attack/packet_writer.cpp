/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma warning(disable:4200)  // nonstandard extension used: bit field types other than int
#pragma warning(disable:4201)  // nonstandard extension used: nameless struct/union
#pragma warning(disable:4204)  // nonstandard extension used: non-constant aggregate initializer
#pragma warning(disable:4214)  // nonstandard extension used: zero-sized array in struct/union
#pragma warning(disable:28931) // Unused Assignment

#include <precomp.h> // from 'core' dir
#include <msquichelper.h>

#include "packet_writer.h"

#define VERIFY_QUIC_SUCCESS(result, ...) \
    if (QUIC_FAILED(result)) { printf(#result " failed.\n"); exit(0); }

struct TlsContext
{
    QUIC_TLS* Ptr;
    QUIC_SEC_CONFIG* SecConfig;
    QUIC_TLS_PROCESS_STATE State;
    QUIC_EVENT ProcessCompleteEvent;
    uint8_t AlpnListBuffer[256];

    TlsContext(_In_z_ const char* Alpn, _In_z_ const char* Sni) :
        Ptr(nullptr), SecConfig(nullptr) {

        AlpnListBuffer[0] = (uint8_t)strlen(Alpn);
        memcpy(&AlpnListBuffer[1], Alpn, AlpnListBuffer[0]);
        QuicEventInitialize(&ProcessCompleteEvent, FALSE, FALSE);

        QuicZeroMemory(&State, sizeof(State));
        State.Buffer = (uint8_t*)QUIC_ALLOC_NONPAGED(8000);
        State.BufferAllocLength = 8000;

        QUIC_CREDENTIAL_CONFIG CredConfig = {
            QUIC_CREDENTIAL_TYPE_NONE,
            QUIC_CREDENTIAL_FLAG_CLIENT & QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION,
            NULL,
            NULL
        };
        VERIFY_QUIC_SUCCESS(
            QuicTlsSecConfigCreate(
                &CredConfig, &SecConfig, OnSecConfigCreateComplete));

        QUIC_CONNECTION Connection = {0};

        QUIC_TRANSPORT_PARAMETERS TP = {0};
        TP.Flags |= QUIC_TP_FLAG_INITIAL_MAX_DATA;
        TP.InitialMaxData = 10000;
        TP.Flags |= QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_LOCAL;
        TP.InitialMaxStreamDataBidiLocal = 10000;
        TP.Flags |= QUIC_TP_FLAG_INITIAL_MAX_STRM_DATA_BIDI_REMOTE;
        TP.InitialMaxStreamDataBidiRemote = 10000;
        TP.Flags |= QUIC_TP_FLAG_INITIAL_MAX_STRMS_BIDI;
        TP.InitialMaxBidiStreams = 3;
        TP.Flags |= QUIC_TP_FLAG_INITIAL_MAX_STRMS_UNI;
        TP.InitialMaxUniStreams = 3;
        TP.Flags |= QUIC_TP_FLAG_INITIAL_SOURCE_CONNECTION_ID;
        TP.InitialSourceConnectionIDLength = sizeof(uint64_t);
        *(uint64_t*)&TP.InitialSourceConnectionID[0] = MagicCid;

        QUIC_TLS_CONFIG Config = {0};
        Config.IsServer = FALSE;
        Config.SecConfig = SecConfig;
        Config.AlpnBuffer = AlpnListBuffer;
        Config.AlpnBufferLength = AlpnListBuffer[0] + 1;
        Config.LocalTPBuffer =
            QuicCryptoTlsEncodeTransportParameters(&Connection, FALSE, &TP, NULL, &Config.LocalTPLength);
        if (!Config.LocalTPBuffer) {
            printf("Failed to encode transport parameters!\n");
        }
        Config.Connection = (QUIC_CONNECTION*)this;
        Config.ProcessCompleteCallback = OnProcessComplete;
        Config.ReceiveTPCallback = OnRecvQuicTP;
        Config.ServerName = Sni;

        VERIFY_QUIC_SUCCESS(
            QuicTlsInitialize(
                &Config,
                &State,
                &Ptr));
    }

    ~TlsContext() {
        QuicTlsUninitialize(Ptr);
        if (SecConfig) {
            QuicTlsSecConfigDelete(SecConfig);
        }
        QuicEventUninitialize(ProcessCompleteEvent);
        QUIC_FREE(State.Buffer);
        for (uint8_t i = 0; i < QUIC_PACKET_KEY_COUNT; ++i) {
            QuicPacketKeyFree(State.ReadKeys[i]);
            QuicPacketKeyFree(State.WriteKeys[i]);
        }
    }

private:

    _Function_class_(QUIC_SEC_CONFIG_CREATE_COMPLETE)
    static void
    QUIC_API
    OnSecConfigCreateComplete(
        _In_ const QUIC_CREDENTIAL_CONFIG* /* CredConfig */,
        _In_opt_ void* Context,
        _In_ QUIC_STATUS /* Status */,
        _In_opt_ QUIC_SEC_CONFIG* SecConfig
        )
    {
        *(QUIC_SEC_CONFIG**)Context = SecConfig;
    }

    QUIC_TLS_RESULT_FLAGS
    ProcessData(
        _In_reads_bytes_(*BufferLength)
            const uint8_t * Buffer,
        _In_ uint32_t * BufferLength
        )
    {
        QuicEventReset(ProcessCompleteEvent);

        auto Result =
            QuicTlsProcessData(
                Ptr,
                QUIC_TLS_CRYPTO_DATA,
                Buffer,
                BufferLength,
                &State);
        if (Result & QUIC_TLS_RESULT_PENDING) {
            QuicEventWaitForever(ProcessCompleteEvent);
            Result = QuicTlsProcessDataComplete(Ptr, BufferLength);
        }

        if (Result & QUIC_TLS_RESULT_ERROR) {
            printf("Failed to process data!\n");
            exit(0);
        }

        return Result;
    }

public:

    QUIC_TLS_RESULT_FLAGS
    ProcessData(
        _Inout_ QUIC_TLS_PROCESS_STATE* PeerState = nullptr
        )
    {
        if (PeerState == nullptr) {
            //
            // Special case for client hello/initial.
            //
            uint32_t Zero = 0;
            return ProcessData(nullptr, &Zero);
        }

        uint32_t Result = 0;

        while (PeerState->BufferLength != 0) {
            uint32_t BufferLength;
            uint32_t StartOffset = PeerState->BufferTotalLength - PeerState->BufferLength;
            if (PeerState->BufferOffset1Rtt != 0 && StartOffset >= PeerState->BufferOffset1Rtt) {
                BufferLength = PeerState->BufferLength;

            } else if (PeerState->BufferOffsetHandshake != 0 && StartOffset >= PeerState->BufferOffsetHandshake) {
                if (PeerState->BufferOffset1Rtt != 0) {
                    BufferLength = (uint16_t)(PeerState->BufferOffset1Rtt - StartOffset);
                } else {
                    BufferLength = PeerState->BufferLength;
                }

            } else {
                if (PeerState->BufferOffsetHandshake != 0) {
                    BufferLength = (uint16_t)(PeerState->BufferOffsetHandshake - StartOffset);
                } else {
                    BufferLength = PeerState->BufferLength;
                }
            }

            Result |=
                (uint32_t)ProcessData(
                    PeerState->Buffer,
                    &BufferLength);

            PeerState->BufferLength -= (uint16_t)BufferLength;
            QuicMoveMemory(
                PeerState->Buffer,
                PeerState->Buffer + BufferLength,
                PeerState->BufferLength);
        }

        return (QUIC_TLS_RESULT_FLAGS)Result;
    }

private:

    static void
    OnProcessComplete(
        _In_ QUIC_CONNECTION* Connection
        )
    {
        QuicEventSet(((TlsContext*)Connection)->ProcessCompleteEvent);
    }

    static BOOLEAN
    OnRecvQuicTP(
        _In_ QUIC_CONNECTION* Connection,
        _In_ uint16_t TPLength,
        _In_reads_(TPLength) const uint8_t* TPBuffer
        )
    {
        UNREFERENCED_PARAMETER(Connection);
        UNREFERENCED_PARAMETER(TPLength);
        UNREFERENCED_PARAMETER(TPBuffer);
        return TRUE;
    }
};

void
PacketWriter::WriteInitialCryptoFrame(
    _In_z_ const char* Alpn,
    _In_z_ const char* Sni,
    _Inout_ uint16_t* Offset,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *Offset)
        uint8_t* Buffer
    )
{
    TlsContext ClientContext(Alpn, Sni);
    ClientContext.ProcessData();

    QUIC_CRYPTO_EX Frame = {
        0, ClientContext.State.BufferLength, ClientContext.State.Buffer
    };

    if (!QuicCryptoFrameEncode(
            &Frame,
            Offset,
            BufferLength,
            Buffer)) {
        printf("QuicCryptoFrameEncode failure!\n");
        exit(0);
    }
}

void
PacketWriter::WriteClientInitialPacket(
    _In_ uint32_t PacketNumber,
    _In_ uint8_t CidLength,
    _In_z_ const char* Alpn,
    _In_z_ const char* Sni,
    _In_ uint16_t BufferLength,
    _Out_writes_to_(BufferLength, *PacketLength)
        uint8_t* Buffer,
    _Out_ uint16_t* PacketLength,
    _Out_ uint16_t* HeaderLength
    )
{
    uint8_t CidBuffer[sizeof(QUIC_CID) + 256] = {0};
    QUIC_CID* Cid = (QUIC_CID*)CidBuffer;
    Cid->IsInitial = TRUE;
    Cid->Length = CidLength;

    uint16_t PayloadLengthOffset = 0;
    uint8_t PacketNumberLength;
    *PacketLength =
        QuicPacketEncodeLongHeaderV1(
            QUIC_VERSION_LATEST,
            QUIC_INITIAL,
            Cid,
            Cid,
            0,
            nullptr,
            PacketNumber,
            BufferLength,
            Buffer,
            &PayloadLengthOffset,
            &PacketNumberLength);

    *HeaderLength = *PacketLength;
    WriteInitialCryptoFrame(Alpn, Sni, PacketLength, BufferLength, Buffer);

    uint16_t PayloadLength = *PacketLength - *HeaderLength;
    QuicVarIntEncode2Bytes(
        PacketNumberLength + PayloadLength + QUIC_ENCRYPTION_OVERHEAD,
        Buffer + PayloadLengthOffset);

    *PacketLength += QUIC_ENCRYPTION_OVERHEAD;
}
