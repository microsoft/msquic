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

const uint32_t CertValidationIgnoreFlags =
    QUIC_CERTIFICATE_FLAG_IGNORE_UNKNOWN_CA |
    QUIC_CERTIFICATE_FLAG_IGNORE_CERTIFICATE_CN_INVALID;

struct TlsSession
{
    QUIC_TLS_SESSION* Ptr;
    TlsSession() : Ptr(nullptr) {
        VERIFY_QUIC_SUCCESS(QuicTlsSessionInitialize(&Ptr));
    }
    ~TlsSession() {
        QuicTlsSessionUninitialize(Ptr);
    }
};

struct TlsContext
{
    QUIC_TLS* Ptr;
    QUIC_SEC_CONFIG* SecConfig;
    QUIC_TLS_PROCESS_STATE State;
    QUIC_EVENT ProcessCompleteEvent;
    uint8_t AlpnListBuffer[256];

    TlsContext(TlsSession& Session, _In_z_ const char* Alpn, _In_z_ const char* Sni) :
        Ptr(nullptr), SecConfig(nullptr) {
            
        AlpnListBuffer[0] = (uint8_t)strlen(Alpn);
        memcpy(&AlpnListBuffer[1], Alpn, AlpnListBuffer[0]);
        QuicEventInitialize(&ProcessCompleteEvent, FALSE, FALSE);

        QuicZeroMemory(&State, sizeof(State));
        State.Buffer = (uint8_t*)QUIC_ALLOC_NONPAGED(8000);
        State.BufferAllocLength = 8000;

        VERIFY_QUIC_SUCCESS(
            QuicTlsClientSecConfigCreate(
                CertValidationIgnoreFlags, &SecConfig));

        QUIC_TLS_CONFIG Config = {0};
        Config.IsServer = FALSE;
        Config.TlsSession = Session.Ptr;
        Config.SecConfig = SecConfig;
        Config.AlpnBuffer = AlpnListBuffer;
        Config.AlpnBufferLength = AlpnListBuffer[0] + 1;
        Config.LocalTPBuffer =
            (uint8_t*)QUIC_ALLOC_NONPAGED(QuicTlsTPHeaderSize + 2);
        QuicZeroMemory((uint8_t*)Config.LocalTPBuffer, QuicTlsTPHeaderSize + 2);
        Config.LocalTPLength = QuicTlsTPHeaderSize + 2;
        Config.Connection = (QUIC_CONNECTION*)this;
        Config.ProcessCompleteCallback = OnProcessComplete;
        Config.ReceiveTPCallback = OnRecvQuicTP;
        Config.ServerName = Sni;

        QUIC_TLS_PROCESS_STATE State = {0};
        VERIFY_QUIC_SUCCESS(
            QuicTlsInitialize(
                &Config,
                &State,
                &Ptr));
    }

    ~TlsContext() {
        QuicTlsUninitialize(Ptr);
        if (SecConfig) {
            QuicTlsSecConfigRelease(SecConfig);
        }
        QuicEventUninitialize(ProcessCompleteEvent);
        QUIC_FREE(State.Buffer);
        for (uint8_t i = 0; i < QUIC_PACKET_KEY_COUNT; ++i) {
            QuicPacketKeyFree(State.ReadKeys[i]);
            QuicPacketKeyFree(State.WriteKeys[i]);
        }
    }

private:

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

        uint32_t Result;

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
    TlsSession Session;
    {
        TlsContext ClientContext(Session, Alpn, Sni);
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

    uint16_t PayloadLengthOffset;
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