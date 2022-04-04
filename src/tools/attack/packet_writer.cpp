/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma warning(disable:4200)  // nonstandard extension used: bit field types other than int
#pragma warning(disable:4201)  // nonstandard extension used: nameless struct/union
#pragma warning(disable:4204)  // nonstandard extension used: non-constant aggregate initializer
#pragma warning(disable:4214)  // nonstandard extension used: zero-sized array in struct/union
#pragma warning(disable:28931) // Unused Assignment

#include "precomp.h" // from 'core' dir
#include "msquichelper.h"

#include "packet_writer.h"

#define VERIFY_QUIC_SUCCESS(result, ...) \
    if (QUIC_FAILED(result)) { printf(#result " failed.\n"); exit(0); }

struct TlsContext
{
    CXPLAT_TLS* Ptr;
    CXPLAT_SEC_CONFIG* SecConfig;
    CXPLAT_TLS_PROCESS_STATE State;
    uint8_t AlpnListBuffer[256];

    TlsContext(_In_z_ const char* Alpn, _In_z_ const char* Sni) :
        Ptr(nullptr), SecConfig(nullptr) {

        AlpnListBuffer[0] = (uint8_t)strlen(Alpn);
        memcpy(&AlpnListBuffer[1], Alpn, AlpnListBuffer[0]);

        CxPlatZeroMemory(&State, sizeof(State));
        State.Buffer = (uint8_t*)CXPLAT_ALLOC_NONPAGED(8000, QUIC_POOL_TOOL);
        State.BufferAllocLength = 8000;

        QUIC_CREDENTIAL_CONFIG CredConfig = {
            QUIC_CREDENTIAL_TYPE_NONE,
            QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION,
            NULL, NULL, NULL, NULL
        };
        CXPLAT_TLS_CALLBACKS TlsCallbacks = {
            OnRecvQuicTP,
            NULL
        };
        VERIFY_QUIC_SUCCESS(
            CxPlatTlsSecConfigCreate(
                &CredConfig,
                CXPLAT_TLS_CREDENTIAL_FLAG_NONE,
                &TlsCallbacks,
                &SecConfig,
                OnSecConfigCreateComplete));

        QUIC_CONNECTION Connection = {};

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

        CXPLAT_TLS_CONFIG Config = {0};
        Config.IsServer = FALSE;
        Config.SecConfig = SecConfig;
        Config.HkdfLabels = &HkdfLabels;
        Config.AlpnBuffer = AlpnListBuffer;
        Config.AlpnBufferLength = AlpnListBuffer[0] + 1;
        Config.LocalTPBuffer =
            QuicCryptoTlsEncodeTransportParameters(&Connection, FALSE, &TP, NULL, &Config.LocalTPLength);
        if (!Config.LocalTPBuffer) {
            printf("Failed to encode transport parameters!\n");
        }
        Config.Connection = (QUIC_CONNECTION*)this;
        Config.ServerName = Sni;

        VERIFY_QUIC_SUCCESS(
            CxPlatTlsInitialize(
                &Config,
                &State,
                &Ptr));
    }

    ~TlsContext() {
        CxPlatTlsUninitialize(Ptr);
        if (SecConfig) {
            CxPlatTlsSecConfigDelete(SecConfig);
        }
        CXPLAT_FREE(State.Buffer, QUIC_POOL_TOOL);
        for (uint8_t i = 0; i < QUIC_PACKET_KEY_COUNT; ++i) {
            QuicPacketKeyFree(State.ReadKeys[i]);
            QuicPacketKeyFree(State.WriteKeys[i]);
        }
    }

private:

    _Function_class_(CXPLAT_SEC_CONFIG_CREATE_COMPLETE)
    static void
    QUIC_API
    OnSecConfigCreateComplete(
        _In_ const QUIC_CREDENTIAL_CONFIG* /* CredConfig */,
        _In_opt_ void* Context,
        _In_ QUIC_STATUS /* Status */,
        _In_opt_ CXPLAT_SEC_CONFIG* SecConfig
        )
    {
        *(CXPLAT_SEC_CONFIG**)Context = SecConfig;
    }

    CXPLAT_TLS_RESULT_FLAGS
    ProcessData(
        _In_reads_bytes_(*BufferLength)
            const uint8_t * Buffer,
        _In_ uint32_t * BufferLength
        )
    {
        auto Result =
            CxPlatTlsProcessData(
                Ptr,
                CXPLAT_TLS_CRYPTO_DATA,
                Buffer,
                BufferLength,
                &State);

        if (Result & CXPLAT_TLS_RESULT_ERROR) {
            printf("Failed to process data!\n");
            exit(0);
        }

        return Result;
    }

public:

    CXPLAT_TLS_RESULT_FLAGS
    ProcessData(
        _Inout_ CXPLAT_TLS_PROCESS_STATE* PeerState = nullptr
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
            CxPlatMoveMemory(
                PeerState->Buffer,
                PeerState->Buffer + BufferLength,
                PeerState->BufferLength);
        }

        return (CXPLAT_TLS_RESULT_FLAGS)Result;
    }

private:

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

PacketWriter::PacketWriter(
    _In_ uint32_t Version,
    _In_z_ const char* Alpn,
    _In_z_ const char* Sni
    )
{
    QuicVersion = Version;
    uint16_t BufferSize = sizeof(CryptoBuffer);
    CryptoBufferLength = 0;
    WriteInitialCryptoFrame(
        Alpn, Sni, &CryptoBufferLength, BufferSize, CryptoBuffer);
}

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
            QuicVersion,
            QUIC_INITIAL_V1,
            Cid,
            Cid,
            0,
            nullptr,
            PacketNumber,
            BufferLength,
            Buffer,
            &PayloadLengthOffset,
            &PacketNumberLength);
    if (*PacketLength + CryptoBufferLength > BufferLength) {
        printf("Crypto Too Big!\n");
        exit(0);
    }

    QuicVarIntEncode2Bytes(
        PacketNumberLength + CryptoBufferLength + CXPLAT_ENCRYPTION_OVERHEAD,
        Buffer + PayloadLengthOffset);
    *HeaderLength = *PacketLength;

    CxPlatCopyMemory(Buffer + *PacketLength, CryptoBuffer, CryptoBufferLength);
    *PacketLength += CryptoBufferLength;
    *PacketLength += CXPLAT_ENCRYPTION_OVERHEAD;
}
