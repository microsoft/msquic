/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#define VERIFY(X) if (!(X)) { printf(#X " FALSE!\n"); exit(0); }

#define MagicCid 0x989898989898989ull

extern const QUIC_HKDF_LABELS HkdfLabels;

class PacketWriter
{
    uint32_t QuicVersion;
    uint8_t CryptoBuffer[4096];
    uint16_t CryptoBufferLength;

    static
    void
    WriteInitialCryptoFrame(
        _In_z_ const char* Alpn,
        _In_z_ const char* Sni,
        _Inout_ uint16_t* Offset,
        _In_ uint16_t BufferLength,
        _Out_writes_to_(BufferLength, *Offset)
            uint8_t* Buffer
        );

public:

    PacketWriter(
        _In_ uint32_t Version,
        _In_z_ const char* Alpn,
        _In_z_ const char* Sni
        );

    void
    WriteClientInitialPacket(
        _In_ uint32_t PacketNumber,
        _In_ uint8_t CidLength,
        _In_ uint16_t BufferLength,
        _Out_writes_to_(BufferLength, *PacketLength)
            uint8_t* Buffer,
        _Out_ uint16_t* PacketLength,
        _Out_ uint16_t* HeaderLength
        );
};
