/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#define VERIFY(X) if (!(X)) { printf(#X " FALSE!\n"); exit(0); }

#define MagicCid 0x989898989898989ull

struct PacketWriter
{
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

    static
    void
    WriteClientInitialPacket(
        _In_ uint32_t PacketNumber,
        _In_ uint8_t CidLength,
        _In_z_ const char* Alpn,
        _In_z_ const char* Sni,
        _In_ uint16_t BufferLength,
        _Out_writes_to_(BufferLength, *PacketLength)
            uint8_t* Buffer,
        _Out_ uint16_t* PacketLength,
        _Out_ uint16_t* HeaderLength
        );
};
