/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#if QUIC_LOG_BUFFERS
//
// Logs a buffer.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicLogBuffer(
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer,
    _In_ uint32_t BufferLength
    );
#else
#define QuicLogBuffer(Buffer, BufferLength) \
    UNREFERENCED_PARAMETER(Buffer); UNREFERENCED_PARAMETER(BufferLength)
#endif

//
// Decompress a packet number based on the expected next packet number.
// A compressed packet number is just the lowest N bytes of the full packet
// number. To decompress the packet number, we do a bit of math to find the
// closest packet number to the next expected packet number, that has the
// given low bytes.
//
inline
uint64_t
QuicPacketNumberDecompress(
    _In_ uint64_t ExpectedPacketNumber,
    _In_ uint64_t CompressedPacketNumber,
    _In_ uint8_t CompressedPacketNumberBytes
    )
{
    QUIC_DBG_ASSERT(CompressedPacketNumberBytes < 8);
    const uint64_t Mask = 0xFFFFFFFFFFFFFFFF << (8 * CompressedPacketNumberBytes);
    const uint64_t PacketNumberInc = (~Mask) + 1;
    uint64_t PacketNumber = (Mask & ExpectedPacketNumber) | CompressedPacketNumber;

    if (PacketNumber < ExpectedPacketNumber) {

        //
        // If our intermediate packet number is less than the expected packet
        // number, then we need see if we would be closer to 'next' high bit
        // packet number.
        //

        uint64_t High = ExpectedPacketNumber - PacketNumber;
        uint64_t Low = PacketNumberInc - High;
        if (Low < High) {
            PacketNumber += PacketNumberInc;
        }

    } else {

        //
        // If our intermediate packet number is greater than or equal to the
        // expected packet number, then we need see if we would be closer to
        // 'previous' high bit packet number.
        //

        uint64_t Low = PacketNumber - ExpectedPacketNumber;
        uint64_t High = PacketNumberInc - Low;
        if (High <= Low && PacketNumber >= PacketNumberInc) {
            PacketNumber -= PacketNumberInc;
        }
    }

    return PacketNumber;
}
