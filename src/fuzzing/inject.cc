/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Fuzzes msquic's untrusted datagram receive path.

    An in-process QUIC server (registration + configuration + listener over
    loopback UDP) is created once. Each fuzz input is turned into UDP
    datagrams that are sent to the listener through the kernel, so the
    packets flow through the real datapath, worker and receive machinery:

      header parse -> version handling -> Initial key derivation ->
      decryption -> frame parsing -> connection/stream state machine ->
      TLS handshake (CRYPTO frames are fed to the TLS stack).

    The fuzz input controls the packet mode (v1/v2 Initial, unknown version
    to trigger Version Negotiation, short header for stateless-reset paths),
    the destination CID and the frame payload bytes. The Initial packets are
    encrypted with the library's own Initial key derivation, so decryption
    succeeds and the attacker-controlled frames are actually processed
    instead of being dropped at the decryption step.

--*/

#define QUIC_TEST_APIS 1
#define QUIC_API_ENABLE_PREVIEW_FEATURES 1
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <string>
#include <vector>

#include "msquichelper.h"
#include "msquic.hpp"
#include "quic_crypt.h"

//
// The datagram size used for Initial packets. RFC 9000 requires clients to
// pad Initial datagrams to at least 1200 bytes; the padding (zero bytes,
// i.e. PADDING frames) is part of the encrypted payload.
//
static const uint16_t InitialDatagramSize = 1200;
static const uint8_t ScidLength = 8;

static const QUIC_BUFFER InjectAlpn = { sizeof("fuzz") - 1, (uint8_t*)"fuzz" };

//
// Version-specific Initial salt and HKDF labels (public constants from the
// QUIC specifications, matching msquic's QuicSupportedVersionList). Wire
// versions are the raw big-endian header bytes.
//
struct INJECT_VERSION {
    uint8_t WireVersion[4];
    uint8_t Salt[20];
    QUIC_HKDF_LABELS Labels;
};

static const INJECT_VERSION InjectVersions[] = {
    { { 0x00, 0x00, 0x00, 0x01 },   // QUIC v1
      { 0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
        0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a },
      { "quic key", "quic iv", "quic hp", "quic ku" } },
    { { 0x6b, 0x33, 0x43, 0xcf },   // QUIC v2
      { 0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
        0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9 },
      { "quicv2 key", "quicv2 iv", "quicv2 hp", "quicv2 ku" } },
};

static MsQuicApi* Api = nullptr;
static HQUIC Registration = nullptr;
static HQUIC Configuration = nullptr;
static HQUIC Listener = nullptr;
static QUIC_CREDENTIAL_CONFIG* CredConfig = nullptr;
static QUIC_ADDR ServerAddr;
static int SendSocket = -1;
static uint32_t PacketNumber = 0;

static void CleanupServer(void);

static QUIC_STATUS QUIC_API
ListenerCallback(
    _In_ HQUIC /* Listener */,
    _In_opt_ void* /* Context */,
    _Inout_ QUIC_LISTENER_EVENT* Event
    )
{
    if (Event->Type == QUIC_LISTENER_EVENT_NEW_CONNECTION) {
        //
        // Accept every connection; the attacker-controlled handshake data
        // is what we want the TLS stack to chew on.
        //
        return Api->ConnectionSetConfiguration(
            Event->NEW_CONNECTION.Connection, Configuration);
    }
    return QUIC_STATUS_SUCCESS;
}

static bool
EnsureSetup(void)
{
    static bool Done = false;
    if (Done) {
        return true;
    }

    Api = new (std::nothrow) MsQuicApi();
    if (Api == nullptr || !Api->IsValid()) {
        return false;
    }

    QUIC_REGISTRATION_CONFIG RegConfig = { "inject", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
    if (QUIC_FAILED(Api->RegistrationOpen(&RegConfig, &Registration))) {
        return false;
    }

    auto LocalCredConfig = CxPlatGetSelfSignedCert(CXPLAT_SELF_SIGN_CERT_USER, FALSE, NULL);
    if (LocalCredConfig == nullptr) {
        return false;
    }
    CredConfig = LocalCredConfig;

    QUIC_SETTINGS Settings{0};
    Settings.PeerBidiStreamCount = 10;
    Settings.IsSet.PeerBidiStreamCount = TRUE;
    Settings.PeerUnidiStreamCount = 10;
    Settings.IsSet.PeerUnidiStreamCount = TRUE;

    if (QUIC_FAILED(
        Api->ConfigurationOpen(
            Registration, &InjectAlpn, 1, &Settings, sizeof(Settings),
            nullptr, &Configuration))) {
        return false;
    }
    if (QUIC_FAILED(Api->ConfigurationLoadCredential(Configuration, CredConfig))) {
        return false;
    }

    if (QUIC_FAILED(Api->ListenerOpen(Registration, ListenerCallback, nullptr, &Listener))) {
        return false;
    }

    QUIC_ADDR BindAddr{0};
    QuicAddrSetFamily(&BindAddr, QUIC_ADDRESS_FAMILY_INET);
    QuicAddrSetPort(&BindAddr, 0); // ephemeral: no fixed-port collisions
    if (QUIC_FAILED(Api->ListenerStart(Listener, &InjectAlpn, 1, &BindAddr))) {
        return false;
    }

    uint32_t Size = sizeof(ServerAddr);
    if (QUIC_FAILED(
        Api->GetParam(Listener, QUIC_PARAM_LISTENER_LOCAL_ADDRESS, &Size, &ServerAddr))) {
        return false;
    }

    SendSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (SendSocket < 0) {
        return false;
    }

    //
    // The server intentionally lives for the whole process; release it in
    // an atexit handler so LeakSanitizer sees a clean shutdown instead of
    // harness-owned allocations.
    //
    atexit(CleanupServer);

    Done = true;
    return true;
}

static void
CleanupServer(void)
{
    if (Listener != nullptr) {
        Api->ListenerClose(Listener);
        Listener = nullptr;
    }
    if (Configuration != nullptr) {
        Api->ConfigurationClose(Configuration);
        Configuration = nullptr;
    }
    if (Registration != nullptr) {
        Api->RegistrationClose(Registration);
        Registration = nullptr;
    }
    if (CredConfig != nullptr) {
        CxPlatFreeSelfSignedCert(CredConfig);
        CredConfig = nullptr;
    }
    if (SendSocket >= 0) {
        close(SendSocket);
        SendSocket = -1;
    }
    delete Api;
    Api = nullptr;
}

//
// Writes a QUIC variable-length integer. Returns the number of bytes written
// (1, 2 or 4); the value must fit, which all our uses do.
//
static uint8_t
WriteVarInt(
    _In_ uint64_t Value,
    _Out_writes_bytes_(4) uint8_t* Buffer
    )
{
    if (Value < 0x40) {
        Buffer[0] = (uint8_t)Value;
        return 1;
    }
    if (Value < 0x4000) {
        Buffer[0] = (uint8_t)((Value >> 8) | 0x40);
        Buffer[1] = (uint8_t)Value;
        return 2;
    }
    Buffer[0] = (uint8_t)((Value >> 24) | 0x80);
    Buffer[1] = (uint8_t)(Value >> 16);
    Buffer[2] = (uint8_t)(Value >> 8);
    Buffer[3] = (uint8_t)Value;
    return 4;
}

//
// Builds, encrypts and sends one Initial packet whose decrypted payload is
// the attacker-controlled frames (zero padded to the RFC minimum datagram
// size). Uses the library's own Initial key derivation, so the server side
// successfully decrypts and processes the frames.
//
static void
SendInitialPacket(
    _In_ const INJECT_VERSION* Version,
    _In_reads_(DcidLength) const uint8_t* Dcid,
    _In_ uint8_t DcidLength,
    _In_reads_bytes_(FramesLength) const uint8_t* Frames,
    _In_ uint16_t FramesLength
    )
{
    uint8_t Datagram[InitialDatagramSize];
    memset(Datagram, 0, sizeof(Datagram));

    QUIC_PACKET_KEY* WriteKey = nullptr;
    if (QUIC_FAILED(
        QuicPacketKeyCreateInitial(
            FALSE, &Version->Labels, Version->Salt, DcidLength, Dcid,
            NULL, &WriteKey)) ||
        WriteKey == nullptr) {
        return;
    }

    size_t Off = 0;
    Datagram[Off++] = 0xC3;              // long header, fixed bit, Initial, 4-byte pn
    Datagram[Off++] = Version->WireVersion[0];
    Datagram[Off++] = Version->WireVersion[1];
    Datagram[Off++] = Version->WireVersion[2];
    Datagram[Off++] = Version->WireVersion[3];
    Datagram[Off++] = DcidLength;
    memcpy(Datagram + Off, Dcid, DcidLength);
    Off += DcidLength;
    Datagram[Off++] = ScidLength;
    memcpy(Datagram + Off, "INJECTSC", ScidLength);
    Off += ScidLength;
    Datagram[Off++] = 0x00;              // token length

    size_t PnOffset = Off + 2;           // worst case length varint
    size_t MaxFrames = InitialDatagramSize - PnOffset - 4 - CXPLAT_ENCRYPTION_OVERHEAD;
    uint16_t PayloadLength =
        (uint16_t)(FramesLength < MaxFrames ? FramesLength : MaxFrames);

    Off += WriteVarInt((uint64_t)(4 + PayloadLength + CXPLAT_ENCRYPTION_OVERHEAD),
                       Datagram + Off);
    size_t AadLength = Off;

    uint32_t Pn = PacketNumber++;
    Datagram[Off++] = (uint8_t)(Pn >> 24);
    Datagram[Off++] = (uint8_t)(Pn >> 16);
    Datagram[Off++] = (uint8_t)(Pn >> 8);
    Datagram[Off++] = (uint8_t)Pn;

    uint8_t* Payload = Datagram + Off;
    memcpy(Payload, Frames, PayloadLength);           // trailing zeros = PADDING

    uint8_t Iv[CXPLAT_IV_LENGTH];
    memcpy(Iv, WriteKey->Iv, sizeof(Iv));
    Iv[0] ^= (uint8_t)(Pn >> 24);
    Iv[1] ^= (uint8_t)(Pn >> 16);
    Iv[2] ^= (uint8_t)(Pn >> 8);
    Iv[3] ^= (uint8_t)Pn;

    if (QUIC_FAILED(
        CxPlatEncrypt(
            WriteKey->PacketKey, Iv, (uint16_t)AadLength, Datagram,
            (uint16_t)(InitialDatagramSize - Off), Payload))) {
        QuicPacketKeyFree(WriteKey);
        return;
    }

    uint8_t Mask[16];
    if (QUIC_FAILED(CxPlatHpComputeMask(WriteKey->HeaderKey, 1, Payload, Mask))) {
        QuicPacketKeyFree(WriteKey);
        return;
    }
    Datagram[0] ^= Mask[0] & 0x1f;
    for (uint8_t i = 0; i < 4; ++i) {
        Datagram[PnOffset + i] ^= Mask[1 + i];
    }

    sendto(
        SendSocket, Datagram, InitialDatagramSize, 0,
        (struct sockaddr*)&ServerAddr, sizeof(ServerAddr));

    QuicPacketKeyFree(WriteKey);
}

//
// Unknown-version packet: drives Version Negotiation and the early header
// parsing paths. No encryption involved.
//
static void
SendVersionNegotiationTrigger(
    _In_reads_(DcidLength) const uint8_t* Dcid,
    _In_ uint8_t DcidLength
    )
{
    uint8_t Datagram[64];
    size_t Off = 0;
    Datagram[Off++] = 0xC0;              // long header, version-unknown form
    Datagram[Off++] = 0x1a; Datagram[Off++] = 0x2a; Datagram[Off++] = 0x3a; Datagram[Off++] = 0x4a;
    Datagram[Off++] = DcidLength;
    memcpy(Datagram + Off, Dcid, DcidLength);
    Off += DcidLength;
    Datagram[Off++] = ScidLength;
    memcpy(Datagram + Off, "INJECTSC", ScidLength);
    Off += ScidLength;

    sendto(
        SendSocket, Datagram, (uint16_t)Off, 0,
        (struct sockaddr*)&ServerAddr, sizeof(ServerAddr));
}

//
// Short-header packet for an (unknown) connection: drives the connection
// lookup, stateless-reset and drop paths.
//
static void
SendShortHeaderPacket(
    _In_reads_(DcidLength) const uint8_t* Dcid,
    _In_ uint8_t DcidLength,
    _In_reads_bytes_(Length) const uint8_t* Data,
    _In_ uint16_t Length
    )
{
    uint8_t Datagram[1280];
    size_t Off = 0;
    Datagram[Off++] = 0x43;              // short header, fixed bit, 4-byte pn
    memcpy(Datagram + Off, Dcid, DcidLength);
    Off += DcidLength;
    uint16_t Copy = (uint16_t)(Length < (sizeof(Datagram) - Off) ? Length : (sizeof(Datagram) - Off));
    memcpy(Datagram + Off, Data, Copy);
    Off += Copy;

    sendto(
        SendSocket, Datagram, (uint16_t)Off, 0,
        (struct sockaddr*)&ServerAddr, sizeof(ServerAddr));
}

//
// A minimal, well-formed TLS 1.3 ClientHello (handshake message, no record
// layer - that is what a QUIC CRYPTO frame carries). Exercises the TLS
// stack's ClientHello parsing when placed in a CRYPTO frame.
//
static uint16_t
WriteCryptoClientHello(
    _Out_writes_bytes_(300) uint8_t* Frame
    )
{
    uint8_t Ch[300];
    size_t Off = 0;
    Ch[Off++] = 0x01;                    // ClientHello
    size_t LenOffset = Off;
    Ch[Off++] = 0x00; Ch[Off++] = 0x00;  // length, patched below
    Ch[Off++] = 0x03; Ch[Off++] = 0x03;  // legacy version
    for (int i = 0; i < 32; ++i) { Ch[Off++] = (uint8_t)i; } // random
    Ch[Off++] = 0x20;                    // session id
    for (int i = 0; i < 32; ++i) { Ch[Off++] = (uint8_t)(0x40 + i); }
    Ch[Off++] = 0x00; Ch[Off++] = 0x06;  // cipher suites
    Ch[Off++] = 0x13; Ch[Off++] = 0x01;
    Ch[Off++] = 0x13; Ch[Off++] = 0x02;
    Ch[Off++] = 0x13; Ch[Off++] = 0x03;
    Ch[Off++] = 0x01; Ch[Off++] = 0x00;  // compression
    Ch[Off++] = 0x00; Ch[Off++] = 0x45;  // extensions length
    // key_share (0x0033), x25519
    Ch[Off++] = 0x00; Ch[Off++] = 0x33; Ch[Off++] = 0x00; Ch[Off++] = 0x26;
    Ch[Off++] = 0x00; Ch[Off++] = 0x1d; Ch[Off++] = 0x00; Ch[Off++] = 0x20;
    for (int i = 0; i < 32; ++i) { Ch[Off++] = (uint8_t)(0x80 + i); }
    // supported_versions (0x002b)
    Ch[Off++] = 0x00; Ch[Off++] = 0x2b; Ch[Off++] = 0x00; Ch[Off++] = 0x05;
    Ch[Off++] = 0x04; Ch[Off++] = 0x03; Ch[Off++] = 0x04; Ch[Off++] = 0x03; Ch[Off++] = 0x03;
    // alpn (0x0010), "fuzz"
    Ch[Off++] = 0x00; Ch[Off++] = 0x10; Ch[Off++] = 0x00; Ch[Off++] = 0x0c;
    Ch[Off++] = 0x00; Ch[Off++] = 0x0a; Ch[Off++] = 0x04;
    Ch[Off++] = 'f'; Ch[Off++] = 'u'; Ch[Off++] = 'z'; Ch[Off++] = 'z';
    Ch[LenOffset] = (uint8_t)((Off - LenOffset - 2) >> 8);
    Ch[LenOffset + 1] = (uint8_t)(Off - LenOffset - 2);

    Frame[0] = 0x06;                     // CRYPTO frame type
    Frame[1] = 0x00;                     // offset varint = 0
    uint8_t LenVarint[4];
    uint8_t LenBytes = WriteVarInt(Off, LenVarint);
    memcpy(Frame + 2, LenVarint, LenBytes);
    memcpy(Frame + 2 + LenBytes, Ch, Off);

    return (uint16_t)(2 + LenBytes + Off);
}

//
// When invoked with INJECT_GEN_SEEDS set, writes a small structured seed
// corpus and exits. Called from LLVMFuzzerInitialize so build scripts can
// generate the corpus with the same encoder the target uses.
//
static void
GenerateSeeds(
    _In_ const char* Dir
    )
{
    uint8_t Dcid[8] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
    uint8_t Frames[1200];
    char Path[512];

    struct SEED_DEF { const char* Name; uint8_t Mode; uint16_t FramesLength; } Seeds[] = {
        { "00_ping",            0, 1 },  // PING
        { "01_crypto_hello",    0, 0 },  // CRYPTO ClientHello (built below)
        { "02_ack",             0, 9 },  // ACK
        { "03_v1_alt_dcid",     4, 1 },
        { "04_v2_initial",      1, 1 },
        { "05_vn_trigger",      2, 1 },
        { "06_short_header",    3, 33 },
        { "07_crypto_ping_mix", 0, 0 },
    };

    for (auto& Seed : Seeds) {
        if (strcmp(Seed.Name, "01_crypto_hello") == 0 ||
            strcmp(Seed.Name, "07_crypto_ping_mix") == 0) {
            Frames[0] = 0x01;                        // PING
            uint16_t Len = WriteCryptoClientHello(Frames + 1);
            if (Seed.FramesLength != 0) {
                Frames[1 + Len] = 0x01;              // trailing PING
                Len += 2;
            }
            Seed.FramesLength = (uint16_t)(1 + Len);
        } else if (strcmp(Seed.Name, "02_ack") == 0) {
            Frames[0] = 0x02;                        // ACK, smallest form
            memset(Frames + 1, 0, Seed.FramesLength - 1);
        } else {
            memset(Frames, 0, Seed.FramesLength);
            Frames[0] = 0x01;                        // PING
        }

        std::string Input;
        Input.push_back((char)Seed.Mode);
        if (Seed.Mode == 4) {
            Input.push_back((char)sizeof(Dcid));
            Input.append((const char*)Dcid, sizeof(Dcid));
        }
        Input.append((const char*)Frames, Seed.FramesLength);

        snprintf(Path, sizeof(Path), "%s/%s.bin", Dir, Seed.Name);
        FILE* F = fopen(Path, "wb");
        if (F != nullptr) {
            fwrite(Input.data(), 1, Input.size(), F);
            fclose(F);
        }
    }
}

static void
InjectOneInput(
    _In_reads_bytes_(Size) const uint8_t* Data,
    _In_ size_t Size
    )
{
    if (Size < 2) {
        return;
    }

    uint8_t Mode = (uint8_t)(Data[0] & 0x07);
    const uint8_t* Frames = Data + 1;
    uint16_t FramesLength = (uint16_t)(Size - 1);

    uint8_t Dcid[8] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };

    switch (Mode) {
    case 1:  // QUIC v2 Initial
        SendInitialPacket(&InjectVersions[1], Dcid, sizeof(Dcid), Frames, FramesLength);
        break;
    case 2:  // Version Negotiation trigger
        SendVersionNegotiationTrigger(Dcid, sizeof(Dcid));
        break;
    case 3:  // short header for an unknown connection
        SendShortHeaderPacket(Dcid, sizeof(Dcid), Frames, FramesLength);
        break;
    case 4:  // QUIC v1 Initial with a different (fixed) destination CID
        if (Size < 3) {
            return;
        }
        SendInitialPacket(&InjectVersions[0], Dcid + 2, sizeof(Dcid) - 2, Frames, FramesLength);
        break;
    default: // QUIC v1 Initial
        SendInitialPacket(&InjectVersions[0], Dcid, sizeof(Dcid), Frames, FramesLength);
        break;
    }

    //
    // Give the msquic worker a moment to drain the datagram, otherwise a
    // fast loop only fills the socket buffer and drops inputs.
    //
    usleep(120);
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    const char* GenDir = getenv("INJECT_GEN_SEEDS");
    if (GenDir != nullptr) {
        if (EnsureSetup()) {
            GenerateSeeds(GenDir);
        }
        exit(0);
    }
    EnsureSetup();
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!EnsureSetup()) {
        return 0;
    }
    InjectOneInput(data, size);
    return 0;
}
