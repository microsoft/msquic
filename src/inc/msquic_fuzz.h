/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file defines an interface to msquic_fuzz which can be used in place
    of msquic to create quic clients or servers. This is an addon which
    exposes hooks into send, receive, and encrypt operations performed by
    the quic library.

    These hooks can be used to create a fuzzer capable of injecting
    payloads into QUIC connections, while still using core library to
    create semantically valid sessions.

    msquic_fuzz also provides a mode of operation which disables the
    use of os-level sockets, and instead provides a "Simulated Receive"
    function, allowing for fuzzers to target and use msquic without
    the need to create unique socket bindings for each quic connection.

--*/

#pragma once

#if defined(__cplusplus)
extern "C" {
#endif

#define QUIC_FUZZ_BUFFER_MAX 0x1000

//
// Callback to be registered and called each time msquic sends a packet.
// In 'Simulated' mode this used to capture the data which would be sent
// via OS sockets.
//
typedef
void
(*QUIC_FUZZ_SEND_CALLBACK_FN) (
    _Inout_ void *CallbackContext,
    _Inout_updates_bytes_(Length) uint8_t *Buffer,
    _In_ DWORD Length
    );

//
// Callback to be registered and called each time msquic receives a packet.
// In 'Simulated' mode this is still called.
//
typedef
void
(*QUIC_FUZZ_RECV_CALLBACK_FN) (
    _Inout_ void *CallbackContext,
    _Inout_updates_bytes_(Length) uint8_t *Buffer,
    _In_ DWORD Length
    );

//
// Callback to be registered and called just prior to msquic encrypting
// a payload. This function may modify or entirely replace the
// datagram's data.
//
typedef
void
(*QUIC_FUZZ_INJECT_CALLBACK_FN) (
    _Inout_ void *CallbackContext,
    _In_ uint8_t *OriginalBuffer,
    _In_ uint32_t OriginalBufferLength,
    _In_ uint16_t HeaderLength,
    _Out_ uint8_t ** NewBuffer,
    _Out_ uint16_t *NewLength
    );

//
// Callback to be registered and called prior to msquic encrypting
// a payload. Can be used to capture or modify valid QUIC payloads.
//
typedef
void
(*QUIC_FUZZ_ENCRYPT_CALLBACK_FN) (
    _Inout_ void *CallbackContext,
    _Inout_updates_bytes_(Length) uint8_t* Buffer,
    _In_ DWORD Length
    );

//
// An internal global structure used to track fuzzer configuration
// and state exposed via msquic_fuzz.
//
typedef struct QUIC_FUZZ_CONTEXT {
    QUIC_FUZZ_SEND_CALLBACK_FN SendCallback;
    QUIC_FUZZ_RECV_CALLBACK_FN RecvCallback;
    QUIC_FUZZ_INJECT_CALLBACK_FN InjectCallback;
    QUIC_FUZZ_ENCRYPT_CALLBACK_FN EncryptCallback;
    uint8_t RedirectDataPath;
    void *CallbackContext;
    //
    // When in 'simulate' mode, is set to the last-used connection's socket
    // structure.
    //
    void *Socket;
    void *RealSendMsg;
    void *RealRecvMsg;
} QUIC_FUZZ_CONTEXT;

extern QUIC_FUZZ_CONTEXT MsQuicFuzzerContext;

//
// Function to enable fuzzing functionality in msquic_fuzz.
//
// CallbackContext is a pointer to an opaque structure that will be
// passed to all callbacks.
//
// Passing a non-zero value as RedirectDataPath will disable
// msquic_fuzz's use of OS sockets, and assume that the consuming
// application will make calls to MsQuicSimulateReceive.
//
void
MsQuicFuzzInit(
    _Inout_ void *CallbackContext,
    _In_ uint8_t RedirectDataPath
    );

//
// Sets callback to be invoked each time msquic_fuzz sends a datagram.
//
void
MsQuicFuzzRegisterSendCallback(
    _In_ QUIC_FUZZ_SEND_CALLBACK_FN Callback
    );

//
// Sets callback to be invoked each time msquic_fuzz receives a datagram.
//
void
MsQuicFuzzRegisterRecvCallback(
    _In_ QUIC_FUZZ_RECV_CALLBACK_FN Callback
    );

//
// Sets callback to be invoked each time msquic_fuzz creates a new datagram.
// to be sent.
//
void
MsQuicFuzzRegisterInjectCallback(
    _In_ QUIC_FUZZ_INJECT_CALLBACK_FN Callback
    );

//
// Sets callback to be invoked each time msquic_fuzz encrypts a datagram.
//
void
MsQuicFuzzRegisterEncryptCallback(
    _In_ QUIC_FUZZ_ENCRYPT_CALLBACK_FN Callback
    );

//
// When operating in 'Simulate' mode, can be called to deliver a datagram.
// to the last-used connection in an msquic_fuzz session.
//
void
MsQuicFuzzSimulateReceive(
    _In_ const QUIC_ADDR *SourceAddress,
    _In_reads_(PacketLength) uint8_t *PacketData,
    _In_ uint16_t PacketLength
    );

#if defined(__cplusplus)
}
#endif
