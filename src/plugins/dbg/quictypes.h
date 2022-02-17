/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Debugger Extension helper for QUIC Types.

--*/

#pragma once

#include "quicdbg.h"

#pragma warning(disable:4201)  // nonstandard extension used: nameless struct/union

typedef enum QUIC_HANDLE_TYPE {

    QUIC_HANDLE_TYPE_REGISTRATION,
    QUIC_HANDLE_TYPE_CONFIGURATION,
    QUIC_HANDLE_TYPE_LISTENER,
    QUIC_HANDLE_TYPE_CONNECTION_CLIENT,
    QUIC_HANDLE_TYPE_CONNECTION_SERVER,
    QUIC_HANDLE_TYPE_STREAM

} QUIC_HANDLE_TYPE;

typedef union QUIC_STREAM_FLAGS {
    uint32_t AllFlags;
    struct {
        BOOLEAN Allocated               : 1;    // Allocated by Connection. Used for Debugging.
        BOOLEAN Initialized             : 1;    // Initialized successfully. Used for Debugging.
        BOOLEAN Started                 : 1;    // The app has started the stream.
        BOOLEAN Unidirectional          : 1;    // Sends/receives in 1 direction only.
        BOOLEAN Opened0Rtt              : 1;    // A 0-RTT packet opened the stream.
        BOOLEAN IndicatePeerAccepted    : 1;    // The app requested the PEER_ACCEPTED event.

        BOOLEAN SendOpen                : 1;    // Send a STREAM frame immediately on start.
        BOOLEAN SendOpenAcked           : 1;    // A STREAM frame has been acknowledged.

        BOOLEAN LocalNotAllowed         : 1;    // Peer's unidirectional stream.
        BOOLEAN LocalCloseFin           : 1;    // Locally closed (graceful).
        BOOLEAN LocalCloseReset         : 1;    // Locally closed (locally aborted).
        BOOLEAN ReceivedStopSending     : 1;    // Peer sent STOP_SENDING frame.
        BOOLEAN LocalCloseAcked         : 1;    // Any close acknowledged.
        BOOLEAN FinAcked                : 1;    // Our FIN was acknowledged.
        BOOLEAN InRecovery              : 1;    // Lost data is being retransmitted and is
                                                // unacknowledged.

        BOOLEAN RemoteNotAllowed        : 1;    // Our unidirectional stream.
        BOOLEAN RemoteCloseFin          : 1;    // Remotely closed.
        BOOLEAN RemoteCloseReset        : 1;    // Remotely closed (remotely aborted).
        BOOLEAN SentStopSending         : 1;    // We sent STOP_SENDING frame.
        BOOLEAN RemoteCloseAcked        : 1;    // Any close acknowledged.

        BOOLEAN SendEnabled             : 1;    // Application is allowed to send data.
        BOOLEAN ReceiveEnabled          : 1;    // Application is ready for receive callbacks.
        BOOLEAN ReceiveFlushQueued      : 1;    // The receive flush operation is queued.
        BOOLEAN ReceiveDataPending      : 1;    // Data (or FIN) is queued and ready for delivery.
        BOOLEAN ReceiveCallPending      : 1;    // There is an uncompleted receive to the app.
        BOOLEAN SendDelayed             : 1;    // A delayed send is currently queued.

        BOOLEAN HandleSendShutdown      : 1;    // Send shutdown complete callback delivered.
        BOOLEAN HandleShutdown          : 1;    // Shutdown callback delivered.
        BOOLEAN HandleClosed            : 1;    // Handle closed by application layer.

        BOOLEAN ShutdownComplete        : 1;    // Both directions have been shutdown and acknowledged.
        BOOLEAN Uninitialized           : 1;    // Uninitialize started/completed. Used for Debugging.
        BOOLEAN Freed                   : 1;    // Freed after last ref count released. Used for Debugging.
    };
} QUIC_STREAM_FLAGS;

typedef union QUIC_CONNECTION_STATE {
    uint32_t Flags;
    struct {
        BOOLEAN Allocated       : 1;    // Allocated. Used for Debugging.
        BOOLEAN Initialized     : 1;    // Initialized successfully. Used for Debugging.
        BOOLEAN Started         : 1;    // Handshake started.
        BOOLEAN Connected       : 1;    // Handshake completed.
        BOOLEAN ClosedLocally   : 1;    // Locally closed.
        BOOLEAN ClosedRemotely  : 1;    // Remotely closed.
        BOOLEAN AppClosed       : 1;    // Application (not transport) closed connection.
        BOOLEAN HandleShutdown  : 1;    // Shutdown callback delivered for handle.
        BOOLEAN HandleClosed    : 1;    // Handle closed by application layer.
        BOOLEAN Uninitialized   : 1;    // Uninitialize started/completed.
        BOOLEAN Freed           : 1;    // Freed. Used for Debugging.

        //
        // Indicates whether packet number encryption is enabled or not for the
        // connection.
        //
        BOOLEAN HeaderProtectionEnabled : 1; // TODO - Remove since it's not used

        //
        // Indicates that 1-RTT encryption has been configured/negotiated to be
        // disabled.
        //
        BOOLEAN Disable1RttEncrytion : 1;

        //
        // Indicates whether the current 'owner' of the connection is internal
        // or external. Client connections are always externally owned. Server
        // connections are internally owned until they are indicated to the
        // appliciation, via the listener callback.
        //
        BOOLEAN ExternalOwner : 1;

        //
        // Indicate the connection is currently in the registration's list of
        // connections and needs to be removed.
        //
        BOOLEAN Registered : 1;

        //
        // This flag indicates the client has gotten response from the server.
        // The response could either be a Retry or server Initial packet. Once
        // this happens, the client must not accept any received Retry packets.
        //
        BOOLEAN GotFirstServerResponse : 1;

        //
        // This flag indicates the Retry packet was used during the handshake.
        //
        BOOLEAN HandshakeUsedRetryPacket : 1;

        //
        // We have confirmed that the peer has completed the handshake.
        //
        BOOLEAN HandshakeConfirmed : 1;

        //
        // The (server side) connection has been accepted by a listener.
        //
        BOOLEAN ListenerAccepted : 1;

        //
        // Indicates whether the local address has been set. It can be set either
        // via the QUIC_PARAM_CONN_LOCAL_ADDRESS parameter by the application, or
        // via UDP binding creation during the connection start phase.
        //
        BOOLEAN LocalAddressSet : 1;

        //
        // Indicates whether the remote address has been set. It can be set either
        // via the QUIC_PARAM_CONN_REMOTE_ADDRESS parameter by the application,
        // before starting the connection, or via name resolution during the
        // connection start phase.
        //
        BOOLEAN RemoteAddressSet : 1;

        //
        // Indicates the peer transport parameters variable has been set.
        //
        BOOLEAN PeerTransportParameterValid : 1;

        //
        // Indicates the connection needs to queue onto a new worker thread.
        //
        BOOLEAN UpdateWorker : 1;

        //
        // The peer didn't acknowledge the shutdown.
        //
        BOOLEAN ShutdownCompleteTimedOut : 1;

        //
        // The application needs to be notified of a shutdown complete event.
        //
        BOOLEAN SendShutdownCompleteNotif : 1;

        //
        // Indicates whether this connection shares bindings with others.
        //
        BOOLEAN ShareBinding : 1;

        //
        // Indicates the TestTransportParameter variable has been set by the app.
        //
        BOOLEAN TestTransportParameterSet : 1;

        //
        // Indicates the connection is using the round robin stream scheduling
        // scheme.
        //
        BOOLEAN UseRoundRobinStreamScheduling : 1;

        //
        // Indicates that this connection has resumption enabled and needs to
        // keep the TLS state and transport parameters until it is done sending
        // resumption tickets.
        //
        BOOLEAN ResumptionEnabled : 1;

        //
        // When true, this indicates that reordering shouldn't elict an
        // immediate acknowledgement.
        //
        BOOLEAN IgnoreReordering : 1;

        //
        // When true, this indicates that the connection is currently executing
        // an API call inline (from a reentrant call on a callback).
        //
        BOOLEAN InlineApiExecution : 1;

#ifdef CxPlatVerifierEnabledByAddr
        //
        // The calling app is being verified (app or driver verifier).
        //
        BOOLEAN IsVerifying : 1;
#endif
    };
} QUIC_CONNECTION_STATE;

inline
ULONG64
LinkEntryToType(
    _In_ ULONG64 LinkAddr,
    _In_ PSTR StructType,
    _In_ PSTR FieldName
    )
{
    ULONG FieldOffset;
    if (0 != GetFieldOffset(StructType, FieldName, &FieldOffset)) {
        dpError("GetFieldOffset failed\n");
        return 0;
    }
    return LinkAddr - FieldOffset;
}

struct SingleListEntry : Struct {

    SingleListEntry(ULONG64 addr) : Struct("msquic!CXPLAT_SLIST_ENTRY", addr) {
    }

    ULONG64 Next() {
        return ReadPointer("Next");
    }
};

struct ListEntry : Struct {

    ListEntry(ULONG64 addr) : Struct("msquic!CXPLAT_LIST_ENTRY", addr) {
    }

    ULONG64 Flink() {
        return ReadPointer("Flink");
    }

    ULONG64 Blink() {
        return ReadPointer("Blink");
    }
};

struct LinkedList : ListEntry {

    ULONG64 NextAddr;

    LinkedList(ULONG64 addr) : ListEntry(addr) {
        NextAddr = Flink();
        if (NextAddr == Addr) {
            NextAddr = 0;
        }
    }

    bool IsEmpty() { return NextAddr == 0; }

    ULONG64 Next() {
        if (NextAddr == 0) {
            return 0;
        }
        ULONG64 next = NextAddr;
        if (!ReadPointerAtAddr(NextAddr, &NextAddr) ||
            NextAddr == Addr) {
            NextAddr = 0;
        }
        return next;
    }
};

//
// The following hash table logic is magic.
// Copied from %SDXROOT%\onecore\sdktools\debuggers\exts\extsdll\hashtab.cpp
//

#define KDEXT_RTL_HT_SECOND_LEVEL_DIR_SHIFT      7
#define KDEXT_RTL_HT_SECOND_LEVEL_DIR_SIZE   (1 << KDEXT_RTL_HT_SECOND_LEVEL_DIR_SHIFT)

static
void
ComputeDirIndices(
    _In_ ULONG BucketIndex,
    _Out_ PULONG FirstLevelIndex,
    _Out_ PULONG SecondLevelIndex
    )
{
    CONST ULONG AbsoluteIndex = BucketIndex + KDEXT_RTL_HT_SECOND_LEVEL_DIR_SIZE;

    BitScanReverse(FirstLevelIndex, AbsoluteIndex);
    *SecondLevelIndex = (AbsoluteIndex ^ (1 << *FirstLevelIndex));
    *FirstLevelIndex -= KDEXT_RTL_HT_SECOND_LEVEL_DIR_SHIFT;
}

struct HashTable : Struct {

    ULONG TableSize;
    ULONG64 Directory;
    ULONG EntryLinksOffset;
    int Indirection;

    bool ReadBucketHead;
    ULONG Bucket;
    ULONG64 SecondLevelDir;
    ULONG DirIndex;
    ULONG SecondLevelIndex;
    ULONG64 BucketHead;
    ULONG64 Entry;

    HashTable(ULONG64 addr) : Struct("msquic!CXPLAT_HASHTABLE", addr) {
        TableSize = ReadType<ULONG>("TableSize");
        Directory = ReadPointer("Directory");
        GetFieldOffset("msquic!CXPLAT_HASHTABLE_ENTRY", "Linkage", &EntryLinksOffset);
        Indirection = (TableSize <= KDEXT_RTL_HT_SECOND_LEVEL_DIR_SIZE) ? 1 : 2;

        ReadBucketHead = true;
        Bucket = 0;
        SecondLevelDir = 0;
        DirIndex = 0;
        SecondLevelIndex = 0;
    }

    ULONG NumEntries() {
        return ReadType<ULONG>("NumEntries");
    }

    bool GetNextEntry(ULONG64* EntryAddress) {
        for (Bucket; Bucket < TableSize; Bucket++) {

            if (ReadBucketHead) {
                ReadBucketHead = false;
                ComputeDirIndices(Bucket, &DirIndex, &SecondLevelIndex);

                if (0 == SecondLevelIndex) {
                    if (1 == Indirection) {
                        SecondLevelDir = Directory;
                    } else {
                        if (!ReadPointerAtAddr(
                                Directory + DirIndex * g_ExtInstance.m_PtrSize,
                                &SecondLevelDir)) {
                            dprintf("Failed to read second-level dir %u\n", DirIndex);
                            return false;
                        }
                    }
                }

                BucketHead = SecondLevelDir + SecondLevelIndex * (2 * g_ExtInstance.m_PtrSize);
                Entry = BucketHead;
            }

            if (!ReadPointerFromStructAddr(
                    Entry,
                    "msquic!CXPLAT_LIST_ENTRY",
                    "Flink",
                    &Entry)) {
                dprintf("Failed to walk bucket %08lx at %p\n", Bucket, BucketHead);
                return false;
            }

            if (!IsEqualPointer(Entry, BucketHead)) {
                *EntryAddress = Entry - EntryLinksOffset;
                return true;
            }

            ReadBucketHead = true;
        }

        return false;
    }
};

// End of magic

inline char QuicHalfByteToStr(UCHAR b)
{
    return b < 10 ? ('0' + b) : ('A' + b - 10);
}

struct CidStr {
    char Data[256];

    CidStr(ULONG64 Addr, UCHAR Length) {
        if (Length == 0) {
            strcpy(Data, "empty");
        } else {
            for (UCHAR i = 0; i < Length; i++) {
                UCHAR Byte;
                ReadTypeAtAddr(Addr + i, &Byte);
                Data[i * 2] = QuicHalfByteToStr(Byte >> 4);
                Data[i * 2 + 1] = QuicHalfByteToStr(Byte & 0xF);
            }
            Data[Length * 2] = 0;
        }
    }
};

struct Cid : Struct {

    Cid(ULONG64 Addr) : Struct("msquic!QUIC_CID", Addr) { }

    UCHAR Length() {
        return ReadType<UCHAR>("Length");
    }

    ULONG64 SequenceNumber() {
        return ReadType<ULONG64>("SequenceNumber");
    }

    ULONG64 Data() {
        return AddrOf("Data");
    }

    CidStr Str() {
        return CidStr(Data(), Length());
    }
};

struct CidHashEntry : Struct {

    CidHashEntry(ULONG64 Addr) : Struct("msquic!QUIC_CID_HASH_ENTRY", Addr) { }

    static CidHashEntry FromEntry(ULONG64 EntryAddr) {
        return CidHashEntry(LinkEntryToType(EntryAddr, "msquic!QUIC_CID_HASH_ENTRY", "Entry"));
    }

    static CidHashEntry FromLink(ULONG64 LinkAddr) {
        return CidHashEntry(LinkEntryToType(LinkAddr, "msquic!QUIC_CID_HASH_ENTRY", "Link"));
    }

    ULONG64 GetConnection() {
        return ReadPointer("Connection");
    }

    Cid GetCid() {
        return Cid(AddrOf("CID"));
    }
};

struct Settings : Struct {

    Settings(ULONG64 Addr) : Struct("msquic!QUIC_SETTINGS", Addr) { }

    UINT16 RetryMemoryLimit() {
        return ReadType<UINT16>("RetryMemoryLimit");
    }
};

struct QuicHandle : Struct {

    QuicHandle(ULONG64 Addr) : Struct("msquic!QUIC_HANDLE", Addr) { }

    QUIC_HANDLE_TYPE Type() {
        return ReadType<QUIC_HANDLE_TYPE>("Type");
    }

    PSTR TypeStr() {
        switch (Type()) {
        case QUIC_HANDLE_TYPE_REGISTRATION:
            return "REGISTRATION";
        case QUIC_HANDLE_TYPE_CONFIGURATION:
            return "CONFIGURATION";
        case QUIC_HANDLE_TYPE_LISTENER:
            return "LISTENER";
        case QUIC_HANDLE_TYPE_CONNECTION_CLIENT:
        case QUIC_HANDLE_TYPE_CONNECTION_SERVER:
            return "CONNECTION";
        case QUIC_HANDLE_TYPE_STREAM:
            return "STREAM";
        default:
            return "INVALID";
        }
    }

    PSTR CommandStr() {
        switch (Type()) {
        case QUIC_HANDLE_TYPE_REGISTRATION:
            return "registration";
        case QUIC_HANDLE_TYPE_CONFIGURATION:
            return "congifuration";
        case QUIC_HANDLE_TYPE_LISTENER:
            return "listener";
        case QUIC_HANDLE_TYPE_CONNECTION_CLIENT:
        case QUIC_HANDLE_TYPE_CONNECTION_SERVER:
            return "connection";
        case QUIC_HANDLE_TYPE_STREAM:
            return "stream";
        default:
            return "handle";
        }
    }

    ULONG64 ClientContext() {
        return ReadPointer("ClientContext");
    }
};

struct SendRequest : Struct {

    SendRequest(ULONG64 Addr) : Struct("msquic!QUIC_SEND_REQUEST", Addr) { }

    ULONG64 Next() {
        return ReadPointer("Next");
    }

    ULONG64 Buffers() {
        return ReadPointer("Buffers");
    }

    ULONG BufferCount() {
        return ReadType<ULONG>("BufferCount");
    }

    ULONG Flags() {
        return ReadType<ULONG>("Flags");
    }

    ULONG64 StreamOffset() {
        return ReadType<ULONG64>("StreamOffset");
    }

    ULONG64 TotalLength() {
        return ReadType<ULONG64>("TotalLength");
    }
};

struct RecvBuffer : Struct {

    RecvBuffer(ULONG64 Addr) : Struct("msquic!QUIC_RECV_BUFFER", Addr) { }

    ULONG64 Buffer() {
        return ReadPointer("Buffer");
    }

    ULONG AllocBufferLength() {
        return ReadType<ULONG>("AllocBufferLength");
    }

    ULONG VirtualBufferLength() {
        return ReadType<ULONG>("VirtualBufferLength");
    }

    ULONG BufferStart() {
        return ReadType<ULONG>("BufferStart");
    }

    ULONG64 BaseOffset() {
        return ReadType<ULONG64>("BaseOffset");
    }
};

#define QUIC_STREAM_SEND_FLAG_DATA_BLOCKED  0x0001
#define QUIC_STREAM_SEND_FLAG_MAX_DATA      0x0002
#define QUIC_STREAM_SEND_FLAG_SEND_ABORT    0x0004
#define QUIC_STREAM_SEND_FLAG_RECV_ABORT    0x0008
#define QUIC_STREAM_SEND_FLAG_DATA          0x0010
#define QUIC_STREAM_SEND_FLAG_OPEN          0x0020
#define QUIC_STREAM_SEND_FLAG_FIN           0x0040

struct Stream : Struct {

    Stream(ULONG64 Addr) : Struct("msquic!QUIC_STREAM", Addr) { }

    static Stream FromLink(ULONG64 LinkAddr) {
        return Stream(LinkEntryToType(LinkAddr, "msquic!QUIC_STREAM", "Link"));
    }

    static Stream FromSendLink(ULONG64 LinkAddr) {
        return Stream(LinkEntryToType(LinkAddr, "msquic!QUIC_STREAM", "SendLink"));
    }

    static Stream FromHashTableEntry(ULONG64 LinkAddr) {
        return Stream(LinkEntryToType(LinkAddr, "msquic!QUIC_STREAM", "TableEntry"));
    }

    LONG RefCount() {
        return ReadType<LONG>("RefCount");
    }

    ULONG64 ID() {
        return ReadType<ULONG64>("ID");
    }

    QUIC_STREAM_FLAGS Flags() {
        QUIC_STREAM_FLAGS Flags;
        Flags.AllFlags = ReadType<ULONG>("Flags");
        return Flags;
    }

    PSTR StateStr() {
        QUIC_STREAM_FLAGS flags = Flags();
        auto LocallyClosed = flags.LocalCloseFin || flags.LocalCloseReset;
        auto RemotelyClosed = flags.RemoteCloseFin || flags.RemoteCloseReset;
        if (flags.HandleClosed) {
            return "CLOSED";
        } else if (flags.HandleShutdown) {
            return "SHUTDOWN";
        } else if (LocallyClosed && RemotelyClosed) {
            return "SHUTTING DOWN";
        } else if (RemotelyClosed) {
            return "HALF OPEN (Local)";
        } else if (LocallyClosed) {
            return "HALF OPEN (Remote)";
        } else {
            return "OPEN";
        }
    }

    ListEntry SendLink() {
        return ListEntry(AddrOf("SendLink"));
    }

    USHORT SendFlags() {
        return ReadType<USHORT>("SendFlags");
    }

    ULONG64 GetConnection() {
        return ReadPointer("Connection");
    }

    //
    // Send
    //

    PSTR SendStateStr() {
        QUIC_STREAM_FLAGS flags = Flags();
        if (flags.LocalCloseAcked) {
            return "SHUTDOWN";
        } else if (flags.LocalCloseReset) {
            return "RESET";
        } else if (flags.LocalCloseFin) {
            return "FIN";
        } else {
            return "OPEN";
        }
    }

    ULONG64 QueuedSendOffset() {
        return ReadType<ULONG64>("QueuedSendOffset");
    }

    ULONG64 MaxAllowedSendOffset() {
        return ReadType<ULONG64>("MaxAllowedSendOffset");
    }

    ULONG64 MaxSentLength() {
        return ReadType<ULONG64>("MaxSentLength");
    }

    ULONG64 UnAckedOffset() {
        return ReadType<ULONG64>("MaxSentLength");
    }

    ULONG64 NextSendOffset() {
        return ReadType<ULONG64>("MaxSentLength");
    }

    bool InRecovery() {
        return Flags().InRecovery != FALSE;
    }

    ULONG64 RecoveryNextOffset() {
        return ReadType<ULONG64>("RecoveryNextOffset");
    }

    ULONG64 RecoveryEndOffset() {
        return ReadType<ULONG64>("RecoveryEndOffset");
    }

    bool RecoveryWindowOpen() {
        return RecoveryNextOffset() < RecoveryEndOffset();
    }

    ULONG64 SendRequests() {
        return ReadPointer("SendRequests");
    }

    //
    // Recv
    //

    PSTR RecvStateStr() {
        QUIC_STREAM_FLAGS flags = Flags();
        if (flags.RemoteCloseAcked) {
            return "SHUTDOWN";
        } else if (flags.RemoteCloseReset) {
            return "RESET";
        } else if (flags.RemoteCloseFin) {
            return "FIN";
        } else {
            return "OPEN";
        }
    }

    ULONG64 MaxAllowedRecvOffset() {
        return ReadType<ULONG64>("MaxAllowedRecvOffset");
    }

    ULONG64 RecvMax0RttLength() {
        return ReadType<ULONG64>("RecvMax0RttLength");
    }

    RecvBuffer GetRecvBuffer() {
        return RecvBuffer(AddrOf("RecvBuffer"));
    }
};

#define QUIC_CONN_SEND_FLAG_ACK                     0x00000001
#define QUIC_CONN_SEND_FLAG_CRYPTO                  0x00000002
#define QUIC_CONN_SEND_FLAG_CONNECTION_CLOSE        0x00000004
#define QUIC_CONN_SEND_FLAG_APPLICATION_CLOSE       0x00000008
#define QUIC_CONN_SEND_FLAG_DATA_BLOCKED            0x00000010
#define QUIC_CONN_SEND_FLAG_MAX_DATA                0x00000020
#define QUIC_CONN_SEND_FLAG_MAX_STREAMS_BIDI        0x00000040
#define QUIC_CONN_SEND_FLAG_MAX_STREAMS_UNI         0x00000080
#define QUIC_CONN_SEND_FLAG_NEW_CONNECTION_ID       0x00000100
#define QUIC_CONN_SEND_FLAG_RETIRE_CONNECTION_ID    0x00000200
#define QUIC_CONN_SEND_FLAG_PATH_CHALLENGE          0x00000400
#define QUIC_CONN_SEND_FLAG_PATH_RESPONSE           0x00000800
#define QUIC_CONN_SEND_FLAG_PING                    0x00001000
#define QUIC_CONN_SEND_FLAG_HANDSHAKE_DONE          0x00002000
#define QUIC_CONN_SEND_FLAG_DATAGRAM                0x00004000
#define QUIC_CONN_SEND_FLAG_DPLPMTUD                0x80000000

struct Send : Struct {

    Send(ULONG64 Addr) : Struct("msquic!QUIC_SEND", Addr) { }

    ULONG64 NextPacketNumber() {
        return ReadType<ULONG64>("NextPacketNumber");
    }

    UINT32 SendFlags() {
        return ReadType<UINT32>("SendFlags");
    }

    LinkedList GetSendStreams() {
        return LinkedList(AddrOf("SendStreams"));
    }
};

typedef enum QUIC_FRAME_TYPE {
    QUIC_FRAME_PADDING              = 0x0ULL,
    QUIC_FRAME_PING                 = 0x1ULL,
    QUIC_FRAME_ACK                  = 0x2ULL, // to 0x3
    QUIC_FRAME_ACK_1                = 0x3ULL,
    QUIC_FRAME_RESET_STREAM         = 0x4ULL,
    QUIC_FRAME_STOP_SENDING         = 0x5ULL,
    QUIC_FRAME_CRYPTO               = 0x6ULL,
    QUIC_FRAME_NEW_TOKEN            = 0x7ULL,
    QUIC_FRAME_STREAM               = 0x8ULL, // to 0xf
    QUIC_FRAME_STREAM_1             = 0x9ULL,
    QUIC_FRAME_STREAM_2             = 0xaULL,
    QUIC_FRAME_STREAM_3             = 0xbULL,
    QUIC_FRAME_STREAM_4             = 0xcULL,
    QUIC_FRAME_STREAM_5             = 0xdULL,
    QUIC_FRAME_STREAM_6             = 0xeULL,
    QUIC_FRAME_STREAM_7             = 0xfULL,
    QUIC_FRAME_MAX_DATA             = 0x10ULL,
    QUIC_FRAME_MAX_STREAM_DATA      = 0x11ULL,
    QUIC_FRAME_MAX_STREAMS          = 0x12ULL, // to 0x13
    QUIC_FRAME_MAX_STREAMS_1        = 0x13ULL,
    QUIC_FRAME_DATA_BLOCKED         = 0x14ULL,
    QUIC_FRAME_STREAM_DATA_BLOCKED  = 0x15ULL,
    QUIC_FRAME_STREAMS_BLOCKED      = 0x16ULL, // to 0x17
    QUIC_FRAME_STREAMS_BLOCKED_1    = 0x17ULL,
    QUIC_FRAME_NEW_CONNECTION_ID    = 0x18ULL,
    QUIC_FRAME_RETIRE_CONNECTION_ID = 0x19ULL,
    QUIC_FRAME_PATH_CHALLENGE       = 0x1aULL,
    QUIC_FRAME_PATH_RESPONSE        = 0x1bULL,
    QUIC_FRAME_CONNECTION_CLOSE     = 0x1cULL, // to 0x1d
    QUIC_FRAME_CONNECTION_CLOSE_1   = 0x1dULL,
    QUIC_FRAME_HANDSHAKE_DONE       = 0x1eULL,
    /* 0x1f to 0x2f are unused currently */
    QUIC_FRAME_DATAGRAM             = 0x30ULL, // to 0x31
    QUIC_FRAME_DATAGRAM_1           = 0x31ULL,
    /* 0x32 to 0xad are unused currently */
    QUIC_FRAME_ACK_FREQUENCY        = 0xafULL,

    QUIC_FRAME_MAX_SUPPORTED

} QUIC_FRAME_TYPE;

struct SentFrameMetadata : Struct {

    SentFrameMetadata(ULONG64 Addr) : Struct("msquic!QUIC_SENT_FRAME_METADATA", Addr) { }

    QUIC_FRAME_TYPE Type() {
        return (QUIC_FRAME_TYPE)ReadType<UINT8>("Type");
    }

    PCSTR TypeStr() {
        auto type = Type();
        switch (type) {
        case QUIC_FRAME_PADDING:
            return "PADDING";
        case QUIC_FRAME_PING:
            return "PING";
        case QUIC_FRAME_ACK:
        case QUIC_FRAME_ACK_1:
            return "ACK";
        case QUIC_FRAME_RESET_STREAM:
            return "RESET_STREAM";
        case QUIC_FRAME_STOP_SENDING:
            return "STOP_SENDING";
        case QUIC_FRAME_CRYPTO:
            return "CRYPTO";
        case QUIC_FRAME_NEW_TOKEN:
            return "NEW_TOKEN";
        case QUIC_FRAME_STREAM:
        case QUIC_FRAME_STREAM_1:
        case QUIC_FRAME_STREAM_2:
        case QUIC_FRAME_STREAM_3:
        case QUIC_FRAME_STREAM_4:
        case QUIC_FRAME_STREAM_5:
        case QUIC_FRAME_STREAM_6:
        case QUIC_FRAME_STREAM_7:
            return "STREAM";
        case QUIC_FRAME_MAX_DATA:
            return "MAX_DATA";
        case QUIC_FRAME_MAX_STREAM_DATA:
            return "MAX_STREAM_DATA";
        case QUIC_FRAME_MAX_STREAMS:
            return "MAX_STREAMS (BIDI)";
        case QUIC_FRAME_MAX_STREAMS_1:
            return "MAX_STREAMS (UNI)";
        case QUIC_FRAME_DATA_BLOCKED:
            return "DATA_BLOCKED";
        case QUIC_FRAME_STREAM_DATA_BLOCKED:
            return "STREAM_DATA_BLOCKED";
        case QUIC_FRAME_STREAMS_BLOCKED:
            return "STREAMS_BLOCKED (BIDI)";
        case QUIC_FRAME_STREAMS_BLOCKED_1:
            return "STREAMS_BLOCKED (UNI_";
        case QUIC_FRAME_NEW_CONNECTION_ID:
            return "NEW_CONNECTION_ID";
        case QUIC_FRAME_RETIRE_CONNECTION_ID:
            return "RETIRE_CONNECTION_ID";
        case QUIC_FRAME_PATH_CHALLENGE:
            return "PATH_CHALLENGE";
        case QUIC_FRAME_PATH_RESPONSE:
            return "PATH_RESPONSE";
        case QUIC_FRAME_CONNECTION_CLOSE:
            return "CONNECTION_CLOSE";
        case QUIC_FRAME_CONNECTION_CLOSE_1:
            return "CONNECTION_CLOSE (APP)";
        case QUIC_FRAME_HANDSHAKE_DONE:
            return "HANDSHAKE_DONE";
        case QUIC_FRAME_DATAGRAM:
        case QUIC_FRAME_DATAGRAM_1:
            return "DATAGRAM";
        case QUIC_FRAME_ACK_FREQUENCY:
            return "ACK_FREQUENCY";
        default:
            return "INVALID FRAME";
        }
    }

    UINT8 Flags() {
        return ReadType<UINT8>("Flags");
    }
};

typedef struct QUIC_SEND_PACKET_FLAGS {

    UINT8 KeyType                   : 2;
    BOOLEAN IsAckEliciting          : 1;
    BOOLEAN IsMtuProbe              : 1;
    BOOLEAN SuspectedLost           : 1;

    PCSTR KeyTypeStr() {
        switch (KeyType) {
        case 0:
            return "None";
        case 1:
            return "0-RTT";
        case 2:
            return "Handshake";
        case 3:
            return "1-RTT";
        }
        return "IMPOSSIBLE";
    }

} QUIC_SEND_PACKET_FLAGS;

struct SentPacketMetadata : Struct {

    SentPacketMetadata(ULONG64 Addr) : Struct("msquic!QUIC_SENT_PACKET_METADATA", Addr) { }

    ULONG64 Next() {
        return ReadPointer("Next");
    }

    UINT64 PacketNumber() {
        return ReadType<UINT64>("PacketNumber");
    }

    UINT32 SentTime() {
        return ReadType<UINT32>("SentTime"); // Microseconds
    }

    UINT16 PacketLength() {
        return ReadType<UINT16>("PacketLength");
    }

    QUIC_SEND_PACKET_FLAGS Flags() {
        UINT8 Raw = ReadType<UINT8>("Flags");
        return *(QUIC_SEND_PACKET_FLAGS*)&Raw;
    }

    UINT8 FrameCount() {
        return ReadType<UINT8>("FrameCount");
    }

    SentFrameMetadata GetFrame(UINT32 i) {
        ULONG64 BaseAddr = AddrOf("Frames");
        ULONG64 Size = GetTypeSize("msquic!QUIC_SENT_FRAME_METADATA");
        return SentFrameMetadata(BaseAddr + Size * i);
    }
};

struct LossDetection : Struct {

    LossDetection(ULONG64 Addr) : Struct("msquic!QUIC_LOSS_DETECTION", Addr) { }

    UINT32 SmoothedRtt() {
        return ReadType<UINT32>("SmoothedRtt"); // Microseconds
    }

    UINT32 RttVariance() {
        return ReadType<UINT32>("RttVariance"); // Microseconds
    }

    ULONG64 GetSendPackets() {
        return ReadPointer("SentPackets");
    }

    ULONG64 GetLostPackets() {
        return ReadPointer("LostPackets");
    }
};

typedef enum QUIC_API_TYPE {

    QUIC_API_TYPE_CONN_CLOSE,
    QUIC_API_TYPE_CONN_SHUTDOWN,
    QUIC_API_TYPE_CONN_START,
    QUIC_API_TYPE_CONN_SET_CONFIGURATION,
    QUIC_API_TYPE_CONN_SEND_RESUMPTION_TICKET,

    QUIC_API_TYPE_STRM_CLOSE,
    QUIC_API_TYPE_STRM_SHUTDOWN,
    QUIC_API_TYPE_STRM_START,
    QUIC_API_TYPE_STRM_SEND,
    QUIC_API_TYPE_STRM_RECV_COMPLETE,
    QUIC_API_TYPE_STRM_RECV_SET_ENABLED,

    QUIC_API_TYPE_SET_PARAM,
    QUIC_API_TYPE_GET_PARAM,

    QUIC_API_TYPE_DATAGRAM_SEND,

} QUIC_API_TYPE;

struct ApiCall : Struct {

    ApiCall(ULONG64 Addr) : Struct("msquic!QUIC_API_CONTEXT", Addr) { }

    QUIC_API_TYPE Type() {
        return ReadType<QUIC_API_TYPE>("Type");
    }

    PCSTR TypeStr() {
        switch (Type()) {
        case QUIC_API_TYPE_CONN_CLOSE:
            return "API_CONN_CLOSE";
        case QUIC_API_TYPE_CONN_SHUTDOWN:
            return "API_CONN_SHUTDOWN";
        case QUIC_API_TYPE_CONN_START:
            return "API_CONN_START";
        case QUIC_API_TYPE_CONN_SET_CONFIGURATION:
            return "API_TYPE_CONN_SET_CONFIGURATION";
        case QUIC_API_TYPE_CONN_SEND_RESUMPTION_TICKET:
            return "QUIC_API_TYPE_CONN_SEND_RESUMPTION_TICKET";
        case QUIC_API_TYPE_STRM_CLOSE:
            return "API_STRM_CLOSE";
        case QUIC_API_TYPE_STRM_SHUTDOWN:
            return "API_STRM_SHUTDOWN";
        case QUIC_API_TYPE_STRM_START:
            return "API_TYPE_STRM_START";
        case QUIC_API_TYPE_STRM_SEND:
            return "API_STRM_SEND";
        case QUIC_API_TYPE_STRM_RECV_COMPLETE:
            return "API_TYPE_STRM_RECV_COMPLETE";
        case QUIC_API_TYPE_STRM_RECV_SET_ENABLED:
            return "API_TYPE_STRM_RECV_SET_ENABLED";
        case QUIC_API_TYPE_SET_PARAM:
            return "API_SET_PARAM";
        case QUIC_API_TYPE_GET_PARAM:
            return "API_GET_PARAM";
        case QUIC_API_TYPE_DATAGRAM_SEND:
            return "API_TYPE_DATAGRAM_SEND";
        default:
            return "INVALID API";
        }
    }
};

typedef enum QUIC_OPERATION_TYPE {
    QUIC_OPER_TYPE_API_CALL,            // Process an API call from the app.
    QUIC_OPER_TYPE_FLUSH_RECV,          // Process queue of receive packets.
    QUIC_OPER_TYPE_UNREACHABLE,         // Process UDP unreachable event.
    QUIC_OPER_TYPE_FLUSH_STREAM_RECV,   // Indicate a stream data to the app.
    QUIC_OPER_TYPE_FLUSH_SEND,          // Frame packets and send them.
    QUIC_OPER_TYPE_TLS_COMPLETE,        // A TLS process call completed.
    QUIC_OPER_TYPE_TIMER_EXPIRED,       // A timer expired.
    QUIC_OPER_TYPE_TRACE_RUNDOWN,       // A trace rundown was triggered.

    //
    // All stateless operations follow.
    //

    QUIC_OPER_TYPE_VERSION_NEGOTIATION, // A version negotiation needs to be sent.
    QUIC_OPER_TYPE_STATELESS_RESET,     // A stateless reset needs to be sent.
    QUIC_OPER_TYPE_RETRY,               // A retry needs to be sent.

} QUIC_OPERATION_TYPE;

struct Operation : Struct {

    Operation(ULONG64 Addr) : Struct("msquic!QUIC_OPERATION", Addr) { }

    static Operation FromLink(ULONG64 LinkAddr) {
        return Operation(LinkEntryToType(LinkAddr, "msquic!QUIC_OPERATION", "Link"));
    }

    QUIC_OPERATION_TYPE Type() {
        return ReadType<QUIC_OPERATION_TYPE>("Type");
    }

    PCSTR TypeStr() {
        switch (Type()) {
        case QUIC_OPER_TYPE_API_CALL:
            return GetApiCall().TypeStr();
        case QUIC_OPER_TYPE_FLUSH_RECV:
            return "FLUSH_RECV";
        case QUIC_OPER_TYPE_UNREACHABLE:
            return "UNREACHABLE";
        case QUIC_OPER_TYPE_FLUSH_STREAM_RECV:
            return "FLUSH_STREAM_RECV";
        case QUIC_OPER_TYPE_FLUSH_SEND:
            return "FLUSH_SEND";
        case QUIC_OPER_TYPE_TLS_COMPLETE:
            return "TLS_COMPLETE";
        case QUIC_OPER_TYPE_TIMER_EXPIRED:
            return "TIMER_EXPIRED"; // TODO - Timer details.
        case QUIC_OPER_TYPE_TRACE_RUNDOWN:
            return "TRACE_RUNDOWN";
        case QUIC_OPER_TYPE_VERSION_NEGOTIATION:
            return "VERSION_NEGOTIATION";
        case QUIC_OPER_TYPE_STATELESS_RESET:
            return "STATELESS_RESET";
        case QUIC_OPER_TYPE_RETRY:
            return "RETRY";
        default:
            return "INVALID";
        }
    }

    ApiCall GetApiCall() {
        return ApiCall(ReadPointer("API_CALL.Context"));
    }
};

struct OperQueue : Struct {

    OperQueue(ULONG64 Addr) : Struct("msquic!QUIC_OPERATION_QUEUE", Addr) { }

    LinkedList GetOperations() {
        return LinkedList(AddrOf("List"));
    }
};

struct StreamSet : Struct {

    StreamSet(ULONG64 Addr) : Struct("msquic!QUIC_STREAM_SET", Addr) { }

    ULONG64 GetStreamTable() {
        return ReadPointer("StreamTable");
    }
};

struct Connection : Struct {

    Connection(ULONG64 Addr) : Struct("msquic!QUIC_CONNECTION", Addr) { }

    static Connection FromRegistrationLink(ULONG64 LinkAddr) {
        return Connection(LinkEntryToType(LinkAddr, "msquic!QUIC_CONNECTION", "RegistrationLink"));
    }

    static Connection FromWorkerLink(ULONG64 LinkAddr) {
        return Connection(LinkEntryToType(LinkAddr, "msquic!QUIC_CONNECTION", "WorkerLink"));
    }

    ULONG64 RegistrationPtr() {
        return ReadPointer("Registration");
    }

    ULONG64 WorkerPtr() {
        return ReadPointer("Worker");
    }

    LONG RefCount() {
        return ReadType<LONG>("RefCount");
    }

    ULONG Version() {
        return ntohl(ReadType<ULONG>("Stats.QuicVersion"));
    }

    QUIC_HANDLE_TYPE Type() {
        return ReadTypeAtOffset<QUIC_HANDLE_TYPE>(0);
    }

    PSTR TypeStr() {
        switch (Type()) {
        case QUIC_HANDLE_TYPE_CONNECTION_CLIENT:
            return "CLIENT";
        case QUIC_HANDLE_TYPE_CONNECTION_SERVER:
            return "SERVER";
        default:
            return "INVALID";
        }
    }

    bool IsClient() {
        return Type() == QUIC_HANDLE_TYPE_CONNECTION_CLIENT;
    }

    bool IsServer() {
        return Type() == QUIC_HANDLE_TYPE_CONNECTION_SERVER;
    }

    QUIC_CONNECTION_STATE State() {
        QUIC_CONNECTION_STATE State;
        State.Flags = ReadType<ULONG>("State");
        return State;
    }

    PSTR StateStr() {
        QUIC_CONNECTION_STATE state = State();
        if (state.Freed) {
            return "FREED";
        } else if (state.HandleClosed) {
            return "CLOSED";
        } else if (state.HandleShutdown) {
            return "SHUTDOWN";
        } else if (state.ClosedLocally || state.ClosedRemotely) {
            return "SHUTTING DOWN";
        } else if (state.HandshakeConfirmed) {
            return "CONNECTED (Confirmed)";
        } else if (state.Connected) {
            return "CONNECTED";
        } else if (state.Started) {
            return "CONNECTING";
        } else if (state.Initialized) {
            return "INITIALIZED";
        } else if (state.Allocated) {
            return "ALLOCATED";
        } else {
            return "INVALID";
        }
    }

    IpAddress GetLocalAddress() {
        return IpAddress(AddrOf("LocalAddress")); // TODO - Broken
    }

    IpAddress GetRemoteAddress() {
        return IpAddress(AddrOf("RemoteAddress")); // TODO - Broken
    }

    SingleListEntry GetSourceCids() {
        return SingleListEntry(AddrOf("SourceCids"));
    }

    Send GetSend() {
        return Send(AddrOf("Send"));
    }

    LossDetection GetLossDetection() {
        return LossDetection(AddrOf("LossDetection"));
    }

    StreamSet GetStreams() {
        return StreamSet(AddrOf("Streams"));
    }

    OperQueue GetOperQueue() {
        return OperQueue(AddrOf("OperQ"));
    }
};

struct Listener : Struct {

    Listener(ULONG64 Addr) : Struct("msquic!QUIC_LISTENER", Addr) { }

    static Listener FromLink(ULONG64 LinkAddr) {
        return Listener(LinkEntryToType(LinkAddr, "msquic!QUIC_LISTENER", "Link"));
    }

    bool WildCard() {
        return ReadType<UCHAR>("WildCard") != 0;
    }

    ULONG64 GetRegistration() {
        return ReadPointer("Registration");
    }

    ULONG64 GetBinding() {
        return ReadPointer("Binding");
    }

    IpAddress GetLocalAddress() {
        return IpAddress(AddrOf("LocalAddress"));
    }

    ULONG64 GetRawAlpnList() {
        return AddrOf("AlpnList");
    }

    USHORT GetAlpnListLength() {
        return ReadType<USHORT>("AlpnListLength");
    }

    String GetAlpns() {
        ULONG64 AlpnList = GetRawAlpnList();
        USHORT AlpnListLength = GetAlpnListLength();

        String Str;
        ULONG StrOffset = 0;
        while (AlpnListLength != 0) {
            UINT8 Length;
            ReadTypeAtAddr<UINT8>(AlpnList, &Length);
            AlpnList++;
            AlpnListLength--;

            ULONG cbRead;
            ReadMemory(AlpnList, Str.Data + StrOffset, Length, &cbRead);
            AlpnList += Length;
            AlpnListLength -= Length;
            StrOffset += Length + 1;
            Str.Data[StrOffset] = ',';
        }

        Str.Data[StrOffset - 1] = 0;

        return Str;
    }
};

struct Worker : Struct {

    Worker(ULONG64 Addr) : Struct("msquic!QUIC_WORKER", Addr) { }

    BOOLEAN Enabled() {
        return ReadType<BOOLEAN>("Enabled");
    }

    BOOLEAN IsActive() {
        return ReadType<BOOLEAN>("IsActive");
    }

    PSTR StateStr() {
        bool HasWorkQueue = !GetConnections().IsEmpty() || !GetOperations().IsEmpty();
        if (IsActive()) {
            return HasWorkQueue ? "ACTIVE (+queue)" : "ACTIVE";
        } else {
            return HasWorkQueue ? "QUEUE" : "IDLE";
        }
    }

    UINT8 IdealProcessor() {
        return ReadType<UINT8>("IdealProcessor");
    }

    UINT32 ThreadID() {
        return ReadType<UINT32>("ThreadID");
    }

    ULONG64 Thread() {
        return ReadPointer("Thread");
    }

    LinkedList GetConnections() {
        return LinkedList(AddrOf("Connections"));
    }

    LinkedList GetOperations() {
        return LinkedList(AddrOf("Operations"));
    }
};

struct WorkerPool : Struct {

    WorkerPool(ULONG64 Addr) : Struct("msquic!QUIC_WORKER_POOL", Addr) { }

    UINT8 WorkerCount() {
        return ReadType<UINT8>("WorkerCount");
    }

    Worker GetWorker(UCHAR Index) {
        ULONG64 ArrayAddr = AddrOf("Workers");
        ULONG TypeSize = GetTypeSize("msquic!QUIC_WORKER");
        return Worker(ArrayAddr + Index * TypeSize);
    }
};

struct Configuration : Struct {

    Configuration(ULONG64 Addr) : Struct("msquic!QUIC_CONFIGURATION", Addr) { }

    static Configuration FromLink(ULONG64 LinkAddr) {
        return Configuration(LinkEntryToType(LinkAddr, "msquic!QUIC_CONFIGURATION", "Link"));
    }

    ULONG64 GetRegistration() {
        return ReadPointer("Registration");
    }

    ULONG64 GetRawAlpnList() {
        return AddrOf("AlpnList");
    }

    USHORT GetAlpnListLength() {
        return ReadType<USHORT>("AlpnListLength");
    }

    String GetAlpns() {
        ULONG64 AlpnList = GetRawAlpnList();
        USHORT AlpnListLength = GetAlpnListLength();

        String Str;
        ULONG StrOffset = 0;
        while (AlpnListLength != 0) {
            UINT8 Length;
            ReadTypeAtAddr<UINT8>(AlpnList, &Length);
            AlpnList++;
            AlpnListLength--;

            ULONG cbRead;
            ReadMemory(AlpnList, Str.Data+StrOffset, Length, &cbRead);
            AlpnList += Length;
            AlpnListLength -= Length;
            StrOffset += Length + 1;
            Str.Data[StrOffset] = ',';
        }

        Str.Data[StrOffset-1] = 0;

        return Str;
    }
};

struct Registration : Struct {

    Registration(ULONG64 Addr) : Struct("msquic!QUIC_REGISTRATION", Addr) { }

    static Registration FromLink(ULONG64 LinkAddr) {
        return Registration(LinkEntryToType(LinkAddr, "msquic!QUIC_REGISTRATION", "Link"));
    }

    WorkerPool GetWorkerPool() {
        return WorkerPool(ReadPointer("WorkerPool"));
    }

    LinkedList GetConfigurations() {
        return LinkedList(AddrOf("Configurations"));
    }

    LinkedList GetConnections() {
        return LinkedList(AddrOf("Connections"));
    }

    String GetAppName() {
        return String(AddrOf("AppName"));
    }
};

struct LookupHashTable : Struct {

    LookupHashTable(ULONG64 Addr) : Struct("msquic!QUIC_PARTITIONED_HASHTABLE", Addr) { }

    ULONG64 GetTablePtr() {
        return AddrOf("Table"); // TODO - Need Hash Table Enumeration.
    }
};

struct Lookup : Struct {

    Lookup(ULONG64 Addr) : Struct("msquic!QUIC_LOOKUP", Addr) { }

    bool MaximizePartitioning() {
        return ReadType<UCHAR>("MaximizePartitioning") != 0;
    }

    UINT32 CidCount() {
        return ReadType<UINT32>("CidCount");
    }

    UINT8 PartitionCount() {
        return ReadType<UINT8>("PartitionCount");
    }

    ULONG64 GetLookupPtr() {
        return ReadPointer("LookupTable");
    }

    LookupHashTable GetLookupTable(UCHAR Index) {
        ULONG64 ArrayAddr = ReadPointer("LookupTable");
        ULONG TypeSize = GetTypeSize("msquic!QUIC_PARTITIONED_HASHTABLE");
        return LookupHashTable(ArrayAddr + Index * TypeSize);
    }
};

struct Socket : Struct {

    Socket(ULONG64 Addr) : Struct("msquic!CXPLAT_SOCKET", Addr) { }

    IpAddress GetLocalAddress() {
        return IpAddress(AddrOf("LocalAddress"));
    }

    IpAddress GetRemoteAddress() {
        return IpAddress(AddrOf("RemoteAddress"));
    }
};

struct Binding : Struct {

    Binding(ULONG64 Addr) : Struct("msquic!QUIC_BINDING", Addr) { }

    static Binding FromLink(ULONG64 LinkAddr) {
        return Binding(LinkEntryToType(LinkAddr, "msquic!QUIC_BINDING", "Link"));
    }

    bool Exclusive() {
        return ReadType<UCHAR>("Exclusive") != 0;
    }

    bool Connected() {
        return ReadType<UCHAR>("Connected") != 0;
    }

    long RefCount() {
        return ReadType<long>("RefCount");
    }

    LinkedList GetListeners() {
        return LinkedList(AddrOf("Listeners"));
    }

    Lookup GetLookup() {
        return Lookup(AddrOf("Lookup"));
    }

    Socket GetSocket() {
        return Socket(ReadPointer("Socket"));
    }
};

struct QuicLibrary : Struct {

    QuicLibrary() : Struct("msquic!QUIC_LIBRARY", GetExpression("msquic!MsQuicLib")) { }

    ULONG RefCount() {
        return ReadType<ULONG>("RefCount");
    }

    UINT8 PartitionCount() {
        return ReadType<UINT8>("PartitionCount");
    }

    UINT64 CurrentHandshakeMemoryUsage() {
        return ReadType<UINT64>("CurrentHandshakeMemoryUsage");
    }

    UINT64 TotalMemory() {
        UINT64 CxPlatTotalMemory;
        ReadTypeAtAddr<UINT64>(GetExpression("msquic!CxPlatTotalMemory"), &CxPlatTotalMemory);
        return CxPlatTotalMemory;
    }

    UINT64 RetryHandshakeMemoryLimit() {
        return (GetSettings().RetryMemoryLimit() * TotalMemory()) / UINT16_MAX;
    }

    bool IsSendingRetries() {
        return CurrentHandshakeMemoryUsage() >= RetryHandshakeMemoryLimit();
    }

    LinkedList GetRegistrations() {
        return LinkedList(AddrOf("Registrations"));
    }

    LinkedList GetBindings() {
        return LinkedList(AddrOf("Bindings"));
    }

    WorkerPool GetWorkerPool() {
        return WorkerPool(ReadPointer("WorkerPool"));
    }

    Settings GetSettings() {
        return Settings(AddrOf("Settings"));
    }
};
