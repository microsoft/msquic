/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Implements the TLS unit tests.

--*/

#define QUIC_TEST_APIS 1

#include "quic_platform.h"
#include "msquic.h"
#include "msquicp.h"
#include "quic_tls.h"

#define LOGINFO(fmt, ...) \
    printf("[INFO]: " fmt "\n", ##__VA_ARGS__)

#define LOGERROR(fmt, ...) \
    printf("[ERROR]: " fmt "\n", ##__VA_ARGS__)


static QUIC_RUNDOWN_REF TalTestSecConfigRundown = {0};
static QUIC_EVENT TalTestSecConfigDoneEvent = NULL;
static QUIC_EVENT TalTestProcessCompleteEvent = NULL;

static QUIC_SEC_CONFIG_PARAMS* TalTestSelfSignedCert = NULL;


//
// Test case info.
//

typedef struct _TAL_TESTCASE {
    //
    // Test case runner.
    //

    BOOLEAN(*TestCaseFunc)();

    //
    // Test case name.
    //

    char* TestCaseName;

} TAL_TESTCASE, *PTAL_TESTCASE;


static
void
TalTestSetUpTestCase(
    void
    );

static
void
TalTestTearDownTestCase(
    void
    );

static
void
TalTestHelp(
    _In_ char *argv[]
    );

static
BOOLEAN
TalTestInitialize(
    void
    );

static
BOOLEAN
TalTestHandshake(
    void
    );

static
BOOLEAN
TalTestHandshakeFragmented(
    void
    );

static
BOOLEAN
TalTestHandshakeSerial(
    void
    );

static
BOOLEAN
TalTestHandshakeInterleaved(
    void
    );

static
BOOLEAN
TalTestOneRttKey(
    void
    );

static
BOOLEAN
TalTestKeyUpdate(
    void
    );


static
QUIC_TLS_RESULT_FLAGS
TalTestProcessData2(
    _In_ QUIC_TLS* TlsContext,
    _Inout_ QUIC_TLS_PROCESS_STATE* State,
    _In_ QUIC_PACKET_KEY_TYPE BufferKey,
    _In_reads_bytes_(*BufferLength) const uint8_t * Buffer,
    _In_ uint32_t * BufferLength
    );

static
QUIC_TLS_RESULT_FLAGS
TalTestProcessData(
    _In_ QUIC_TLS* TlsContext,
    _Inout_ QUIC_TLS_PROCESS_STATE* State,
    _Inout_ QUIC_TLS_PROCESS_STATE* PeerState,
    _In_ uint32_t FragmentSize
    );

static
BOOLEAN
TalTestDoHandshake(
    _In_ QUIC_TLS* ServerContext,
    _In_ QUIC_TLS* ClientContext,
    _Inout_ QUIC_TLS_PROCESS_STATE *ServerState,
    _Inout_ QUIC_TLS_PROCESS_STATE *ClientState,
    _In_ uint32_t FragmentSize
    );

static
QUIC_TLS_RESULT_FLAGS
TalTestProcessFragmentedData(
    _In_ QUIC_TLS* TlsContext,
    _Inout_ QUIC_TLS_PROCESS_STATE* State,
    _In_ QUIC_PACKET_KEY_TYPE BufferKey,
    _In_reads_bytes_(BufferLength) const uint8_t * Buffer,
    _In_ uint32_t BufferLength,
    _In_ uint32_t FragmentSize
    );


static
void
TalTestOnSecConfigCreateComplete(
    _In_opt_ void* Context,
    _In_ QUIC_STATUS Status,
    _In_opt_ QUIC_SEC_CONFIG* SecConfig
    )

{
    QUIC_SEC_CONFIG** ServerConfig = Context;

    *ServerConfig = SecConfig;
    QuicEventSet(TalTestSecConfigDoneEvent);
}


static
void
TalTestSetUpTestCase(
    void
    )

{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    char Template[] = "/tmp/quictest.XXXXXX";

    QuicRundownInitialize(&TalTestSecConfigRundown);
    QuicEventInitialize(&TalTestSecConfigDoneEvent, FALSE, FALSE);
    QuicEventInitialize(&TalTestProcessCompleteEvent, FALSE, FALSE);

    TalTestSelfSignedCert = QuicPlatGetSelfSignedCert(QUIC_SELF_SIGN_CERT_USER);
    if (TalTestSelfSignedCert == NULL) {
        LOGERROR("QuicPlatGetSelfSignedCert() failed");

        //
        // Kill the test as all the tests are dependent on this.
        //

        exit(EXIT_FAILURE);
    }
}


static
void
TalTestTearDownTestCase(
    void
    )

{
    char RmCmd[26] = {0};

    if (TalTestProcessCompleteEvent != NULL) {
        QuicEventUninitialize(TalTestProcessCompleteEvent);
        TalTestProcessCompleteEvent = NULL;
    }

    if (TalTestSecConfigDoneEvent != NULL) {
        QuicEventUninitialize(TalTestSecConfigDoneEvent);
        TalTestSecConfigDoneEvent = NULL;
    }

    QuicRundownUninitialize(&TalTestSecConfigRundown);

    QuicPlatFreeSelfSignedCert(TalTestSelfSignedCert);
    TalTestSelfSignedCert = NULL;
}


//
// List of all test cases.
//

static TAL_TESTCASE TestCases[] = {
    { TalTestInitialize, "TalTestInitialize" },
    { TalTestHandshake, "TalTestHandshake" },
    { TalTestHandshakeFragmented, "TalTestHandshakeFragmented" },
    { TalTestHandshakeSerial, "TalTestHandshakeSerial" },
    { TalTestHandshakeInterleaved, "TalTestHandshakeInterleaved" },
    { TalTestOneRttKey, "TalTestOneRttKey" },
    { TalTestKeyUpdate, "TalTestKeyUpdate" },
};


static
void
TalTestOnProcessComplete(
    _In_ QUIC_CONNECTION* Connection
    )

{
    QUIC_EVENT Event = (QUIC_EVENT)Connection;

    QuicEventSet(Event);
}

static
BOOLEAN
TalTestOnRecvQuicTP(
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


static
QUIC_TLS_RESULT_FLAGS
TalTestProcessData2(
    _In_ QUIC_TLS* TlsContext,
    _Inout_ QUIC_TLS_PROCESS_STATE* State,
    _In_ QUIC_PACKET_KEY_TYPE BufferKey,
    _In_reads_bytes_(*BufferLength) const uint8_t * Buffer,
    _In_ uint32_t * BufferLength
    )
{
    QUIC_FRE_ASSERT(Buffer != NULL || *BufferLength == 0);

    if (Buffer != NULL) {
        if (BufferKey != State->ReadKey) {
            LOGERROR("BufferKey != State->ReadKey");
            return 0;
        }
    }

    QUIC_TLS_RESULT_FLAGS Result =
        QuicTlsProcessData(
            TlsContext,
            Buffer,
            BufferLength,
            State);

    if (Result & QUIC_TLS_RESULT_PENDING) {
        QuicEventWaitForever(TalTestProcessCompleteEvent);
        Result = QuicTlsProcessDataComplete(TlsContext, BufferLength);
    }

    if ((Result & QUIC_TLS_RESULT_ERROR) != 0) {
        LOGERROR("Result & QUIC_TLS_RESULT_ERROR) != 0");
    }

    return Result;
}


static
QUIC_TLS_RESULT_FLAGS
TalTestProcessFragmentedData(
    _In_ QUIC_TLS* TlsContext,
    _Inout_ QUIC_TLS_PROCESS_STATE* State,
    _In_ QUIC_PACKET_KEY_TYPE BufferKey,
    _In_reads_bytes_(BufferLength) const uint8_t * Buffer,
    _In_ uint32_t BufferLength,
    _In_ uint32_t FragmentSize
    )
{
    uint32_t Result = 0;
    uint32_t ConsumedBuffer = FragmentSize;
    uint32_t Count = 1;
    uint32_t TotalBufferLength = BufferLength;

    while (BufferLength != 0) {

        if (BufferLength < FragmentSize) {
            FragmentSize = BufferLength;
            ConsumedBuffer = FragmentSize;
        }

        LOGINFO("Processing fragment of %u/%u bytes", FragmentSize, TotalBufferLength);

        Result |=
            (uint32_t)TalTestProcessData2(
                TlsContext,
                State,
                BufferKey,
                Buffer,
                &ConsumedBuffer);

        if ((Result & QUIC_TLS_RESULT_ERROR) != 0) {
            goto Exit;
        }

        if (ConsumedBuffer > 0) {
            Buffer += ConsumedBuffer;
            BufferLength -= ConsumedBuffer;
        } else {
            ConsumedBuffer = FragmentSize * ++Count;
            ConsumedBuffer = min(ConsumedBuffer, BufferLength);
        }
    }

Exit:

    return (QUIC_TLS_RESULT_FLAGS)Result;
}


static
QUIC_TLS_RESULT_FLAGS
TalTestProcessData(
    _In_ QUIC_TLS* TlsContext,
    _Inout_ QUIC_TLS_PROCESS_STATE* State,
    _Inout_ QUIC_TLS_PROCESS_STATE* PeerState,
    _In_ uint32_t FragmentSize
    )
{
    if (PeerState == NULL) {
        //
        // Special case for client hello/initial.
        //
        uint32_t Zero = 0;
        return TalTestProcessData2(TlsContext, State, QUIC_PACKET_KEY_INITIAL, NULL, &Zero);
    }

    uint32_t Result;

    while (PeerState->BufferLength != 0) {
        uint16_t BufferLength;
        QUIC_PACKET_KEY_TYPE PeerWriteKey;

        uint32_t StartOffset = PeerState->BufferTotalLength - PeerState->BufferLength;
        if (PeerState->BufferOffset1Rtt != 0 && StartOffset >= PeerState->BufferOffset1Rtt) {
            PeerWriteKey = QUIC_PACKET_KEY_1_RTT;
            BufferLength = PeerState->BufferLength;

        } else if (PeerState->BufferOffsetHandshake != 0 && StartOffset >= PeerState->BufferOffsetHandshake) {
            PeerWriteKey = QUIC_PACKET_KEY_HANDSHAKE;
            if (PeerState->BufferOffset1Rtt != 0) {
                BufferLength = (uint16_t)(PeerState->BufferOffset1Rtt - StartOffset);
            } else {
                BufferLength = PeerState->BufferLength;
            }

        } else {
            PeerWriteKey = QUIC_PACKET_KEY_INITIAL;
            if (PeerState->BufferOffsetHandshake != 0) {
                BufferLength = (uint16_t)(PeerState->BufferOffsetHandshake - StartOffset);
            } else {
                BufferLength = PeerState->BufferLength;
            }
        }

        Result |=
            (uint32_t)TalTestProcessFragmentedData(
                TlsContext,
                State,
                PeerWriteKey,
                PeerState->Buffer,
                BufferLength,
                FragmentSize);

        PeerState->BufferLength -= BufferLength;
        QuicMoveMemory(
            PeerState->Buffer,
            PeerState->Buffer + BufferLength,
            PeerState->BufferLength);
    }

    return (QUIC_TLS_RESULT_FLAGS)Result;
}


static
BOOLEAN
TalTestDoHandshake(
    _In_ QUIC_TLS* ServerContext,
    _In_ QUIC_TLS* ClientContext,
    _Inout_ QUIC_TLS_PROCESS_STATE *ServerState,
    _Inout_ QUIC_TLS_PROCESS_STATE *ClientState,
    _In_ uint32_t FragmentSize
    )
{
    BOOLEAN Ret = TRUE;

    ClientState->BufferAllocLength = 8000;
    ClientState->Buffer = (uint8_t*)QUIC_ALLOC_NONPAGED(8000);

    if (ClientState->Buffer == NULL) {
        LOGERROR("Buffer alloc failure");
        Ret = FALSE;
        goto Exit;
    }

    ServerState->BufferAllocLength = 8000;
    ServerState->Buffer = (uint8_t*)QUIC_ALLOC_NONPAGED(8000);

    if (ServerState->Buffer == NULL) {
        LOGERROR("Buffer alloc failure");
        Ret = FALSE;
        goto Exit;
    }

    QUIC_TLS_RESULT_FLAGS Result =
        TalTestProcessData(
            ClientContext,
            ClientState,
            NULL,
            FragmentSize);

    if (!(Result & QUIC_TLS_RESULT_DATA)) {
        LOGERROR("!(Result & QUIC_TLS_RESULT_DATA)");
        Ret = FALSE;
        goto Exit;
    }

    Result =
        TalTestProcessData(
            ServerContext,
            ServerState,
            ClientState,
            FragmentSize);

    if (!(Result & QUIC_TLS_RESULT_DATA)) {
        LOGERROR("!(Result & QUIC_TLS_RESULT_DATA)");
        Ret = FALSE;
        goto Exit;
    }

    if (ServerState->WriteKeys[QUIC_PACKET_KEY_1_RTT] == NULL) {
        LOGERROR("TalTestServerState.WriteKeys[QUIC_PACKET_KEY_1_RTT] == NULL");
        Ret = FALSE;
        goto Exit;
    }

    Result =
        TalTestProcessData(
            ClientContext,
            ClientState,
            ServerState,
            FragmentSize);

    if (!(Result & QUIC_TLS_RESULT_DATA)) {
        LOGERROR("!(Result & QUIC_TLS_RESULT_DATA)");
        Ret = FALSE;
        goto Exit;
    }

    if (!(Result & QUIC_TLS_RESULT_COMPLETE)) {
        LOGERROR("!(Result & QUIC_TLS_RESULT_COMPLETE)");
        Ret = FALSE;
        goto Exit;
    }

    if (ClientState->WriteKeys[QUIC_PACKET_KEY_1_RTT] == NULL) {
        LOGERROR("TalTestServerState.WriteKeys[QUIC_PACKET_KEY_1_RTT] == NULL");
        Ret = FALSE;
        goto Exit;
    }

    Result =
        TalTestProcessData(
            ServerContext,
            ServerState,
            ClientState,
            FragmentSize);

    if (!(Result & QUIC_TLS_RESULT_COMPLETE)) {
        LOGERROR("!(Result & QUIC_TLS_RESULT_COMPLETE)");
        Ret = FALSE;
        goto Exit;
    }

Exit:

    if (ClientState->Buffer != NULL) {
        QuicFree(ClientState->Buffer);
        ClientState->Buffer = NULL;
    }

    if (ServerState->Buffer != NULL) {
        QuicFree(ServerState->Buffer);
        ServerState->Buffer = NULL;
    }

    return Ret;
}


BOOLEAN
TalTestInitializeServer(
    _In_ QUIC_TLS_SESSION* Session,
    _In_ QUIC_SEC_CONFIG* SecConfig,
    _Out_ QUIC_TLS* *TlsContext
    )

{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_TLS_CONFIG Config = {0};
    QUIC_TLS* TempTlsContext = NULL;
    uint32_t QuicVersion = 1;
    QUIC_EVENT ProcessCompletionEvent = NULL;

    QuicEventInitialize(&ProcessCompletionEvent, TRUE, FALSE);

    Config.IsServer = TRUE;
    Config.LocalTPBuffer = QuicAlloc(QuicTlsTPHeaderSize + 64);
    QUIC_FRE_ASSERT(Config.LocalTPBuffer != NULL);
    Config.LocalTPLength = QuicTlsTPHeaderSize + 64;
    Config.ProcessCompleteCallback = TalTestOnProcessComplete;
    Config.ReceiveTPCallback = TalTestOnRecvQuicTP;
    Config.SecConfig = (QUIC_SEC_CONFIG*) SecConfig;
    Config.TlsSession = Session;
    Config.Connection = NULL;

    Status = QuicTlsInitialize(&Config, &TempTlsContext);

    if (QUIC_FAILED(Status)) {
        LOGERROR("TLS server init failed, error: %lu.", Status);
        return FALSE;
    }

    *TlsContext = TempTlsContext;
    return TRUE;
}


BOOLEAN
TalTestInitializeClient(
    _In_ QUIC_TLS_SESSION* Session,
    _In_ QUIC_SEC_CONFIG* SecConfig,
    _Out_ QUIC_TLS* *TlsContext
    )

{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_TLS_CONFIG Config = {0};
    QUIC_TLS* TempTlsContext = NULL;
    uint32_t QuicVersion = 1;
    QUIC_EVENT ProcessCompletionEvent = NULL;

    QuicEventInitialize(&ProcessCompletionEvent, TRUE, FALSE);

    Config.ServerName = "localhost";
    Config.IsServer = FALSE;
    Config.LocalTPBuffer = QuicAlloc(QuicTlsTPHeaderSize + 64);
    QUIC_FRE_ASSERT(Config.LocalTPBuffer != NULL);
    Config.LocalTPLength = QuicTlsTPHeaderSize + 64;
    Config.ProcessCompleteCallback = TalTestOnProcessComplete;
    Config.ReceiveTPCallback = TalTestOnRecvQuicTP;
    Config.SecConfig = (QUIC_SEC_CONFIG*) SecConfig;
    Config.TlsSession = Session;
    Config.Connection = NULL;

    Status = QuicTlsInitialize(&Config, &TempTlsContext);

    if (QUIC_FAILED(Status)) {
        printf("TLS client init failed, error: %lu.", Status);
        return FALSE;
    }

    *TlsContext = TempTlsContext;
    return TRUE;
}


static
BOOLEAN
TalTestInitialize(
    void
    )

{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    BOOLEAN Ret = TRUE;
    QUIC_SEC_CONFIG* ClientConfig = NULL;
    QUIC_SEC_CONFIG* ServerConfig = NULL;
    QUIC_TLS* ClientTlsContext = NULL;
    QUIC_TLS* ServerTlsContext = NULL;
    QUIC_TLS_SESSION* TlsSession = NULL;

    Status = QuicTlsSessionInitialize("MsQuicTest", &TlsSession);

    if (!QUIC_SUCCEEDED(Status)) {
        LOGERROR("QuicTlsSessionInitialize() failed, error %lu", Status);
        Ret = FALSE;
        goto Exit;
    }

    Status =
        QuicTlsServerSecConfigCreate(
            &TalTestSecConfigRundown,
            (QUIC_SEC_CONFIG_FLAGS)TalTestSelfSignedCert->Flags,
            TalTestSelfSignedCert->Certificate,
            TalTestSelfSignedCert->Principal,
            &ServerConfig,
            TalTestOnSecConfigCreateComplete);

    if (!QUIC_SUCCEEDED(Status)) {
        LOGERROR("QuicTlsServerSecConfigCreate() failed, error %lu", Status);
        Ret = FALSE;
        goto Exit;
    }

    QuicEventWaitWithTimeout(TalTestSecConfigDoneEvent, 2000);

    if (!TalTestInitializeServer(
            TlsSession,
            ServerConfig,
            &ServerTlsContext)) {
        return FALSE;
    }

    Status = QuicTlsClientSecConfigCreate(0, &ClientConfig);

    if (!QUIC_SUCCEEDED(Status)) {
        LOGERROR("QuicTlsClientSecConfigCreate() failed, error %lu", Status);
        Ret = FALSE;
        goto Exit;
    }

    if (!TalTestInitializeClient(
            TlsSession,
            ClientConfig,
            &ClientTlsContext)) {
        return FALSE;
    }

Exit:

    if (ServerTlsContext != NULL) {
        QuicTlsUninitialize(ServerTlsContext);
        ServerTlsContext = NULL;
    }

    if (ServerConfig != NULL) {
        QuicTlsSecConfigRelease(ServerConfig);
        ServerConfig = NULL;
    }

    if (ClientTlsContext != NULL) {
        QuicTlsUninitialize(ClientTlsContext);
        ClientTlsContext = NULL;
    }

    if (ClientConfig != NULL) {
        QuicTlsSecConfigRelease(ClientConfig);
        ClientConfig = NULL;
    }

    if (TlsSession != NULL) {
        QuicTlsSessionUninitialize(TlsSession);
        TlsSession = NULL;
    }

    return Ret;
}


static
BOOLEAN
TalTestHandshake(
    void
    )

{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    BOOLEAN Ret = TRUE;
    QUIC_SEC_CONFIG* ClientConfig = NULL;
    QUIC_SEC_CONFIG* ServerConfig = NULL;
    QUIC_TLS* ClientTlsContext = NULL;
    QUIC_TLS* ServerTlsContext = NULL;
    QUIC_TLS_PROCESS_STATE ClientState = {0};
    QUIC_TLS_PROCESS_STATE ServerState = {0};
    QUIC_TLS_SESSION* TlsSession = NULL;

    Status = QuicTlsSessionInitialize("MsQuicTest", &TlsSession);

    if (!QUIC_SUCCEEDED(Status)) {
        LOGERROR("QuicTlsSessionInitialize() failed, error %lu", Status);
        Ret = FALSE;
        goto Exit;
    }

    Status =
        QuicTlsServerSecConfigCreate(
            &TalTestSecConfigRundown,
            (QUIC_SEC_CONFIG_FLAGS)TalTestSelfSignedCert->Flags,
            TalTestSelfSignedCert->Certificate,
            TalTestSelfSignedCert->Principal,
            &ServerConfig,
            TalTestOnSecConfigCreateComplete);

    if (!QUIC_SUCCEEDED(Status)) {
        LOGERROR("QuicTlsServerSecConfigCreate() failed, error %lu", Status);
        Ret = FALSE;
        goto Exit;
    }

    QuicEventWaitWithTimeout(TalTestSecConfigDoneEvent, 2000);

    if (!TalTestInitializeServer(
            TlsSession,
            ServerConfig,
            &ServerTlsContext)) {
        Ret = FALSE;
        goto Exit;
    }

    Status = QuicTlsClientSecConfigCreate(0, &ClientConfig);

    if (!QUIC_SUCCEEDED(Status)) {
        LOGERROR("QuicTlsClientSecConfigCreate() failed, error %lu", Status);
        Ret = FALSE;
        goto Exit;
    }

    if (!TalTestInitializeClient(
            TlsSession,
            ClientConfig,
            &ClientTlsContext)) {
        Ret = FALSE;
        goto Exit;
    }

    if (!TalTestDoHandshake(
            ServerTlsContext,
            ClientTlsContext,
            &ServerState,
            &ClientState,
            1200)) {
        Ret = FALSE;
        goto Exit;
    }

Exit:

    if (ServerTlsContext != NULL) {
        QuicTlsUninitialize(ServerTlsContext);
        ServerTlsContext = NULL;
    }

    if (ServerConfig != NULL) {
        QuicTlsSecConfigRelease(ServerConfig);
        ServerConfig = NULL;
    }

    if (ClientTlsContext != NULL) {
        QuicTlsUninitialize(ClientTlsContext);
        ClientTlsContext = NULL;
    }

    if (ClientConfig != NULL) {
        QuicTlsSecConfigRelease(ClientConfig);
        ClientConfig = NULL;
    }

    if (TlsSession != NULL) {
        QuicTlsSessionUninitialize(TlsSession);
        TlsSession = NULL;
    }

    return Ret;
}


static
BOOLEAN
TalTestHandshakeFragmented(
    void
    )

{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    BOOLEAN Ret = TRUE;
    QUIC_SEC_CONFIG* ClientConfig = NULL;
    QUIC_SEC_CONFIG* ServerConfig = NULL;
    QUIC_TLS* ClientTlsContext = NULL;
    QUIC_TLS* ServerTlsContext = NULL;
    QUIC_TLS_PROCESS_STATE ClientState = {0};
    QUIC_TLS_PROCESS_STATE ServerState = {0};
    QUIC_TLS_SESSION* TlsSession = NULL;

    Status = QuicTlsSessionInitialize("MsQuicTest", &TlsSession);

    if (!QUIC_SUCCEEDED(Status)) {
        LOGERROR("QuicTlsSessionInitialize() failed, error %lu", Status);
        Ret = FALSE;
        goto Exit;
    }

    QuicEventReset(TalTestSecConfigDoneEvent);

    Status =
        QuicTlsServerSecConfigCreate(
            &TalTestSecConfigRundown,
            (QUIC_SEC_CONFIG_FLAGS)TalTestSelfSignedCert->Flags,
            TalTestSelfSignedCert->Certificate,
            TalTestSelfSignedCert->Principal,
            &ServerConfig,
            TalTestOnSecConfigCreateComplete);

    if (!QUIC_SUCCEEDED(Status)) {
        LOGERROR("Test Init failed. QuicTlsServerSecConfigCreate() failed, error %lu", Status);
        Ret = FALSE;
        goto Exit;
    }

    QuicEventWaitWithTimeout(TalTestSecConfigDoneEvent, 2000);

    if (!TalTestInitializeServer(
            TlsSession,
            ServerConfig,
            &ServerTlsContext)) {
        Ret = FALSE;
        goto Exit;
    }

    Status = QuicTlsClientSecConfigCreate(0, &ClientConfig);

    if (!QUIC_SUCCEEDED(Status)) {
        LOGERROR("QuicTlsClientSecConfigCreate() failed, error %lu", Status);
        Ret = FALSE;
        goto Exit;
    }


    if (!TalTestInitializeClient(
            TlsSession,
            ClientConfig,
            &ClientTlsContext)) {
        Ret = FALSE;
        goto Exit;
    }

    if (!TalTestDoHandshake(ServerTlsContext, ClientTlsContext, &ServerState, &ClientState, 300)) {
        Ret = FALSE;
        goto Exit;
    }

Exit:

    if (ServerTlsContext != NULL) {
        QuicTlsUninitialize(ServerTlsContext);
        ServerTlsContext = NULL;
    }

    if (ServerConfig != NULL) {
        QuicTlsSecConfigRelease(ServerConfig);
        ServerConfig = NULL;
    }

    if (ClientTlsContext != NULL) {
        QuicTlsUninitialize(ClientTlsContext);
        ClientTlsContext = NULL;
    }

    if (ClientConfig != NULL) {
        QuicTlsSecConfigRelease(ClientConfig);
        ClientConfig = NULL;
    }

    if (TlsSession != NULL) {
        QuicTlsSessionUninitialize(TlsSession);
        TlsSession = NULL;
    }

    return Ret;
}


static
BOOLEAN
TalTestHandshakeSerial(
    void
    )

{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    BOOLEAN Ret = TRUE;
    QUIC_SEC_CONFIG* ClientConfig = NULL;
    QUIC_SEC_CONFIG* ServerConfig = NULL;
    QUIC_TLS* ClientTlsContext1 = NULL;
    QUIC_TLS* ClientTlsContext2 = NULL;
    QUIC_TLS* ServerTlsContext1= NULL;
    QUIC_TLS* ServerTlsContext2 = NULL;
    QUIC_TLS_PROCESS_STATE ClientState1 = {0};
    QUIC_TLS_PROCESS_STATE ServerState1 = {0};
    QUIC_TLS_PROCESS_STATE ClientState2 = {0};
    QUIC_TLS_PROCESS_STATE ServerState2 = {0};
    QUIC_TLS_SESSION* TlsSession = NULL;

    Status = QuicTlsSessionInitialize("MsQuicTest", &TlsSession);

    if (!QUIC_SUCCEEDED(Status)) {
        LOGERROR("QuicTlsSessionInitialize() failed, error %lu", Status);
        Ret = FALSE;
        goto Exit;
    }

    QuicEventReset(TalTestSecConfigDoneEvent);

    Status =
        QuicTlsServerSecConfigCreate(
            &TalTestSecConfigRundown,
            (QUIC_SEC_CONFIG_FLAGS)TalTestSelfSignedCert->Flags,
            TalTestSelfSignedCert->Certificate,
            TalTestSelfSignedCert->Principal,
            &ServerConfig,
            TalTestOnSecConfigCreateComplete);

    if (!QUIC_SUCCEEDED(Status)) {
        LOGERROR("Test Init failed. QuicTlsServerSecConfigCreate() failed, error %lu", Status);
        Ret = FALSE;
        goto Exit;
    }

    QuicEventWaitWithTimeout(TalTestSecConfigDoneEvent, 2000);

    if (!TalTestInitializeServer(
            TlsSession,
            ServerConfig,
            &ServerTlsContext1)) {
        Ret = FALSE;
        goto Exit;
    }

    Status = QuicTlsClientSecConfigCreate(0, &ClientConfig);

    if (!QUIC_SUCCEEDED(Status)) {
        LOGERROR("QuicTlsClientSecConfigCreate() failed, error %lu", Status);
        Ret = FALSE;
        goto Exit;
    }

    if (!TalTestInitializeClient(
            TlsSession,
            ClientConfig,
            &ClientTlsContext1)) {
        Ret = FALSE;
        goto Exit;
    }

    if (!TalTestDoHandshake(ServerTlsContext1, ClientTlsContext1, &ServerState1, &ClientState1, 1200)) {
        Ret = FALSE;
        goto Exit;
    }

    if (!TalTestInitializeServer(
            TlsSession,
            ServerConfig,
            &ServerTlsContext2)) {
        Ret = FALSE;
        goto Exit;
    }

    if (!TalTestInitializeClient(
            TlsSession,
            ClientConfig,
            &ClientTlsContext2)) {
        Ret = FALSE;
        goto Exit;
    }

    if (!TalTestDoHandshake(ServerTlsContext2, ClientTlsContext2, &ServerState2, &ClientState2, 1200)) {
        Ret = FALSE;
        goto Exit;
    }

Exit:

    if (ServerTlsContext1 != NULL) {
        QuicTlsUninitialize(ServerTlsContext1);
        ServerTlsContext1 = NULL;
    }

    if (ServerTlsContext2 != NULL) {
        QuicTlsUninitialize(ServerTlsContext2);
        ServerTlsContext2 = NULL;
    }

    if (ServerConfig != NULL) {
        QuicTlsSecConfigRelease(ServerConfig);
        ServerConfig = NULL;
    }

    if (ClientTlsContext1 != NULL) {
        QuicTlsUninitialize(ClientTlsContext1);
        ClientTlsContext1 = NULL;
    }

    if (ClientTlsContext2!= NULL) {
        QuicTlsUninitialize(ClientTlsContext2);
        ClientTlsContext2 = NULL;
    }

    if (ClientConfig != NULL) {
        QuicTlsSecConfigRelease(ClientConfig);
        ClientConfig = NULL;
    }

    if (TlsSession != NULL) {
        QuicTlsSessionUninitialize(TlsSession);
        TlsSession = NULL;
    }

    return Ret;
}


static
BOOLEAN
TalTestHandshakeInterleaved(
    void
    )

{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    BOOLEAN Ret = TRUE;
    QUIC_SEC_CONFIG* ClientConfig = NULL;
    QUIC_SEC_CONFIG* ServerConfig = NULL;
    QUIC_TLS* ClientTlsContext1 = NULL;
    QUIC_TLS* ClientTlsContext2 = NULL;
    QUIC_TLS* ServerTlsContext1 = NULL;
    QUIC_TLS* ServerTlsContext2 = NULL;
    QUIC_TLS_SESSION* TlsSession = NULL;
    QUIC_TLS_PROCESS_STATE ClientState1 = {0};
    QUIC_TLS_PROCESS_STATE ServerState1 = {0};
    QUIC_TLS_PROCESS_STATE ClientState2 = {0};
    QUIC_TLS_PROCESS_STATE ServerState2 = {0};

    ClientState1.BufferAllocLength = 8000;
    ClientState1.Buffer = (uint8_t*)QUIC_ALLOC_NONPAGED(8000);

    if (ClientState1.Buffer == NULL) {
        LOGERROR("Buffer alloc failure");
        Ret = FALSE;
        goto Exit;
    }

    ClientState2.BufferAllocLength = 8000;
    ClientState2.Buffer = (uint8_t*)QUIC_ALLOC_NONPAGED(8000);

    if (ClientState2.Buffer == NULL) {
        LOGERROR("Buffer alloc failure");
        Ret = FALSE;
        goto Exit;
    }

    ServerState1.BufferAllocLength = 8000;
    ServerState1.Buffer = (uint8_t*)QUIC_ALLOC_NONPAGED(8000);

    if (ServerState1.Buffer == NULL) {
        LOGERROR("Buffer alloc failure");
        Ret = FALSE;
        goto Exit;
    }

    ServerState2.BufferAllocLength = 8000;
    ServerState2.Buffer = (uint8_t*)QUIC_ALLOC_NONPAGED(8000);

    if (ServerState2.Buffer == NULL) {
        LOGERROR("Buffer alloc failure");
        Ret = FALSE;
        goto Exit;
    }

    Status = QuicTlsSessionInitialize("MsQuicTest", &TlsSession);

    if (!QUIC_SUCCEEDED(Status)) {
        LOGERROR("QuicTlsSessionInitialize() failed, error %lu", Status);
        Ret = FALSE;
        goto Exit;
    }

    QuicEventReset(TalTestSecConfigDoneEvent);

    Status =
        QuicTlsServerSecConfigCreate(
            &TalTestSecConfigRundown,
            (QUIC_SEC_CONFIG_FLAGS)TalTestSelfSignedCert->Flags,
            TalTestSelfSignedCert->Certificate,
            TalTestSelfSignedCert->Principal,
            &ServerConfig,
            TalTestOnSecConfigCreateComplete);

    if (!QUIC_SUCCEEDED(Status)) {
        LOGERROR("Test Init failed. QuicTlsServerSecConfigCreate() failed, error %lu", Status);
        Ret = FALSE;
        goto Exit;
    }

    QuicEventWaitWithTimeout(TalTestSecConfigDoneEvent, 2000);

    if (!TalTestInitializeServer(
            TlsSession,
            ServerConfig,
            &ServerTlsContext1)) {
        Ret = FALSE;
        goto Exit;
    }

    Status = QuicTlsClientSecConfigCreate(0, &ClientConfig);

    if (!QUIC_SUCCEEDED(Status)) {
        LOGERROR("QuicTlsClientSecConfigCreate() failed, error %lu", Status);
        Ret = FALSE;
        goto Exit;
    }

    if (!TalTestInitializeClient(
            TlsSession,
            ClientConfig,
            &ClientTlsContext1)) {
        Ret = FALSE;
        goto Exit;
    }

    if (!TalTestInitializeServer(
            TlsSession,
            ServerConfig,
            &ServerTlsContext2)) {
        Ret = FALSE;
        goto Exit;
    }

    if (!TalTestInitializeClient(
            TlsSession,
            ClientConfig,
            &ClientTlsContext2)) {
        Ret = FALSE;
        goto Exit;
    }

    QUIC_TLS_RESULT_FLAGS Result =
        TalTestProcessData(
            ClientTlsContext1,
            &ClientState1,
            NULL,
            1200);

    if (!(Result & QUIC_TLS_RESULT_DATA)) {
        LOGERROR("!(Result & QUIC_TLS_RESULT_DATA)");
        Ret = FALSE;
        goto Exit;
    }

    Result =
        TalTestProcessData(
            ClientTlsContext2,
            &ClientState2,
            NULL,
            1200);

    if (!(Result & QUIC_TLS_RESULT_DATA)) {
        LOGERROR("!(Result & QUIC_TLS_RESULT_DATA)");
        Ret = FALSE;
        goto Exit;
    }

    Result =
        TalTestProcessData(
            ServerTlsContext1,
            &ServerState1,
            &ClientState1,
            1200);

    if (!(Result & QUIC_TLS_RESULT_DATA)) {
        LOGERROR("!(Result & QUIC_TLS_RESULT_DATA)");
        Ret = FALSE;
        goto Exit;
    }

    if (ServerState1.WriteKeys[QUIC_PACKET_KEY_1_RTT] == NULL) {
        LOGERROR("TalTestServerState.WriteKeys[QUIC_PACKET_KEY_1_RTT] == NULL");
        Ret = FALSE;
        goto Exit;
    }

    Result =
        TalTestProcessData(
            ServerTlsContext2,
            &ServerState2,
            &ClientState2,
            1200);

    if (!(Result & QUIC_TLS_RESULT_DATA)) {
        LOGERROR("!(Result & QUIC_TLS_RESULT_DATA)");
        Ret = FALSE;
        goto Exit;
    }

    if (ServerState2.WriteKeys[QUIC_PACKET_KEY_1_RTT] == NULL) {
        LOGERROR("TalTestServerState.WriteKeys[QUIC_PACKET_KEY_1_RTT] == NULL");
        Ret = FALSE;
        goto Exit;
    }

    Result =
        TalTestProcessData(
            ClientTlsContext1,
            &ClientState1,
            &ServerState1,
            1200);

    if (!(Result & QUIC_TLS_RESULT_DATA)) {
        LOGERROR("!(Result & QUIC_TLS_RESULT_DATA)");
        Ret = FALSE;
        goto Exit;
    }

    if (!(Result & QUIC_TLS_RESULT_COMPLETE)) {
        LOGERROR("!(Result & QUIC_TLS_RESULT_COMPLETE)");
        Ret = FALSE;
        goto Exit;
    }

    if (ClientState1.WriteKeys[QUIC_PACKET_KEY_1_RTT] == NULL) {
        LOGERROR("TalTestServerState.WriteKeys[QUIC_PACKET_KEY_1_RTT] == NULL");
        Ret = FALSE;
        goto Exit;
    }

    Result =
        TalTestProcessData(
            ClientTlsContext2,
            &ClientState2,
            &ServerState2,
            1200);

    if (!(Result & QUIC_TLS_RESULT_DATA)) {
        LOGERROR("!(Result & QUIC_TLS_RESULT_DATA)");
        Ret = FALSE;
        goto Exit;
    }

    if (!(Result & QUIC_TLS_RESULT_COMPLETE)) {
        LOGERROR("!(Result & QUIC_TLS_RESULT_COMPLETE)");
        Ret = FALSE;
        goto Exit;
    }

    if (ClientState2.WriteKeys[QUIC_PACKET_KEY_1_RTT] == NULL) {
        LOGERROR("TalTestServerState.WriteKeys[QUIC_PACKET_KEY_1_RTT] == NULL");
        Ret = FALSE;
        goto Exit;
    }

    Result =
        TalTestProcessData(
            ServerTlsContext1,
            &ServerState1,
            &ClientState1,
            1200);

    if (!(Result & QUIC_TLS_RESULT_COMPLETE)) {
        LOGERROR("!(Result & QUIC_TLS_RESULT_COMPLETE)");
        Ret = FALSE;
        goto Exit;
    }

    Result =
        TalTestProcessData(
            ServerTlsContext2,
            &ServerState2,
            &ClientState2,
            1200);

    if (!(Result & QUIC_TLS_RESULT_COMPLETE)) {
        LOGERROR("!(Result & QUIC_TLS_RESULT_COMPLETE)");
        Ret = FALSE;
        goto Exit;
    }

Exit:

    if (ServerTlsContext1 != NULL) {
        QuicTlsUninitialize(ServerTlsContext1);
        ServerTlsContext1 = NULL;
    }

    if (ServerTlsContext2 != NULL) {
        QuicTlsUninitialize(ServerTlsContext2);
        ServerTlsContext2 = NULL;
    }

    if (ServerConfig != NULL) {
        QuicTlsSecConfigRelease(ServerConfig);
        ServerConfig = NULL;
    }

    if (ClientTlsContext1 != NULL) {
        QuicTlsUninitialize(ClientTlsContext1);
        ClientTlsContext1 = NULL;
    }

    if (ClientTlsContext2 != NULL) {
        QuicTlsUninitialize(ClientTlsContext2);
        ClientTlsContext2 = NULL;
    }

    if (ClientConfig != NULL) {
        QuicTlsSecConfigRelease(ClientConfig);
        ClientConfig = NULL;
    }

    if (TlsSession != NULL) {
        QuicTlsSessionUninitialize(TlsSession);
        TlsSession = NULL;
    }

    if (ClientState1.Buffer != NULL) {
        QuicFree(ClientState1.Buffer);
        ClientState1.Buffer = NULL;
    }

    if (ServerState1.Buffer != NULL) {
        QuicFree(ServerState1.Buffer);
        ServerState1.Buffer = NULL;
    }

    if (ClientState2.Buffer != NULL) {
        QuicFree(ClientState2.Buffer);
        ClientState2.Buffer = NULL;
    }

    if (ServerState2.Buffer != NULL) {
        QuicFree(ServerState2.Buffer);
        ServerState2.Buffer = NULL;
    }

    return Ret;
}


static
BOOLEAN
TalTestOneRttKey(
    void
    )

{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    BOOLEAN Ret = TRUE;
    QUIC_SEC_CONFIG* ClientConfig = NULL;
    QUIC_SEC_CONFIG* ServerConfig = NULL;
    QUIC_TLS* ClientTlsContext = NULL;
    QUIC_TLS* ServerTlsContext = NULL;
    QUIC_TLS_PROCESS_STATE ClientState = {0};
    QUIC_TLS_PROCESS_STATE ServerState = {0};
    QUIC_TLS_SESSION* TlsSession = NULL;

    Status = QuicTlsSessionInitialize("MsQuicTest", &TlsSession);

    if (!QUIC_SUCCEEDED(Status)) {
        LOGERROR("QuicTlsSessionInitialize() failed, error %lu", Status);
        Ret = FALSE;
        goto Exit;
    }

    Status =
        QuicTlsServerSecConfigCreate(
            &TalTestSecConfigRundown,
            (QUIC_SEC_CONFIG_FLAGS)TalTestSelfSignedCert->Flags,
            TalTestSelfSignedCert->Certificate,
            TalTestSelfSignedCert->Principal,
            &ServerConfig,
            TalTestOnSecConfigCreateComplete);

    if (!QUIC_SUCCEEDED(Status)) {
        LOGERROR("Test Init failed. QuicTlsServerSecConfigCreate() failed, error %lu", Status);
        Ret = FALSE;
        goto Exit;
    }

    QuicEventWaitWithTimeout(TalTestSecConfigDoneEvent, 2000);

    if (!TalTestInitializeServer(
            TlsSession,
            ServerConfig,
            &ServerTlsContext)) {
        Ret = FALSE;
        goto Exit;
    }

    Status = QuicTlsClientSecConfigCreate(0, &ClientConfig);

    if (!QUIC_SUCCEEDED(Status)) {
        LOGERROR("QuicTlsClientSecConfigCreate() failed, error %lu", Status);
        Ret = FALSE;
        goto Exit;
    }

    if (!TalTestInitializeClient(
            TlsSession,
            ClientConfig,
            &ClientTlsContext)) {
        Ret = FALSE;
        goto Exit;
    }

    if (!TalTestDoHandshake(ServerTlsContext, ClientTlsContext, &ServerState, &ClientState, 1200)) {
        Ret = FALSE;
        goto Exit;
    }

    uint8_t Header[32] = { 1, 2, 3, 4 };
    uint64_t PacketNumber = 0;
    uint8_t Buffer[1000] = { 0 };
    uint8_t Iv[QUIC_IV_LENGTH] = {0};

    QuicCryptoCombineIvAndPacketNumber(
        ServerState.WriteKeys[QUIC_PACKET_KEY_1_RTT]->Iv,
        (uint8_t *)&PacketNumber,
        Iv);

    if (QuicEncrypt(
            ServerState.WriteKeys[QUIC_PACKET_KEY_1_RTT]->PacketKey,
            Iv,
            sizeof(Header),
            Header,
            sizeof(Buffer),
            Buffer) != QUIC_STATUS_SUCCESS) {
        Ret = FALSE;
        goto Exit;
    }

    uint8_t Mask[16];

    if (QuicHpComputeMask(
            ServerState.WriteKeys[QUIC_PACKET_KEY_1_RTT]->HeaderKey,
            1,
            Buffer,
            Mask) != QUIC_STATUS_SUCCESS) {
        Ret = FALSE;
        goto Exit;
    }

    for (uint32_t i = 0; i < sizeof(Mask); i++) {
        Header[i] ^= Mask[i];
    }

    if (QuicHpComputeMask(
            ClientState.ReadKeys[QUIC_PACKET_KEY_1_RTT]->HeaderKey,
            1,
            Buffer,
            Mask) != QUIC_STATUS_SUCCESS) {
         Ret = FALSE;
         goto Exit;
     }

    for (uint32_t i = 0; i < sizeof(Mask); i++) {
        Header[i] ^= Mask[i];
    }

    QuicCryptoCombineIvAndPacketNumber(
        ServerState.ReadKeys[QUIC_PACKET_KEY_1_RTT]->Iv,
        (uint8_t *)&PacketNumber,
        Iv);

    if (QuicDecrypt(
            ClientState.ReadKeys[QUIC_PACKET_KEY_1_RTT]->PacketKey,
            Iv,
            sizeof(Header),
            Header,
            sizeof(Buffer),
            Buffer) != QUIC_STATUS_SUCCESS) {
        Ret = FALSE;
        goto Exit;
    }

    if (Header[0] != 1 ||
        Header[1] != 2 ||
        Header[2] != 3 ||
        Header[3] != 4) {
        Ret = FALSE;
        goto Exit;
    }

    for (uint32_t i = 0; i < sizeof(Buffer) - QUIC_ENCRYPTION_OVERHEAD; i++) {
        if (Buffer[i] != 0) {
            Ret = FALSE;
            goto Exit;
        }
    }

Exit:

    if (ServerTlsContext != NULL) {
        QuicTlsUninitialize(ServerTlsContext);
        ServerTlsContext = NULL;
    }

    if (ServerConfig != NULL) {
        QuicTlsSecConfigRelease(ServerConfig);
        ServerConfig = NULL;
    }

    if (ClientTlsContext != NULL) {
        QuicTlsUninitialize(ClientTlsContext);
        ClientTlsContext = NULL;
    }

    if (ClientConfig != NULL) {
        QuicTlsSecConfigRelease(ClientConfig);
        ClientConfig = NULL;
    }

    if (TlsSession != NULL) {
        QuicTlsSessionUninitialize(TlsSession);
        TlsSession = NULL;
    }

    return Ret;
}


static
BOOLEAN
TalTestKeyUpdate(
    void
    )

{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    BOOLEAN Ret = TRUE;
    QUIC_SEC_CONFIG* ClientConfig = NULL;
    QUIC_SEC_CONFIG* ServerConfig = NULL;
    QUIC_TLS* ClientTlsContext = NULL;
    QUIC_TLS* ServerTlsContext = NULL;
    QUIC_TLS_PROCESS_STATE ClientState = {0};
    QUIC_TLS_PROCESS_STATE ServerState = {0};
    QUIC_TLS_SESSION* TlsSession = NULL;
    QUIC_PACKET_KEY *UpdateWriteKey = NULL;
    QUIC_PACKET_KEY *UpdateReadKey = NULL;

    Status = QuicTlsSessionInitialize("MsQuicTest", &TlsSession);

    if (!QUIC_SUCCEEDED(Status)) {
        LOGERROR("QuicTlsSessionInitialize() failed, error %lu", Status);
        Ret = FALSE;
        goto Exit;
    }

    Status =
        QuicTlsServerSecConfigCreate(
            &TalTestSecConfigRundown,
            (QUIC_SEC_CONFIG_FLAGS)TalTestSelfSignedCert->Flags,
            TalTestSelfSignedCert->Certificate,
            TalTestSelfSignedCert->Principal,
            &ServerConfig,
            TalTestOnSecConfigCreateComplete);

    if (!QUIC_SUCCEEDED(Status)) {
        LOGERROR("Test Init failed. QuicTlsServerSecConfigCreate() failed, error %lu", Status);
        Ret = FALSE;
        goto Exit;
    }

    QuicEventWaitWithTimeout(TalTestSecConfigDoneEvent, 2000);

    if (!TalTestInitializeServer(
            TlsSession,
            ServerConfig,
            &ServerTlsContext)) {
        Ret = FALSE;
        goto Exit;
    }

    Status = QuicTlsClientSecConfigCreate(0, &ClientConfig);

    if (!QUIC_SUCCEEDED(Status)) {
        LOGERROR("QuicTlsClientSecConfigCreate() failed, error %lu", Status);
        Ret = FALSE;
        goto Exit;
    }

    if (!TalTestInitializeClient(
            TlsSession,
            ClientConfig,
            &ClientTlsContext)) {
        Ret = FALSE;
        goto Exit;
    }

    if (!TalTestDoHandshake(ServerTlsContext, ClientTlsContext, &ServerState, &ClientState, 1200)) {
        Ret = FALSE;
        goto Exit;
    }

    if (!QUIC_SUCCEEDED(
            QuicPacketKeyUpdate(
                ServerState.WriteKeys[QUIC_PACKET_KEY_1_RTT],
                &UpdateWriteKey))) {
        Ret = FALSE;
        goto Exit;
    }

    if (!QUIC_SUCCEEDED(
            QuicPacketKeyUpdate(
                ClientState.ReadKeys[QUIC_PACKET_KEY_1_RTT],
                &UpdateReadKey))) {
        Ret = FALSE;
        goto Exit;
    }

    uint8_t Header[32] = { 1, 2, 3, 4 };
    uint64_t PacketNumber = 0;
    uint8_t Buffer[1000] = { 0 };
    uint8_t Iv[QUIC_IV_LENGTH] = {0};

    QuicCryptoCombineIvAndPacketNumber(
        UpdateWriteKey->Iv,
        (uint8_t *)&PacketNumber,
        Iv);

    if (QuicEncrypt(
            UpdateWriteKey->PacketKey,
            Iv,
            sizeof(Header),
            Header,
            sizeof(Buffer),
            Buffer) != QUIC_STATUS_SUCCESS) {
        Ret = FALSE;
        goto Exit;
    }

    uint8_t Mask[16];

    if (QuicHpComputeMask(
            UpdateWriteKey->HeaderKey,
            1,
            Buffer,
            Mask) != QUIC_STATUS_SUCCESS) {
        Ret = FALSE;
        goto Exit;
    }

    for (uint32_t i = 0; i < sizeof(Mask); i++) {
        Header[i] ^= Mask[i];
    }

    if (QuicHpComputeMask(
            UpdateReadKey->HeaderKey,
            1,
            Buffer,
            Mask) != QUIC_STATUS_SUCCESS) {
         Ret = FALSE;
         goto Exit;
     }

    for (uint32_t i = 0; i < sizeof(Mask); i++) {
        Header[i] ^= Mask[i];
    }

    QuicCryptoCombineIvAndPacketNumber(
        UpdateReadKey->Iv,
        (uint8_t *)&PacketNumber,
        Iv);

    if (QuicDecrypt(
            UpdateReadKey->PacketKey,
            Iv,
            sizeof(Header),
            Header,
            sizeof(Buffer),
            Buffer) != QUIC_STATUS_SUCCESS) {
        Ret = FALSE;
        goto Exit;
    }

    if (Header[0] != 1 ||
        Header[1] != 2 ||
        Header[2] != 3 ||
        Header[3] != 4) {
        Ret = FALSE;
        goto Exit;
    }

    for (uint32_t i = 0; i < sizeof(Buffer) - QUIC_ENCRYPTION_OVERHEAD; i++) {
        if (Buffer[i] != 0) {
            Ret = FALSE;
            goto Exit;
        }
    }

Exit:

    if (ServerTlsContext != NULL) {
        QuicTlsUninitialize(ServerTlsContext);
        ServerTlsContext = NULL;
    }

    if (ServerConfig != NULL) {
        QuicTlsSecConfigRelease(ServerConfig);
        ServerConfig = NULL;
    }

    if (ClientTlsContext != NULL) {
        QuicTlsUninitialize(ClientTlsContext);
        ClientTlsContext = NULL;
    }

    if (ClientConfig != NULL) {
        QuicTlsSecConfigRelease(ClientConfig);
        ClientConfig = NULL;
    }

    if (TlsSession != NULL) {
        QuicTlsSessionUninitialize(TlsSession);
        TlsSession = NULL;
    }

    return Ret;
}


static
void
TalTestExecuteTestCase(
    _In_ uint32_t TestCaseIndex
    )

{
    LOGINFO("*Start Testcase: %s.*", TestCases[TestCaseIndex].TestCaseName);
    if ((TestCases[TestCaseIndex].TestCaseFunc)()) {
        LOGINFO("*Testcase succeeded.*");
    } else {
        LOGERROR("*Testcase failed.*");
    }
    LOGINFO("*Stop Testcase:%s.*", TestCases[TestCaseIndex].TestCaseName);
}


static
void
TalTestHelp(
    _In_ char *argv[]
    )

{
    printf("Usage: \n");
    printf("To execute all tests: %s %ld \n", argv[0], ARRAYSIZE(TestCases));
    printf("To execute a specific test: %s <testcaseno> \n", argv[0]);
    printf("Test cases: \n");
    for (uint32_t Iter = 0; Iter < ARRAYSIZE(TestCases); Iter++) {
        printf("\t%lu: %s\n", Iter, TestCases[Iter].TestCaseName);
    }
}


int
main(
    _In_ int argc,
    _In_reads_(argc) char *argv[]
    )
/*++

Routine Description:

    Program entry point.

Arguments:

    argc - Number of tokens.

    argv - Array of tokens. The caller will populate the first token with the
        program name/path.

Return Value:

    Exit Code.

--*/
{
    uint32_t Input = 0;

    if (argc != 2) {
        TalTestHelp(argv);
        return 0;
    }

    TalTestSetUpTestCase();

    Input = atoi(argv[1]);
    if (Input < ARRAYSIZE(TestCases)) {
        TalTestExecuteTestCase(Input);
    } else if (Input == ARRAYSIZE(TestCases)) {
        for (uint32_t Iter = 0; Iter < ARRAYSIZE(TestCases); Iter++) {
            TalTestExecuteTestCase(Iter);
        }
    } else {
        LOGERROR("Incorrect Input");
        TalTestHelp(argv);
    }

    TalTestTearDownTestCase();
}

