/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Interop Test Client. It tests all the major QUIC features of known
    public QUIC endpoints.

--*/

#include "interop.h"

#define VERIFY_QUIC_SUCCESS(X) { \
    QUIC_STATUS s = X; \
    if (QUIC_FAILED(s)) { printf(#X " FAILURE: 0x%x!!\n", s); } \
}

#define HTTP_NO_ERROR       0x0ui16
#define HTTP_INTERNAL_ERROR 0x3ui16

QUIC_API_V1* MsQuic;
HQUIC Registration;
int EndpointIndex = -1;
uint32_t TestCases = QuicTestFeatureAll;
uint32_t WaitTimeoutMs = 5000;

const BOOLEAN UseSendBuffering = FALSE;
const uint32_t CertificateValidationFlags = QUIC_CERTIFICATE_FLAG_DISABLE_CERT_VALIDATION;
const uint32_t RandomReservedVersion = 168430090ul; // Random reserved version to force VN.
const uint8_t RandomTransportParameterPayload[2345] = {0};
QUIC_PRIVATE_TRANSPORT_PARAMETER RandomTransportParameter = {
    77,
    sizeof(RandomTransportParameterPayload),
    RandomTransportParameterPayload
};

const char* Alpns[] = {
    ALPN_HTTP_OVER_QUIC,
    "h3-24"
};

const uint16_t Ports[] = {
    443, 4433, 4434
};

//
// Represents the information of a well-known public QUIC endpoint.
//
struct QuicPublicEndpoint {
    const char* ImplementationName;
    const char* ServerName;
};

const QuicPublicEndpoint PublicEndpoints[] = {
    { "aioquic",        "quic.aiortc.org" },
    { "applequic",      "12.181.55.166" },
    { "ats",            "quic.ogre.com" },
    { "f5",             "f5quic.com" },
    { "gquic",          "quic.rocks" },
    { "lsquic",         "http3-test.litespeedtech.com" },
    { "mvfst",          "fb.mvfst.net" },
    { "msquic",         "quic.westus.cloudapp.azure.com" },
    { "msquic-west",    "http3.westus2.cloudapp.azure.com" },
    { "msquic-east",    "http3.eastus2.cloudapp.azure.com" },
    { "ngtcp2",         "nghttp2.org" },
    { "ngx_quic",       "cloudflare-quic.com" },
    { "Pandora",        "pandora.cm.in.tum.de" },
    { "picoquic",       "test.privateoctopus.com" },
    { "quant",          "quant.eggert.org" },
    { "quinn",          "ralith.com" },
    { "quic-go",        "quic.seemann.io" },
    { "quiche",         "quic.tech" },
    { "quicker",        "quicker.edm.uhasselt.be" },
    { "quicly-quic",    "quic.examp1e.net" },
    { "quicly-h20",     "h2o.examp1e.net" },
};

struct QuicTestResults {
    const char* Alpn;
    uint32_t QuicVersion;
    uint32_t Features;
};

QuicTestResults TestResults[ARRAYSIZE(PublicEndpoints)];
QUIC_LOCK TestResultsLock;

const uint32_t MaxThreadCount =
    ARRAYSIZE(Alpns) *
    ARRAYSIZE(Ports) *
    ARRAYSIZE(PublicEndpoints) *
    QuicTestFeatureCount;
PQUIC_THREAD Threads[MaxThreadCount];
uint32_t CurrentThreadCount;

extern "C" void QuicTraceRundown(void) { }

void
PrintUsage()
{
    printf("\nquicinterop tests all the major QUIC features of an endpoint.\n\n");

    printf("Usage:\n");
    printf("  quicinterop.exe [-target:<implementation>] [-test:<test case>]"
           " [-timeout:<milliseconds>]\n\n");

    printf("Examples:\n");
    printf("  quicinterop.exe\n");
    printf("  quicinterop.exe -target:msquic\n");
}

class GetRequest : public QUIC_BUFFER {
    UINT8 RawBuffer[64];
public:
    GetRequest(const char *Request, bool Http1_1 = false) {
        Buffer = RawBuffer;
        if (Http1_1) {
            Length = (UINT32)sprintf_s((char*)RawBuffer, sizeof(RawBuffer), "GET %s HTTP/1.1\r\n", Request);
        } else {
            Length = (UINT32)sprintf_s((char*)RawBuffer, sizeof(RawBuffer), "GET %s\r\n", Request);
        }
    }
};

class InteropConnection {
    HQUIC Connection;
    GetRequest SendRequest;
    QUIC_EVENT ConnectionComplete;
    QUIC_EVENT RequestComplete;
    QUIC_EVENT ShutdownComplete;
public:
    bool VersionUnsupported : 1;
    bool Connected : 1;
    bool Resumed : 1;
    bool UsedZeroRtt : 1;
    bool ReceivedResponse : 1;
    InteropConnection(HQUIC Session, bool VerNeg = false, bool LargeTP = false) :
        Connection(nullptr),
        SendRequest("/"),
        VersionUnsupported(false),
        Connected(false),
        Resumed(false),
        UsedZeroRtt(false),
        ReceivedResponse(false)
    {
        QuicEventInitialize(&ConnectionComplete, TRUE, FALSE);
        QuicEventInitialize(&RequestComplete, TRUE, FALSE);
        QuicEventInitialize(&ShutdownComplete, TRUE, FALSE);

        VERIFY_QUIC_SUCCESS(
            MsQuic->ConnectionOpen(
                Session,
                InteropConnection::ConnectionCallback,
                this,
                &Connection));
        VERIFY_QUIC_SUCCESS(
            MsQuic->SetParam(
                Connection,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_CERT_VALIDATION_FLAGS,
                sizeof(CertificateValidationFlags),
                &CertificateValidationFlags));
        VERIFY_QUIC_SUCCESS(
            MsQuic->SetParam(
                Connection,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_SEND_BUFFERING,
                sizeof(UseSendBuffering),
                &UseSendBuffering));
        uint64_t IdleTimeoutMs = WaitTimeoutMs;
        VERIFY_QUIC_SUCCESS(
            MsQuic->SetParam(
                Connection,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_IDLE_TIMEOUT,
                sizeof(IdleTimeoutMs),
                &IdleTimeoutMs));
        if (VerNeg) {
            VERIFY_QUIC_SUCCESS(
                MsQuic->SetParam(
                    Connection,
                    QUIC_PARAM_LEVEL_CONNECTION,
                    QUIC_PARAM_CONN_QUIC_VERSION,
                    sizeof(RandomReservedVersion),
                    &RandomReservedVersion));
        }
        if (LargeTP) {
            VERIFY_QUIC_SUCCESS(
                MsQuic->SetParam(
                    Connection,
                    QUIC_PARAM_LEVEL_CONNECTION,
                    QUIC_PARAM_CONN_TEST_TRANSPORT_PARAMETER,
                    sizeof(RandomTransportParameter),
                    &RandomTransportParameter));
        }
    }
    ~InteropConnection()
    {
        Shutdown();
        MsQuic->ConnectionClose(Connection);
        QuicEventUninitialize(ShutdownComplete);
        QuicEventUninitialize(RequestComplete);
        QuicEventUninitialize(ConnectionComplete);
    }
    bool SetKeepAlive(uint32_t KeepAliveMs) {
        return
            QUIC_SUCCEEDED(
                MsQuic->SetParam(
                    Connection,
                    QUIC_PARAM_LEVEL_CONNECTION,
                    QUIC_PARAM_CONN_KEEP_ALIVE,
                    sizeof(KeepAliveMs),
                    &KeepAliveMs));
    }
    bool ConnectToServer(const char* ServerName, UINT16 ServerPort) {
        if (QUIC_SUCCEEDED(
            MsQuic->ConnectionStart(
                Connection,
                AF_UNSPEC,
                ServerName,
                ServerPort))) {
            WaitForSingleObject(ConnectionComplete, WaitTimeoutMs);
        }
        return Connected;
    }
    bool Shutdown() {
        MsQuic->ConnectionShutdown(
            Connection,
            QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
            Connected ? HTTP_NO_ERROR : HTTP_INTERNAL_ERROR);
        return QuicEventWaitWithTimeout(ShutdownComplete, WaitTimeoutMs);
    }
    bool SendHttpRequest(bool WaitForResponse = true) {
        QuicEventReset(RequestComplete);
        ReceivedResponse = false;

        HQUIC Stream;
        if (QUIC_FAILED(
            MsQuic->StreamOpen(
                Connection,
                QUIC_STREAM_OPEN_FLAG_NONE,
                InteropConnection::StreamCallback,
                this,
                &Stream))) {
            return false;
        }
        if (QUIC_FAILED(
            MsQuic->StreamStart(
                Stream,
                QUIC_STREAM_START_FLAG_IMMEDIATE))) {
            MsQuic->StreamClose(Stream);
            return false;
        }
        if (QUIC_FAILED(
            MsQuic->StreamSend(
                Stream,
                &SendRequest,
                1,
                QUIC_SEND_FLAG_ALLOW_0_RTT | QUIC_SEND_FLAG_FIN,
                nullptr))) {
            MsQuic->StreamShutdown(
                Stream,
                QUIC_STREAM_SHUTDOWN_FLAG_ABORT | QUIC_STREAM_SHUTDOWN_FLAG_IMMEDIATE,
                0);
            return false;
        }
        return !WaitForResponse || WaitForHttpResponse();
    }
    bool WaitForHttpResponse() {
        return
            QuicEventWaitWithTimeout(RequestComplete, WaitTimeoutMs) &&
            ReceivedResponse;
    }
    bool WaitForTicket() {
        int TryCount = 0;
        UINT32 TicketLength = 0;
        while (TryCount++ < 20) {
            if (QUIC_STATUS_BUFFER_TOO_SMALL ==
                MsQuic->GetParam(
                    Connection,
                    QUIC_PARAM_LEVEL_CONNECTION,
                    QUIC_PARAM_CONN_RESUMPTION_STATE,
                    &TicketLength,
                    nullptr)) {
                break;
            }
            Sleep(100);
        }
        return TryCount < 20;
    }
    bool ForceKeyUpdate() {
        return
            QUIC_SUCCEEDED(
            MsQuic->SetParam(
                Connection,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_FORCE_KEY_UPDATE,
                0,
                nullptr));
    }
    bool GetQuicVersion(uint32_t& QuicVersion) {
        uint32_t Buffer = UINT32_MAX;
        uint32_t BufferLength = sizeof(Buffer);
        if (QUIC_SUCCEEDED(
            MsQuic->GetParam(
                Connection,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_QUIC_VERSION,
                &BufferLength,
                &Buffer)) &&
            BufferLength == sizeof(Buffer) &&
            Buffer != UINT32_MAX) {
            QuicVersion = Buffer;
            return true;
        }
        return false;
    }
    bool GetStatistics(QUIC_STATISTICS& Stats) {
        uint32_t BufferLength = sizeof(Stats);
        if (QUIC_SUCCEEDED(
            MsQuic->GetParam(
                Connection,
                QUIC_PARAM_LEVEL_CONNECTION,
                QUIC_PARAM_CONN_STATISTICS,
                &BufferLength,
                &Stats)) &&
            BufferLength == sizeof(Stats)) {
            return true;
        }
        return false;
    }
private:
    static
    _IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_CONNECTION_CALLBACK)
    QUIC_STATUS
    QUIC_API
    ConnectionCallback(
        _In_ HQUIC /* Connection */,
        _In_opt_ void* Context,
        _Inout_ QUIC_CONNECTION_EVENT* Event
        )
    {
        InteropConnection* pThis = (InteropConnection*)Context;
        switch (Event->Type) {
        case QUIC_CONNECTION_EVENT_CONNECTED:
            pThis->Connected = true;
            if (Event->CONNECTED.EarlyDataAccepted) {
                pThis->Resumed = true;
            }
            SetEvent(pThis->ConnectionComplete);
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
            if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status == QUIC_STATUS_VER_NEG_ERROR) {
                pThis->VersionUnsupported = TRUE;
            }
            __fallthrough;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
            SetEvent(pThis->RequestComplete);
            SetEvent(pThis->ConnectionComplete);
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
            SetEvent(pThis->RequestComplete);
            SetEvent(pThis->ConnectionComplete);
            SetEvent(pThis->ShutdownComplete);
            break;
        case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
            MsQuic->SetCallbackHandler(
                Event->PEER_STREAM_STARTED.Stream, NoOpStreamCallback, pThis);
            break;
        }
        return QUIC_STATUS_SUCCESS;
    }
    static
    _IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_STREAM_CALLBACK)
    QUIC_STATUS
    QUIC_API
    StreamCallback(
        _In_ HQUIC Stream,
        _In_opt_ void* Context,
        _Inout_ QUIC_STREAM_EVENT* Event
        )
    {
        InteropConnection* pThis = (InteropConnection*)Context;
        switch (Event->Type) {
        case QUIC_STREAM_EVENT_SEND_COMPLETE:
            break;
        case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
            SetEvent(pThis->RequestComplete);
            break;
        case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
            pThis->ReceivedResponse = true;
            break;
        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE: {
            uint64_t Length = 0;
            uint32_t LengthLength = sizeof(Length);
            if (QUIC_SUCCEEDED(
                MsQuic->GetParam(
                    Stream,
                    QUIC_PARAM_LEVEL_STREAM,
                    QUIC_PARAM_STREAM_0RTT_LENGTH,
                    &LengthLength,
                    &Length)) &&
                Length > 0) {
                pThis->UsedZeroRtt = true;
            }
            SetEvent(pThis->RequestComplete);
            break;
        }
        }
        return QUIC_STATUS_SUCCESS;
    }
    static
    _IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_STREAM_CALLBACK)
    QUIC_STATUS
    QUIC_API
    NoOpStreamCallback(
        _In_ HQUIC Stream,
        _In_opt_ void* /* Context */,
        _Inout_ QUIC_STREAM_EVENT* Event
        )
    {
        switch (Event->Type) {
        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE: {
            MsQuic->StreamClose(Stream);
            break;
        }
        }
        return QUIC_STATUS_SUCCESS;
    }
};

bool
RunInteropTest(
    const QuicPublicEndpoint& Endpoint,
    const char* Alpn,
    uint16_t Port,
    QuicTestFeature Feature,
    uint32_t& QuicVersionUsed
    )
{
    bool Success = false;

    HQUIC Session;
    VERIFY_QUIC_SUCCESS(
        MsQuic->SessionOpen(
            Registration,
            Alpn,
            nullptr,
            &Session));
    uint16_t UniStreams = 3;
    VERIFY_QUIC_SUCCESS(
        MsQuic->SetParam(
            Session,
            QUIC_PARAM_LEVEL_SESSION,
            QUIC_PARAM_SESSION_PEER_UNIDI_STREAM_COUNT,
            sizeof(UniStreams),
            &UniStreams));

    switch (Feature) {
    case VersionNegotiation: {
        InteropConnection Connection(Session, true);
        if (Connection.ConnectToServer(Endpoint.ServerName, Port)) {
            Connection.GetQuicVersion(QuicVersionUsed);
            QUIC_STATISTICS Stats;
            if (Connection.GetStatistics(Stats)) {
                Success = Stats.VersionNegotiation != 0;
            }
        } else if (Connection.VersionUnsupported) {
            Success = Connection.VersionUnsupported;
        }
        break;
    }

    case Handshake:
    case ConnectionClose:
    case Resumption:
    case StatelessRetry:
    case PostQuantum: {
        if (Feature == Resumption) {
            InteropConnection Connection(Session);
            if (!Connection.ConnectToServer(Endpoint.ServerName, Port) ||
                !Connection.WaitForTicket()) {
                break;
            }
        }
        InteropConnection Connection(Session, false, Feature == PostQuantum);
        if (Connection.ConnectToServer(Endpoint.ServerName, Port)) {
            Connection.GetQuicVersion(QuicVersionUsed);
            if (Feature == StatelessRetry) {
                QUIC_STATISTICS Stats;
                if (Connection.GetStatistics(Stats)) {
                    Success = Stats.StatelessRetry != 0;
                }
            } else if (Feature == ConnectionClose) {
                Success = Connection.Shutdown();
            } else {
                Success = true;
            }
        }
        break;
    }

    case StreamData:
    case ZeroRtt: {
        if (Feature == ZeroRtt) {
            InteropConnection Connection(Session);
            if (!Connection.ConnectToServer(Endpoint.ServerName, Port) ||
                !Connection.WaitForTicket()) {
                break;
            }
        }
        InteropConnection Connection(Session, false);
        if (Connection.SendHttpRequest(false) &&
            Connection.ConnectToServer(Endpoint.ServerName, Port) &&
            Connection.WaitForHttpResponse()) {
            Connection.GetQuicVersion(QuicVersionUsed);
            if (Feature == ZeroRtt) {
                Success = Connection.UsedZeroRtt;
            } else {
                Success = true;
            }
        }
        break;
    }

    case KeyUpdate: {
        uint64_t MaxBytesPerKey = 10; // Force a key update after every 10 bytes sent
        VERIFY_QUIC_SUCCESS(
            MsQuic->SetParam(
                Session,
                QUIC_PARAM_LEVEL_SESSION,
                QUIC_PARAM_SESSION_MAX_BYTES_PER_KEY,
                sizeof(MaxBytesPerKey),
                &MaxBytesPerKey));
        InteropConnection Connection(Session);
        if (Connection.SetKeepAlive(50) &&
            Connection.ConnectToServer(Endpoint.ServerName, Port)) {
            Connection.GetQuicVersion(QuicVersionUsed);
            QuicSleep(2000); // Allow keep alive packets to trigger key updates.
            QUIC_STATISTICS Stats;
            if (Connection.GetStatistics(Stats)) {
                Success = Stats.Misc.KeyUpdateCount > 1;
            }
        }
        break;
    }
    }

    MsQuic->SessionClose(Session);

    return Success;
}

struct InteropTestContext {
    uint32_t EndpointIndex;
    const char* Alpn;
    uint16_t Port;
    QuicTestFeature Feature;
};

QUIC_THREAD_CALLBACK(InteropTestCallback, Context)
{
    auto TestContext = (InteropTestContext*)Context;

    uint32_t QuicVersion;
    if (RunInteropTest(
            PublicEndpoints[TestContext->EndpointIndex],
            TestContext->Alpn,
            TestContext->Port,
            TestContext->Feature,
            QuicVersion)) {
        QuicLockAcquire(&TestResultsLock);
        TestResults[TestContext->EndpointIndex].Features |= TestContext->Feature;
        if (TestResults[TestContext->EndpointIndex].QuicVersion == 0) {
            TestResults[TestContext->EndpointIndex].QuicVersion = QuicVersion;
        }
        if (TestResults[TestContext->EndpointIndex].Alpn == nullptr) {
            TestResults[TestContext->EndpointIndex].Alpn = TestContext->Alpn;
        }
        QuicLockRelease(&TestResultsLock);
    }

    delete TestContext;

    QUIC_THREAD_RETURN(0);
}

void
StartTest(
    _In_ uint32_t EndpointIndex,
    _In_ const char* Alpn,
    _In_ uint16_t Port,
    _In_ QuicTestFeature Feature
    )
{
    auto TestContext = new InteropTestContext;
    TestContext->EndpointIndex = EndpointIndex;
    TestContext->Alpn = Alpn;
    TestContext->Port = Port;
    TestContext->Feature = Feature;

    QUIC_THREAD_CONFIG ThreadConfig = {
        0,
        0,
        "QuicInterop",
        InteropTestCallback,
        TestContext
    };

    VERIFY_QUIC_SUCCESS(
        QuicThreadCreate(&ThreadConfig, &Threads[CurrentThreadCount++]));
}

void
PrintTestResults(
    uint32_t Endpoint
    )
{
    char ResultCodes[] = "VHDCRZSQU";
    for (uint32_t i = 0; i < QuicTestFeatureCount; ++i) {
        if (!(TestResults[Endpoint].Features & (1 << i))) {
            ResultCodes[i] = '-';
        }
    }
    if (TestResults[Endpoint].QuicVersion == 0) {
        printf("%12s\t%s\n", PublicEndpoints[Endpoint].ImplementationName, ResultCodes);
    } else {
        printf("%12s\t%s\t0x%X %s\n", PublicEndpoints[Endpoint].ImplementationName,
            ResultCodes, TestResults[Endpoint].QuicVersion,
            TestResults[Endpoint].Alpn);
    }
}

void
RunInteropTests()
{
    for (uint32_t a = 0; a < ARRAYSIZE(Alpns); ++a) {
        for (uint32_t b = 0; b < ARRAYSIZE(Ports); ++b) {
            for (uint32_t c = 0; c < QuicTestFeatureCount; ++c) {
                if (TestCases & (1 << c)) {
                    if (EndpointIndex == -1) {
                        for (uint32_t d = 0; d < ARRAYSIZE(PublicEndpoints); ++d) {
                            StartTest(d, Alpns[a], Ports[b], (QuicTestFeature)(1 << c));
                        }
                    } else {
                        StartTest((uint32_t)EndpointIndex, Alpns[a], Ports[b], (QuicTestFeature)(1 << c));
                    }
                }
            }
        }
    }

    for (uint32_t i = 0; i < CurrentThreadCount; ++i) {
        if (Threads[i] != nullptr) {
            QuicThreadWait(Threads[i]);
            QuicThreadDelete(Threads[i]);
        }
    }

    printf("\nResults:\n");
    if (EndpointIndex == -1) {
        for (uint32_t i = 0; i < ARRAYSIZE(PublicEndpoints); ++i) {
            PrintTestResults(i);
        }
    } else {
        PrintTestResults((uint32_t)EndpointIndex);
    }
}

int
QUIC_MAIN_EXPORT
main(
    _In_ int argc,
    _In_count_(argc) LPSTR argv[]
    )
{
    if (GetValue(argc, argv, "help") ||
        GetValue(argc, argv, "?")) {
        PrintUsage();
        return 0;
    }

    if (GetValue(argc, argv, "list")) {
        printf("\nKnown implementations and servers:\n");
        for (int i = 0; i < ARRAYSIZE(PublicEndpoints); ++i) {
            printf("  %12s\t%s\n", PublicEndpoints[i].ImplementationName,
                PublicEndpoints[i].ServerName);
        }
        return 0;
    }

    QuicPlatformSystemLoad();

    QUIC_STATUS Status;
    if (QUIC_FAILED(Status = QuicPlatformInitialize())) {
        printf("QuicPlatformInitialize failed, 0x%x!\n", Status);
        QuicPlatformSystemUnload();
        return Status;
    }

    QuicLockInitialize(&TestResultsLock);

    if (QUIC_FAILED(Status = MsQuicOpenV1(&MsQuic))) {
        printf("MsQuicOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    if (QUIC_FAILED(Status = MsQuic->RegistrationOpen("quicinterop", &Registration))) {
        printf("RegistrationOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    TryGetValue(argc, argv, "timeout", &WaitTimeoutMs);
    if (TryGetValue(argc, argv, "test", &TestCases)) {
        TestCases &= QuicTestFeatureAll;
        if (TestCases == 0) {
            printf("Invalid test cases!\n");
            goto Error;
        }
    }

    const char* Target;
    if (TryGetValue(argc, argv, "target", &Target)) {
        bool Found = false;
        for (int i = 0; i < ARRAYSIZE(PublicEndpoints); ++i) {
            if (strcmp(Target, PublicEndpoints[i].ImplementationName) == 0) {
                EndpointIndex = i;
                Found = true;
                break;
            }
        }
        if (!Found) {
            printf("Unknown implementation '%s'\n", Target);
            goto Error;
        }
    }

    RunInteropTests();

Error:

    if (MsQuic != nullptr) {
        if (Registration != nullptr) {
            MsQuic->RegistrationClose(Registration);
        }
        MsQuicClose(MsQuic);
    }

    QuicLockUninitialize(&TestResultsLock);
    QuicPlatformUninitialize();
    QuicPlatformSystemUnload();

    return (int)Status;
}
