/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Interop Test Client. It tests all the major QUIC features of known
    public QUIC endpoints.

--*/

#include "interop.h"
#ifdef QUIC_CLOG
#include "interop.cpp.clog.h"
#endif

#define VERIFY_QUIC_SUCCESS(X) { \
    QUIC_STATUS s = X; \
    if (QUIC_FAILED(s)) { printf(#X " FAILURE: 0x%x!!\n", s); } \
}

#define HTTP_NO_ERROR       0
#define HTTP_INTERNAL_ERROR 3

const QUIC_API_TABLE* MsQuic;
HQUIC Registration;
uint32_t TestCases = QuicTestFeatureAll;
uint32_t WaitTimeoutMs = 10000;
uint32_t InitialVersion = 0;
bool RunSerially = false;
bool TestFailed = false; // True if any test failed

const uint32_t RandomReservedVersion = 168430090ul; // Random reserved version to force VN.
const uint8_t RandomTransportParameterPayload[2345] = {0};
QUIC_PRIVATE_TRANSPORT_PARAMETER RandomTransportParameter = {
    77,
    sizeof(RandomTransportParameterPayload),
    RandomTransportParameterPayload
};

const QUIC_BUFFER HandshakeAlpns[] = {
    { sizeof("hq-interop") - 1, (uint8_t*)"hq-interop" },
    { sizeof("h3") - 1, (uint8_t*)"h3" },
    { sizeof("hq-29") - 1, (uint8_t*)"hq-29" },
    { sizeof("h3-29") - 1, (uint8_t*)"h3-29" },
};

const QUIC_BUFFER DatapathAlpns[] = {
    { sizeof("hq-interop") - 1, (uint8_t*)"hq-interop" },
    { sizeof("hq-29") - 1, (uint8_t*)"hq-29" },
};

const QUIC_BUFFER DatagramAlpns[] = {
    { sizeof("siduck") - 1,    (uint8_t*)"siduck" },
    { sizeof("siduck-00") - 1, (uint8_t*)"siduck-00" },
};

const uint16_t PublicPorts[] = {
    443, 4433, 4434
};

const uint32_t PublicPortsCount = ARRAYSIZE(PublicPorts);

const QUIC_BUFFER QuackBuffer = { sizeof("quack") - 1, (uint8_t*)"quack" };
const QUIC_BUFFER QuackAckBuffer = { sizeof("quack-ack") - 1, (uint8_t*)"quack-ack" };

//
// Represents the information of a well-known public QUIC endpoint.
//
struct QuicPublicEndpoint {
    const char* ImplementationName;
    const char* ServerName;
};

QuicPublicEndpoint PublicEndpoints[] = {
    { "aioquic",        "quic.aiortc.org" },
    { "akamaiquic",     "ietf.akaquic.com" },
    { "applequic",      "71.202.41.169" },
    { "ats",            "quic.ogre.com" },
    { "f5",             "f5quic.com" },
    { "gquic",          "quic.rocks" },
    { "haskell",        "mew.org" },
    { "lsquic",         "http3-test.litespeedtech.com" },
    { "mvfst",          "fb.mvfst.net" },
    { "msquic",         "msquic.net" },
    { "ngtcp2",         "nghttp2.org" },
    { "ngx_quic",       "cloudflare-quic.com" },
    { "Pandora",        "pandora.cm.in.tum.de" },
    { "picoquic",       "test.privateoctopus.com" },
    { "quant",          "quant.eggert.org" },
    { "quinn",          "h3.stammw.eu" },
    { "quic-go",        "quic.seemann.io" },
    { "quiche",         "quic.tech" },
    { "quicker",        "quicker.edm.uhasselt.be" },
    { "quicly-quic",    "quic.examp1e.net" },
    { "quicly-h20",     "h2o.examp1e.net" },
    { nullptr,          nullptr },              // Used for -custom cmd arg
};

const uint32_t PublicEndpointsCount = ARRAYSIZE(PublicEndpoints) - 1;

struct QuicTestResults {
    const char* Alpn;
    uint32_t QuicVersion;
    uint32_t Features;
};

QuicTestResults TestResults[ARRAYSIZE(PublicEndpoints)];
CXPLAT_LOCK TestResultsLock;

const uint32_t MaxThreadCount =
    PublicPortsCount * PublicEndpointsCount * QuicTestFeatureCount;
CXPLAT_THREAD Threads[MaxThreadCount];
uint32_t CurrentThreadCount;

uint16_t CustomPort = 0;

bool CustomUrlPath = false;
std::vector<std::string> Urls;

const char* SslKeyLogFileParam = nullptr;

void
PrintUsage()
{
    printf("\nquicinterop tests all the major QUIC features of an endpoint.\n\n");

    printf("Usage:\n");
    printf("  quicinterop.exe -help\n");
    printf("  quicinterop.exe -list\n");
    printf("  quicinterop.exe [-target:<implementation> | -custom:<hostname>] [-port:<####>] [-test:<test case>] [-timeout:<milliseconds>] [-version:<####>]\n\n");

    printf("Examples:\n");
    printf("  quicinterop.exe\n");
    printf("  quicinterop.exe -test:H\n");
    printf("  quicinterop.exe -target:msquic\n");
    printf("  quicinterop.exe -custom:localhost -test:16\n");
}

class GetRequest : public QUIC_BUFFER {
    uint8_t RawBuffer[512];
public:
    GetRequest(const char *Request, bool Http1_1 = false) {
        Buffer = RawBuffer;
        if (Http1_1) {
            Length = (uint32_t)sprintf_s((char*)RawBuffer, sizeof(RawBuffer), "GET %s HTTP/1.1\r\n", Request);
        } else {
            Length = (uint32_t)sprintf_s((char*)RawBuffer, sizeof(RawBuffer), "GET %s\r\n", Request);
        }
    }
};

class InteropStream {
    HQUIC Stream;
    CXPLAT_EVENT RequestComplete;
    GetRequest SendRequest;
    const char* RequestPath;
    const char* FileName;
    FILE* File;
    uint64_t DownloadStartTime;
    uint64_t LastReceiveTime;
    int64_t LastReceiveDuration;
public:
    bool ReceivedResponse : 1;
    bool UsedZeroRtt : 1;
    InteropStream(HQUIC Connection, const char* Request) :
        Stream(nullptr),
        SendRequest(Request),
        RequestPath(Request),
        FileName(nullptr),
        File(nullptr),
        DownloadStartTime(0),
        LastReceiveTime(0),
        LastReceiveDuration(0),
        ReceivedResponse(false),
        UsedZeroRtt(false)
    {
        CxPlatEventInitialize(&RequestComplete, TRUE, FALSE);

        VERIFY_QUIC_SUCCESS(
            MsQuic->StreamOpen(
                Connection,
                QUIC_STREAM_OPEN_FLAG_NONE,
                InteropStream::StreamCallback,
                this,
                &Stream));
    }
    ~InteropStream() {
        MsQuic->StreamClose(Stream);
        CxPlatEventUninitialize(RequestComplete);
    }

    bool SendHttpRequest(bool WaitForResponse = true) {
        CxPlatEventReset(RequestComplete);
        if (QUIC_FAILED(
            MsQuic->StreamStart(
                Stream,
                QUIC_STREAM_START_FLAG_IMMEDIATE))) {
            MsQuic->StreamClose(Stream);
            return false;
        }

        if (CustomUrlPath) {
            printf("Sending request: %s", SendRequest.Buffer);
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
            CxPlatEventWaitWithTimeout(RequestComplete, WaitTimeoutMs) &&
            ReceivedResponse;
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
        InteropStream* pThis = (InteropStream*)Context;
        int64_t Now = CxPlatTimeMs64();
        switch (Event->Type) {
        case QUIC_STREAM_EVENT_RECEIVE:
            if (CustomUrlPath) {
                if (pThis->File == nullptr) {
                    pThis->DownloadStartTime = Now;
                    pThis->FileName = strrchr(pThis->RequestPath, '/') + 1;
                    pThis->File = fopen(pThis->FileName, "wb");
                    if (pThis->File == nullptr) {
                        printf("Failed to open file %s\n", pThis->FileName);
                        break;
                    }
                }
                uint64_t TotalBytesWritten = 0;
                for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; ++i) {
                    uint32_t DataLength = Event->RECEIVE.Buffers[i].Length;
                    if (fwrite(
                            Event->RECEIVE.Buffers[i].Buffer,
                            1,
                            DataLength,
                            pThis->File) < DataLength) {
                        printf("Failed to write to file!\n");
                        break;
                    }
                    TotalBytesWritten += DataLength;
                }
                int64_t ReceiveDuration = (int64_t)(pThis->LastReceiveTime == 0) ? 0 : CxPlatTimeDiff64(pThis->LastReceiveTime, Now);
                int64_t ReceiveTimeDiff = (int64_t)CxPlatTimeDiff64(pThis->LastReceiveDuration, ReceiveDuration);
                printf(
                    "%s: Wrote %llu bytes.(%llu ms/%lld ms/%lld ms)\n",
                    pThis->FileName,
                    (unsigned long long)TotalBytesWritten,
                    (unsigned long long)CxPlatTimeDiff64(pThis->DownloadStartTime, Now),
                    (long long)ReceiveDuration,
                    (long long)ReceiveTimeDiff);
                pThis->LastReceiveTime = Now;
                pThis->LastReceiveDuration = ReceiveDuration;
            }
            break;
        case QUIC_STREAM_EVENT_SEND_COMPLETE:
            break;
        case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
            if (CustomUrlPath) {
                printf("%s: Peer aborted send! (%llu ms)\n",
                    pThis->FileName,
                    (unsigned long long)CxPlatTimeDiff64(pThis->DownloadStartTime, Now));
            }
            CxPlatEventSet(pThis->RequestComplete);
            break;
        case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
            if (pThis->File) {
                fflush(pThis->File);
                fclose(pThis->File);
                pThis->File = nullptr;
                printf("%s: Completed download! (%llu ms)\n",
                    pThis->FileName,
                    (unsigned long long)CxPlatTimeDiff64(pThis->DownloadStartTime, Now));
            }
            pThis->ReceivedResponse = true;
            break;
        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE: {
            if (pThis->File) {
                printf("%s: Request closed incomplete. (%llu ms)\n",
                    pThis->FileName,
                    (unsigned long long)CxPlatTimeDiff64(pThis->DownloadStartTime, Now));
                fclose(pThis->File); // Didn't get closed properly.
                pThis->File = nullptr;
            }
            uint64_t Length = 0;
            uint32_t LengthLength = sizeof(Length);
            if (QUIC_SUCCEEDED(
                MsQuic->GetParam(
                    Stream,
                    QUIC_PARAM_STREAM_0RTT_LENGTH,
                    &LengthLength,
                    &Length)) &&
                Length > 0) {
                pThis->UsedZeroRtt = true;
            }
            CxPlatEventSet(pThis->RequestComplete);
            break;
        }
        default:
            break;
        }
        return QUIC_STATUS_SUCCESS;
    }
};

class InteropConnection {
    HQUIC Configuration;
    HQUIC Connection;
    std::vector<InteropStream*> Streams;
    CXPLAT_EVENT ConnectionComplete;
    CXPLAT_EVENT RequestComplete;
    CXPLAT_EVENT QuackAckReceived;
    CXPLAT_EVENT ShutdownComplete;
    CXPLAT_EVENT TicketReceived;
    char* NegotiatedAlpn;
    const uint8_t* ResumptionTicket;
    uint32_t ResumptionTicketLength;
    QUIC_TLS_SECRETS TlsSecrets;
    const char* SslKeyLogFile;
public:
    bool VersionUnsupported : 1;
    bool Connected : 1;
    bool Resumed : 1;
    bool ReceivedQuackAck : 1;
    InteropConnection(HQUIC Configuration, bool VerNeg = false, bool LargeTP = false) :
        Configuration(Configuration),
        Connection(nullptr),
        NegotiatedAlpn(nullptr),
        ResumptionTicket(nullptr),
        ResumptionTicketLength(0),
        TlsSecrets({}),
        SslKeyLogFile(SslKeyLogFileParam),
        VersionUnsupported(false),
        Connected(false),
        Resumed(false),
        ReceivedQuackAck(false)
    {
        CxPlatEventInitialize(&ConnectionComplete, TRUE, FALSE);
        CxPlatEventInitialize(&RequestComplete, TRUE, FALSE);
        CxPlatEventInitialize(&QuackAckReceived, TRUE, FALSE);
        CxPlatEventInitialize(&ShutdownComplete, TRUE, FALSE);
        CxPlatEventInitialize(&TicketReceived, TRUE, FALSE);

        VERIFY_QUIC_SUCCESS(
            MsQuic->ConnectionOpen(
                Registration,
                InteropConnection::ConnectionCallback,
                this,
                &Connection));
        if (VerNeg) {
            uint32_t SupportedVersions[] = { RandomReservedVersion, 0x709a50c4U, 0x00000001U, 0xff00001dU };
            QUIC_VERSION_SETTINGS Settings = { 0 };
            Settings.AcceptableVersions = SupportedVersions;
            Settings.AcceptableVersionsLength = ARRAYSIZE(SupportedVersions);
            Settings.OfferedVersions = SupportedVersions;
            Settings.OfferedVersionsLength = ARRAYSIZE(SupportedVersions);
            Settings.FullyDeployedVersions = SupportedVersions;
            Settings.FullyDeployedVersionsLength = ARRAYSIZE(SupportedVersions);
            VERIFY_QUIC_SUCCESS(
                MsQuic->SetParam(
                    Connection,
                    QUIC_PARAM_CONN_VERSION_SETTINGS,
                    sizeof(Settings),
                    &Settings));
        } else if (InitialVersion != 0) {
            uint32_t SupportedVersions[] = { InitialVersion, 0x709a50c4U, 0x00000001U, 0xff00001dU };
            QUIC_VERSION_SETTINGS Settings = { 0 };
            Settings.AcceptableVersions = SupportedVersions;
            Settings.AcceptableVersionsLength = ARRAYSIZE(SupportedVersions);
            Settings.OfferedVersions = SupportedVersions;
            Settings.OfferedVersionsLength = ARRAYSIZE(SupportedVersions);
            Settings.FullyDeployedVersions = SupportedVersions;
            Settings.FullyDeployedVersionsLength = ARRAYSIZE(SupportedVersions);
            VERIFY_QUIC_SUCCESS(
                MsQuic->SetParam(
                    Connection,
                    QUIC_PARAM_CONN_VERSION_SETTINGS,
                    sizeof(Settings),
                    &Settings));
        }
        if (LargeTP) {
            VERIFY_QUIC_SUCCESS(
                MsQuic->SetParam(
                    Connection,
                    QUIC_PARAM_CONN_TEST_TRANSPORT_PARAMETER,
                    sizeof(RandomTransportParameter),
                    &RandomTransportParameter));
        }
        if (SslKeyLogFile != nullptr) {
            QUIC_STATUS Status =
                MsQuic->SetParam(
                    Connection,
                    QUIC_PARAM_CONN_TLS_SECRETS,
                    sizeof(TlsSecrets),
                    (uint8_t*)&TlsSecrets);
            if (QUIC_FAILED(Status)) {
                SslKeyLogFile = nullptr;
                VERIFY_QUIC_SUCCESS(Status);
            }
        }
    }
    ~InteropConnection()
    {
        if (SslKeyLogFile != nullptr) {
            WriteSslKeyLogFile(SslKeyLogFile, TlsSecrets);
        }
        for (InteropStream* Stream : Streams) {
            delete Stream;
        }
        Streams.clear();
        Shutdown();
        MsQuic->ConnectionClose(Connection);
        CxPlatEventUninitialize(TicketReceived);
        CxPlatEventUninitialize(ShutdownComplete);
        CxPlatEventUninitialize(RequestComplete);
        CxPlatEventUninitialize(QuackAckReceived);
        CxPlatEventUninitialize(ConnectionComplete);
        delete [] NegotiatedAlpn;
        delete [] ResumptionTicket;
    }
    bool SetKeepAlive(uint32_t KeepAliveMs) {
        QUIC_SETTINGS Settings{0};
        Settings.KeepAliveIntervalMs = KeepAliveMs;
        Settings.IsSet.KeepAliveIntervalMs = TRUE;
        return
            QUIC_SUCCEEDED(
                MsQuic->SetParam(
                    Connection,
                    QUIC_PARAM_CONN_SETTINGS,
                    sizeof(Settings),
                    &Settings));
    }
    bool SetDisconnectTimeout(uint32_t TimeoutMs) {
        QUIC_SETTINGS Settings{0};
        Settings.DisconnectTimeoutMs = TimeoutMs;
        Settings.IsSet.DisconnectTimeoutMs = TRUE;
        return
            QUIC_SUCCEEDED(
                MsQuic->SetParam(
                    Connection,
                    QUIC_PARAM_CONN_SETTINGS,
                    sizeof(Settings),
                    &Settings));
    }
    bool SetResumptionTicket(const uint8_t* Ticket, uint32_t TicketLength) {
        return
            QUIC_SUCCEEDED(
                MsQuic->SetParam(
                    Connection,
                    QUIC_PARAM_CONN_RESUMPTION_TICKET,
                    TicketLength,
                    Ticket));
    }
    bool ConnectToServer(const char* ServerName, uint16_t ServerPort) {
        if (QUIC_SUCCEEDED(
            MsQuic->ConnectionStart(
                Connection,
                Configuration,
                QUIC_ADDRESS_FAMILY_UNSPEC,
                ServerName,
                ServerPort))) {
            CxPlatEventWaitWithTimeout(ConnectionComplete, WaitTimeoutMs);
        }
        return Connected;
    }
    bool Shutdown() {
        MsQuic->ConnectionShutdown(
            Connection,
            QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
            Connected ? HTTP_NO_ERROR : HTTP_INTERNAL_ERROR);
        return WaitForShutdownComplete();
    }
    bool WaitForShutdownComplete() {
        return CxPlatEventWaitWithTimeout(ShutdownComplete, WaitTimeoutMs);
    }
    bool SendHttpRequests(bool WaitForResponse = true) {
        for (auto& Url : Urls) {
            InteropStream* Stream = new InteropStream(Connection, Url.c_str());
            Streams.push_back(Stream);
            if (!Stream->SendHttpRequest(WaitForResponse)) {
                return false;
            }
        }
        return !WaitForResponse || WaitForHttpResponses();
    }
    bool WaitForHttpResponses() {
        bool Result = true;
        for (InteropStream* Stream : Streams) {
            Result &= Stream->WaitForHttpResponse();
        }
        return Result;
    }
    bool SendQuack() {
        BOOLEAN DatagramEnabled = TRUE;
        VERIFY_QUIC_SUCCESS(
            MsQuic->SetParam(
                Connection,
                QUIC_PARAM_CONN_DATAGRAM_RECEIVE_ENABLED,
                sizeof(DatagramEnabled),
                &DatagramEnabled));
        if (QUIC_FAILED(
            MsQuic->DatagramSend(
                Connection,
                &QuackBuffer,
                1,
                QUIC_SEND_FLAG_NONE,
                nullptr))) {
            return false;
        }
        return true;
    }
    bool WaitForQuackAck() {
        return
            CxPlatEventWaitWithTimeout(QuackAckReceived, WaitTimeoutMs) &&
            ReceivedQuackAck;
    }
    bool WaitForTicket() {
        return CxPlatEventWaitWithTimeout(TicketReceived, WaitTimeoutMs);
    }
    bool UsedZeroRtt() {
        bool Result = true;
        for (InteropStream* Stream : Streams) {
            Result &= Stream->UsedZeroRtt;
        }
        return Result;
    }
    bool ForceCidUpdate() {
        return
            QUIC_SUCCEEDED(
            MsQuic->SetParam(
                Connection,
                QUIC_PARAM_CONN_FORCE_CID_UPDATE,
                0,
                nullptr));
    }
    bool SimulateNatRebinding() {
        QUIC_ADDR LocalAddress = {0}; // Unspecified
        uint32_t LocalAddrSize = sizeof(LocalAddress);
        if (!QUIC_SUCCEEDED(
            MsQuic->GetParam(
                Connection,
                QUIC_PARAM_CONN_LOCAL_ADDRESS,
                &LocalAddrSize,
                &LocalAddress))) {
            return FALSE;
        }
        uint16_t PrevPort = QuicAddrGetPort(&LocalAddress);
        for (uint16_t i = 1236; i <= 1246; ++i) {
            QuicAddrSetPort(&LocalAddress, PrevPort + i);
            if (QUIC_SUCCEEDED(
                MsQuic->SetParam(
                    Connection,
                    QUIC_PARAM_CONN_LOCAL_ADDRESS,
                    sizeof(LocalAddress),
                    &LocalAddress))) {
                return TRUE;
            }
        }
        return FALSE;
    }
    bool GetQuicVersion(uint32_t& QuicVersion) {
        uint32_t Buffer = UINT32_MAX;
        uint32_t BufferLength = sizeof(Buffer);
        if (QUIC_SUCCEEDED(
            MsQuic->GetParam(
                Connection,
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
    bool GetNegotiatedAlpn(const char* &Alpn) {
        if (NegotiatedAlpn == nullptr) return false;
        Alpn = strdup(NegotiatedAlpn);
        return true;
    }
    bool GetStatistics(QUIC_STATISTICS_V2& Stats) {
        uint32_t BufferLength = sizeof(Stats);
        if (QUIC_SUCCEEDED(
            MsQuic->GetParam(
                Connection,
                QUIC_PARAM_CONN_STATISTICS_V2,
                &BufferLength,
                &Stats)) &&
            BufferLength == sizeof(Stats)) {
            return true;
        }
        return false;
    }
    bool GetResumptionTicket(const uint8_t*& Ticket, uint32_t& TicketLength) {
        if (!WaitForTicket() || ResumptionTicket == nullptr) {
            return false;
        }
        Ticket = ResumptionTicket;
        TicketLength = ResumptionTicketLength;
        ResumptionTicket = nullptr;
        return true;
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
            pThis->NegotiatedAlpn = new char[Event->CONNECTED.NegotiatedAlpnLength + 1];
            memcpy(pThis->NegotiatedAlpn, Event->CONNECTED.NegotiatedAlpn, Event->CONNECTED.NegotiatedAlpnLength);
            pThis->NegotiatedAlpn[Event->CONNECTED.NegotiatedAlpnLength] = 0;
            if (Event->CONNECTED.SessionResumed) {
                pThis->Resumed = true;
            }
            CxPlatEventSet(pThis->ConnectionComplete);
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
            if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status == QUIC_STATUS_VER_NEG_ERROR) {
                pThis->VersionUnsupported = TRUE;
            }
            __fallthrough;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
            CxPlatEventSet(pThis->RequestComplete);
            CxPlatEventSet(pThis->QuackAckReceived);
            CxPlatEventSet(pThis->ConnectionComplete);
            break;
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
            CxPlatEventSet(pThis->RequestComplete);
            CxPlatEventSet(pThis->QuackAckReceived);
            CxPlatEventSet(pThis->ConnectionComplete);
            CxPlatEventSet(pThis->ShutdownComplete);
            break;
        case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
            MsQuic->SetCallbackHandler(
                Event->PEER_STREAM_STARTED.Stream, (void*)NoOpStreamCallback, pThis);
            break;
        case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED:
            if (Event->DATAGRAM_RECEIVED.Buffer->Length == QuackAckBuffer.Length &&
                !memcmp(Event->DATAGRAM_RECEIVED.Buffer->Buffer, QuackAckBuffer.Buffer, QuackAckBuffer.Length)) {
                pThis->ReceivedQuackAck = true;
                CxPlatEventSet(pThis->QuackAckReceived);
            }
            break;
        case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
            pThis->ResumptionTicketLength = Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength;
            pThis->ResumptionTicket = new uint8_t[pThis->ResumptionTicketLength];
            memcpy(
                (uint8_t*)pThis->ResumptionTicket,
                Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket,
                Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);
            CxPlatEventSet(pThis->TicketReceived);
            break;
        default:
            break;
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
        default:
            break;
        }
        }
        return QUIC_STATUS_SUCCESS;
    }
};

bool
RunInteropTest(
    const QuicPublicEndpoint& Endpoint,
    uint16_t Port,
    QuicTestFeature Feature,
    uint32_t& QuicVersionUsed,
    const char* &NegotiatedAlpn
    )
{
    bool Success = false;

    QUIC_SETTINGS Settings{0};
    Settings.PeerUnidiStreamCount = 3;
    Settings.IsSet.PeerUnidiStreamCount = TRUE;
    Settings.InitialRttMs = 50; // Be more aggressive with RTT for interop testing
    Settings.IsSet.InitialRttMs = TRUE;
    Settings.SendBufferingEnabled = FALSE;
    Settings.IsSet.SendBufferingEnabled = TRUE;
    Settings.IdleTimeoutMs = WaitTimeoutMs;
    Settings.IsSet.IdleTimeoutMs = TRUE;
    if (Feature == KeyUpdate) {
        Settings.MaxBytesPerKey = 10; // Force a key update after every 10 bytes sent
        Settings.IsSet.MaxBytesPerKey = TRUE;
    }

    const QUIC_BUFFER* Alpns;
    uint32_t AlpnCount;
    if (Feature & QuicTestFeatureDataPath) {
        Alpns = DatapathAlpns;
        AlpnCount = ARRAYSIZE(DatapathAlpns);
    } else if (Feature == Datagram) {
        Alpns = DatagramAlpns;
        AlpnCount = ARRAYSIZE(DatagramAlpns);
    } else {
        Alpns = HandshakeAlpns;
        AlpnCount = ARRAYSIZE(HandshakeAlpns);
    }

    HQUIC Configuration;
    VERIFY_QUIC_SUCCESS(
        MsQuic->ConfigurationOpen(
            Registration,
            Alpns,
            AlpnCount,
            &Settings,
            sizeof(Settings),
            nullptr,
            &Configuration));

    QUIC_CREDENTIAL_CONFIG CredConfig;
    CxPlatZeroMemory(&CredConfig, sizeof(CredConfig));
    CredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;

    if (Feature == ChaCha20) {
        CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_SET_ALLOWED_CIPHER_SUITES;
        CredConfig.AllowedCipherSuites = QUIC_ALLOWED_CIPHER_SUITE_CHACHA20_POLY1305_SHA256;
    }

    VERIFY_QUIC_SUCCESS(
        MsQuic->ConfigurationLoadCredential(
            Configuration,
            &CredConfig));

    switch (Feature) {
    case VersionNegotiation: {
        InteropConnection Connection(Configuration, true);
        if (Connection.ConnectToServer(Endpoint.ServerName, Port)) {
            Connection.GetQuicVersion(QuicVersionUsed);
            Connection.GetNegotiatedAlpn(NegotiatedAlpn);
            QUIC_STATISTICS_V2 Stats;
            if (Connection.GetStatistics(Stats)) {
                Success = Stats.VersionNegotiation != 0;
            }
            if (Success && CustomUrlPath) {
                Success = Connection.SendHttpRequests();
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
    case PostQuantum:
    case ChaCha20: {
        const uint8_t* ResumptionTicket = nullptr;
        uint32_t ResumptionTicketLength = 0;
        if (Feature == Resumption) {
            InteropConnection Connection(Configuration);
            if (!Connection.ConnectToServer(Endpoint.ServerName, Port) ||
                !Connection.WaitForTicket() ||
                !Connection.GetResumptionTicket(ResumptionTicket, ResumptionTicketLength)) {
                break;
            }
        }
        InteropConnection Connection(Configuration, false, Feature == PostQuantum);
        if (Feature == Resumption) {
            Connection.SetResumptionTicket(ResumptionTicket, ResumptionTicketLength);
        }
        if (Connection.ConnectToServer(Endpoint.ServerName, Port)) {
            Connection.GetQuicVersion(QuicVersionUsed);
            Connection.GetNegotiatedAlpn(NegotiatedAlpn);
            if (Feature == StatelessRetry) {
                QUIC_STATISTICS_V2 Stats;
                if (Connection.GetStatistics(Stats)) {
                    Success = Stats.StatelessRetry != 0;
                }
            } else if (Feature == ConnectionClose) {
                Success = Connection.Shutdown();
            } else if (Feature == Resumption) {
                Success = Connection.Resumed;
            } else {
                Success = true;
            }
            if (Success && CustomUrlPath) {
                Success = Connection.SendHttpRequests();
            }
        }
        delete [] ResumptionTicket;
        break;
    }

    case StreamData:
    case ZeroRtt: {
        const uint8_t* ResumptionTicket = nullptr;
        uint32_t ResumptionTicketLength = 0;
        if (Feature == ZeroRtt) {
            InteropConnection Connection(Configuration);
            if (!Connection.ConnectToServer(Endpoint.ServerName, Port) ||
                !Connection.WaitForTicket() ||
                !Connection.GetResumptionTicket(ResumptionTicket, ResumptionTicketLength)) {
                break;
            }
        }
        InteropConnection Connection(Configuration, false);
        if (Feature == ZeroRtt) {
            Connection.SetResumptionTicket(ResumptionTicket, ResumptionTicketLength);
        }
        if (Connection.SendHttpRequests(false) &&
            Connection.ConnectToServer(Endpoint.ServerName, Port) &&
            Connection.WaitForHttpResponses()) {
            Connection.GetQuicVersion(QuicVersionUsed);
            Connection.GetNegotiatedAlpn(NegotiatedAlpn);
            if (Feature == ZeroRtt) {
                Success = Connection.UsedZeroRtt();
            } else {
                Success = true;
            }
        }
        delete [] ResumptionTicket;
        break;
    }

    case KeyUpdate: {
        InteropConnection Connection(Configuration);
        if (Connection.SetKeepAlive(50) &&
            Connection.ConnectToServer(Endpoint.ServerName, Port)) {
            Connection.GetQuicVersion(QuicVersionUsed);
            Connection.GetNegotiatedAlpn(NegotiatedAlpn);
            CxPlatSleep(2000); // Allow keep alive packets to trigger key updates.
            QUIC_STATISTICS_V2 Stats;
            if (Connection.GetStatistics(Stats)) {
                Success = Stats.KeyUpdateCount > 1;
            }
            if (Success && CustomUrlPath) {
                Success = Connection.SendHttpRequests();
            }
        }
        break;
    }

    case CidUpdate: {
        InteropConnection Connection(Configuration);
        if (Connection.ConnectToServer(Endpoint.ServerName, Port)) {
            Connection.GetQuicVersion(QuicVersionUsed);
            Connection.GetNegotiatedAlpn(NegotiatedAlpn);
            CxPlatSleep(250);
            if (Connection.SetDisconnectTimeout(1000) &&
                Connection.ForceCidUpdate() &&
                Connection.SetKeepAlive(50) &&
                !Connection.WaitForShutdownComplete()) {
                Success = true;
            }
            if (Success && CustomUrlPath) {
                Success = Connection.SendHttpRequests();
            }
        }
        break;
    }

    case NatRebinding: {
        InteropConnection Connection(Configuration);
        if (Connection.ConnectToServer(Endpoint.ServerName, Port)) {
            Connection.GetQuicVersion(QuicVersionUsed);
            Connection.GetNegotiatedAlpn(NegotiatedAlpn);
            CxPlatSleep(250);
            if (Connection.SetDisconnectTimeout(1000) &&
                Connection.SimulateNatRebinding() &&
                Connection.SetKeepAlive(50) &&
                !Connection.WaitForShutdownComplete()) {
                Success = true;
            }
            if (Success && CustomUrlPath) {
                Success = Connection.SendHttpRequests();
            }
        }
        break;
    }

    case Datagram: {
        InteropConnection Connection(Configuration, false);
        if (Connection.SendQuack() &&
            Connection.ConnectToServer(Endpoint.ServerName, Port) &&
            Connection.WaitForQuackAck()) {
            Connection.GetQuicVersion(QuicVersionUsed);
            Connection.GetNegotiatedAlpn(NegotiatedAlpn);
            Success = true;
        }
    }
    }

    MsQuic->ConfigurationClose(Configuration); // TODO - Wait on connection

    if (CustomUrlPath && !Success) {
        //
        // Delete any file we might have downloaded, because the test didn't
        // actually succeed.
        //
        for (auto& Url : Urls) {
            const char* FileName = strrchr(Url.c_str(), '/') + 1;
            (void)remove(FileName);
        }
    }

    return Success;
}

struct InteropTestContext {
    uint32_t EndpointIndex;
    uint16_t Port;
    QuicTestFeature Feature;
};

CXPLAT_THREAD_CALLBACK(InteropTestCallback, Context)
{
    auto TestContext = (InteropTestContext*)Context;

    QuicTraceLogInfo(
        InteropTestStart,
        "[ntrp] Test Start, Server: %s, Port: %hu, Tests: 0x%x.",
        PublicEndpoints[TestContext->EndpointIndex].ServerName,
        TestContext->Port,
        (uint32_t)TestContext->Feature);

    uint32_t QuicVersion = 0;
    const char* Alpn = nullptr;
    bool ThisTestFailed = false;
    if (RunInteropTest(
            PublicEndpoints[TestContext->EndpointIndex],
            TestContext->Port,
            TestContext->Feature,
            QuicVersion,
            Alpn)) {
        CxPlatLockAcquire(&TestResultsLock);
        TestResults[TestContext->EndpointIndex].Features |= TestContext->Feature;
        if (TestResults[TestContext->EndpointIndex].QuicVersion == 0) {
            TestResults[TestContext->EndpointIndex].QuicVersion = QuicVersion;
        }
        if (TestResults[TestContext->EndpointIndex].Alpn == nullptr) {
            TestResults[TestContext->EndpointIndex].Alpn = Alpn;
        }
        CxPlatLockRelease(&TestResultsLock);
    } else {
        TestFailed = true;
        ThisTestFailed = true;
    }

    QuicTraceLogInfo(
        InteropTestStop,
        "[ntrp] Test Stop, Server: %s, Port: %hu, Tests: 0x%x, Negotiated Alpn: %s, Passed: %s.",
        PublicEndpoints[TestContext->EndpointIndex].ServerName,
        TestContext->Port,
        (uint32_t)TestContext->Feature,
        Alpn,
        ThisTestFailed ? "false" : "true");

    if (ThisTestFailed) {
        free((void*)Alpn);
    }
    delete TestContext;

    CXPLAT_THREAD_RETURN(0);
}

void
StartTest(
    _In_ uint32_t EndpointIdx,
    _In_ uint16_t Port,
    _In_ QuicTestFeature Feature
    )
{
    auto TestContext = new InteropTestContext;
    TestContext->EndpointIndex = EndpointIdx;
    TestContext->Port = Port;
    TestContext->Feature = Feature;

    CXPLAT_THREAD_CONFIG ThreadConfig = {
        0,
        0,
        "QuicInterop",
        InteropTestCallback,
        TestContext
    };

    VERIFY_QUIC_SUCCESS(
        CxPlatThreadCreate(&ThreadConfig, &Threads[CurrentThreadCount++]));

    if (RunSerially) {
        CxPlatThreadWait(&Threads[CurrentThreadCount-1]);
    }
}

void
PrintTestResults(
    uint32_t Endpoint
    )
{
    char ResultCodes[] = QuicTestFeatureCodes;
    for (uint32_t i = 0; i < QuicTestFeatureCount; ++i) {
        if (!(TestResults[Endpoint].Features & (1 << i))) {
            ResultCodes[i] = '-';
        }
    }
    if (TestResults[Endpoint].QuicVersion == 0) {
        printf("%12s  %s\n", PublicEndpoints[Endpoint].ImplementationName, ResultCodes);
    } else {
        printf("%12s  %s  0x%08X  %s\n", PublicEndpoints[Endpoint].ImplementationName,
            ResultCodes, TestResults[Endpoint].QuicVersion,
            TestResults[Endpoint].Alpn);
    }
}

void
RunInteropTests(int EndpointIndex)
{
    const uint16_t* Ports = CustomPort == 0 ? PublicPorts : &CustomPort;
    const uint32_t PortsCount = CustomPort == 0 ? PublicPortsCount : 1;
    uint32_t StartTime = 0, StopTime = 0;

    StartTime = CxPlatTimeMs32();
    for (uint32_t b = 0; b < PortsCount; ++b) {
        for (uint32_t c = 0; c < QuicTestFeatureCount; ++c) {
            if (TestCases & (1 << c)) {
                if (EndpointIndex == -1) {
                    for (uint32_t d = 0; d < PublicEndpointsCount; ++d) {
                        StartTest(d, Ports[b], (QuicTestFeature)(1 << c));
                    }
                } else {
                    StartTest((uint32_t)EndpointIndex, Ports[b], (QuicTestFeature)(1 << c));
                }
            }
        }
    }

    for (uint32_t i = 0; i < CurrentThreadCount; ++i) {
        CxPlatThreadWait(&Threads[i]);
        CxPlatThreadDelete(&Threads[i]);
    }
    StopTime = CxPlatTimeMs32();

    printf("\n%12s  %s    %s   %s\n", "TARGET", QuicTestFeatureCodes, "VERSION", "ALPN");
    printf(" ============================================\n");
    if (EndpointIndex == -1) {
        for (uint32_t i = 0; i < PublicEndpointsCount; ++i) {
            PrintTestResults(i);
        }
    } else {
        PrintTestResults((uint32_t)EndpointIndex);
    }
    printf("\n");
    printf(
        "Total execution time: %u.%03us\n",
        (StopTime - StartTime) / 1000,
        (StopTime - StartTime) % 1000);
    printf("\n");
}

bool
ParseCommandLineUrls(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    bool ProcessingUrls = false;
    for (int i = 0; i < argc; ++i) {
        if (_strnicmp(argv[i] + 1, "urls", 4) == 0) {
            if (argv[i][1 + 4] != ':') {
                printf("Invalid URLs! First URL needs a : between the parameter name and it.\n");
                return false;
            }
            CustomUrlPath = true;
            ProcessingUrls = true;
            argv[i] += 5; // Advance beyond the parameter name.
        }
        if (ProcessingUrls) {
            if (argv[i][0] == '-') {
                ProcessingUrls = false;
                continue;
            }
            const char* Url = argv[i];
            for (int j = 0; j < 3; ++j) {
                Url = strchr(Url, '/');
                if (Url == nullptr) {
                    printf("Invalid URL provided! Must match 'http[s]://server[:port]/\n");
                    return false;
                }
                if (j < 2) {
                    ++Url;
                }
            }
            Urls.push_back(Url);
        }
    }
    return true;
}

int
QUIC_MAIN_EXPORT
main(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    int EndpointIndex = -1;

    if (GetFlag(argc, argv, "help") ||
        GetFlag(argc, argv, "?")) {
        PrintUsage();
        return 0;
    }

    if (GetFlag(argc, argv, "list")) {
        printf("\nKnown implementations and servers:\n");
        for (uint32_t i = 0; i < PublicEndpointsCount; ++i) {
            printf("  %12s\t%s\n", PublicEndpoints[i].ImplementationName,
                PublicEndpoints[i].ServerName);
        }
        return 0;
    }

    const char* TestCaseStr = GetValue(argc, argv, "test");
    if (TestCaseStr) {
        TestCases = 0;
        const uint32_t Len = (uint32_t)strlen(TestCaseStr);
        for (uint32_t i = 0; i < QuicTestFeatureCount; ++i) {
            for (uint32_t j = 0; j < Len; ++j) {
                if (QuicTestFeatureCodes[i] == TestCaseStr[j]) {
                    TestCases |= (1 << i);
                }
            }
        }
        if (TestCases == 0) {
            TestCases = QuicTestFeatureAll & (uint32_t)atoi(TestCaseStr);
            if (TestCases == 0) {
                printf("Invalid test cases!\n");
                return 0;
            }
        }
    }

    RunSerially = GetFlag(argc, argv, "serial");

    CxPlatSystemLoad();

    QUIC_STATUS Status;
    const QUIC_REGISTRATION_CONFIG RegConfig = { "quicinterop", QUIC_EXECUTION_PROFILE_LOW_LATENCY };

    if (QUIC_FAILED(Status = CxPlatInitialize())) {
        printf("CxPlatInitialize failed, 0x%x!\n", Status);
        CxPlatSystemUnload();
        return Status;
    }

    CxPlatLockInitialize(&TestResultsLock);

    if (QUIC_FAILED(Status = MsQuicOpen2(&MsQuic))) {
        printf("MsQuicOpen2 failed, 0x%x!\n", Status);
        goto Error;
    }

    if (QUIC_FAILED(Status = MsQuic->RegistrationOpen(&RegConfig, &Registration))) {
        printf("RegistrationOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    TryGetValue(argc, argv, "timeout", &WaitTimeoutMs);
    TryGetValue(argc, argv, "version", &InitialVersion);
    TryGetValue(argc, argv, "port", &CustomPort);
    if (!ParseCommandLineUrls(argc, argv)) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }
    if (!CustomUrlPath) {
        Urls.push_back("/");
    }

    TryGetValue(argc, argv, "sslkeylogfile", &SslKeyLogFileParam);

    const char* Target, *Custom;
    if (TryGetValue(argc, argv, "target", &Target)) {
        bool Found = false;
        for (uint32_t i = 0; i < PublicEndpointsCount; ++i) {
            if (strcmp(Target, PublicEndpoints[i].ImplementationName) == 0) {
                EndpointIndex = (int)i;
                Found = true;
                break;
            }
        }
        if (!Found) {
            printf("Unknown implementation '%s'\n", Target);
            goto Error;
        }
    } else if (TryGetValue(argc, argv, "custom", &Custom)) {
        PublicEndpoints[PublicEndpointsCount].ImplementationName = Custom;
        PublicEndpoints[PublicEndpointsCount].ServerName = Custom;
        EndpointIndex = (int)PublicEndpointsCount;
    }

    RunInteropTests(EndpointIndex);

    if (CustomUrlPath && TestFailed) {
        Status = QUIC_STATUS_ABORTED;
    }

Error:

    if (MsQuic != nullptr) {
        if (Registration != nullptr) {
            MsQuic->RegistrationClose(Registration);
        }
        MsQuicClose(MsQuic);
    }

    CxPlatLockUninitialize(&TestResultsLock);
    CxPlatUninitialize();
    CxPlatSystemUnload();

    return (int)Status;
}
