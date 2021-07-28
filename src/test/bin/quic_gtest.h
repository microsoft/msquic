/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#define QUIC_TEST_APIS 1

#include "quic_platform.h"
#include "MsQuicTests.h"
#include "msquichelper.h"
#include "quic_trace.h"
#include "quic_driver_helpers.h"
#undef min // gtest headers conflict with previous definitions of min/max.
#undef max
#include "gtest/gtest.h"
#ifdef QUIC_CLOG
#include "quic_gtest.h.clog.h"
#endif

extern bool TestingKernelMode;

std::ostream& operator << (std::ostream& o, const QUIC_TEST_ARGS& args) {
    switch (args.Type) {
    case QUIC_TEST_TYPE_NULL: return o <<
        "NULL";
    case QUIC_TEST_TYPE_BOOLEAN: return o <<
        (args.Bool ? "true" : "false");
    case QUIC_TEST_TYPE_FAMILY: return o <<
        (args.Family == 4 ? "v4" : "v6");
    case QUIC_TEST_TYPE_NUMBER: return o <<
        args.Number;
    case QUIC_TEST_TYPE_CERTIFICATE_HASH_STORE: return o <<
        "Certificate Hash Store";
    case QUIC_TEST_TYPE_CONNECT: return o <<
        (args.Connect.Family == 4 ? "v4" : "v6") << "/" <<
        (args.Connect.ServerStatelessRetry ? "Retry" : "NoRetry") << "/" <<
        (args.Connect.ClientUsesOldVersion ? "UseOldVersion" : "NormalVersion") << "/" <<
        (args.Connect.MultipleALPNs ? "MultipleALPNs" : "SingleALPN") << "/" <<
        (args.Connect.AsyncConfiguration ? "AsyncConfig" : "SyncConfig") << "/" <<
        (args.Connect.MultiPacketClientInitial ? "MultipleInitials" : "SingleInitial") << "/" <<
        (args.Connect.SessionResumption ? "Resumption" : "NoResumption") << "/" <<
        args.Connect.RandomLossPercentage << " loss";
    case QUIC_TEST_TYPE_CONNECT_AND_PING: return o <<
        (args.ConnectAndPing.Family == 4 ? "v4" : "v6") << "/" <<
        args.ConnectAndPing.Length << "bytes/" <<
        args.ConnectAndPing.ConnectionCount << "conns/" <<
        args.ConnectAndPing.StreamCount << "streams/" <<
        args.ConnectAndPing.StreamBurstCount << "burst/" <<
        args.ConnectAndPing.StreamBurstDelayMs << "delay/" <<
        (args.ConnectAndPing.ServerStatelessRetry ? "Retry" : "NoRetry") << "/" <<
        (args.ConnectAndPing.ClientRebind ? "Rebind" : "NoRebind") << "/" <<
        (args.ConnectAndPing.ClientZeroRtt ? "0rtt" : "1rtt") << "/" <<
        (args.ConnectAndPing.ServerRejectZeroRtt ? "Reject" : "Accept") << "/" <<
        (args.ConnectAndPing.UseSendBuffer ? "SendBuffer" : "NoSendBuffer") << "/" <<
        (args.ConnectAndPing.UnidirectionalStreams ? "Unidi" : "Bidi") << "/" <<
        (args.ConnectAndPing.ServerInitiatedStreams ? "Server" : "Client") << "/" <<
        (args.ConnectAndPing.FifoScheduling ? "FiFo" : "RoundRobin");
    case QUIC_TEST_TYPE_KEY_UPDATE: return o <<
        "Key update";
    case QUIC_TEST_TYPE_ABORTIVE_SHUTDOWN: return o <<
        "Abortive shutdown";
    case QUIC_TEST_TYPE_CID_UPDATE: return o <<
        "Cid update";
    case QUIC_TEST_TYPE_RECEIVE_RESUME: return o <<
        "Receive resume";
    case QUIC_TEST_TYPE_DRILL_INITIAL_PACKET_CID: return o <<
        "Drill";
    case QUIC_TEST_TYPE_CUSTOM_CERT_VALIDATION: return o <<
        "Custom cert validation";
    case QUIC_TEST_TYPE_VERSION_NEGOTIATION_EXT: return o <<
        "Version negotiation ext";
    case QUIC_TEST_TYPE_CONNECT_CLIENT_CERT: return o <<
        "Connect Client Cert";
    case QUIC_TEST_TYPE_CRED_VALIDATION: return o <<
        "Cred validation";
    case QUIC_TEST_TYPE_ABORT_RECEIVE_TYPE: return o <<
        "Abort receive type";
    case QUIC_TEST_TYPE_KEY_UPDATE_RANDOM_LOSS_ARGS: return o <<
        "key update random loss";
    case QUIC_TEST_TYPE_MTU_DISCOVERY_ARGS: return o <<
        (args.MtuDiscovery.Family == 4 ? "v4" : "v6") << "/" <<
        (args.MtuDiscovery.DropClientProbePackets ? "true" : "false") << "/" <<
        (args.MtuDiscovery.DropClientProbePackets ? "true" : "false") << "/" <<
        (args.MtuDiscovery.RaiseMinimumMtu ? "true" : "false");
    case QUIC_TEST_TYPE_REBIND_ARGS: return o <<
        "rebind args";
    }
    CXPLAT_DBG_ASSERTMSG(FALSE, "Please update operation for unexpected arg type!");
    return o << "UNKNOWN ARGS TYPE";
}

class BooleanArgs : public testing::Test, public testing::WithParamInterface<QUIC_TEST_ARGS> {
    public: static ::std::vector<QUIC_TEST_ARGS> Generate() {
        ::std::vector<QUIC_TEST_ARGS> list;
        list.push_back({ QUIC_TEST_TYPE_BOOLEAN, FALSE });
        list.push_back({ QUIC_TEST_TYPE_BOOLEAN, TRUE });
        return list;
    }
};

class FamilyArgs : public testing::Test, public testing::WithParamInterface<QUIC_TEST_ARGS> {
    public: static ::std::vector<QUIC_TEST_ARGS> Generate() {
        ::std::vector<QUIC_TEST_ARGS> list;
        list.push_back({ QUIC_TEST_TYPE_FAMILY, 4 });
        list.push_back({ QUIC_TEST_TYPE_FAMILY, 6 });
        return list;
    }
};

class MtuArgs : public testing::Test, public testing::WithParamInterface<QUIC_TEST_ARGS> {
    public: static ::std::vector<QUIC_TEST_ARGS> Generate() {
        ::std::vector<QUIC_TEST_ARGS> list;
        for (uint32_t Family : { 4, 6}) {
        for (uint8_t DropClientProbePackets : {0, 1}) {
        for (uint8_t DropClientProbePackets : {0, 1}) {
        for (uint8_t RaiseMinimumMtu : {0, 1}) {
            QUIC_TEST_ARGS Args {QUIC_TEST_TYPE_MTU_DISCOVERY_ARGS};
            Args.MtuDiscovery = {Family, DropClientProbePackets, DropClientProbePackets, RaiseMinimumMtu};
            list.push_back(Args);
        }}}}
        return list;
    }
};

class ValidateConnectionEventArgs : public testing::Test, public testing::WithParamInterface<QUIC_TEST_ARGS> {
    public: static ::std::vector<QUIC_TEST_ARGS> Generate() {
        ::std::vector<QUIC_TEST_ARGS> list;
#ifndef QUIC_DISABLE_0RTT_TESTS
        for (uint32_t Test = 0; Test < 3; ++Test) {
#else
        for (uint32_t Test = 0; Test < 2; ++Test) {
#endif
            QUIC_TEST_ARGS Args {QUIC_TEST_TYPE_NUMBER};
            Args.Number = Test;
            list.push_back(Args);
        }
        return list;
    }
};

class ValidateStreamEventArgs : public testing::Test, public testing::WithParamInterface<QUIC_TEST_ARGS> {
    public: static ::std::vector<QUIC_TEST_ARGS> Generate() {
        ::std::vector<QUIC_TEST_ARGS> list;
        for (uint32_t Test = 0; Test < 7; ++Test) {
            QUIC_TEST_ARGS Args {QUIC_TEST_TYPE_NUMBER};
            Args.Number = Test;
            list.push_back(Args);
        }
        return list;
    }
};

struct HandshakeArgs1 {
    uint32_t Family;
    bool ServerStatelessRetry;
    bool MultipleALPNs;
    bool MultiPacketClientInitial;
    static ::std::vector<HandshakeArgs1> Generate() {
        ::std::vector<HandshakeArgs1> list;
        for (uint32_t Family : { 4, 6})
        for (bool ServerStatelessRetry : { false, true })
        for (bool MultipleALPNs : { false, true })
        for (bool MultiPacketClientInitial : { false, true })
            list.push_back({ Family, ServerStatelessRetry, MultipleALPNs, MultiPacketClientInitial });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const HandshakeArgs1& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        (args.ServerStatelessRetry ? "Retry" : "NoRetry") << "/" <<
        (args.MultipleALPNs ? "MultipleALPNs" : "SingleALPN") << "/" <<
        (args.MultiPacketClientInitial ? "MultipleInitials" : "SingleInitial");
}

class WithHandshakeArgs1 : public testing::Test,
    public testing::WithParamInterface<HandshakeArgs1> {
};

struct HandshakeArgs2 {
    uint32_t Family;
    bool ServerStatelessRetry;
    static ::std::vector<HandshakeArgs2> Generate() {
        ::std::vector<HandshakeArgs2> list;
        for (uint32_t Family : { 4, 6})
        for (bool ServerStatelessRetry : { false, true })
            list.push_back({ Family, ServerStatelessRetry });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const HandshakeArgs2& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        (args.ServerStatelessRetry ? "Retry" : "NoRetry");
}

class WithHandshakeArgs2 : public testing::Test,
    public testing::WithParamInterface<HandshakeArgs2> {
};

struct HandshakeArgs3 {
    uint32_t Family;
    bool ServerStatelessRetry;
    bool MultipleALPNs;
    static ::std::vector<HandshakeArgs3> Generate() {
        ::std::vector<HandshakeArgs3> list;
        for (uint32_t Family : { 4, 6})
        for (bool ServerStatelessRetry : { false, true })
        for (bool MultipleALPNs : { false, true })
            list.push_back({ Family, ServerStatelessRetry, MultipleALPNs });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const HandshakeArgs3& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        (args.ServerStatelessRetry ? "Retry" : "NoRetry") << "/" <<
        (args.MultipleALPNs ? "MultipleALPNs" : "SingleALPN");
}

class WithHandshakeArgs3 : public testing::Test,
    public testing::WithParamInterface<HandshakeArgs3> {
};

struct HandshakeArgs4 {
    uint32_t Family;
    bool ServerStatelessRetry;
    bool MultiPacketClientInitial;
    uint8_t RandomLossPercentage;
    static ::std::vector<HandshakeArgs4> Generate() {
        ::std::vector<HandshakeArgs4> list;
        for (uint32_t Family : { 4, 6})
        for (bool ServerStatelessRetry : { false, true })
        for (bool MultiPacketClientInitial : { false, true })
        for (uint8_t RandomLossPercentage : { 1, 5, 10 })
            list.push_back({ Family, ServerStatelessRetry, MultiPacketClientInitial, RandomLossPercentage });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const HandshakeArgs4& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        (args.ServerStatelessRetry ? "Retry" : "NoRetry") << "/" <<
        (args.MultiPacketClientInitial ? "MultipleInitials" : "SingleInitial") << "/" <<
        (uint32_t)args.RandomLossPercentage << "% loss";
}

class WithHandshakeArgs4 : public testing::Test,
    public testing::WithParamInterface<HandshakeArgs4> {
};

struct HandshakeArgs5 {
    bool AcceptCert;
    bool AsyncValidation;
    static ::std::vector<HandshakeArgs5> Generate() {
        ::std::vector<HandshakeArgs5> list;
        for (bool AcceptCert : { false, true })
        for (bool AsyncValidation : { false, true })
            list.push_back({ AcceptCert, AsyncValidation });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const HandshakeArgs5& args) {
    return o <<
        (args.AcceptCert ? "Accept" : "Reject") << "/" <<
        (args.AsyncValidation ? "Async" : "Sync");
}

class WithHandshakeArgs5 : public testing::Test,
    public testing::WithParamInterface<HandshakeArgs5> {
};

struct VersionNegotiationExtArgs {
    uint32_t Family;
    bool DisableVNEClient;
    bool DisableVNEServer;
    static ::std::vector<VersionNegotiationExtArgs> Generate() {
        ::std::vector<VersionNegotiationExtArgs> list;
        for (uint32_t Family : { 4, 6 })
        for (bool DisableVNEClient : { false, true })
        for (bool DisableVNEServer : { false, true })
            list.push_back({ Family, DisableVNEClient, DisableVNEServer });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const VersionNegotiationExtArgs& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        (args.DisableVNEClient ? "DisableClient" : "EnableClient") << "/" <<
        (args.DisableVNEServer ? "DisableServer" : "EnableServer");
}

class WithVersionNegotiationExtArgs : public testing::Test,
    public testing::WithParamInterface<VersionNegotiationExtArgs> {
};

struct HandshakeArgs6 {
    uint32_t Family;
    bool UseClientCertificate;
    static ::std::vector<HandshakeArgs6> Generate() {
        ::std::vector<HandshakeArgs6> list;
        for (uint32_t Family : { 4, 6 })
        for (bool UseClientCertificate : { false, true })
            list.push_back({ Family, UseClientCertificate });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const HandshakeArgs6& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        (args.UseClientCertificate ? "Cert" : "NoCert");
}

class WithHandshakeArgs6 : public testing::Test,
    public testing::WithParamInterface<HandshakeArgs6> {
};

struct SendArgs1 {
    uint32_t Family;
    uint64_t Length;
    uint32_t ConnectionCount;
    uint32_t StreamCount;
    bool UseSendBuffer;
    bool UnidirectionalStreams;
    bool ServerInitiatedStreams;
    static ::std::vector<SendArgs1> Generate() {
        ::std::vector<SendArgs1> list;
        for (uint32_t Family : { 4, 6 })
        for (uint64_t Length : { 0, 1000, 10000 })
        for (uint32_t ConnectionCount : { 1, 2, 4 })
        for (uint32_t StreamCount : { 1, 2, 4 })
        for (bool UseSendBuffer : { false, true })
        for (bool UnidirectionalStreams : { false, true })
        for (bool ServerInitiatedStreams : { false, true })
            list.push_back({ Family, Length, ConnectionCount, StreamCount, UseSendBuffer, UnidirectionalStreams, ServerInitiatedStreams });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const SendArgs1& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        args.Length << "/" <<
        args.ConnectionCount << "/" <<
        args.StreamCount << "/" <<
        (args.UseSendBuffer ? "SendBuffer" : "NoSendBuffer") << "/" <<
        (args.UnidirectionalStreams ? "Uni" : "Bidi") << "/" <<
        (args.ServerInitiatedStreams ? "Server" : "Client");
}

struct SendArgs2 {
    uint32_t Family;
    bool UseSendBuffer;
    bool UseZeroRtt;
    static ::std::vector<SendArgs2> Generate() {
        ::std::vector<SendArgs2> list;
        for (uint32_t Family : { 4, 6 })
        for (bool UseSendBuffer : { false, true })
#ifndef QUIC_DISABLE_0RTT_TESTS
        for (bool UseZeroRtt : { false, true })
#else
        for (bool UseZeroRtt : { false })
#endif
            list.push_back({ Family, UseSendBuffer, UseZeroRtt });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const SendArgs2& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        (args.UseSendBuffer ? "SendBuffer" : "NoSendBuffer") << "/" <<
        (args.UseZeroRtt ? "0-RTT" : "1-RTT");
}

class WithSendArgs2 : public testing::Test,
    public testing::WithParamInterface<SendArgs2> {
};

struct SendArgs3 {
    uint32_t Family;
    uint64_t Length;
    uint32_t BurstCount;
    uint32_t BurstDelay;
    bool UseSendBuffer;
    static ::std::vector<SendArgs3> Generate() {
        ::std::vector<SendArgs3> list;
        for (uint32_t Family : { 4, 6 })
        for (uint64_t Length : { 1000, 10000 })
        for (uint32_t BurstCount : { 2, 4, 8 })
        for (uint32_t BurstDelay : { 100, 500, 1000 })
        for (bool UseSendBuffer : { false, true })
            list.push_back({ Family, Length, BurstCount, BurstDelay, UseSendBuffer });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const SendArgs3& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        args.Length << "/" <<
        args.BurstCount << "/" <<
        args.BurstDelay << "ms/" <<
        (args.UseSendBuffer ? "SendBuffer" : "NoSendBuffer");
}

class WithSendArgs3 : public testing::Test,
    public testing::WithParamInterface<SendArgs3> {
};

class WithSendArgs1 : public testing::Test,
    public testing::WithParamInterface<SendArgs1> {
};

struct Send0RttArgs1 {
    uint32_t Family;
    uint64_t Length;
    uint32_t ConnectionCount;
    uint32_t StreamCount;
    bool UseSendBuffer;
    bool UnidirectionalStreams;
    static ::std::vector<Send0RttArgs1> Generate() {
        ::std::vector<Send0RttArgs1> list;
        for (uint32_t Family : { 4, 6 })
        for (uint64_t Length : { 0, 100, 1000, 2000 })
        for (uint32_t ConnectionCount : { 1, 2, 4 })
        for (uint32_t StreamCount : { 1, 2, 4 })
        for (bool UseSendBuffer : { false, true })
        for (bool UnidirectionalStreams : { false, true })
            list.push_back({ Family, Length, ConnectionCount, StreamCount, UseSendBuffer, UnidirectionalStreams });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const Send0RttArgs1& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        args.Length << "/" <<
        args.ConnectionCount << "/" <<
        args.StreamCount << "/" <<
        (args.UseSendBuffer ? "SendBuffer" : "NoSendBuffer") << "/" <<
        (args.UnidirectionalStreams ? "Uni" : "Bidi");
}

class WithSend0RttArgs1 : public testing::Test,
    public testing::WithParamInterface<Send0RttArgs1> {
};

struct Send0RttArgs2 {
    uint32_t Family;
    uint64_t Length;
    static ::std::vector<Send0RttArgs2> Generate() {
        ::std::vector<Send0RttArgs2> list;
        for (uint32_t Family : { 4, 6 })
        for (uint64_t Length : { 0, 1000, 10000, 20000 })
            list.push_back({ Family, Length });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const Send0RttArgs2& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        args.Length;
}

class WithSend0RttArgs2 : public testing::Test,
    public testing::WithParamInterface<Send0RttArgs2> {
};

struct KeyUpdateArgs1 {
    uint32_t Family;
    int KeyUpdate;
    static ::std::vector<KeyUpdateArgs1> Generate() {
        ::std::vector<KeyUpdateArgs1> list;
        for (uint32_t Family : { 4, 6 })
        for (int KeyUpdate : { 0, 1, 2, 3 })
            list.push_back({ Family, KeyUpdate });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const KeyUpdateArgs1& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        args.KeyUpdate;
}

class WithKeyUpdateArgs1 : public testing::Test,
    public testing::WithParamInterface<KeyUpdateArgs1> {
};

struct KeyUpdateArgs2 {
    uint32_t Family;
    uint8_t RandomLossPercentage;
    static ::std::vector<KeyUpdateArgs2> Generate() {
        ::std::vector<KeyUpdateArgs2> list;
        for (uint32_t Family : { 4, 6 })
        for (int RandomLossPercentage : { 1, 5, 10 })
            list.push_back({ Family, (uint8_t)RandomLossPercentage });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const KeyUpdateArgs2& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        args.RandomLossPercentage;
}

class WithKeyUpdateArgs2 : public testing::Test,
    public testing::WithParamInterface<KeyUpdateArgs2> {
};

struct AbortiveArgs {
    uint32_t Family;
    QUIC_ABORTIVE_TRANSFER_FLAGS Flags;
    static ::std::vector<AbortiveArgs> Generate() {
        ::std::vector<AbortiveArgs> list;
        for (uint32_t Family : { 4, 6 })
        for (uint32_t DelayStreamCreation : { 0, 1 })
        for (uint32_t SendDataOnStream : { 0, 1 })
        for (uint32_t ClientShutdown : { 0, 1 })
        for (uint32_t DelayClientShutdown : { 0, 1 })
        for (uint32_t WaitForStream : { 1 })
        for (uint32_t ShutdownDirection : { 0, 1, 2 })
        for (uint32_t UnidirectionStream : { 0, 1 })
        for (uint32_t PauseReceive : { 0, 1 })
        for (uint32_t PendReceive : { 0, 1 })
            list.push_back({ Family, {{ DelayStreamCreation, SendDataOnStream, ClientShutdown, DelayClientShutdown, WaitForStream, ShutdownDirection, UnidirectionStream, PauseReceive, PendReceive }} });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const AbortiveArgs& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        args.Flags.DelayStreamCreation << "/" <<
        args.Flags.SendDataOnStream << "/" <<
        args.Flags.ClientShutdown << "/" <<
        args.Flags.DelayClientShutdown << "/" <<
        args.Flags.WaitForStream << "/" <<
        args.Flags.ShutdownDirection << "/" <<
        args.Flags.UnidirectionalStream << "/" <<
        args.Flags.PauseReceive << "/" <<
        args.Flags.PendReceive;
}

class WithAbortiveArgs : public testing::Test,
    public testing::WithParamInterface<AbortiveArgs> {
};

struct CidUpdateArgs {
    uint32_t Family;
    uint16_t Iterations;
    static ::std::vector<CidUpdateArgs> Generate() {
        ::std::vector<CidUpdateArgs> list;
        for (uint32_t Family : { 4, 6 })
        for (int Iterations : { 1, 2, 4 })
            list.push_back({ Family, (uint16_t)Iterations });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const CidUpdateArgs& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        args.Iterations;
}

class WithCidUpdateArgs : public testing::Test,
    public testing::WithParamInterface<CidUpdateArgs> {
};

struct ReceiveResumeArgs {
    uint32_t Family;
    int SendBytes;
    int ConsumeBytes;
    QUIC_RECEIVE_RESUME_SHUTDOWN_TYPE ShutdownType;
    QUIC_RECEIVE_RESUME_TYPE PauseType;
    bool PauseFirst;
    static ::std::vector<ReceiveResumeArgs> Generate() {
        ::std::vector<ReceiveResumeArgs> list;
        for (int SendBytes : { 100 })
        for (uint32_t Family : { 4, 6 })
        for (bool PauseFirst : { false, true })
        for (int ConsumeBytes : { 0, 1, 99 })
        for (QUIC_RECEIVE_RESUME_SHUTDOWN_TYPE ShutdownType : { NoShutdown, GracefulShutdown, AbortShutdown })
        for (QUIC_RECEIVE_RESUME_TYPE PauseType : { ReturnConsumedBytes, ReturnStatusPending, ReturnStatusContinue })
            list.push_back({ Family, SendBytes, ConsumeBytes, ShutdownType, PauseType, PauseFirst });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const ReceiveResumeArgs& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        args.SendBytes << "/" <<
        args.ConsumeBytes << "/" <<
        (args.ShutdownType ? (args.ShutdownType == AbortShutdown ? "Abort" : "Graceful") : "NoShutdown") << "/" <<
        (args.PauseType ? (args.PauseType == ReturnStatusPending ? "ReturnPending" : "ReturnContinue") : "ConsumePartial") << "/" <<
        (args.PauseFirst ? "PauseBeforeSend" : "PauseAfterSend");
}

class WithReceiveResumeArgs : public testing::Test,
    public testing::WithParamInterface<ReceiveResumeArgs> {
};

struct ReceiveResumeNoDataArgs {
    uint32_t Family;
    QUIC_RECEIVE_RESUME_SHUTDOWN_TYPE ShutdownType;
    static ::std::vector<ReceiveResumeNoDataArgs> Generate() {
        ::std::vector<ReceiveResumeNoDataArgs> list;
        for (uint32_t Family : { 4, 6 })
        for (QUIC_RECEIVE_RESUME_SHUTDOWN_TYPE ShutdownType : { GracefulShutdown, AbortShutdown })
            list.push_back({ Family, ShutdownType });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const ReceiveResumeNoDataArgs& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        (args.ShutdownType ? (args.ShutdownType == AbortShutdown ? "Abort" : "Graceful") : "NoShutdown");
}

class WithReceiveResumeNoDataArgs : public testing::Test,
    public testing::WithParamInterface<ReceiveResumeNoDataArgs> {
};

struct DatagramNegotiationArgs {
    uint32_t Family;
    bool DatagramReceiveEnabled;
    static ::std::vector<DatagramNegotiationArgs> Generate() {
        ::std::vector<DatagramNegotiationArgs> list;
        for (uint32_t Family : { 4, 6 })
        for (bool DatagramReceiveEnabled : { false, true })
            list.push_back({ Family, DatagramReceiveEnabled });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const DatagramNegotiationArgs& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        (args.DatagramReceiveEnabled ? "DatagramReceiveEnabled" : "DatagramReceiveDisabled");
}

class WithDatagramNegotiationArgs : public testing::Test,
    public testing::WithParamInterface<DatagramNegotiationArgs> {
};

struct DrillInitialPacketCidArgs {
    uint32_t Family;
    bool SourceOrDest;
    bool ActualCidLengthValid;
    bool ShortCidLength;
    bool CidLengthFieldValid;

    static ::std::vector<DrillInitialPacketCidArgs> Generate() {
        ::std::vector<DrillInitialPacketCidArgs> list;
        for (uint32_t Family : { 4, 6 })
        for (bool SourceOrDest : { true, false })
        for (bool ActualCidLengthValid : { true, false })
        for (bool ShortCidLength : { true, false })
        for (bool CidLengthFieldValid : { true, false })
            list.push_back({ Family, SourceOrDest, ActualCidLengthValid, ShortCidLength, CidLengthFieldValid });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const DrillInitialPacketCidArgs& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        (args.SourceOrDest ? "SourceCid" : "DestCid") << "/" <<
        (args.ActualCidLengthValid ? "Valid" : "Invalid") << "/" <<
        (args.ShortCidLength ? "Short" : "Long") << "/" <<
        (args.CidLengthFieldValid ? "Valid" : "Invalid") << " length";
}

class WithDrillInitialPacketCidArgs: public testing::TestWithParam<DrillInitialPacketCidArgs> {
protected:
};

struct RebindPaddingArgs {
    uint32_t Family;
    uint16_t Padding;
    static ::std::vector<RebindPaddingArgs> Generate() {
        ::std::vector<RebindPaddingArgs> list;
        for (uint32_t Family : { 4, 6 })
        for (uint16_t Padding = 1; Padding < 50; ++Padding)
            list.push_back({ Family, Padding });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const RebindPaddingArgs& args) {
    return o << (args.Family == 4 ? "v4" : "v6") << "/"
        << args.Padding;
}

class WithRebindPaddingArgs : public testing::Test,
    public testing::WithParamInterface<RebindPaddingArgs> {
};
