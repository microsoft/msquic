/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#define QUIC_TEST_APIS 1

#include "quic_platform.h"
#include "MsQuicTests.h"
#include "msquichelper.h"
#include "quic_trace.h"
#undef min // gtest headers conflict with previous definitions of min/max.
#undef max
#include "gtest/gtest.h"
#ifdef QUIC_CLOG
#include "quic_gtest.h.clog.h"
#endif

extern bool TestingKernelMode;
extern std::vector<QUIC_CREDENTIAL_CONFIG> CertCleanup;

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
    case QUIC_TEST_TYPE_DATAGRAM_NEGOTIATION: return o <<
        "datagram negotiation";
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
    case QUIC_TEST_TYPE_KEY_UPDATE_RANDOM_LOSS: return o <<
        "key update random loss";
    case QUIC_TEST_TYPE_MTU_DISCOVERY: return o <<
        (args.MtuDiscovery.Family == 4 ? "v4" : "v6") << "/" <<
        (args.MtuDiscovery.DropClientProbePackets ? "true" : "false") << "/" <<
        (args.MtuDiscovery.DropClientProbePackets ? "true" : "false") << "/" <<
        (args.MtuDiscovery.RaiseMinimumMtu ? "true" : "false");
    case QUIC_TEST_TYPE_REBIND: return o <<
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
        for (uint32_t Family : { 4, 6})
        for (uint8_t DropClientProbePackets : {0, 1})
        for (uint8_t DropClientProbePackets : {0, 1})
        for (uint8_t RaiseMinimumMtu : {0, 1}) {
            QUIC_TEST_ARGS Args {QUIC_TEST_TYPE_MTU_DISCOVERY};
            Args.MtuDiscovery = {Family, DropClientProbePackets, DropClientProbePackets, RaiseMinimumMtu};
            list.push_back(Args);
        }
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

struct HandshakeArgs1 : public testing::Test, public testing::WithParamInterface<QUIC_TEST_ARGS> {
    static ::std::vector<QUIC_TEST_ARGS> Generate() {
        ::std::vector<QUIC_TEST_ARGS> list;
        for (uint32_t Family : { 4, 6})
        for (bool ServerStatelessRetry : { false, true })
        for (bool MultipleALPNs : { false, true })
        for (bool MultiPacketClientInitial : { false, true }) {
            QUIC_TEST_ARGS Args {QUIC_TEST_TYPE_CONNECT};
            Args.Connect = {Family, ServerStatelessRetry, FALSE, MultipleALPNs, FALSE, MultiPacketClientInitial, FALSE, 0};
            list.push_back(Args);
        }
        return list;
    }
};

struct HandshakeArgs2 : public testing::Test, public testing::WithParamInterface<QUIC_TEST_ARGS> {
    static ::std::vector<QUIC_TEST_ARGS> Generate() {
        ::std::vector<QUIC_TEST_ARGS> list;
        for (uint32_t Family : { 4, 6})
        for (bool ServerStatelessRetry : { false, true }) {
            QUIC_TEST_ARGS Args {QUIC_TEST_TYPE_CONNECT};
            Args.Connect = {Family, ServerStatelessRetry, FALSE, FALSE, FALSE, FALSE, FALSE, 0};
            list.push_back(Args);
        }
        return list;
    }
};

struct HandshakeArgs3 : public testing::Test, public testing::WithParamInterface<QUIC_TEST_ARGS> {
    static ::std::vector<QUIC_TEST_ARGS> Generate() {
        ::std::vector<QUIC_TEST_ARGS> list;
        for (uint32_t Family : { 4, 6})
        for (bool ServerStatelessRetry : { false, true })
        for (bool MultipleALPNs : { false, true }) {
            QUIC_TEST_ARGS Args {QUIC_TEST_TYPE_CONNECT};
            Args.Connect = {Family, ServerStatelessRetry, FALSE, MultipleALPNs, FALSE, FALSE, FALSE, 0};
            list.push_back(Args);
        }
        return list;
    }
};
struct HandshakeArgs4 : public testing::Test, public testing::WithParamInterface<QUIC_TEST_ARGS> {
    static ::std::vector<QUIC_TEST_ARGS> Generate() {
        ::std::vector<QUIC_TEST_ARGS> list;
        for (uint32_t Family : { 4, 6})
        for (bool ServerStatelessRetry : { false, true })
        for (bool MultiPacketClientInitial : { false, true })
        for (uint8_t RandomLossPercentage : { 1, 5, 10 }) {
            QUIC_TEST_ARGS Args {QUIC_TEST_TYPE_CONNECT};
            Args.Connect = {Family, ServerStatelessRetry, FALSE, FALSE, FALSE, MultiPacketClientInitial, FALSE, RandomLossPercentage};
            list.push_back(Args);
        }
        return list;
    }
};

struct CustomCertArgs : public testing::Test, public testing::WithParamInterface<QUIC_TEST_ARGS> {
    static ::std::vector<QUIC_TEST_ARGS> Generate() {
        ::std::vector<QUIC_TEST_ARGS> list;
        for (bool AcceptCert : { false, true })
        for (bool AsyncValidation : { false, true }) {
            QUIC_TEST_ARGS Args {QUIC_TEST_TYPE_CUSTOM_CERT_VALIDATION};
            Args.CustomCertValidation = {AcceptCert, AsyncValidation};
            list.push_back(Args);
        }
        return list;
    }
};

struct VersionNegotiationExtArgs : public testing::Test, public testing::WithParamInterface<QUIC_TEST_ARGS> {
    static ::std::vector<QUIC_TEST_ARGS> Generate() {
        ::std::vector<QUIC_TEST_ARGS> list;
        for (uint32_t Family : { 4, 6 })
        for (bool DisableVNEClient : { false, true })
        for (bool DisableVNEServer : { false, true }) {
            QUIC_TEST_ARGS Args {QUIC_TEST_TYPE_VERSION_NEGOTIATION_EXT};
            Args.VersionNegotiationExt = {Family, DisableVNEClient, DisableVNEServer};
            list.push_back(Args);
        }
        return list;
    }
};

struct ConnectClientCertArgs : public testing::Test, public testing::WithParamInterface<QUIC_TEST_ARGS> {
    static ::std::vector<QUIC_TEST_ARGS> Generate() {
        ::std::vector<QUIC_TEST_ARGS> list;
        for (uint32_t Family : { 4, 6 })
        for (bool UseClientCertificate : { false, true }) {
            QUIC_TEST_ARGS Args {QUIC_TEST_TYPE_CONNECT_CLIENT_CERT};
            Args.ConnectClientCert = {Family, UseClientCertificate};
            list.push_back(Args);
        }
        return list;
    }
};

struct SendArgs1 : public testing::Test, public testing::WithParamInterface<QUIC_TEST_ARGS> {
    static ::std::vector<QUIC_TEST_ARGS> Generate() {
        ::std::vector<QUIC_TEST_ARGS> list;
        for (uint32_t Family : { 4, 6 })
        for (uint64_t Length : { 0, 1000, 10000 })
        for (uint32_t ConnectionCount : { 1, 2, 4 })
        for (uint32_t StreamCount : { 1, 2, 4 })
        for (bool UseSendBuffer : { false, true })
        for (bool UnidirectionalStreams : { false, true })
        for (bool ServerInitiatedStreams : { false, true }) {
            QUIC_TEST_ARGS Args {QUIC_TEST_TYPE_CONNECT_AND_PING};
            Args.ConnectAndPing = {Family, Length, ConnectionCount, StreamCount, 1, 0, 0, 0, 0, 0, UseSendBuffer, UnidirectionalStreams, ServerInitiatedStreams, 0};
            list.push_back(Args);
        }
        return list;
    }
};

struct SendArgs2 : public testing::Test, public testing::WithParamInterface<QUIC_TEST_ARGS> {
    static ::std::vector<QUIC_TEST_ARGS> Generate() {
        ::std::vector<QUIC_TEST_ARGS> list;
        for (uint32_t Family : { 4, 6 })
        for (bool UseSendBuffer : { false, true })
#ifndef QUIC_DISABLE_0RTT_TESTS
        for (bool UseZeroRtt : { false, true }) {
#else
        for (bool UseZeroRtt : { false }) {
#endif
            QUIC_TEST_ARGS Args {QUIC_TEST_TYPE_CONNECT_AND_PING};
            Args.ConnectAndPing = {Family, 100000000llu, 1, 1, 1, 0, 0, 0, UseSendBuffer, 0, UseSendBuffer, 0, 0, 1};
            list.push_back(Args);
        }
        return list;
    }
};

struct SendArgs3 : public testing::Test, public testing::WithParamInterface<QUIC_TEST_ARGS> {
    static ::std::vector<QUIC_TEST_ARGS> Generate() {
        ::std::vector<QUIC_TEST_ARGS> list;
        for (uint32_t Family : { 4, 6 })
        for (uint64_t Length : { 1000, 10000 })
        for (uint32_t BurstCount : { 2, 4, 8 })
        for (uint32_t BurstDelay : { 100, 500, 1000 })
        for (bool UseSendBuffer : { false, true }) {
            QUIC_TEST_ARGS Args {QUIC_TEST_TYPE_CONNECT_AND_PING};
            Args.ConnectAndPing = {Family, Length, 1, 1, BurstCount, BurstDelay, 0, 0, 0, 0, UseSendBuffer, 0, 0, 0};
            list.push_back(Args);
        }
        return list;
    }
};

struct Send0RttArgs1 : public testing::Test, public testing::WithParamInterface<QUIC_TEST_ARGS> {
    static ::std::vector<QUIC_TEST_ARGS> Generate() {
        ::std::vector<QUIC_TEST_ARGS> list;
        for (uint32_t Family : { 4, 6 })
        for (uint64_t Length : { 0, 100, 1000, 2000 })
        for (uint32_t ConnectionCount : { 1, 2, 4 })
        for (uint32_t StreamCount : { 1, 2, 4 })
        for (bool UseSendBuffer : { false, true })
        for (bool UnidirectionalStreams : { false, true }) {
            QUIC_TEST_ARGS Args {QUIC_TEST_TYPE_CONNECT_AND_PING};
            Args.ConnectAndPing = {Family, Length, ConnectionCount, StreamCount, 1, 0, 0, 0, 1, 0, UseSendBuffer, UnidirectionalStreams, 0, 0};
            list.push_back(Args);
        }
        return list;
    }
};

struct Send0RttArgs2 : public testing::Test, public testing::WithParamInterface<QUIC_TEST_ARGS> {
    static ::std::vector<QUIC_TEST_ARGS> Generate() {
        ::std::vector<QUIC_TEST_ARGS> list;
        for (uint32_t Family : { 4, 6 })
        for (uint64_t Length : { 0, 1000, 10000, 20000 }) {
            QUIC_TEST_ARGS Args {QUIC_TEST_TYPE_CONNECT_AND_PING};
            Args.ConnectAndPing = {Family, Length, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0};
            list.push_back(Args);
        }
        return list;
    }
};

struct KeyUpdateArgs1 : public testing::Test, public testing::WithParamInterface<QUIC_TEST_ARGS> {
    static ::std::vector<QUIC_TEST_ARGS> Generate() {
        ::std::vector<QUIC_TEST_ARGS> list;
        for (uint32_t Family : { 4, 6 })
        for (uint16_t KeyUpdate : { 0, 1, 2, 3 }) {
            QUIC_TEST_ARGS Args {QUIC_TEST_TYPE_KEY_UPDATE};
            Args.KeyUpdate = {Family, (uint16_t)(KeyUpdate == 0 ? 5 : 1), 0, KeyUpdate == 0, (uint8_t)(KeyUpdate & 1), (uint8_t)(KeyUpdate & 2)};
            list.push_back(Args);
        }
        return list;
    }
};

struct KeyUpdateArgs2 : public testing::Test, public testing::WithParamInterface<QUIC_TEST_ARGS> {
    static ::std::vector<QUIC_TEST_ARGS> Generate() {
        ::std::vector<QUIC_TEST_ARGS> list;
        for (uint32_t Family : { 4, 6 })
        for (uint8_t RandomLossPercentage : { 1, 5, 10 }) {
            QUIC_TEST_ARGS Args {QUIC_TEST_TYPE_KEY_UPDATE_RANDOM_LOSS};
            Args.KeyUpdateRandomLoss = {Family, RandomLossPercentage};
            list.push_back(Args);
        }
        return list;
    }
};

struct AbortiveArgs : public testing::Test, public testing::WithParamInterface<QUIC_TEST_ARGS> {
    static ::std::vector<QUIC_TEST_ARGS> Generate() {
        ::std::vector<QUIC_TEST_ARGS> list;
        for (uint32_t Family : { 4, 6 })
        for (uint32_t DelayStreamCreation : { 0, 1 })
        for (uint32_t SendDataOnStream : { 0, 1 })
        for (uint32_t ClientShutdown : { 0, 1 })
        for (uint32_t DelayClientShutdown : { 0, 1 })
        for (uint32_t WaitForStream : { 1 })
        for (uint32_t ShutdownDirection : { 0, 1, 2 })
        for (uint32_t UnidirectionStream : { 0, 1 })
        for (uint32_t PauseReceive : { 0, 1 })
        for (uint32_t PendReceive : { 0, 1 }) {
            QUIC_TEST_ARGS Args {QUIC_TEST_TYPE_ABORTIVE_SHUTDOWN};
            Args.AbortiveShutdown = {Family, {{ DelayStreamCreation, SendDataOnStream, ClientShutdown, DelayClientShutdown, WaitForStream, ShutdownDirection, UnidirectionStream, PauseReceive, PendReceive }}};
            list.push_back(Args);
        }
        return list;
    }
};

struct CidUpdateArgs : public testing::Test, public testing::WithParamInterface<QUIC_TEST_ARGS> {
    static ::std::vector<QUIC_TEST_ARGS> Generate() {
        ::std::vector<QUIC_TEST_ARGS> list;
        for (uint32_t Family : { 4, 6 })
        for (uint16_t Iterations : { 1, 2, 4 }) {
            QUIC_TEST_ARGS Args {QUIC_TEST_TYPE_CID_UPDATE};
            Args.CidUpdate = {Family, Iterations};
            list.push_back(Args);
        }
        return list;
    }
};

struct ReceiveResumeArgs : public testing::Test, public testing::WithParamInterface<QUIC_TEST_ARGS> {
    static ::std::vector<QUIC_TEST_ARGS> Generate() {
        ::std::vector<QUIC_TEST_ARGS> list;
        for (uint32_t Family : { 4, 6 })
        for (uint32_t SendBytes : { 100 })
        for (uint32_t ConsumeBytes : { 0, 1, 99 })
        for (QUIC_RECEIVE_RESUME_SHUTDOWN_TYPE ShutdownType : { NoShutdown, GracefulShutdown, AbortShutdown })
        for (QUIC_RECEIVE_RESUME_TYPE PauseType : { ReturnConsumedBytes, ReturnStatusPending, ReturnStatusContinue })
        for (bool PauseFirst : { false, true }) {
            QUIC_TEST_ARGS Args {QUIC_TEST_TYPE_RECEIVE_RESUME};
            Args.ReceiveResume = {Family, SendBytes, ConsumeBytes, ShutdownType, PauseType, PauseFirst};
            list.push_back(Args);
        }
        return list;
    }
};

struct ReceiveResumeNoDataArgs : public testing::Test, public testing::WithParamInterface<QUIC_TEST_ARGS> {
    static ::std::vector<QUIC_TEST_ARGS> Generate() {
        ::std::vector<QUIC_TEST_ARGS> list;
        for (uint32_t Family : { 4, 6 })
        for (QUIC_RECEIVE_RESUME_SHUTDOWN_TYPE ShutdownType : { GracefulShutdown, AbortShutdown }) {
            QUIC_TEST_ARGS Args {QUIC_TEST_TYPE_RECEIVE_RESUME};
            Args.ReceiveResume = {Family, 0, 0, ShutdownType, ReturnConsumedBytes, 0};
            list.push_back(Args);
        }
        return list;
    }
};

struct DatagramNegotiationArgs : public testing::Test, public testing::WithParamInterface<QUIC_TEST_ARGS> {
    static ::std::vector<QUIC_TEST_ARGS> Generate() {
        ::std::vector<QUIC_TEST_ARGS> list;
        for (uint32_t Family : { 4, 6 })
        for (bool DatagramReceiveEnabled : { false, true }) {
            QUIC_TEST_ARGS Args {QUIC_TEST_TYPE_DATAGRAM_NEGOTIATION};
            Args.DatagramNegotiation = {Family, DatagramReceiveEnabled};
            list.push_back(Args);
        }
        return list;
    }
};

struct DrillInitialPacketCidArgs : public testing::Test, public testing::WithParamInterface<QUIC_TEST_ARGS> {
    static ::std::vector<QUIC_TEST_ARGS> Generate() {
        ::std::vector<QUIC_TEST_ARGS> list;
        for (uint32_t Family : { 4, 6 })
        for (bool SourceOrDest : { true, false })
        for (bool ActualCidLengthValid : { true, false })
        for (bool ShortCidLength : { true, false })
        for (bool CidLengthFieldValid : { true, false }) {
            QUIC_TEST_ARGS Args {QUIC_TEST_TYPE_DRILL_INITIAL_PACKET_CID};
            Args.Drill = {Family, SourceOrDest, ActualCidLengthValid, ShortCidLength, CidLengthFieldValid};
            list.push_back(Args);
        }
        return list;
    }
};

struct RebindArgs : public testing::Test, public testing::WithParamInterface<QUIC_TEST_ARGS> {
    static ::std::vector<QUIC_TEST_ARGS> Generate() {
        ::std::vector<QUIC_TEST_ARGS> list;
        for (uint32_t Family : { 4, 6 }) {
            QUIC_TEST_ARGS Args {QUIC_TEST_TYPE_REBIND};
            Args.Rebind = {Family, 0};
            list.push_back(Args);
        }
        return list;
    }
};

struct RebindPaddingArgs : public testing::Test, public testing::WithParamInterface<QUIC_TEST_ARGS> {
    static ::std::vector<QUIC_TEST_ARGS> Generate() {
        ::std::vector<QUIC_TEST_ARGS> list;
        for (uint32_t Family : { 4, 6 })
        for (uint16_t Padding = 1; Padding < 50; ++Padding) {
            QUIC_TEST_ARGS Args {QUIC_TEST_TYPE_REBIND};
            Args.Rebind = {Family, Padding};
            list.push_back(Args);
        }
        return list;
    }
};

struct AbortReceiveArgs : public testing::Test, public testing::WithParamInterface<QUIC_TEST_ARGS> {
    static ::std::vector<QUIC_TEST_ARGS> Generate() {
        ::std::vector<QUIC_TEST_ARGS> list;
        for (QUIC_TEST_ARGS_ABORT_RECEIVE_TYPE Type : { QUIC_ABORT_RECEIVE_PAUSED, QUIC_ABORT_RECEIVE_PENDING, QUIC_ABORT_RECEIVE_INCOMPLETE }) {
            QUIC_TEST_ARGS Args {QUIC_TEST_TYPE_ABORT_RECEIVE_TYPE};
            Args.AbortReceive = Type;
            list.push_back(Args);
        }
        return list;
    }
};

bool GenerateCert(CXPLAT_TEST_CERT_TYPE Type, uint32_t CredType, _Out_ QUIC_TEST_ARGS* Args) {
    if (CxPlatGetTestCertificate(
            Type,
            TestingKernelMode ?
                CXPLAT_SELF_SIGN_CERT_MACHINE :
                CXPLAT_SELF_SIGN_CERT_USER,
            CredType,
            &Args->CredValidation.CredConfig,
            &Args->CredValidation.CertHash,
            &Args->CredValidation.CertHashStore,
            Args->CredValidation.PrincipalString)) {
        //CertCleanup.push_back(Args->CredValidation.CredConfig);
        return true;
    } else {
        //printf("WARNING: Failed to find test cert!\n");
    }
    return false;
}

struct ExpiredServerCredValidationArgs : public testing::Test, public testing::WithParamInterface<QUIC_TEST_ARGS> {
    static ::std::vector<QUIC_TEST_ARGS> Generate() {
        ::std::vector<QUIC_TEST_ARGS> list;
        for (auto CredType : { QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH, QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE }) {
            QUIC_TEST_ARGS Args {QUIC_TEST_TYPE_CRED_VALIDATION};
            if (GenerateCert(CXPLAT_TEST_CERT_EXPIRED_SERVER, CredType, &Args)) {
                list.push_back(Args);
            }
        }
        if (!TestingKernelMode) {
            QUIC_TEST_ARGS Args {QUIC_TEST_TYPE_CRED_VALIDATION};
            if (GenerateCert(CXPLAT_TEST_CERT_EXPIRED_SERVER, QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT, &Args)) {
                list.push_back(Args);
            }
        }
        return list;
    }
};

struct ValidServerCredValidationArgs : public testing::Test, public testing::WithParamInterface<QUIC_TEST_ARGS> {
    static ::std::vector<QUIC_TEST_ARGS> Generate() {
        ::std::vector<QUIC_TEST_ARGS> list;
        for (auto CredType : { QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH, QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE }) {
            QUIC_TEST_ARGS Args {QUIC_TEST_TYPE_CRED_VALIDATION};
            if (GenerateCert(CXPLAT_TEST_CERT_VALID_SERVER, CredType, &Args)) {
                list.push_back(Args);
            }
        }
        if (!TestingKernelMode) {
            QUIC_TEST_ARGS Args {QUIC_TEST_TYPE_CRED_VALIDATION};
            if (GenerateCert(CXPLAT_TEST_CERT_VALID_SERVER, QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT, &Args)) {
                list.push_back(Args);
            }
        }
        return list;
    }
};

struct ExpiredClientCredValidationArgs : public testing::Test, public testing::WithParamInterface<QUIC_TEST_ARGS> {
    static ::std::vector<QUIC_TEST_ARGS> Generate() {
        ::std::vector<QUIC_TEST_ARGS> list;
        for (auto CredType : { QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH, QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE }) {
            QUIC_TEST_ARGS Args {QUIC_TEST_TYPE_CRED_VALIDATION};
            if (GenerateCert(CXPLAT_TEST_CERT_EXPIRED_CLIENT, CredType, &Args)) {
                list.push_back(Args);
            }
        }
        if (!TestingKernelMode) {
            QUIC_TEST_ARGS Args {QUIC_TEST_TYPE_CRED_VALIDATION};
            if (GenerateCert(CXPLAT_TEST_CERT_EXPIRED_CLIENT, QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT, &Args)) {
                list.push_back(Args);
            }
        }
        return list;
    }
};

struct ValidClientCredValidationArgs : public testing::Test, public testing::WithParamInterface<QUIC_TEST_ARGS> {
    static ::std::vector<QUIC_TEST_ARGS> Generate() {
        ::std::vector<QUIC_TEST_ARGS> list;
        for (auto CredType : { QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH, QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE }) {
            QUIC_TEST_ARGS Args {QUIC_TEST_TYPE_CRED_VALIDATION};
            if (GenerateCert(CXPLAT_TEST_CERT_VALID_CLIENT, CredType, &Args)) {
                list.push_back(Args);
            }
        }
        if (!TestingKernelMode) {
            QUIC_TEST_ARGS Args {QUIC_TEST_TYPE_CRED_VALIDATION};
            if (GenerateCert(CXPLAT_TEST_CERT_VALID_CLIENT, QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT, &Args)) {
                list.push_back(Args);
            }
        }
        return list;
    }
};
