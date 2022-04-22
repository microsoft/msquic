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

class WithBool : public testing::Test,
    public testing::WithParamInterface<bool> {
};

struct MtuArgs {
    int Family;
    int DropMode;
    uint8_t RaiseMinimum;
    static ::std::vector<MtuArgs> Generate() {
        ::std::vector<MtuArgs> list;
        for (int Family : { 4, 6}) {
            for (int DropMode : {0, 1, 2, 3}) {
                for (uint8_t RaiseMinimum : {0, 1}) {
                    list.push_back({ Family, DropMode, RaiseMinimum });
                }
            }
        }
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const MtuArgs& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        args.DropMode << "/" << args.RaiseMinimum << "/";
}

class WithMtuArgs : public testing::Test,
    public testing::WithParamInterface<MtuArgs> {
};

struct FamilyArgs {
    int Family;
    static ::std::vector<FamilyArgs> Generate() {
        ::std::vector<FamilyArgs> list;
        for (int Family : { 4, 6})
            list.push_back({ Family });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const FamilyArgs& args) {
    return o << (args.Family == 4 ? "v4" : "v6");
}

class WithFamilyArgs : public testing::Test,
    public testing::WithParamInterface<FamilyArgs> {
};

struct HandshakeArgs1 {
    int Family;
    bool ServerStatelessRetry;
    bool MultipleALPNs;
    bool MultiPacketClientInitial;
    static ::std::vector<HandshakeArgs1> Generate() {
        ::std::vector<HandshakeArgs1> list;
        for (int Family : { 4, 6})
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
    int Family;
    bool ServerStatelessRetry;
    static ::std::vector<HandshakeArgs2> Generate() {
        ::std::vector<HandshakeArgs2> list;
        for (int Family : { 4, 6})
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
    int Family;
    bool ServerStatelessRetry;
    bool MultipleALPNs;
    bool DelayedAsyncConfig;
    static ::std::vector<HandshakeArgs3> Generate() {
        ::std::vector<HandshakeArgs3> list;
        for (int Family : { 4, 6})
        for (bool ServerStatelessRetry : { false, true })
        for (bool MultipleALPNs : { false, true })
        for (bool DelayedAsyncConfig : { false, true })
            list.push_back({ Family, ServerStatelessRetry, MultipleALPNs, DelayedAsyncConfig });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const HandshakeArgs3& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        (args.ServerStatelessRetry ? "Retry" : "NoRetry") << "/" <<
        (args.MultipleALPNs ? "MultipleALPNs" : "SingleALPN") << "/" <<
        (args.DelayedAsyncConfig ? "DelayedAsyncConfig" : "AsyncConfig");
}

class WithHandshakeArgs3 : public testing::Test,
    public testing::WithParamInterface<HandshakeArgs3> {
};

struct HandshakeArgs4 {
    int Family;
    bool ServerStatelessRetry;
    bool MultiPacketClientInitial;
    uint8_t RandomLossPercentage;
    static ::std::vector<HandshakeArgs4> Generate() {
        ::std::vector<HandshakeArgs4> list;
        for (int Family : { 4, 6})
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
    int Family;
    bool DisableVNEClient;
    bool DisableVNEServer;
    static ::std::vector<VersionNegotiationExtArgs> Generate() {
        ::std::vector<VersionNegotiationExtArgs> list;
        for (int Family : { 4, 6 })
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
    int Family;
    bool UseClientCertificate;
    static ::std::vector<HandshakeArgs6> Generate() {
        ::std::vector<HandshakeArgs6> list;
        for (int Family : { 4, 6 })
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

struct HandshakeArgs7 {
    int Family;
    uint8_t Mode;
    static ::std::vector<HandshakeArgs7> Generate() {
        ::std::vector<HandshakeArgs7> list;
        for (int Family : { 4, 6 })
        for (uint8_t Mode : { 0, 1, 2, 3 })
            list.push_back({ Family, Mode });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const HandshakeArgs7& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        (int)args.Mode;
}

class WithHandshakeArgs7 : public testing::Test,
    public testing::WithParamInterface<HandshakeArgs7> {
};

struct SendArgs1 {
    int Family;
    uint64_t Length;
    uint32_t ConnectionCount;
    uint32_t StreamCount;
    bool UseSendBuffer;
    bool UnidirectionalStreams;
    bool ServerInitiatedStreams;
    static ::std::vector<SendArgs1> Generate() {
        ::std::vector<SendArgs1> list;
        for (int Family : { 4, 6 })
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
    int Family;
    bool UseSendBuffer;
    bool UseZeroRtt;
    static ::std::vector<SendArgs2> Generate() {
        ::std::vector<SendArgs2> list;
        for (int Family : { 4, 6 })
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
    int Family;
    uint64_t Length;
    uint32_t BurstCount;
    uint32_t BurstDelay;
    bool UseSendBuffer;
    static ::std::vector<SendArgs3> Generate() {
        ::std::vector<SendArgs3> list;
        for (int Family : { 4, 6 })
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
    int Family;
    uint64_t Length;
    uint32_t ConnectionCount;
    uint32_t StreamCount;
    bool UseSendBuffer;
    bool UnidirectionalStreams;
    static ::std::vector<Send0RttArgs1> Generate() {
        ::std::vector<Send0RttArgs1> list;
        for (int Family : { 4, 6 })
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
    int Family;
    uint64_t Length;
    static ::std::vector<Send0RttArgs2> Generate() {
        ::std::vector<Send0RttArgs2> list;
        for (int Family : { 4, 6 })
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
    int Family;
    int KeyUpdate;
    static ::std::vector<KeyUpdateArgs1> Generate() {
        ::std::vector<KeyUpdateArgs1> list;
        for (int Family : { 4, 6 })
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
    int Family;
    uint8_t RandomLossPercentage;
    static ::std::vector<KeyUpdateArgs2> Generate() {
        ::std::vector<KeyUpdateArgs2> list;
        for (int Family : { 4, 6 })
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
    int Family;
    QUIC_ABORTIVE_TRANSFER_FLAGS Flags;
    static ::std::vector<AbortiveArgs> Generate() {
        ::std::vector<AbortiveArgs> list;
        for (int Family : { 4, 6 })
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
    int Family;
    uint16_t Iterations;
    static ::std::vector<CidUpdateArgs> Generate() {
        ::std::vector<CidUpdateArgs> list;
        for (int Family : { 4, 6 })
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
    int Family;
    int SendBytes;
    int ConsumeBytes;
    QUIC_RECEIVE_RESUME_SHUTDOWN_TYPE ShutdownType;
    QUIC_RECEIVE_RESUME_TYPE PauseType;
    bool PauseFirst;
    static ::std::vector<ReceiveResumeArgs> Generate() {
        ::std::vector<ReceiveResumeArgs> list;
        for (int SendBytes : { 100 })
        for (int Family : { 4, 6 })
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
    int Family;
    QUIC_RECEIVE_RESUME_SHUTDOWN_TYPE ShutdownType;
    static ::std::vector<ReceiveResumeNoDataArgs> Generate() {
        ::std::vector<ReceiveResumeNoDataArgs> list;
        for (int Family : { 4, 6 })
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
    int Family;
    bool DatagramReceiveEnabled;
    static ::std::vector<DatagramNegotiationArgs> Generate() {
        ::std::vector<DatagramNegotiationArgs> list;
        for (int Family : { 4, 6 })
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
    int Family;
    bool SourceOrDest;
    bool ActualCidLengthValid;
    bool ShortCidLength;
    bool CidLengthFieldValid;

    static ::std::vector<DrillInitialPacketCidArgs> Generate() {
        ::std::vector<DrillInitialPacketCidArgs> list;
        for (int Family : { 4, 6 })
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

struct DrillInitialPacketTokenArgs {
    int Family;

    static ::std::vector<DrillInitialPacketTokenArgs> Generate() {
        ::std::vector<DrillInitialPacketTokenArgs> list;
        for (int Family : { 4, 6 })
            list.push_back({ Family, });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const DrillInitialPacketTokenArgs& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6");
}

class WithDrillInitialPacketTokenArgs: public testing::Test,
    public testing::WithParamInterface<DrillInitialPacketTokenArgs> {
};

struct ValidateConnectionEventArgs {
    uint32_t Test;
    static ::std::vector<ValidateConnectionEventArgs> Generate() {
        ::std::vector<ValidateConnectionEventArgs> list;
#ifndef QUIC_DISABLE_0RTT_TESTS
        for (uint32_t Test = 0; Test < 3; ++Test)
#else
        for (uint32_t Test = 0; Test < 2; ++Test)
#endif
            list.push_back({ Test });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const ValidateConnectionEventArgs& args) {
    return o << args.Test;
}

class WithValidateConnectionEventArgs : public testing::Test,
    public testing::WithParamInterface<ValidateConnectionEventArgs> {
};

struct ValidateStreamEventArgs {
    uint32_t Test;
    static ::std::vector<ValidateStreamEventArgs> Generate() {
        ::std::vector<ValidateStreamEventArgs> list;
        for (uint32_t Test = 0; Test < 8; ++Test)
            list.push_back({ Test });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const ValidateStreamEventArgs& args) {
    return o << args.Test;
}

class WithValidateStreamEventArgs : public testing::Test,
    public testing::WithParamInterface<ValidateStreamEventArgs> {
};

struct RebindPaddingArgs {
    int Family;
    uint16_t Padding;
    static ::std::vector<RebindPaddingArgs> Generate() {
        ::std::vector<RebindPaddingArgs> list;
        for (int Family : { 4, 6 })
        for (uint16_t Padding = 1; Padding < 75; ++Padding)
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

struct TlsConfigArgs {

    QUIC_CREDENTIAL_TYPE CredType;
    CXPLAT_TEST_CERT_TYPE CertType;

    static ::std::vector<TlsConfigArgs> Generate() {
        ::std::vector<TlsConfigArgs> List;
        for (auto CredType : {
#ifdef _WIN32
            QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH,
            QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE,
            QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT,
#else
            QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE,
            QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED,
            QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12
#endif
        })
        for (auto CertType : {CXPLAT_TEST_CERT_SELF_SIGNED_SERVER, CXPLAT_TEST_CERT_SELF_SIGNED_CLIENT}) {
            List.push_back({CredType, CertType});
        }
        return List;
    }
};

std::ostream& operator << (std::ostream& o, const CXPLAT_TEST_CERT_TYPE& type) {
    switch (type) {
    case CXPLAT_TEST_CERT_VALID_SERVER:
        return o << "Valid Server";
    case CXPLAT_TEST_CERT_VALID_CLIENT:
        return o << "Valid Client";
    case CXPLAT_TEST_CERT_EXPIRED_SERVER:
        return o << "Expired Server";
    case CXPLAT_TEST_CERT_EXPIRED_CLIENT:
        return o << "Expired Client";
    case CXPLAT_TEST_CERT_SELF_SIGNED_SERVER:
        return o << "Self-signed Server";
    case CXPLAT_TEST_CERT_SELF_SIGNED_CLIENT:
        return o << "Self-signed Client";
    default:
        return o << "Unknown";
    }
}

std::ostream& operator << (std::ostream& o, const QUIC_CREDENTIAL_TYPE& type) {
    switch (type) {
    case QUIC_CREDENTIAL_TYPE_NONE:
        return o << "None";
    case QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH:
        return o << "Hash";
    case QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE:
        return o << "HashStore";
    case QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT:
        return o << "Context";
    case QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE:
        return o << "File";
    case QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED:
        return o << "FileProtected";
    case QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12:
        return o << "Pkcs12";
    default:
        return o << "Unknown";
    }
}

std::ostream& operator << (std::ostream& o, const TlsConfigArgs& args) {
    return o << args.CredType << "/" << args.CertType;
}

class WithValidateTlsConfigArgs : public testing::Test,
    public testing::WithParamInterface<TlsConfigArgs> {
};
