/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#define QUIC_TEST_APIS 1

#include <quic_platform.h>
#include <MsQuicTests.h>
#include <msquichelper.h>
#include "quic_trace.h"
#include "quic_driver_helpers.h"
#undef min // gtest headers conflict with previous definitions of min/max.
#undef max
#include "gtest/gtest.h"
#ifdef QUIC_CLOG
#include "quic_gtest.h.clog.h"
#endif

class WithBool : public testing::Test,
    public testing::WithParamInterface<bool> {
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
    bool SessionResumption;
    static ::std::vector<HandshakeArgs1> Generate() {
        ::std::vector<HandshakeArgs1> list;
        for (int Family : { 4, 6})
        for (bool ServerStatelessRetry : { false, true })
        for (bool MultipleALPNs : { false, true })
        for (bool MultiPacketClientInitial : { false, true })
#ifdef QUIC_DISABLE_RESUMPTION
        for (bool SessionResumption : { false })
#else
        for (bool SessionResumption : { false, true })
#endif
            list.push_back({ Family, ServerStatelessRetry, MultipleALPNs, MultiPacketClientInitial, SessionResumption });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const HandshakeArgs1& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        (args.ServerStatelessRetry ? "Retry" : "NoRetry") << "/" <<
        (args.MultipleALPNs ? "MultipleALPNs" : "SingleALPN") << "/" <<
        (args.MultiPacketClientInitial ? "MultipleInitials" : "SingleInitial") << "/" <<
        (args.SessionResumption ? "Resume" : "NoResume");
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
    static ::std::vector<HandshakeArgs3> Generate() {
        ::std::vector<HandshakeArgs3> list;
        for (int Family : { 4, 6})
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
    int Family;
    bool ServerStatelessRetry;
    bool MultiPacketClientInitial;
    bool SessionResumption;
    uint8_t RandomLossPercentage;
    static ::std::vector<HandshakeArgs4> Generate() {
        ::std::vector<HandshakeArgs4> list;
        for (int Family : { 4, 6})
        for (bool ServerStatelessRetry : { false, true })
        for (bool MultiPacketClientInitial : { false, true })
#ifdef QUIC_DISABLE_RESUMPTION
        for (bool SessionResumption : { false })
#else
        for (bool SessionResumption : { false, true })
#endif
        for (uint8_t RandomLossPercentage : { 1, 5, 10 })
            list.push_back({ Family, ServerStatelessRetry, MultiPacketClientInitial, SessionResumption, RandomLossPercentage });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const HandshakeArgs4& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        (args.ServerStatelessRetry ? "Retry" : "NoRetry") << "/" <<
        (args.MultiPacketClientInitial ? "MultipleInitials" : "SingleInitial") << "/" <<
        (args.SessionResumption ? "Resume" : "NoResume") << "/" <<
        (uint32_t)args.RandomLossPercentage << "% loss";
}

class WithHandshakeArgs4 : public testing::Test,
    public testing::WithParamInterface<HandshakeArgs4> {
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
            list.push_back({ Family, {{ DelayStreamCreation, SendDataOnStream, ClientShutdown, DelayClientShutdown, WaitForStream, ShutdownDirection, UnidirectionStream }} });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const AbortiveArgs& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        args.Flags.IntValue;
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
