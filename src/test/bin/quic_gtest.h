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
extern bool UseDuoNic;
#if defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
extern bool UseQTIP;
#endif

class WithBool : public testing::Test,
    public testing::WithParamInterface<bool> {
};

std::ostream& operator << (std::ostream& o, const MtuArgs& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        args.DropMode << "/" << args.RaiseMinimum << "/";
}

struct WithMtuArgs : public testing::Test,
    public testing::WithParamInterface<MtuArgs> {
    static ::std::vector<MtuArgs> Generate() {
        ::std::vector<MtuArgs> list;
        for (int Family : { 4, 6 })
        for (uint8_t DropMode : {0, 1, 2, 3})
        for (uint8_t RaiseMinimum : {0, 1})
            list.push_back({ Family, DropMode, RaiseMinimum });
        return list;
    }
};

struct WithFamilyArgs :
    public testing::Test,
    public testing::WithParamInterface<FamilyArgs> {

    static ::std::vector<FamilyArgs> Generate() {
        return {{4}, {6}};
    }
};

std::ostream& operator << (std::ostream& o, const FamilyArgs& args) {
    return o << (args.Family == 4 ? "v4" : "v6");
}

struct HandshakeArgs10 {
    int Family;
    QUIC_CONGESTION_CONTROL_ALGORITHM CcAlgo;
    static ::std::vector<HandshakeArgs10> Generate() {
        ::std::vector<HandshakeArgs10> list;
        for (int Family : { 4, 6 })
#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
        for (auto CcAlgo : { QUIC_CONGESTION_CONTROL_ALGORITHM_CUBIC, QUIC_CONGESTION_CONTROL_ALGORITHM_BBR })
#else
        for (auto CcAlgo : { QUIC_CONGESTION_CONTROL_ALGORITHM_CUBIC })
#endif
            list.push_back({ Family, CcAlgo });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const HandshakeArgs10& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        (args.CcAlgo == QUIC_CONGESTION_CONTROL_ALGORITHM_CUBIC ? "cubic" : "bbr");
}

class WithHandshakeArgs10 : public testing::Test,
    public testing::WithParamInterface<HandshakeArgs10> {
};

struct HandshakeArgs11 {
    bool ClientShutdown;
    static ::std::vector<HandshakeArgs11> Generate() {
        ::std::vector<HandshakeArgs11> list;
        for (bool ClientShutdown : { false, true })
            list.push_back({ ClientShutdown });
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const HandshakeArgs11& args) {
    return o << (args.ClientShutdown ? "Client" : "Server");
};

class WithHandshakeArgs11 : public testing::Test,
    public testing::WithParamInterface<HandshakeArgs11> {
};

struct HandshakeArgs12 {
    int Family;
    uint16_t NumberOfConnections;
    bool XdpSupported;
    bool TestCibirSupport;
    static ::std::vector<HandshakeArgs12> Generate() {
        ::std::vector<HandshakeArgs12> list;
        for (int Family : { 4, 6 })
        for (uint16_t NumberOfConnections : { 1, 2, 4 })
        for (bool TestCibir : { false, true })
        for (bool XdpSupported : { false, true }) {
#if !defined(_WIN32)
            if (XdpSupported) continue;
#endif
            if (!UseDuoNic && XdpSupported) {
                continue;
            }
            list.push_back({ Family, NumberOfConnections, XdpSupported, TestCibir });
        }
        return list;
    }
};

std::ostream& operator << (std::ostream& o, const HandshakeArgs12& args) {
    return o <<
        (args.Family == 4 ? "v4" : "v6") << "/" <<
        args.NumberOfConnections << "/" <<
        (args.XdpSupported ? "XDP" : "NoXDP") << "/" <<
        (args.TestCibirSupport ? "TestCibir" : "NoCibir");
}

class WithHandshakeArgs12 : public testing::Test,
    public testing::WithParamInterface<HandshakeArgs12> {
};

#if defined(QUIC_API_ENABLE_PREVIEW_FEATURES)
std::ostream& operator << (std::ostream& o, const ValidateNetStatsConnEventArgs& args) {
    return o << args.Test;
}

struct WithValidateNetStatsConnEventArgs : public testing::Test,
    public testing::WithParamInterface<ValidateNetStatsConnEventArgs> {
    static ::std::vector<ValidateNetStatsConnEventArgs> Generate() {
        ::std::vector<ValidateNetStatsConnEventArgs> list;
        for (uint32_t Test = 0; Test < 2; ++Test)
            list.push_back({ Test });
        return list;
    }
};
#endif

std::ostream& operator << (std::ostream& o, const ValidateStreamEventArgs& args) {
    return o << args.Test;
}

struct WithValidateStreamEventArgs : public testing::Test,
    public testing::WithParamInterface<ValidateStreamEventArgs> {
    static ::std::vector<ValidateStreamEventArgs> Generate() {
        ::std::vector<ValidateStreamEventArgs> list;
        for (uint32_t Test = 0; Test < 9; ++Test)
            list.push_back({ Test });
        return list;
    }
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
