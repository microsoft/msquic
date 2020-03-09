/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#define QUIC_TEST_APIS 1

#include <quic_platform.h>
#include <MsQuicTests.h>
#include <msquichelper.h>
#include "quic_trace.h"
#undef min // gtest headers conflict with previous definitions of min/max.
#undef max
#include "gtest/gtest.h"
// BUGBUG : CLOG IS DISABLED due to unknown import issue (prob cdecl/stdcall)
#if defined(QUIC_LOGS_WPP) || defined(QUIC_LOGS_CLOG)
; //<-- WPP line was here
//#include "quic_gtest.cpp.clog"
#endif
#define QuicTraceLogError(...)
#define QuicTraceLogInfo(...)
#define QuicTraceLogVerbose(...)
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

class WithSendArgs1 : public testing::Test,
    public testing::WithParamInterface<SendArgs1> {
};

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
    static void SetUpTestSuite()
    {
        QUIC_STATUS Status;
        uint8_t Disabled = FALSE;

        Status =
            MsQuic->SetParam(
                Registration,
                QUIC_PARAM_LEVEL_REGISTRATION,
                QUIC_PARAM_REGISTRATION_ENCRYPTION,
                sizeof(Disabled),
                &Disabled);
        if (QUIC_FAILED(Status)) {
            QuicTraceLogError("Failed to disable encryption for test. 0x%x", Status);
            GTEST_NONFATAL_FAILURE_("Failed to disable encryption for test.");
        }
    }

    static void TearDownTestSuite()
    {
        QUIC_STATUS Status;
        uint8_t Enabled = TRUE;

        Status =
            MsQuic->SetParam(
                Registration,
                QUIC_PARAM_LEVEL_REGISTRATION,
                QUIC_PARAM_REGISTRATION_ENCRYPTION,
                sizeof(Enabled),
                &Enabled);
        if (QUIC_FAILED(Status)) {
            QuicTraceLogError("Failed to re-enable encryption after test. 0x%x", Status);
            GTEST_NONFATAL_FAILURE_("Failed to re-enable encryption for test.");
        }
    }
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

//
// Windows Kernel Mode Helpers
//

#ifdef _WIN32

class QuicDriverService {
    SC_HANDLE ScmHandle;
    SC_HANDLE ServiceHandle;
public:
    QuicDriverService() :
        ScmHandle(nullptr),
        ServiceHandle(nullptr) {
    }
    bool Initialize() {
        uint32_t Error;
        ScmHandle = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
        if (ScmHandle == nullptr) {
            Error = GetLastError();
            QuicTraceLogError("[test] GetFullPathName failed, 0x%x.", Error);
            return false;
        }
    QueryService:
        ServiceHandle =
            OpenServiceA(
                ScmHandle,
                QUIC_TEST_DRIVER_NAME,
                SERVICE_ALL_ACCESS);
        if (ServiceHandle == nullptr) {
            QuicTraceLogError("[test] OpenService failed, 0x%x.", GetLastError());
            char DriverFilePath[MAX_PATH];
            Error =
                GetFullPathNameA(
                    "msquictest.sys",
                    sizeof(DriverFilePath),
                    DriverFilePath,
                    nullptr);
            if (Error == 0) {
                Error = GetLastError();
                QuicTraceLogError("[test] GetFullPathName failed, 0x%x.", Error);
                return false;
            }
            ServiceHandle =
                CreateServiceA(
                    ScmHandle,
                    QUIC_TEST_DRIVER_NAME,
                    QUIC_TEST_DRIVER_NAME,
                    SC_MANAGER_ALL_ACCESS,
                    SERVICE_KERNEL_DRIVER,
                    SERVICE_DEMAND_START,
                    SERVICE_ERROR_NORMAL,
                    DriverFilePath,
                    nullptr,
                    nullptr,
                    "msquic\0",
                    nullptr,
                    nullptr);
            if (ServiceHandle == nullptr) {
                Error = GetLastError();
                if (Error == ERROR_SERVICE_EXISTS) {
                    goto QueryService;
                }
                QuicTraceLogError("[test] CreateService failed, 0x%x.", Error);
                return false;
            }
        }
        return true;
    }
    void Uninitialize() {
        if (ServiceHandle != nullptr) {
            CloseServiceHandle(ServiceHandle);
        }
        if (ScmHandle != nullptr) {
            CloseServiceHandle(ScmHandle);
        }
    }
    bool Start() {
        if (!StartServiceA(ServiceHandle, 0, nullptr)) {
            uint32_t Error = GetLastError();
            if (Error != ERROR_SERVICE_ALREADY_RUNNING) {
                QuicTraceLogError("[test] StartService failed, 0x%x.", Error);
                return false;
            }
        }
        return true;
    }
};

#else

class QuicDriverService {
public:
    bool Initialize() { return false; }
    void Uninitialize() { }
    bool Start() { return false; }
};

#endif // _WIN32

#ifdef _WIN32

class QuicDriverClient {
    HANDLE DeviceHandle;
public:
    QuicDriverClient() : DeviceHandle(INVALID_HANDLE_VALUE) { }
    bool Initialize(
        _In_ QUIC_SEC_CONFIG_PARAMS* SecConfigParams
        ) {
        uint32_t Error;
        DeviceHandle =
            CreateFileA(
                QUIC_TEST_IOCTL_PATH,
                GENERIC_READ | GENERIC_WRITE,
                0,
                nullptr,                // no SECURITY_ATTRIBUTES structure
                OPEN_EXISTING,          // No special create flags
                FILE_FLAG_OVERLAPPED,   // Allow asynchronous requests
                nullptr);
        if (DeviceHandle == INVALID_HANDLE_VALUE) {
            Error = GetLastError();
            QuicTraceLogError("[test] CreateFile failed, 0x%x.", Error);
            return false;
        }
        if (!Run(IOCTL_QUIC_SEC_CONFIG, SecConfigParams->Thumbprint, sizeof(SecConfigParams->Thumbprint), 30000)) {
            CloseHandle(DeviceHandle);
            DeviceHandle = INVALID_HANDLE_VALUE;
            QuicTraceLogError("[test] Run(IOCTL_QUIC_SEC_CONFIG) failed.");
            return false;
        }
        return true;
    }
    void Uninitialize() {
        if (DeviceHandle != INVALID_HANDLE_VALUE) {
            CloseHandle(DeviceHandle);
        }
    }
    bool Run(
        _In_ uint32_t IoControlCode,
        _In_reads_bytes_opt_(InBufferSize)
            void* InBuffer,
        _In_ uint32_t InBufferSize,
        _In_ uint32_t TimeoutMs = 30000
        ) {
        uint32_t Error;
        OVERLAPPED Overlapped = { 0 };
        Overlapped.hEvent = CreateEvent(nullptr, FALSE, FALSE, nullptr);
        if (Overlapped.hEvent == nullptr) {
            Error = GetLastError();
            QuicTraceLogError("[test] CreateEvent failed, 0x%x.", Error);
            return false;
        }
        QuicTraceLogVerbose("[test] Sending IOCTL %u with %u bytes.",
            IoGetFunctionCodeFromCtlCode(IoControlCode), InBufferSize);
        if (!DeviceIoControl(
                DeviceHandle,
                IoControlCode,
                InBuffer, InBufferSize,
                nullptr, 0,
                nullptr,
                &Overlapped)) {
            Error = GetLastError();
            if (Error != ERROR_IO_PENDING) {
                CloseHandle(Overlapped.hEvent);
                QuicTraceLogError("[test] DeviceIoControl failed, 0x%x.", Error);
                return false;
            }
        }
        DWORD dwBytesReturned;
        if (!GetOverlappedResultEx(
                DeviceHandle,
                &Overlapped,
                &dwBytesReturned,
                TimeoutMs,
                FALSE)) {
            Error = GetLastError();
            if (Error == WAIT_TIMEOUT) {
                Error = ERROR_TIMEOUT;
                CancelIoEx(DeviceHandle, &Overlapped);
            }
            QuicTraceLogError("[test] GetOverlappedResultEx failed, 0x%x.", Error);
        } else {
            Error = ERROR_SUCCESS;
        }
        CloseHandle(Overlapped.hEvent);
        return Error == ERROR_SUCCESS;
    }
    bool Run(
        _In_ uint32_t IoControlCode,
        _In_ uint32_t TimeoutMs = 30000
        ) {
        return Run(IoControlCode, nullptr, 0, TimeoutMs);
    }
    template<class T>
    bool Run(
        _In_ uint32_t IoControlCode,
        _In_ const T& Data,
        _In_ uint32_t TimeoutMs = 30000
        ) {
        return Run(IoControlCode, (void*)&Data, sizeof(Data), TimeoutMs);
    }
};

#else

class QuicDriverClient {
public:
    bool Initialize(
        _In_ QUIC_SEC_CONFIG_PARAMS* SecConfigParams
    ) {
        UNREFERENCED_PARAMETER(SecConfigParams);
        return false;
    }
    void Uninitialize() { }
    bool Run(
        _In_ uint32_t IoControlCode,
        _In_ void* InBuffer,
        _In_ uint32_t InBufferSize,
        _In_ uint32_t TimeoutMs = 30000
        ) {
        UNREFERENCED_PARAMETER(IoControlCode);
        UNREFERENCED_PARAMETER(InBuffer);
        UNREFERENCED_PARAMETER(InBufferSize);
        UNREFERENCED_PARAMETER(TimeoutMs);
        return false;
    }
    bool
    Run(
        _In_ uint32_t IoControlCode,
        _In_ uint32_t TimeoutMs = 30000
        ) {
        return Run(IoControlCode, nullptr, 0, TimeoutMs);
    }
    template<class T>
    bool
    Run(
        _In_ uint32_t IoControlCode,
        _In_ const T& Data,
        _In_ uint32_t TimeoutMs = 30000
        ) {
        return Run(IoControlCode, (void*)&Data, sizeof(Data), TimeoutMs);
    }
};

#endif // _WIN32
