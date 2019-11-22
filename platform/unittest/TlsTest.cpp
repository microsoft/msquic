/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "quic_platform.h"
#include "msquic.h"
#include "quic_tls.h"

#define LOG_ONLY_FAILURES
#define INLINE_TEST_METHOD_MARKUP
#include <wextestclass.h>
#include <logcontroller.h>

#include "quic_trace.h"

#ifdef QUIC_LOGS_WPP
#include "tlstest.tmh"
#endif

using namespace WEX::Common;
using namespace WEX::Logging;
using namespace WEX::TestExecution;

#define VERIFY_QUIC_SUCCESS(result, ...) VERIFY_IS_TRUE(QUIC_SUCCEEDED(result), __VA_ARGS__)

extern "C" {
void* CreateServerCertificate();
void FreeServerCertificate(void* CertCtx);
}

const uint32_t CertValidationIgnoreFlags =
    QUIC_CERTIFICATE_FLAG_IGNORE_UNKNOWN_CA |
    QUIC_CERTIFICATE_FLAG_IGNORE_CERTIFICATE_CN_INVALID;

struct TlsTest : public WEX::TestClass<TlsTest>
{
    QUIC_RUNDOWN_REF SecConfigRundown;
    HANDLE SecConfigDoneEvent;
    void* SecConfigertContext;
    QUIC_SEC_CONFIG* SecConfig;

    TlsTest() :
        SecConfigDoneEvent(CreateEvent(nullptr, FALSE, FALSE, nullptr)),
        SecConfig(nullptr)
    {
        QuicRundownInitialize(&SecConfigRundown);
    }

    ~TlsTest()
    {
        CloseHandle(SecConfigDoneEvent);
        if (SecConfig != nullptr) {
            QuicTlsSecConfigRelease(SecConfig);
        }
        QuicRundownReleaseAndWait(&SecConfigRundown);
        QuicRundownUninitialize(&SecConfigRundown);
    }

    BEGIN_TEST_CLASS(TlsTest)
    END_TEST_CLASS()

    static void
    OnSecConfigCreateComplete(
        _In_opt_ void* Context,
        _In_ QUIC_STATUS Status,
        _In_opt_ QUIC_SEC_CONFIG* SecConfig
        )
    {
        TlsTest* pThis = (TlsTest*)Context;
        VERIFY_QUIC_SUCCESS(Status);
        pThis->SecConfig = SecConfig;
        SetEvent(pThis->SecConfigDoneEvent);
    }

    TEST_CLASS_SETUP(Setup)
    {
        VERIFY_IS_NOT_NULL((SecConfigertContext = CreateServerCertificate()));
        VERIFY_QUIC_SUCCESS(
            QuicTlsServerSecConfigCreate(
                &SecConfigRundown,
                QUIC_SEC_CONFIG_FLAG_CERTIFICATE_CONTEXT,
                SecConfigertContext,
                nullptr,
                this,
                OnSecConfigCreateComplete));
        VERIFY_IS_TRUE(WaitForSingleObject(SecConfigDoneEvent, 5000) == WAIT_OBJECT_0);
        return SecConfig != nullptr;
    }

    TEST_CLASS_CLEANUP(Cleanup)
    {
        QuicTlsSecConfigRelease(SecConfig);
        SecConfig = nullptr;
        FreeServerCertificate(SecConfigertContext);
        SecConfigertContext = nullptr;
        return true;
    }

    TEST_METHOD_CLEANUP(MethodCleanup)
    {
        return true;
    }

    struct TlsSession
    {
        PQUIC_TLS_SESSION Ptr;
        TlsSession() : Ptr(nullptr) {
            VERIFY_QUIC_SUCCESS(QuicTlsSessionInitialize("MsQuicTest", &Ptr));
        }
        ~TlsSession() {
            QuicTlsSessionUninitialize(Ptr);
        }
    };

    struct TlsContext
    {
        PQUIC_TLS Ptr;
        HANDLE ProcessCompleteEvent;

        QUIC_TLS_PROCESS_STATE State;

        bool Connected;
        bool Key0RttReady;
        bool Key1RttReady;

        TlsContext() :
            Ptr(nullptr),
            ProcessCompleteEvent(CreateEvent(nullptr, FALSE, FALSE, nullptr)),
            Connected(false) {
            RtlZeroMemory(&State, sizeof(State));
            State.Buffer = (UINT8*)QUIC_ALLOC_NONPAGED(8000);
            State.BufferAllocLength = 8000;
        }

        ~TlsContext() {
            QuicTlsUninitialize(Ptr);
            CloseHandle(ProcessCompleteEvent);
            QUIC_FREE(State.Buffer);
            for (uint8_t i = 0; i < QUIC_PACKET_KEY_COUNT; ++i) {
                QuicPacketKeyFree(State.ReadKeys[i]);
                QuicPacketKeyFree(State.WriteKeys[i]);
            }
        }

        void InitializeServer(
            TlsSession& Session,
            const QUIC_SEC_CONFIG* SecConfig,
            uint16_t TPLen = 64
            )
        {
            QUIC_TLS_CONFIG Config = {0};
            Config.IsServer = TRUE;
            Config.TlsSession = Session.Ptr;
            Config.SecConfig = (QUIC_SEC_CONFIG*)SecConfig;
            Config.LocalTPBuffer =
                (uint8_t*)QUIC_ALLOC_NONPAGED(QuicTlsTPHeaderSize + TPLen);
            Config.LocalTPLength = QuicTlsTPHeaderSize + TPLen;
            Config.Connection = (PQUIC_CONNECTION)this;
            Config.ProcessCompleteCallback = OnProcessComplete;
            Config.ReceiveTPCallback = OnRecvQuicTP;

            VERIFY_QUIC_SUCCESS(
                QuicTlsInitialize(
                    &Config,
                    &Ptr));
        }

        void InitializeClient(
            TlsSession& Session,
            QUIC_SEC_CONFIG* ClientConfig,
            uint16_t TPLen = 64
            )
        {
            QUIC_TLS_CONFIG Config = {0};
            Config.IsServer = FALSE;
            Config.TlsSession = Session.Ptr;
            Config.SecConfig = ClientConfig;
            Config.LocalTPBuffer =
                (uint8_t*)QUIC_ALLOC_NONPAGED(QuicTlsTPHeaderSize + TPLen);
            Config.LocalTPLength = QuicTlsTPHeaderSize + TPLen;
            Config.Connection = (PQUIC_CONNECTION)this;
            Config.ProcessCompleteCallback = OnProcessComplete;
            Config.ReceiveTPCallback = OnRecvQuicTP;
            Config.ServerName = "localhost";

            VERIFY_QUIC_SUCCESS(
                QuicTlsInitialize(
                    &Config,
                    &Ptr));
        }

        void InitializeClient(
            TlsSession& Session
            )
        {
            QUIC_SEC_CONFIG* ClientConfig;
            QuicTlsClientSecConfigCreate(
                CertValidationIgnoreFlags, &ClientConfig);
            InitializeClient(Session, ClientConfig);
        }

    private:

        static
        uint32_t
        TlsReadUint24(
            _In_reads_(3) const uint8_t* Buffer
            )
        {
            return
                (((uint32_t)Buffer[0] << 16) +
                ((uint32_t)Buffer[1] << 8) +
                (uint32_t)Buffer[2]);
        }

        static
        uint32_t
        GetCompleteTlsMessagesLength(
            _In_reads_(BufferLength)
                const uint8_t* Buffer,
            _In_ uint32_t BufferLength
            )
        {
            uint32_t MessagesLength = 0;
            do {
                if (BufferLength < 4) {
                    break;
                }
                uint32_t MessageLength = 4 + TlsReadUint24(Buffer + 1);
                if (BufferLength < MessageLength) {
                    break;
                }
                MessagesLength += MessageLength;
                Buffer += MessageLength;
                BufferLength -= MessageLength;
            } while (BufferLength > 0);
            return MessagesLength;
        }

        QUIC_TLS_RESULT_FLAGS
        ProcessData(
            _In_ QUIC_PACKET_KEY_TYPE BufferKey,
            _In_reads_bytes_(*BufferLength)
                const UINT8 * Buffer,
            _In_ UINT32 * BufferLength
            )
        {
            ResetEvent(ProcessCompleteEvent);

            VERIFY_IS_TRUE(Buffer != nullptr || *BufferLength == 0);
            if (Buffer != nullptr) {
                VERIFY_ARE_EQUAL(BufferKey, State.ReadKey);
                *BufferLength = GetCompleteTlsMessagesLength(Buffer, *BufferLength);
                if (*BufferLength == 0) return (QUIC_TLS_RESULT_FLAGS)0;
            }

            auto Result =
                QuicTlsProcessData(
                    Ptr,
                    Buffer,
                    BufferLength,
                    &State);
            if (Result & QUIC_TLS_RESULT_PENDING) {
                WaitForSingleObject(ProcessCompleteEvent, INFINITE);
                Result = QuicTlsProcessDataComplete(Ptr, BufferLength);
            }

            VERIFY_IS_TRUE((Result & QUIC_TLS_RESULT_ERROR) == 0);

            return Result;
        }

        QUIC_TLS_RESULT_FLAGS
        ProcessFragmentedData(
            _In_ QUIC_PACKET_KEY_TYPE BufferKey,
            _In_reads_bytes_(BufferLength)
                const UINT8 * Buffer,
            _In_ UINT32 BufferLength,
            _In_ UINT32 FragmentSize
            )
        {
            UINT32 Result = 0;
            UINT32 ConsumedBuffer = FragmentSize;
            UINT32 Count = 1;
            while (BufferLength != 0) {

                if (BufferLength < FragmentSize) {
                    FragmentSize = BufferLength;
                    ConsumedBuffer = FragmentSize;
                }

                Log::Comment(
                    String().Format(
                        L"Processing fragment of %u bytes", FragmentSize));

                Result |= (UINT32)ProcessData(BufferKey, Buffer, &ConsumedBuffer);

                if (ConsumedBuffer > 0) {
                    Buffer += ConsumedBuffer;
                    BufferLength -= ConsumedBuffer;
                } else {
                    ConsumedBuffer = FragmentSize * ++Count;
                    ConsumedBuffer = min(ConsumedBuffer, BufferLength);
                };
            }

            return (QUIC_TLS_RESULT_FLAGS)Result;
        }

    public:

        QUIC_TLS_RESULT_FLAGS
        ProcessData(
            _Inout_ QUIC_TLS_PROCESS_STATE* PeerState,
            _In_ UINT32 FragmentSize = 1200
            )
        {
            if (PeerState == nullptr) {
                //
                // Special case for client hello/initial.
                //
                UINT32 Zero = 0;
                return ProcessData(QUIC_PACKET_KEY_INITIAL, nullptr, &Zero);
            }

            UINT32 Result;

            while (PeerState->BufferLength != 0) {
                UINT16 BufferLength;
                QUIC_PACKET_KEY_TYPE PeerWriteKey;

                UINT32 StartOffset = PeerState->BufferTotalLength - PeerState->BufferLength;
                if (PeerState->BufferOffset1Rtt != 0 && StartOffset >= PeerState->BufferOffset1Rtt) {
                    PeerWriteKey = QUIC_PACKET_KEY_1_RTT;
                    BufferLength = PeerState->BufferLength;

                } else if (PeerState->BufferOffsetHandshake != 0 && StartOffset >= PeerState->BufferOffsetHandshake) {
                    PeerWriteKey = QUIC_PACKET_KEY_HANDSHAKE;
                    if (PeerState->BufferOffset1Rtt != 0) {
                        BufferLength = (UINT16)(PeerState->BufferOffset1Rtt - StartOffset);
                    } else {
                        BufferLength = PeerState->BufferLength;
                    }

                } else {
                    PeerWriteKey = QUIC_PACKET_KEY_INITIAL;
                    if (PeerState->BufferOffsetHandshake != 0) {
                        BufferLength = (UINT16)(PeerState->BufferOffsetHandshake - StartOffset);
                    } else {
                        BufferLength = PeerState->BufferLength;
                    }
                }

                Result |=
                    (UINT32)ProcessFragmentedData(
                        PeerWriteKey,
                        PeerState->Buffer,
                        BufferLength,
                        FragmentSize);

                PeerState->BufferLength -= BufferLength;
                RtlMoveMemory(
                    PeerState->Buffer,
                    PeerState->Buffer + BufferLength,
                    PeerState->BufferLength);
            }

            return (QUIC_TLS_RESULT_FLAGS)Result;
        }

    private:

        static void
        OnProcessComplete(
            _In_ PQUIC_CONNECTION Connection
            )
        {
            SetEvent(((TlsContext*)Connection)->ProcessCompleteEvent);
        }

        static BOOLEAN
        OnRecvQuicTP(
            _In_ PQUIC_CONNECTION Connection,
            _In_ uint16_t TPLength,
            _In_reads_(TPLength) const uint8_t* TPBuffer
            )
        {
            UNREFERENCED_PARAMETER(Connection);
            UNREFERENCED_PARAMETER(TPLength);
            UNREFERENCED_PARAMETER(TPBuffer);
            return TRUE;
        }
    };

    struct PacketKey
    {
        QUIC_PACKET_KEY* Ptr;
        PacketKey(QUIC_PACKET_KEY* Key) : Ptr(Key) {
            VERIFY_IS_NOT_NULL(Key);
        }

        UINT16
        Overhead()
        {
            return QUIC_ENCRYPTION_OVERHEAD;
        }

        bool
        Encrypt(
            _In_ UINT16 HeaderLength,
            _In_reads_bytes_(HeaderLength)
                const UINT8* const Header,
            _In_ UINT64 PacketNumber,
            _In_ UINT16 BufferLength,
            _Inout_updates_bytes_(BufferLength) PUCHAR Buffer
            )
        {
            uint8_t Iv[QUIC_IV_LENGTH];
            QuicCryptoCombineIvAndPacketNumber(Ptr->Iv, (uint8_t*) &PacketNumber, Iv);

            return
                QUIC_STATUS_SUCCESS ==
                QuicEncrypt(
                    Ptr->PacketKey,
                    Iv,
                    HeaderLength,
                    Header,
                    BufferLength,
                    Buffer);
        }

        bool
        Decrypt(
            _In_ UINT16 HeaderLength,
            _In_reads_bytes_(HeaderLength)
                const UINT8* const Header,
            _In_ UINT64 PacketNumber,
            _In_ UINT16 BufferLength,
            _Inout_updates_bytes_(BufferLength) PUCHAR Buffer
            )
        {
            uint8_t Iv[QUIC_IV_LENGTH];
            QuicCryptoCombineIvAndPacketNumber(Ptr->Iv, (uint8_t*) &PacketNumber, Iv);

            return
                QUIC_STATUS_SUCCESS ==
                QuicDecrypt(
                    Ptr->PacketKey,
                    Iv,
                    HeaderLength,
                    Header,
                    BufferLength,
                    Buffer);
        }

        bool
        ComputeHpMask(
            _In_reads_bytes_(16)
                const UINT8* const Cipher,
            _Out_writes_bytes_(16)
                UINT8* Mask
            )
        {
            return
                QUIC_STATUS_SUCCESS ==
                QuicHpComputeMask(
                    Ptr->HeaderKey,
                    1,
                    Cipher,
                    Mask);
        }
    };

    void
    DoHandshake(
        TlsContext& ServerContext,
        TlsContext& ClientContext,
        UINT32 FragmentSize = 1200
        )
    {
        auto Result = ClientContext.ProcessData(nullptr);
        VERIFY_IS_TRUE(Result & QUIC_TLS_RESULT_DATA);

        Result = ServerContext.ProcessData(&ClientContext.State, FragmentSize);
        VERIFY_IS_TRUE(Result & QUIC_TLS_RESULT_DATA);
        VERIFY_IS_NOT_NULL(ServerContext.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);

        Result = ClientContext.ProcessData(&ServerContext.State, FragmentSize);
        VERIFY_IS_TRUE(Result & QUIC_TLS_RESULT_DATA);
        VERIFY_IS_TRUE(Result & QUIC_TLS_RESULT_COMPLETE);
        VERIFY_IS_NOT_NULL(ClientContext.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);

        Result = ServerContext.ProcessData(&ClientContext.State, FragmentSize);
        VERIFY_IS_TRUE(Result & QUIC_TLS_RESULT_COMPLETE);
    }

    TEST_METHOD(Initialize)
    {
        TlsSession ServerSession, ClientSession;
        {
            TlsContext ServerContext, ClientContext;
            ServerContext.InitializeServer(ServerSession, SecConfig);
            ClientContext.InitializeClient(ClientSession);
        }
    }

    TEST_METHOD(Handshake)
    {
        TlsSession ServerSession, ClientSession;
        {
            TlsContext ServerContext, ClientContext;
            ServerContext.InitializeServer(ServerSession, SecConfig);
            ClientContext.InitializeClient(ClientSession);
            DoHandshake(ServerContext, ClientContext);
        }
    }

    TEST_METHOD(HandshakeFragmented)
    {
        TlsSession ServerSession, ClientSession;
        {
            TlsContext ServerContext, ClientContext;
            ServerContext.InitializeServer(ServerSession, SecConfig);
            ClientContext.InitializeClient(ClientSession);
            DoHandshake(ServerContext, ClientContext, 200);
        }
    }

    TEST_METHOD(HandshakesSerial)
    {
        // Server fails to decrypt message during second handshake with shared ClientSession.
        // Server still fail to decrypt second handshake with separate ClientSessions.
        // Server still fails to decrypt when using the same ServerContext again.
        // passes with different ServerContexts.
        TlsSession ServerSession, ClientSession/*, ClientSession2*/;
        QUIC_SEC_CONFIG* ClientSecConfig = nullptr;
        VERIFY_QUIC_SUCCESS(
            QuicTlsClientSecConfigCreate(
                CertValidationIgnoreFlags,
                &ClientSecConfig));
        {
            TlsContext ServerContext, ClientContext1;
            ServerContext.InitializeServer(ServerSession, SecConfig);
            ClientContext1.InitializeClient(ClientSession, ClientSecConfig);
            DoHandshake(ServerContext, ClientContext1);
        }
        {
            TlsContext ServerContext, ClientContext2;
            ServerContext.InitializeServer(ServerSession, SecConfig);
            ClientContext2.InitializeClient(ClientSession, ClientSecConfig);
            DoHandshake(ServerContext, ClientContext2);
        }
        QuicTlsSecConfigRelease(ClientSecConfig);
    }

    TEST_METHOD(HandshakesInterleaved)
    {
        TlsSession ServerSession, ClientSession;
        QUIC_SEC_CONFIG* ClientSecConfig = nullptr;
        VERIFY_QUIC_SUCCESS(
            QuicTlsClientSecConfigCreate(
                CertValidationIgnoreFlags,
                &ClientSecConfig));
        {
            TlsContext ServerContext1, ServerContext2, ClientContext1, ClientContext2;
            ServerContext1.InitializeServer(ServerSession, SecConfig);
            ClientContext1.InitializeClient(ClientSession, ClientSecConfig);
            ServerContext2.InitializeServer(ServerSession, SecConfig);
            ClientContext2.InitializeClient(ClientSession, ClientSecConfig);

            auto Result = ClientContext1.ProcessData(nullptr);
            VERIFY_IS_TRUE(Result & QUIC_TLS_RESULT_DATA);

            Result = ClientContext2.ProcessData(nullptr);
            VERIFY_IS_TRUE(Result & QUIC_TLS_RESULT_DATA);

            Result = ServerContext1.ProcessData(&ClientContext1.State);
            VERIFY_IS_TRUE(Result & QUIC_TLS_RESULT_DATA);
            VERIFY_IS_NOT_NULL(ServerContext1.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);

            Result = ServerContext2.ProcessData(&ClientContext2.State);
            VERIFY_IS_TRUE(Result & QUIC_TLS_RESULT_DATA);
            VERIFY_IS_NOT_NULL(ServerContext2.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);

            Result = ClientContext1.ProcessData(&ServerContext1.State);
            VERIFY_IS_TRUE(Result & QUIC_TLS_RESULT_DATA);
            VERIFY_IS_TRUE(Result & QUIC_TLS_RESULT_COMPLETE);
            VERIFY_IS_NOT_NULL(ClientContext1.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);

            Result = ClientContext2.ProcessData(&ServerContext2.State);
            VERIFY_IS_TRUE(Result & QUIC_TLS_RESULT_DATA);
            VERIFY_IS_TRUE(Result & QUIC_TLS_RESULT_COMPLETE);
            VERIFY_IS_NOT_NULL(ClientContext2.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);

            Result = ServerContext1.ProcessData(&ClientContext1.State);
            VERIFY_IS_TRUE(Result & QUIC_TLS_RESULT_COMPLETE);

            Result = ServerContext2.ProcessData(&ClientContext2.State);
            VERIFY_IS_TRUE(Result & QUIC_TLS_RESULT_COMPLETE);
        }
        QuicTlsSecConfigRelease(ClientSecConfig);
    }

    TEST_METHOD(One1RttKey)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Data:PNE", L"{0,1}")
        END_TEST_METHOD_PROPERTIES()

        int PNE;
        TestData::TryGetValue(L"PNE", PNE);

        TlsSession ServerSession, ClientSession;
        {
            TlsContext ServerContext, ClientContext;
            ServerContext.InitializeServer(ServerSession, SecConfig);
            ClientContext.InitializeClient(ClientSession);
            DoHandshake(ServerContext, ClientContext);

            PacketKey ServerKey(ServerContext.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);
            PacketKey ClientKey(ClientContext.State.ReadKeys[QUIC_PACKET_KEY_1_RTT]);

            UINT8 Header[32] = { 1, 2, 3, 4 };
            UINT64 PacketNumber = 0;
            UINT8 Buffer[1000] = { 0 };

            VERIFY_IS_TRUE(
                ServerKey.Encrypt(
                    sizeof(Header),
                    Header,
                    PacketNumber,
                    sizeof(Buffer),
                    Buffer));

            if (PNE != 0) {
                UINT8 Mask[16];

                VERIFY_IS_TRUE(
                    ServerKey.ComputeHpMask(
                        Buffer,
                        Mask));

                for (UINT32 i = 0; i < sizeof(Mask); i++) {
                    Header[i] ^= Mask[i];
                }

                VERIFY_IS_TRUE(
                    ClientKey.ComputeHpMask(
                        Buffer,
                        Mask));

                for (UINT32 i = 0; i < sizeof(Mask); i++) {
                    Header[i] ^= Mask[i];
                }
            }

            VERIFY_IS_TRUE(
                ClientKey.Decrypt(
                    sizeof(Header),
                    Header,
                    PacketNumber,
                    sizeof(Buffer),
                    Buffer));
        }
    }

    TEST_METHOD(KeyUpdate)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Data:PNE", L"{0,1}")
        END_TEST_METHOD_PROPERTIES()

        int PNE;
        TestData::TryGetValue(L"PNE", PNE);

        TlsSession ServerSession, ClientSession;
        {
            TlsContext ServerContext, ClientContext;
            ServerContext.InitializeServer(ServerSession, SecConfig);
            ClientContext.InitializeClient(ClientSession);
            DoHandshake(ServerContext, ClientContext);

            QUIC_PACKET_KEY* UpdateWriteKey, *UpdateReadKey = nullptr;

            VERIFY_QUIC_SUCCESS(
                QuicPacketKeyUpdate(
                    ServerContext.State.WriteKeys[QUIC_PACKET_KEY_1_RTT],
                    &UpdateWriteKey));
            VERIFY_QUIC_SUCCESS(
                QuicPacketKeyUpdate(
                    ClientContext.State.ReadKeys[QUIC_PACKET_KEY_1_RTT],
                    &UpdateReadKey));

            if (PNE != 0) {
                //
                // If PNE is enabled, copy the header keys to the new packet
                // key structs.
                //
                UpdateWriteKey->HeaderKey = ServerContext.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]->HeaderKey;
                ServerContext.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]->HeaderKey = NULL;

                UpdateReadKey->HeaderKey = ClientContext.State.ReadKeys[QUIC_PACKET_KEY_1_RTT]->HeaderKey;
                ClientContext.State.ReadKeys[QUIC_PACKET_KEY_1_RTT]->HeaderKey = NULL;
            }

            PacketKey ServerKey(UpdateWriteKey);
            PacketKey ClientKey(UpdateReadKey);

            UINT8 Header[32] = { 1, 2, 3, 4 };
            UINT64 PacketNumber = 0;
            UINT8 Buffer[1000] = { 0 };

            VERIFY_IS_TRUE(
                ServerKey.Encrypt(
                    sizeof(Header),
                    Header,
                    PacketNumber,
                    sizeof(Buffer),
                    Buffer));

            if (PNE != 0) {
                UINT8 Mask[16];

                VERIFY_IS_TRUE(
                    ServerKey.ComputeHpMask(
                        Buffer,
                        Mask));

                for (UINT32 i = 0; i < sizeof(Mask); i++) {
                    Header[i] ^= Mask[i];
                }

                VERIFY_IS_TRUE(
                    ClientKey.ComputeHpMask(
                        Buffer,
                        Mask));

                for (UINT32 i = 0; i < sizeof(Mask); i++) {
                    Header[i] ^= Mask[i];
                }
            }

            VERIFY_IS_TRUE(
                ClientKey.Decrypt(
                    sizeof(Header),
                    Header,
                    PacketNumber,
                    sizeof(Buffer),
                    Buffer));

            QuicPacketKeyFree(UpdateWriteKey);
            QuicPacketKeyFree(UpdateReadKey);
        }
    }

    LONGLONG
    DoEncryption(
        PacketKey& Key,
        UINT16 BufferSize,
        UINT64 LoopCount
        )
    {
        UINT8 Header[32] = { 0 };
        UINT8 Buffer[MAXUINT16] = { 0 };
        UINT16 OverHead = Key.Overhead();

        LARGE_INTEGER Start, End;
        QueryPerformanceCounter(&Start);

        for (UINT64 j = 0; j < LoopCount; ++j) {
            Key.Encrypt(
                sizeof(Header),
                Header,
                j,
                BufferSize + OverHead,
                Buffer);
        }

        QueryPerformanceCounter(&End);

        return End.QuadPart - Start.QuadPart;
    }

    LONGLONG
    DoEncryptionWithPNE(
        PacketKey& Key,
        UINT16 BufferSize,
        UINT64 LoopCount
        )
    {
        UINT8 Header[32] = { 0 };
        UINT8 Buffer[MAXUINT16] = { 0 };
        UINT16 OverHead = Key.Overhead();
        UINT8 Mask[16];

        LARGE_INTEGER Start, End;
        QueryPerformanceCounter(&Start);

        for (UINT64 j = 0; j < LoopCount; ++j) {
            Key.Encrypt(
                sizeof(Header),
                Header,
                j,
                BufferSize + OverHead,
                Buffer);
            Key.ComputeHpMask(Buffer, Mask);
            for (UINT32 i = 0; i < sizeof(Mask); i++) {
                Header[i] ^= Mask[i];
            }
        }

        QueryPerformanceCounter(&End);

        return End.QuadPart - Start.QuadPart;
    }

    TEST_METHOD(PacketEncryptionPerf)
    {
        BEGIN_TEST_METHOD_PROPERTIES()
            TEST_METHOD_PROPERTY(L"Data:PNE", L"{0,1}")
        END_TEST_METHOD_PROPERTIES()

        int PNE;
        TestData::TryGetValue(L"PNE", PNE);

        TlsSession ServerSession, ClientSession;
        {
            TlsContext ServerContext, ClientContext;
            ServerContext.InitializeServer(ServerSession, SecConfig);
            ClientContext.InitializeClient(ClientSession);
            DoHandshake(ServerContext, ClientContext);

            PacketKey ServerKey(ServerContext.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);

            const UINT64 LoopCount = 10000;
            UINT16 BufferSizes[] =
            {
                4,
                16,
                64,
                256,
                600,
                1000,
                1200,
                1450,
                //8000,
                //65000
            };

            LARGE_INTEGER PerfFreq;
            QueryPerformanceFrequency(&PerfFreq);

            HANDLE CurrentThread = GetCurrentThread();
            DWORD ProcNumber = GetCurrentProcessorNumber();
            DWORD_PTR OldAffinityMask =
                SetThreadAffinityMask(CurrentThread, (DWORD_PTR)1 << (DWORD_PTR)ProcNumber);
            SetThreadPriority(CurrentThread, THREAD_PRIORITY_HIGHEST);

            for (UINT8 i = 0; i < ARRAYSIZE(BufferSizes); ++i) {
                LONGLONG elapsedMicroseconds =
                    PNE == 0 ?
                    DoEncryption(ServerKey, BufferSizes[i], LoopCount) :
                    DoEncryptionWithPNE(ServerKey, BufferSizes[i], LoopCount);
                elapsedMicroseconds *= 1000000;
                elapsedMicroseconds /= PerfFreq.QuadPart;

                Log::Comment(
                    String().Format(
                        L"%lld.%d milliseconds elapsed encrypting %u bytes %u times",
                        elapsedMicroseconds / 1000, (int)(elapsedMicroseconds % 1000),
                        BufferSizes[i], LoopCount));
            }

            SetThreadPriority(CurrentThread, THREAD_PRIORITY_NORMAL);
            SetThreadAffinityMask(CurrentThread, OldAffinityMask);
        }
    }
};
