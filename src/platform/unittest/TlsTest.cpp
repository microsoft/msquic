/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "main.h"
#include "msquic.h"
#include "quic_tls.h"
#ifdef QUIC_CLOG
#include "TlsTest.cpp.clog.h"
#endif

const uint32_t CertValidationIgnoreFlags =
    QUIC_CERTIFICATE_FLAG_IGNORE_UNKNOWN_CA |
    QUIC_CERTIFICATE_FLAG_IGNORE_CERTIFICATE_CN_INVALID;

const uint8_t Alpn[] = { 1, 'A' };
const uint8_t MultiAlpn[] = { 1, 'C', 1, 'A', 1, 'B' };

struct TlsTest : public ::testing::TestWithParam<bool>
{
protected:
    QUIC_RUNDOWN_REF SecConfigRundown;
    QUIC_EVENT SecConfigDoneEvent;
    QUIC_SEC_CONFIG* SecConfig;
    static QUIC_SEC_CONFIG_PARAMS* SelfSignedCertParams;

    TlsTest() :
        SecConfig(nullptr)
    {
        QuicRundownInitialize(&SecConfigRundown);
        QuicEventInitialize(&SecConfigDoneEvent, FALSE, FALSE);
    }

    ~TlsTest()
    {
        QuicEventUninitialize(SecConfigDoneEvent);
        if (SecConfig != nullptr) {
            QuicTlsSecConfigRelease(SecConfig);
        }
        QuicRundownReleaseAndWait(&SecConfigRundown);
        QuicRundownUninitialize(&SecConfigRundown);
    }

    _Function_class_(QUIC_SEC_CONFIG_CREATE_COMPLETE)
    static void
    QUIC_API
    OnSecConfigCreateComplete(
        _In_opt_ void* Context,
        _In_ QUIC_STATUS Status,
        _In_opt_ QUIC_SEC_CONFIG* SecConfig
        )
    {
        TlsTest* pThis = (TlsTest*)Context;
        VERIFY_QUIC_SUCCESS(Status);
        pThis->SecConfig = SecConfig;
        QuicEventSet(pThis->SecConfigDoneEvent);
    }

    static void SetUpTestSuite()
    {
        SelfSignedCertParams = QuicPlatGetSelfSignedCert(QUIC_SELF_SIGN_CERT_USER);
        ASSERT_NE(nullptr, SelfSignedCertParams);
    }

    static void TearDownTestSuite()
    {
        QuicPlatFreeSelfSignedCert(SelfSignedCertParams);
        SelfSignedCertParams = nullptr;
    }

    void SetUp() override
    {
        VERIFY_QUIC_SUCCESS(
            QuicTlsServerSecConfigCreate(
                &SecConfigRundown,
                (QUIC_SEC_CONFIG_FLAGS)SelfSignedCertParams->Flags,
                SelfSignedCertParams->Certificate,
                SelfSignedCertParams->Principal,
                this,
                OnSecConfigCreateComplete));
        ASSERT_TRUE(QuicEventWaitWithTimeout(SecConfigDoneEvent, 5000));
    }

    void TearDown() override
    {
        QuicTlsSecConfigRelease(SecConfig);
        SecConfig = nullptr;
    }

    struct TlsSession
    {
        QUIC_TLS_SESSION* Ptr;
        TlsSession() : Ptr(nullptr) {
            EXPECT_EQ(QUIC_STATUS_SUCCESS, QuicTlsSessionInitialize(&Ptr));
        }
        ~TlsSession() {
            QuicTlsSessionUninitialize(Ptr);
        }
    };

    struct TlsContext
    {
        QUIC_TLS* Ptr;
        QUIC_SEC_CONFIG* ClientConfig;
        QUIC_EVENT ProcessCompleteEvent;

        QUIC_TLS_PROCESS_STATE State;

        bool Connected;
        bool Key0RttReady;
        bool Key1RttReady;

        TlsContext() :
            Ptr(nullptr),
            ClientConfig(nullptr),
            Connected(false) {
            QuicEventInitialize(&ProcessCompleteEvent, FALSE, FALSE);
            QuicZeroMemory(&State, sizeof(State));
            State.Buffer = (uint8_t*)QUIC_ALLOC_NONPAGED(8000);
            State.BufferAllocLength = 8000;
        }

        ~TlsContext() {
            QuicTlsUninitialize(Ptr);
            if (ClientConfig != nullptr) {
                QuicTlsSecConfigRelease(ClientConfig);
            }
            QuicEventUninitialize(ProcessCompleteEvent);
            QUIC_FREE(State.Buffer);
            for (uint8_t i = 0; i < QUIC_PACKET_KEY_COUNT; ++i) {
                QuicPacketKeyFree(State.ReadKeys[i]);
                QuicPacketKeyFree(State.WriteKeys[i]);
            }
        }

        void InitializeServer(
            TlsSession& Session,
            const QUIC_SEC_CONFIG* SecConfig,
            bool MultipleAlpns = false,
            uint16_t TPLen = 64
            )
        {
            QUIC_TLS_CONFIG Config = {0};
            Config.IsServer = TRUE;
            Config.TlsSession = Session.Ptr;
            Config.SecConfig = (QUIC_SEC_CONFIG*)SecConfig;
            UNREFERENCED_PARAMETER(MultipleAlpns); // The server must always send back the negotiated ALPN.
            Config.AlpnBuffer = Alpn;
            Config.AlpnBufferLength = sizeof(Alpn);
            Config.LocalTPBuffer =
                (uint8_t*)QUIC_ALLOC_NONPAGED(QuicTlsTPHeaderSize + TPLen);
            Config.LocalTPLength = QuicTlsTPHeaderSize + TPLen;
            Config.Connection = (QUIC_CONNECTION*)this;
            Config.ProcessCompleteCallback = OnProcessComplete;
            Config.ReceiveTPCallback = OnRecvQuicTP;
            State.NegotiatedAlpn = Alpn;

            VERIFY_QUIC_SUCCESS(
                QuicTlsInitialize(
                    &Config,
                    &State,
                    &Ptr));
        }

        void InitializeClient(
            TlsSession& Session,
            QUIC_SEC_CONFIG* SecConfig,
            bool MultipleAlpns = false,
            uint16_t TPLen = 64
            )
        {
            QUIC_TLS_CONFIG Config = {0};
            Config.IsServer = FALSE;
            Config.TlsSession = Session.Ptr;
            Config.SecConfig = SecConfig;
            Config.AlpnBuffer = MultipleAlpns ? MultiAlpn : Alpn;
            Config.AlpnBufferLength = MultipleAlpns ? sizeof(MultiAlpn) : sizeof(Alpn);
            Config.LocalTPBuffer =
                (uint8_t*)QUIC_ALLOC_NONPAGED(QuicTlsTPHeaderSize + TPLen);
            Config.LocalTPLength = QuicTlsTPHeaderSize + TPLen;
            Config.Connection = (QUIC_CONNECTION*)this;
            Config.ProcessCompleteCallback = OnProcessComplete;
            Config.ReceiveTPCallback = OnRecvQuicTP;
            Config.ServerName = "localhost";

            VERIFY_QUIC_SUCCESS(
                QuicTlsInitialize(
                    &Config,
                    &State,
                    &Ptr));
        }

        void InitializeClient(
            TlsSession& Session,
            bool MultipleAlpns = false
            )
        {
            QuicTlsClientSecConfigCreate(
                CertValidationIgnoreFlags, &ClientConfig);
            InitializeClient(Session, ClientConfig, MultipleAlpns);
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
                const uint8_t * Buffer,
            _In_ uint32_t * BufferLength
            )
        {
            QuicEventReset(ProcessCompleteEvent);

            EXPECT_TRUE(Buffer != nullptr || *BufferLength == 0);
            if (Buffer != nullptr) {
                EXPECT_EQ(BufferKey, State.ReadKey);
                *BufferLength = GetCompleteTlsMessagesLength(Buffer, *BufferLength);
                if (*BufferLength == 0) return (QUIC_TLS_RESULT_FLAGS)0;
            }

            auto Result =
                QuicTlsProcessData(
                    Ptr,
                    QUIC_TLS_CRYPTO_DATA,
                    Buffer,
                    BufferLength,
                    &State);
            if (Result & QUIC_TLS_RESULT_PENDING) {
                QuicEventWaitForever(ProcessCompleteEvent);
                Result = QuicTlsProcessDataComplete(Ptr, BufferLength);
            }

            EXPECT_TRUE((Result & QUIC_TLS_RESULT_ERROR) == 0);

            return Result;
        }

        QUIC_TLS_RESULT_FLAGS
        ProcessFragmentedData(
            _In_ QUIC_PACKET_KEY_TYPE BufferKey,
            _In_reads_bytes_(BufferLength)
                const uint8_t * Buffer,
            _In_ uint32_t BufferLength,
            _In_ uint32_t FragmentSize
            )
        {
            uint32_t Result = 0;
            uint32_t ConsumedBuffer = FragmentSize;
            uint32_t Count = 1;
            while (BufferLength != 0 && !(Result & QUIC_TLS_RESULT_ERROR)) {

                if (BufferLength < FragmentSize) {
                    FragmentSize = BufferLength;
                    ConsumedBuffer = FragmentSize;
                }

                //std::cout << "Processing fragment of " << FragmentSize << " bytes" << std::endl;

                Result |= (uint32_t)ProcessData(BufferKey, Buffer, &ConsumedBuffer);

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
            _In_ uint32_t FragmentSize = 1200
            )
        {
            if (PeerState == nullptr) {
                //
                // Special case for client hello/initial.
                //
                uint32_t Zero = 0;
                return ProcessData(QUIC_PACKET_KEY_INITIAL, nullptr, &Zero);
            }

            uint32_t Result = 0;

            while (PeerState->BufferLength != 0 && !(Result & QUIC_TLS_RESULT_ERROR)) {
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
                    (uint32_t)ProcessFragmentedData(
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

    private:

        static void
        OnProcessComplete(
            _In_ QUIC_CONNECTION* Connection
            )
        {
            QuicEventSet(((TlsContext*)Connection)->ProcessCompleteEvent);
        }

        static BOOLEAN
        OnRecvQuicTP(
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
    };

    struct PacketKey
    {
        QUIC_PACKET_KEY* Ptr;
        PacketKey(QUIC_PACKET_KEY* Key) : Ptr(Key) {
            EXPECT_NE(nullptr, Key);
        }

        uint16_t
        Overhead()
        {
            return QUIC_ENCRYPTION_OVERHEAD;
        }

        bool
        Encrypt(
            _In_ uint16_t HeaderLength,
            _In_reads_bytes_(HeaderLength)
                const uint8_t* const Header,
            _In_ uint64_t PacketNumber,
            _In_ uint16_t BufferLength,
            _Inout_updates_bytes_(BufferLength) uint8_t* Buffer
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
            _In_ uint16_t HeaderLength,
            _In_reads_bytes_(HeaderLength)
                const uint8_t* const Header,
            _In_ uint64_t PacketNumber,
            _In_ uint16_t BufferLength,
            _Inout_updates_bytes_(BufferLength) uint8_t* Buffer
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
                const uint8_t* const Cipher,
            _Out_writes_bytes_(16)
                uint8_t* Mask
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
        uint32_t FragmentSize = 1200
        )
    {
        auto Result = ClientContext.ProcessData(nullptr);
        ASSERT_TRUE(Result & QUIC_TLS_RESULT_DATA);

        Result = ServerContext.ProcessData(&ClientContext.State, FragmentSize);
        ASSERT_TRUE(Result & QUIC_TLS_RESULT_DATA);
        ASSERT_NE(nullptr, ServerContext.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);

        Result = ClientContext.ProcessData(&ServerContext.State, FragmentSize);
        ASSERT_TRUE(Result & QUIC_TLS_RESULT_DATA);
        ASSERT_TRUE(Result & QUIC_TLS_RESULT_COMPLETE);
        ASSERT_NE(nullptr, ClientContext.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);

        Result = ServerContext.ProcessData(&ClientContext.State, FragmentSize);
        ASSERT_TRUE(Result & QUIC_TLS_RESULT_COMPLETE);
    }

    int64_t
    DoEncryption(
        PacketKey& Key,
        uint16_t BufferSize,
        uint64_t LoopCount
        )
    {
        uint8_t Header[32] = { 0 };
        uint8_t Buffer[(uint16_t)~0] = { 0 };
        uint16_t OverHead = Key.Overhead();

        uint64_t Start, End;
        Start = QuicTimeUs64();

        for (uint64_t j = 0; j < LoopCount; ++j) {
            Key.Encrypt(
                sizeof(Header),
                Header,
                j,
                BufferSize + OverHead,
                Buffer);
        }

        End = QuicTimeUs64();

        return End - Start;
    }

    int64_t
    DoEncryptionWithPNE(
        PacketKey& Key,
        uint16_t BufferSize,
        uint64_t LoopCount
        )
    {
        uint8_t Header[32] = { 0 };
        uint8_t Buffer[(uint16_t)~0] = { 0 };
        uint16_t OverHead = Key.Overhead();
        uint8_t Mask[16];

        uint64_t Start, End;
        Start = QuicTimeUs64();

        for (uint64_t j = 0; j < LoopCount; ++j) {
            Key.Encrypt(
                sizeof(Header),
                Header,
                j,
                BufferSize + OverHead,
                Buffer);
            Key.ComputeHpMask(Buffer, Mask);
            for (uint32_t i = 0; i < sizeof(Mask); i++) {
                Header[i] ^= Mask[i];
            }
        }

        End = QuicTimeUs64();

        return End - Start;
    }
};

QUIC_SEC_CONFIG_PARAMS* TlsTest::SelfSignedCertParams = nullptr;

TEST_F(TlsTest, Initialize)
{
    TlsSession ServerSession, ClientSession;
    {
        TlsContext ServerContext, ClientContext;
        ServerContext.InitializeServer(ServerSession, SecConfig);
        ClientContext.InitializeClient(ClientSession);
    }
}

TEST_F(TlsTest, Handshake)
{
    TlsSession ServerSession, ClientSession;
    {
        TlsContext ServerContext, ClientContext;
        ServerContext.InitializeServer(ServerSession, SecConfig);
        ClientContext.InitializeClient(ClientSession);
        DoHandshake(ServerContext, ClientContext);
    }
}

TEST_F(TlsTest, HandshakeMultiAlpnServer)
{
    TlsSession ServerSession, ClientSession;
    {
        TlsContext ServerContext, ClientContext;
        ServerContext.InitializeServer(ServerSession, SecConfig, true);
        ClientContext.InitializeClient(ClientSession);
        DoHandshake(ServerContext, ClientContext);
    }
}

TEST_F(TlsTest, HandshakeMultiAlpnClient)
{
    TlsSession ServerSession, ClientSession;
    {
        TlsContext ServerContext, ClientContext;
        ServerContext.InitializeServer(ServerSession, SecConfig);
        ClientContext.InitializeClient(ClientSession, true);
        DoHandshake(ServerContext, ClientContext);
    }
}

TEST_F(TlsTest, HandshakeMultiAlpnBoth)
{
    TlsSession ServerSession, ClientSession;
    {
        TlsContext ServerContext, ClientContext;
        ServerContext.InitializeServer(ServerSession, SecConfig, true);
        ClientContext.InitializeClient(ClientSession, true);
        DoHandshake(ServerContext, ClientContext);
    }
}

TEST_F(TlsTest, HandshakeFragmented)
{
    TlsSession ServerSession, ClientSession;
    {
        TlsContext ServerContext, ClientContext;
        ServerContext.InitializeServer(ServerSession, SecConfig);
        ClientContext.InitializeClient(ClientSession);
        DoHandshake(ServerContext, ClientContext, 200);
    }
}

TEST_F(TlsTest, HandshakesSerial)
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

TEST_F(TlsTest, HandshakesInterleaved)
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
        ASSERT_TRUE(Result & QUIC_TLS_RESULT_DATA);

        Result = ClientContext2.ProcessData(nullptr);
        ASSERT_TRUE(Result & QUIC_TLS_RESULT_DATA);

        Result = ServerContext1.ProcessData(&ClientContext1.State);
        ASSERT_TRUE(Result & QUIC_TLS_RESULT_DATA);
        ASSERT_NE(nullptr, ServerContext1.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);

        Result = ServerContext2.ProcessData(&ClientContext2.State);
        ASSERT_TRUE(Result & QUIC_TLS_RESULT_DATA);
        ASSERT_NE(nullptr, ServerContext2.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);

        Result = ClientContext1.ProcessData(&ServerContext1.State);
        ASSERT_TRUE(Result & QUIC_TLS_RESULT_DATA);
        ASSERT_TRUE(Result & QUIC_TLS_RESULT_COMPLETE);
        ASSERT_NE(nullptr, ClientContext1.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);

        Result = ClientContext2.ProcessData(&ServerContext2.State);
        ASSERT_TRUE(Result & QUIC_TLS_RESULT_DATA);
        ASSERT_TRUE(Result & QUIC_TLS_RESULT_COMPLETE);
        ASSERT_NE(nullptr, ClientContext2.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);

        Result = ServerContext1.ProcessData(&ClientContext1.State);
        ASSERT_TRUE(Result & QUIC_TLS_RESULT_COMPLETE);

        Result = ServerContext2.ProcessData(&ClientContext2.State);
        ASSERT_TRUE(Result & QUIC_TLS_RESULT_COMPLETE);
    }
    QuicTlsSecConfigRelease(ClientSecConfig);
}

TEST_P(TlsTest, One1RttKey)
{
    bool PNE = GetParam();

    TlsSession ServerSession, ClientSession;
    {
        TlsContext ServerContext, ClientContext;
        ServerContext.InitializeServer(ServerSession, SecConfig);
        ClientContext.InitializeClient(ClientSession);
        DoHandshake(ServerContext, ClientContext);

        PacketKey ServerKey(ServerContext.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);
        PacketKey ClientKey(ClientContext.State.ReadKeys[QUIC_PACKET_KEY_1_RTT]);

        uint8_t Header[32] = { 1, 2, 3, 4 };
        uint64_t PacketNumber = 0;
        uint8_t Buffer[1000] = { 0 };

        ASSERT_TRUE(
            ServerKey.Encrypt(
                sizeof(Header),
                Header,
                PacketNumber,
                sizeof(Buffer),
                Buffer));

        if (PNE) {
            uint8_t Mask[16];

            ASSERT_TRUE(
                ServerKey.ComputeHpMask(
                    Buffer,
                    Mask));

            for (uint32_t i = 0; i < sizeof(Mask); i++) {
                Header[i] ^= Mask[i];
            }

            ASSERT_TRUE(
                ClientKey.ComputeHpMask(
                    Buffer,
                    Mask));

            for (uint32_t i = 0; i < sizeof(Mask); i++) {
                Header[i] ^= Mask[i];
            }
        }

        ASSERT_TRUE(
            ClientKey.Decrypt(
                sizeof(Header),
                Header,
                PacketNumber,
                sizeof(Buffer),
                Buffer));
    }
}

TEST_P(TlsTest, KeyUpdate)
{

    bool PNE = GetParam();

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

        if (PNE) {
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

        uint8_t Header[32] = { 1, 2, 3, 4 };
        uint64_t PacketNumber = 0;
        uint8_t Buffer[1000] = { 0 };

        ASSERT_TRUE(
            ServerKey.Encrypt(
                sizeof(Header),
                Header,
                PacketNumber,
                sizeof(Buffer),
                Buffer));

        if (PNE) {
            uint8_t Mask[16];

            ASSERT_TRUE(
                ServerKey.ComputeHpMask(
                    Buffer,
                    Mask));

            for (uint32_t i = 0; i < sizeof(Mask); i++) {
                Header[i] ^= Mask[i];
            }

            ASSERT_TRUE(
                ClientKey.ComputeHpMask(
                    Buffer,
                    Mask));

            for (uint32_t i = 0; i < sizeof(Mask); i++) {
                Header[i] ^= Mask[i];
            }
        }

        ASSERT_TRUE(
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


TEST_P(TlsTest, PacketEncryptionPerf)
{

    bool PNE = GetParam();

    TlsSession ServerSession, ClientSession;
    {
        TlsContext ServerContext, ClientContext;
        ServerContext.InitializeServer(ServerSession, SecConfig);
        ClientContext.InitializeClient(ClientSession);
        DoHandshake(ServerContext, ClientContext);

        PacketKey ServerKey(ServerContext.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);

        const uint64_t LoopCount = 10000;
        uint16_t BufferSizes[] =
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

#ifdef _WIN32
        HANDLE CurrentThread = GetCurrentThread();
        DWORD ProcNumber = GetCurrentProcessorNumber();
        DWORD_PTR OldAffinityMask =
            SetThreadAffinityMask(CurrentThread, (DWORD_PTR)1 << (DWORD_PTR)ProcNumber);
        SetThreadPriority(CurrentThread, THREAD_PRIORITY_HIGHEST);
#endif

        for (uint8_t i = 0; i < ARRAYSIZE(BufferSizes); ++i) {
            int64_t elapsedMicroseconds =
                PNE == 0 ?
                DoEncryption(ServerKey, BufferSizes[i], LoopCount) :
                DoEncryptionWithPNE(ServerKey, BufferSizes[i], LoopCount);

            std::cout << elapsedMicroseconds / 1000 << "." << (int)(elapsedMicroseconds % 1000) <<
                " milliseconds elapsed encrypting "
                << BufferSizes[i] << " bytes " << LoopCount << " times" << std::endl;
        }

#ifdef _WIN32
        SetThreadPriority(CurrentThread, THREAD_PRIORITY_NORMAL);
        SetThreadAffinityMask(CurrentThread, OldAffinityMask);
#endif
    }
}

INSTANTIATE_TEST_SUITE_P(TlsTest, TlsTest, ::testing::Bool());
