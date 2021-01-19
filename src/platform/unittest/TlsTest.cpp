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

const uint16_t UnknownCaError = 48;

const uint32_t DefaultFragmentSize = 1200;

const uint8_t Alpn[] = { 1, 'A' };
const uint8_t MultiAlpn[] = { 1, 'C', 1, 'A', 1, 'B' };

struct TlsTest : public ::testing::TestWithParam<bool>
{
protected:
    CXPLAT_SEC_CONFIG* ServerSecConfig {nullptr};
    CXPLAT_SEC_CONFIG* ClientSecConfig {nullptr};
    CXPLAT_SEC_CONFIG* ClientSecConfigNoCertValidation {nullptr};
    static const QUIC_CREDENTIAL_CONFIG* SelfSignedCertParams;

    TlsTest() { }

    ~TlsTest()
    {
        if (ClientSecConfigNoCertValidation) {
            CxPlatTlsSecConfigDelete(ClientSecConfigNoCertValidation);
            ClientSecConfigNoCertValidation = nullptr;
        }
        if (ClientSecConfig) {
            CxPlatTlsSecConfigDelete(ClientSecConfig);
            ClientSecConfig = nullptr;
        }
        if (ServerSecConfig) {
            CxPlatTlsSecConfigDelete(ServerSecConfig);
            ServerSecConfig = nullptr;
        }
    }

    _Function_class_(CXPLAT_SEC_CONFIG_CREATE_COMPLETE)
    static void
    QUIC_API
    OnSecConfigCreateComplete(
        _In_ const QUIC_CREDENTIAL_CONFIG* /* CredConfig */,
        _In_opt_ void* Context,
        _In_ QUIC_STATUS Status,
        _In_opt_ CXPLAT_SEC_CONFIG* SecConfig
        )
    {
        VERIFY_QUIC_SUCCESS(Status);
        ASSERT_NE(nullptr, SecConfig);
        *(CXPLAT_SEC_CONFIG**)Context = SecConfig;
    }

    static void SetUpTestSuite()
    {
        SelfSignedCertParams = CxPlatPlatGetSelfSignedCert(CXPLAT_SELF_SIGN_CERT_USER);
        ASSERT_NE(nullptr, SelfSignedCertParams);
    }

    static void TearDownTestSuite()
    {
        CxPlatPlatFreeSelfSignedCert(SelfSignedCertParams);
        SelfSignedCertParams = nullptr;
    }

    void SetUp() override
    {
        VERIFY_QUIC_SUCCESS(
            CxPlatTlsSecConfigCreate(
                SelfSignedCertParams,
                &TlsContext::TlsServerCallbacks,
                &ServerSecConfig,
                OnSecConfigCreateComplete));
        ASSERT_NE(nullptr, ServerSecConfig);

        QUIC_CREDENTIAL_CONFIG ClientCredConfig = {
            QUIC_CREDENTIAL_TYPE_NONE,
            QUIC_CREDENTIAL_FLAG_CLIENT,
            NULL,
            NULL
        };
        VERIFY_QUIC_SUCCESS(
            CxPlatTlsSecConfigCreate(
                &ClientCredConfig,
                &TlsContext::TlsClientCallbacks,
                &ClientSecConfig,
                OnSecConfigCreateComplete));
        ASSERT_NE(nullptr, ClientSecConfig);

        ClientCredConfig.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
        VERIFY_QUIC_SUCCESS(
            CxPlatTlsSecConfigCreate(
                &ClientCredConfig,
                &TlsContext::TlsClientCallbacks,
                &ClientSecConfigNoCertValidation,
                OnSecConfigCreateComplete));
        ASSERT_NE(nullptr, ClientSecConfigNoCertValidation);
    }

    void TearDown() override
    {
        if (ClientSecConfigNoCertValidation) {
            CxPlatTlsSecConfigDelete(ClientSecConfigNoCertValidation);
            ClientSecConfigNoCertValidation = nullptr;
        }
        if (ClientSecConfig) {
            CxPlatTlsSecConfigDelete(ClientSecConfig);
            ClientSecConfig = nullptr;
        }
        if (ServerSecConfig) {
            CxPlatTlsSecConfigDelete(ServerSecConfig);
            ServerSecConfig = nullptr;
        }
    }

    struct TlsContext
    {
        CXPLAT_TLS* Ptr;
        CXPLAT_SEC_CONFIG* SecConfig;
        CXPLAT_EVENT ProcessCompleteEvent;

        CXPLAT_TLS_PROCESS_STATE State;

        static const CXPLAT_TLS_CALLBACKS TlsServerCallbacks;
        static const CXPLAT_TLS_CALLBACKS TlsClientCallbacks;

        bool Connected;
        bool Key0RttReady;
        bool Key1RttReady;

        TlsContext() :
            Ptr(nullptr),
            SecConfig(nullptr),
            Connected(false) {
            CxPlatEventInitialize(&ProcessCompleteEvent, FALSE, FALSE);
            CxPlatZeroMemory(&State, sizeof(State));
            State.Buffer = (uint8_t*)CXPLAT_ALLOC_NONPAGED(8000, QUIC_POOL_TEST);
            State.BufferAllocLength = 8000;
        }

        ~TlsContext() {
            CxPlatTlsUninitialize(Ptr);
            CxPlatEventUninitialize(ProcessCompleteEvent);
            CXPLAT_FREE(State.Buffer, QUIC_POOL_TEST);
            for (uint8_t i = 0; i < QUIC_PACKET_KEY_COUNT; ++i) {
                QuicPacketKeyFree(State.ReadKeys[i]);
                QuicPacketKeyFree(State.WriteKeys[i]);
            }
            if (ResumptionTicket.Buffer) {
                CXPLAT_FREE(ResumptionTicket.Buffer, QUIC_POOL_CRYPTO_RESUMPTION_TICKET);
            }
        }

        void InitializeServer(
            const CXPLAT_SEC_CONFIG* SecConfiguration,
            bool MultipleAlpns = false,
            uint16_t TPLen = 64
            )
        {
            CXPLAT_TLS_CONFIG Config = {0};
            Config.IsServer = TRUE;
            Config.SecConfig = (CXPLAT_SEC_CONFIG*)SecConfiguration;
            UNREFERENCED_PARAMETER(MultipleAlpns); // The server must always send back the negotiated ALPN.
            Config.AlpnBuffer = Alpn;
            Config.AlpnBufferLength = sizeof(Alpn);
            Config.TPType = TLS_EXTENSION_TYPE_QUIC_TRANSPORT_PARAMETERS;
            Config.LocalTPBuffer =
                (uint8_t*)CXPLAT_ALLOC_NONPAGED(CxPlatTlsTPHeaderSize + TPLen, QUIC_POOL_TLS_TRANSPARAMS);
            Config.LocalTPLength = CxPlatTlsTPHeaderSize + TPLen;
            Config.Connection = (QUIC_CONNECTION*)this;
            State.NegotiatedAlpn = Alpn;

            VERIFY_QUIC_SUCCESS(
                CxPlatTlsInitialize(
                    &Config,
                    &State,
                    &Ptr));
        }

        void InitializeClient(
            CXPLAT_SEC_CONFIG* SecConfiguration,
            bool MultipleAlpns = false,
            uint16_t TPLen = 64,
            QUIC_BUFFER* Ticket = nullptr
            )
        {
            CXPLAT_TLS_CONFIG Config = {0};
            Config.IsServer = FALSE;
            Config.SecConfig = SecConfiguration;
            Config.AlpnBuffer = MultipleAlpns ? MultiAlpn : Alpn;
            Config.AlpnBufferLength = MultipleAlpns ? sizeof(MultiAlpn) : sizeof(Alpn);
            Config.TPType = TLS_EXTENSION_TYPE_QUIC_TRANSPORT_PARAMETERS;
            Config.LocalTPBuffer =
                (uint8_t*)CXPLAT_ALLOC_NONPAGED(CxPlatTlsTPHeaderSize + TPLen, QUIC_POOL_TLS_TRANSPARAMS);
            Config.LocalTPLength = CxPlatTlsTPHeaderSize + TPLen;
            Config.Connection = (QUIC_CONNECTION*)this;
            Config.ServerName = "localhost";
            if (Ticket) {
                Config.ResumptionTicketBuffer = Ticket->Buffer;
                Config.ResumptionTicketLength = Ticket->Length;
                Ticket->Buffer = nullptr;
            }

            VERIFY_QUIC_SUCCESS(
                CxPlatTlsInitialize(
                    &Config,
                    &State,
                    &Ptr));
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

        CXPLAT_TLS_RESULT_FLAGS
        ProcessData(
            _In_ QUIC_PACKET_KEY_TYPE BufferKey,
            _In_reads_bytes_(*BufferLength)
                const uint8_t * Buffer,
            _In_ uint32_t * BufferLength,
            _In_ bool ExpectError,
            _In_ CXPLAT_TLS_DATA_TYPE DataType
            )
        {
            CxPlatEventReset(ProcessCompleteEvent);

            EXPECT_TRUE(Buffer != nullptr || *BufferLength == 0);
            if (Buffer != nullptr) {
                EXPECT_EQ(BufferKey, State.ReadKey);
                if (DataType != CXPLAT_TLS_TICKET_DATA) {
                    *BufferLength = GetCompleteTlsMessagesLength(Buffer, *BufferLength);
                    if (*BufferLength == 0) return (CXPLAT_TLS_RESULT_FLAGS)0;
                }
            }

            //std::cout << "Processing " << *BufferLength << " bytes of type " << DataType << std::endl;

            auto Result =
                CxPlatTlsProcessData(
                    Ptr,
                    DataType,
                    Buffer,
                    BufferLength,
                    &State);
            if (Result & CXPLAT_TLS_RESULT_PENDING) {
                CxPlatEventWaitForever(ProcessCompleteEvent);
                Result = CxPlatTlsProcessDataComplete(Ptr, BufferLength);
            }

            if (!ExpectError) {
                EXPECT_TRUE((Result & CXPLAT_TLS_RESULT_ERROR) == 0);
            }

            return Result;
        }

        CXPLAT_TLS_RESULT_FLAGS
        ProcessFragmentedData(
            _In_ QUIC_PACKET_KEY_TYPE BufferKey,
            _In_reads_bytes_(BufferLength)
                const uint8_t * Buffer,
            _In_ uint32_t BufferLength,
            _In_ uint32_t FragmentSize,
            _In_ bool ExpectError,
            _In_ CXPLAT_TLS_DATA_TYPE DataType
            )
        {
            uint32_t Result = 0;
            uint32_t ConsumedBuffer = FragmentSize;
            uint32_t Count = 1;
            do {
                if (BufferLength < FragmentSize) {
                    FragmentSize = BufferLength;
                    ConsumedBuffer = FragmentSize;
                }

                //std::cout << "Processing fragment of " << FragmentSize << " bytes of type " << DataType << std::endl;

                Result |= (uint32_t)ProcessData(BufferKey, Buffer, &ConsumedBuffer, ExpectError, DataType);

                if (ConsumedBuffer > 0) {
                    Buffer += ConsumedBuffer;
                    BufferLength -= ConsumedBuffer;
                } else {
                    ConsumedBuffer = FragmentSize * ++Count;
                    ConsumedBuffer = min(ConsumedBuffer, BufferLength);
                }

            } while (BufferLength != 0 && !(Result & CXPLAT_TLS_RESULT_ERROR));

            return (CXPLAT_TLS_RESULT_FLAGS)Result;
        }

    public:

        QUIC_BUFFER ResumptionTicket {0, nullptr};

        CXPLAT_TLS_RESULT_FLAGS
        ProcessData(
            _Inout_ CXPLAT_TLS_PROCESS_STATE* PeerState,
            _In_ uint32_t FragmentSize = DefaultFragmentSize,
            _In_ bool ExpectError = false,
            _In_ CXPLAT_TLS_DATA_TYPE DataType = CXPLAT_TLS_CRYPTO_DATA
            )
        {
            if (PeerState == nullptr) {
                //
                // Special case for client hello/initial.
                //
                uint32_t Zero = 0;
                return ProcessData(QUIC_PACKET_KEY_INITIAL, nullptr, &Zero, ExpectError, DataType);
            }

            uint32_t Result = 0;

            do {
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
                        FragmentSize,
                        ExpectError,
                        DataType);

                PeerState->BufferLength -= BufferLength;
                CxPlatMoveMemory(
                    PeerState->Buffer,
                    PeerState->Buffer + BufferLength,
                    PeerState->BufferLength);

            } while (PeerState->BufferLength != 0 && !(Result & CXPLAT_TLS_RESULT_ERROR));

            return (CXPLAT_TLS_RESULT_FLAGS)Result;
        }

    private:

        static void
        OnProcessComplete(
            _In_ QUIC_CONNECTION* Connection
            )
        {
            CxPlatEventSet(((TlsContext*)Connection)->ProcessCompleteEvent);
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

        static BOOLEAN
        OnRecvTicketServer(
            _In_ QUIC_CONNECTION* Connection,
            _In_ uint32_t TicketLength,
            _In_reads_(TicketLength) const uint8_t* Ticket
            )
        {
            UNREFERENCED_PARAMETER(Connection);
            UNREFERENCED_PARAMETER(TicketLength);
            UNREFERENCED_PARAMETER(Ticket);
            return TRUE;
        }

        static BOOLEAN
        OnRecvTicketClient(
            _In_ QUIC_CONNECTION* Connection,
            _In_ uint32_t TicketLength,
            _In_reads_(TicketLength) const uint8_t* Ticket
            )
        {
            auto Context = (TlsContext*)Connection;
            if (Context->ResumptionTicket.Buffer == nullptr) {
                Context->ResumptionTicket.Buffer =
                    (uint8_t*)CXPLAT_ALLOC_NONPAGED(TicketLength, QUIC_POOL_CRYPTO_RESUMPTION_TICKET);
                CxPlatCopyMemory(
                    Context->ResumptionTicket.Buffer,
                    Ticket,
                    TicketLength);
            }
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
            return CXPLAT_ENCRYPTION_OVERHEAD;
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
            uint8_t Iv[CXPLAT_IV_LENGTH];
            QuicCryptoCombineIvAndPacketNumber(Ptr->Iv, (uint8_t*) &PacketNumber, Iv);

            return
                QUIC_STATUS_SUCCESS ==
                CxPlatEncrypt(
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
            uint8_t Iv[CXPLAT_IV_LENGTH];
            QuicCryptoCombineIvAndPacketNumber(Ptr->Iv, (uint8_t*) &PacketNumber, Iv);

            return
                QUIC_STATUS_SUCCESS ==
                CxPlatDecrypt(
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
                CxPlatHpComputeMask(
                    Ptr->HeaderKey,
                    1,
                    Cipher,
                    Mask);
        }
    };

    static
    void
    DoHandshake(
        TlsContext& ServerContext,
        TlsContext& ClientContext,
        uint32_t FragmentSize = DefaultFragmentSize,
        bool SendResumptionTicket = false
        )
    {
        //std::cout << "==DoHandshake==" << std::endl;

        auto Result = ClientContext.ProcessData(nullptr);
        ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);

        Result = ServerContext.ProcessData(&ClientContext.State, FragmentSize);
        ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
        ASSERT_NE(nullptr, ServerContext.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);

        Result = ClientContext.ProcessData(&ServerContext.State, FragmentSize);
        ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
        ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_COMPLETE);
        ASSERT_NE(nullptr, ClientContext.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);

        Result = ServerContext.ProcessData(&ClientContext.State, FragmentSize);
        ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_COMPLETE);

        if (SendResumptionTicket) {
            Result = ServerContext.ProcessData(&ClientContext.State, FragmentSize, false, CXPLAT_TLS_TICKET_DATA);
            ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);

            Result = ClientContext.ProcessData(&ServerContext.State, FragmentSize);
        }
    }

    static CXPLAT_THREAD_CALLBACK(HandshakeAsync, Context)
    {
        TlsTest* This = (TlsTest*)Context;
        for (uint32_t i = 0; i < 100; ++i) {
            TlsContext ServerContext, ClientContext;
            ServerContext.InitializeServer(This->ServerSecConfig);
            ClientContext.InitializeClient(This->ClientSecConfigNoCertValidation);
            DoHandshake(ServerContext, ClientContext);
        }
        CXPLAT_THREAD_RETURN(0);
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
        Start = CxPlatTimeUs64();

        for (uint64_t j = 0; j < LoopCount; ++j) {
            Key.Encrypt(
                sizeof(Header),
                Header,
                j,
                BufferSize + OverHead,
                Buffer);
        }

        End = CxPlatTimeUs64();

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
        Start = CxPlatTimeUs64();

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

        End = CxPlatTimeUs64();

        return End - Start;
    }
};

const CXPLAT_TLS_CALLBACKS TlsTest::TlsContext::TlsServerCallbacks = {
    TlsTest::TlsContext::OnProcessComplete,
    TlsTest::TlsContext::OnRecvQuicTP,
    TlsTest::TlsContext::OnRecvTicketServer
};

const CXPLAT_TLS_CALLBACKS TlsTest::TlsContext::TlsClientCallbacks = {
    TlsTest::TlsContext::OnProcessComplete,
    TlsTest::TlsContext::OnRecvQuicTP,
    TlsTest::TlsContext::OnRecvTicketClient
};

const QUIC_CREDENTIAL_CONFIG* TlsTest::SelfSignedCertParams = nullptr;

TEST_F(TlsTest, Initialize)
{
    TlsContext ServerContext, ClientContext;
    ServerContext.InitializeServer(ServerSecConfig);
    ClientContext.InitializeClient(ClientSecConfigNoCertValidation);
}

TEST_F(TlsTest, Handshake)
{
    TlsContext ServerContext, ClientContext;
    ServerContext.InitializeServer(ServerSecConfig);
    ClientContext.InitializeClient(ClientSecConfigNoCertValidation);
    DoHandshake(ServerContext, ClientContext);
}

TEST_F(TlsTest, HandshakeParallel)
{
    CXPLAT_THREAD_CONFIG Config = {
        0,
        0,
        "TlsWorker",
        HandshakeAsync,
        this
    };

    CXPLAT_THREAD Threads[64];
    CxPlatZeroMemory(&Threads, sizeof(Threads));

    for (uint32_t i = 0; i < ARRAYSIZE(Threads); ++i) {
        VERIFY_QUIC_SUCCESS(CxPlatThreadCreate(&Config, &Threads[i]));
    }

    for (uint32_t i = 0; i < ARRAYSIZE(Threads); ++i) {
        CxPlatThreadWait(&Threads[i]);
        CxPlatThreadDelete(&Threads[i]);
    }
}

#ifndef QUIC_DISABLE_0RTT_TESTS
TEST_F(TlsTest, HandshakeResumption)
{
    TlsContext ServerContext, ClientContext;
    ServerContext.InitializeServer(ServerSecConfig);
    ClientContext.InitializeClient(ClientSecConfigNoCertValidation);
    DoHandshake(ServerContext, ClientContext, DefaultFragmentSize, true);

    ASSERT_NE(nullptr, ClientContext.ResumptionTicket.Buffer);

    TlsContext ServerContext2, ClientContext2;
    ServerContext2.InitializeServer(ServerSecConfig);
    ClientContext2.InitializeClient(ClientSecConfigNoCertValidation, false, 64, &ClientContext.ResumptionTicket);
    DoHandshake(ServerContext2, ClientContext2);
}
#endif

TEST_F(TlsTest, HandshakeMultiAlpnServer)
{
    TlsContext ServerContext, ClientContext;
    ServerContext.InitializeServer(ServerSecConfig, true);
    ClientContext.InitializeClient(ClientSecConfigNoCertValidation);
    DoHandshake(ServerContext, ClientContext);
}

TEST_F(TlsTest, HandshakeMultiAlpnClient)
{
    TlsContext ServerContext, ClientContext;
    ServerContext.InitializeServer(ServerSecConfig);
    ClientContext.InitializeClient(ClientSecConfigNoCertValidation, true);
    DoHandshake(ServerContext, ClientContext);
}

TEST_F(TlsTest, HandshakeMultiAlpnBoth)
{
    TlsContext ServerContext, ClientContext;
    ServerContext.InitializeServer(ServerSecConfig, true);
    ClientContext.InitializeClient(ClientSecConfigNoCertValidation, true);
    DoHandshake(ServerContext, ClientContext);
}

TEST_F(TlsTest, HandshakeFragmented)
{
    TlsContext ServerContext, ClientContext;
    ServerContext.InitializeServer(ServerSecConfig);
    ClientContext.InitializeClient(ClientSecConfigNoCertValidation);
    DoHandshake(ServerContext, ClientContext, 200);
}

TEST_F(TlsTest, HandshakesSerial)
{
    {
        TlsContext ServerContext, ClientContext1;
        ServerContext.InitializeServer(ServerSecConfig);
        ClientContext1.InitializeClient(ClientSecConfigNoCertValidation);
        DoHandshake(ServerContext, ClientContext1);
    }
    {
        TlsContext ServerContext, ClientContext2;
        ServerContext.InitializeServer(ServerSecConfig);
        ClientContext2.InitializeClient(ClientSecConfigNoCertValidation);
        DoHandshake(ServerContext, ClientContext2);
    }
}

TEST_F(TlsTest, HandshakesInterleaved)
{
    TlsContext ServerContext1, ServerContext2, ClientContext1, ClientContext2;
    ServerContext1.InitializeServer(ServerSecConfig);
    ClientContext1.InitializeClient(ClientSecConfigNoCertValidation);
    ServerContext2.InitializeServer(ServerSecConfig);
    ClientContext2.InitializeClient(ClientSecConfigNoCertValidation);

    auto Result = ClientContext1.ProcessData(nullptr);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);

    Result = ClientContext2.ProcessData(nullptr);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);

    Result = ServerContext1.ProcessData(&ClientContext1.State);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    ASSERT_NE(nullptr, ServerContext1.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);

    Result = ServerContext2.ProcessData(&ClientContext2.State);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    ASSERT_NE(nullptr, ServerContext2.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);

    Result = ClientContext1.ProcessData(&ServerContext1.State);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_COMPLETE);
    ASSERT_NE(nullptr, ClientContext1.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);

    Result = ClientContext2.ProcessData(&ServerContext2.State);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_COMPLETE);
    ASSERT_NE(nullptr, ClientContext2.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);

    Result = ServerContext1.ProcessData(&ClientContext1.State);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_COMPLETE);

    Result = ServerContext2.ProcessData(&ClientContext2.State);
    ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_COMPLETE);
}

TEST_F(TlsTest, CertificateError)
{
    TlsContext ServerContext, ClientContext;
    ServerContext.InitializeServer(ServerSecConfig);
    ClientContext.InitializeClient(ClientSecConfig);
    {
        auto Result = ClientContext.ProcessData(nullptr);
        ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);

        Result = ServerContext.ProcessData(&ClientContext.State);
        ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_DATA);
        ASSERT_NE(nullptr, ServerContext.State.WriteKeys[QUIC_PACKET_KEY_1_RTT]);

        Result = ClientContext.ProcessData(&ServerContext.State, DefaultFragmentSize, true);
        ASSERT_TRUE(Result & CXPLAT_TLS_RESULT_ERROR);
        ASSERT_EQ(ClientContext.State.AlertCode, UnknownCaError);
    }
}

TEST_P(TlsTest, One1RttKey)
{
    bool PNE = GetParam();

    TlsContext ServerContext, ClientContext;
    ServerContext.InitializeServer(ServerSecConfig);
    ClientContext.InitializeClient(ClientSecConfigNoCertValidation);
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

TEST_P(TlsTest, KeyUpdate)
{
    bool PNE = GetParam();

    TlsContext ServerContext, ClientContext;
    ServerContext.InitializeServer(ServerSecConfig);
    ClientContext.InitializeClient(ClientSecConfigNoCertValidation);
    DoHandshake(ServerContext, ClientContext);

    QUIC_PACKET_KEY* UpdateWriteKey = nullptr, *UpdateReadKey = nullptr;

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


TEST_P(TlsTest, PacketEncryptionPerf)
{
    bool PNE = GetParam();

    TlsContext ServerContext, ClientContext;
    ServerContext.InitializeServer(ServerSecConfig);
    ClientContext.InitializeClient(ClientSecConfigNoCertValidation);
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

uint64_t LockedCounter(
    const uint64_t LoopCount
    )
{
    uint64_t Start, End;
    CXPLAT_DISPATCH_LOCK Lock;
    uint64_t Counter = 0;

    CxPlatDispatchLockInitialize(&Lock);
    Start = CxPlatTimeUs64();
    for (uint64_t j = 0; j < LoopCount; ++j) {
        CxPlatDispatchLockAcquire(&Lock);
        Counter++;
        CxPlatDispatchLockRelease(&Lock);
    }
    End = CxPlatTimeUs64();

    CxPlatDispatchLockUninitialize(&Lock);

    CXPLAT_FRE_ASSERT(Counter == LoopCount);

    return End - Start;
}

uint64_t InterlockedCounter(
    const uint64_t LoopCount
    )
{
    uint64_t Start, End;
    int64_t Counter = 0;

    Start = CxPlatTimeUs64();
    for (uint64_t j = 0; j < LoopCount; ++j) {
        InterlockedIncrement64(&Counter);
    }
    End = CxPlatTimeUs64();

    CXPLAT_FRE_ASSERT((uint64_t)Counter == LoopCount);

    return End - Start;
}

uint64_t UnlockedCounter(
    const uint64_t LoopCount
    )
{
    uint64_t Start, End;
    uint64_t Counter = 0;
    Start = CxPlatTimeUs64();
    for (uint64_t j = 0; j < LoopCount; ++j) {
        Counter++;
    }
    End = CxPlatTimeUs64();

    CXPLAT_FRE_ASSERT(Counter == LoopCount);

    return End - Start;
}


TEST_F(TlsTest, LockPerfTest)
{
    uint64_t (*const TestFuncs[]) (uint64_t) = {LockedCounter, InterlockedCounter, UnlockedCounter};
    const char* const TestName[] = {"Locking/unlocking", "Interlocked incrementing", "Unlocked incrementing"};
    const uint64_t LoopCount = 100000;

#ifdef _WIN32
    HANDLE CurrentThread = GetCurrentThread();
    DWORD ProcNumber = GetCurrentProcessorNumber();
    DWORD_PTR OldAffinityMask =
        SetThreadAffinityMask(CurrentThread, (DWORD_PTR)1 << (DWORD_PTR)ProcNumber);
    SetThreadPriority(CurrentThread, THREAD_PRIORITY_HIGHEST);
#endif

    for (uint8_t i = 0; i < ARRAYSIZE(TestName); ++i) {

        const uint64_t elapsedMicroseconds = TestFuncs[i](LoopCount);

        std::cout << elapsedMicroseconds / 1000 << "." << (int)(elapsedMicroseconds % 1000) <<
            " milliseconds elapsed "
            << TestName[i] << " counter " << LoopCount << " times" << std::endl;
    }

#ifdef _WIN32
    SetThreadPriority(CurrentThread, THREAD_PRIORITY_NORMAL);
    SetThreadAffinityMask(CurrentThread, OldAffinityMask);
#endif
}

INSTANTIATE_TEST_SUITE_P(TlsTest, TlsTest, ::testing::Bool());
