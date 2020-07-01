/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "main.h"
#include "msquic.h"
#include "quic_tls.h"

#include "msquichelper.h"
#ifdef QUIC_CLOG
#include "CryptTest.cpp.clog.h"
#endif

#ifndef QUIC_TLS_STUB

void
LogTestBuffer(
    _In_z_ const char* Name,
    _In_reads_(Length) const uint8_t* Buffer,
    _In_ size_t Length
    )
{
    char* Str = new char[Length * 2 + 1];
    for (size_t i = 0; i < Length; ++i) {
        sprintf_s(&Str[i*2], 3, "%.2X", Buffer[i]);
    }
    std::cout << Name << "[" << Length << "]: " << Str << std::endl;
    delete [] Str;
}

struct CryptTest : public ::testing::TestWithParam<int32_t>
{
    protected:

    struct QuicKey
    {
        QUIC_KEY* Ptr;
        QuicKey(QUIC_AEAD_TYPE AeadType, const uint8_t* const RawKey) : Ptr(NULL) {
            QUIC_STATUS Status = QuicKeyCreate(AeadType, RawKey, &Ptr);
            if (Status == QUIC_STATUS_NOT_SUPPORTED) {
                GTEST_SKIP_NO_RETURN_(": AEAD Type unsupported");
                return;
            }
            EXPECT_EQ(Status, QUIC_STATUS_SUCCESS);
            EXPECT_NE(Ptr, nullptr);
        }

        ~QuicKey() {
            QuicKeyFree(Ptr);
        }

        bool
        Encrypt(
            _In_reads_bytes_(QUIC_IV_LENGTH)
                const uint8_t* const Iv,
            _In_ uint16_t AuthDataLength,
            _In_reads_bytes_opt_(AuthDataLength)
                const uint8_t* const AuthData,
            _In_ uint16_t BufferLength,
            _Inout_updates_bytes_(BufferLength)
                uint8_t* Buffer
            )
        {
            return
                QUIC_STATUS_SUCCESS ==
                QuicEncrypt(
                    Ptr,
                    Iv,
                    AuthDataLength,
                    AuthData,
                    BufferLength,
                    Buffer);
        }

        bool
        Decrypt(
            _In_reads_bytes_(QUIC_IV_LENGTH)
                const uint8_t* const Iv,
            _In_ uint16_t AuthDataLength,
            _In_reads_bytes_opt_(AuthDataLength)
                const uint8_t* const AuthData,
            _In_ uint16_t BufferLength,
            _Inout_updates_bytes_(BufferLength)
                uint8_t* Buffer
            )
        {
            return
                QUIC_STATUS_SUCCESS ==
                QuicDecrypt(
                    Ptr,
                    Iv,
                    AuthDataLength,
                    AuthData,
                    BufferLength,
                    Buffer);
        }
    };

    struct QuicHash
    {
        QUIC_HASH* Ptr;
        QuicHash(
            _In_ QUIC_HASH_TYPE HashType,
            _In_reads_(SaltLength)
                const uint8_t* const Salt,
            _In_ uint32_t SaltLength
            ) : Ptr(NULL) {
            QUIC_STATUS Status = QuicHashCreate(HashType, Salt, SaltLength, &Ptr);
            if (Status == QUIC_STATUS_NOT_SUPPORTED) {
                GTEST_SKIP_NO_RETURN_(": HASH Type unsupported");
                return;
            }
            EXPECT_EQ(Status, QUIC_STATUS_SUCCESS);
            EXPECT_NE(Ptr, nullptr);
        }

        ~QuicHash() {
            QuicHashFree(Ptr);
        }

        bool
        Compute(
            _In_reads_(InputLength)
                const uint8_t* const Input,
            _In_ uint32_t InputLength,
            _In_ uint32_t OutputLength,
            _Out_writes_all_(OutputLength)
                uint8_t* const Output
            )
        {
            return
                QUIC_STATUS_SUCCESS ==
                QuicHashCompute(
                    Ptr,
                    Input,
                    InputLength,
                    OutputLength,
                    Output);
        }
    };

    struct QuicBuffer
    {
        uint8_t* Data;
        uint16_t Length;

        QuicBuffer(const char* HexBytes)
        {
            Length = (uint16_t)(strlen(HexBytes) / 2);
            Data = new uint8_t[Length];

            for (uint16_t i = 0; i < Length; ++i) {
                Data[i] =
                    (DecodeHexChar(HexBytes[i * 2]) << 4) |
                    DecodeHexChar(HexBytes[i * 2 + 1]);
            }
        }

        ~QuicBuffer()
        {
            delete [] Data;
        }
    };
};

TEST_F(CryptTest, WellKnownClientInitial)
{
    const QuicBuffer InitialSalt("afbfec289993d24c9e9786f19c6111e04390a899");
    const QuicBuffer ConnectionID("8394c8f03e515708");

    const QuicBuffer InitialPacketHeader("c3ff00001d088394c8f03e5157080000449e00000002");
    const QuicBuffer InitialPacketPayload("060040c4010000c003036660261ff947cea49cce6cfad687f457cf1b14531ba14131a0e8f309a1d0b9c4000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d00204cfdfcd178b784bf328cae793b136f2aedce005ff183d7bb1495207236647037002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001");
    const uint64_t InitialPacketNumber = 2;

    uint8_t PacketBuffer[1200] = {0};
    memcpy(PacketBuffer, InitialPacketHeader.Data, InitialPacketHeader.Length);
    memcpy(PacketBuffer + InitialPacketHeader.Length, InitialPacketPayload.Data, InitialPacketPayload.Length);

    QUIC_TLS_PROCESS_STATE State = {0};
    VERIFY_QUIC_SUCCESS(
        QuicPacketKeyCreateInitial(
            FALSE,
            InitialSalt.Data,
            (uint8_t)ConnectionID.Length,
            ConnectionID.Data,
            &State.ReadKeys[QUIC_PACKET_KEY_INITIAL],
            &State.WriteKeys[QUIC_PACKET_KEY_INITIAL]));

    uint8_t Iv[QUIC_IV_LENGTH];
    QuicCryptoCombineIvAndPacketNumber(State.WriteKeys[0]->Iv, (uint8_t*) &InitialPacketNumber, Iv);

    VERIFY_QUIC_SUCCESS(
        QuicEncrypt(
            State.WriteKeys[0]->PacketKey,
            Iv,
            InitialPacketHeader.Length,
            PacketBuffer,
            sizeof(PacketBuffer) - InitialPacketHeader.Length,
            PacketBuffer + InitialPacketHeader.Length));

    const QuicBuffer ExpectedSample("fb66bc5f93032b7ddd89fe0ff15d9c4f");
    //LogTestBuffer("ExpectedSample", ExpectedSample.Data, ExpectedSample.Length);
    //LogTestBuffer("  ActualSample", PacketBuffer + InitialPacketHeader.Length, ExpectedSample.Length);
    ASSERT_EQ(0, memcmp(ExpectedSample.Data, PacketBuffer + InitialPacketHeader.Length, ExpectedSample.Length));

    uint8_t HpMask[16];
    VERIFY_QUIC_SUCCESS(
        QuicHpComputeMask(
            State.WriteKeys[0]->HeaderKey,
            1,
            PacketBuffer + InitialPacketHeader.Length,
            HpMask));

    const QuicBuffer ExpectedHpMask("d64a952459");
    //LogTestBuffer("ExpectedHpMask", ExpectedHpMask.Data, ExpectedHpMask.Length);
    //LogTestBuffer("  ActualHpMask", HpMask, ExpectedHpMask.Length);
    ASSERT_EQ(0, memcmp(ExpectedHpMask.Data, HpMask, ExpectedHpMask.Length));

    PacketBuffer[0] ^= HpMask[0] & 0x0F;
    for (uint8_t i = 1; i < 5; ++i) {
        PacketBuffer[17 + i] ^= HpMask[i];
    }

    const QuicBuffer ExpectedHeader("c5ff00001d088394c8f03e5157080000449e4a95245b");
    //LogTestBuffer("ExpectedHeader", ExpectedHeader.Data, ExpectedHeader.Length);
    //LogTestBuffer("  ActualHeader", PacketBuffer, ExpectedHeader.Length);
    ASSERT_EQ(0, memcmp(ExpectedHeader.Data, PacketBuffer, ExpectedHeader.Length));

    const QuicBuffer EncryptedPacket("c5ff00001d088394c8f03e5157080000449e4a95245bfb66bc5f93032b7ddd89fe0ff15d9c4f7050fccdb71c1cd80512d4431643a53aafa1b0b518b44968b18b8d3e7a4d04c30b3ed9410325b2abb2dafb1c12f8b70479eb8df98abcaf95dd8f3d1c78660fbc719f88b23c8aef6771f3d50e10fdfb4c9d92386d44481b6c52d59e5538d3d3942de9f13a7f8b702dc31724180da9df22714d01003fc5e3d165c950e630b8540fbd81c9df0ee63f94997026c4f2e1887a2def79050ac2d86ba318e0b3adc4c5aa18bcf63c7cf8e85f569249813a2236a7e72269447cd1c755e451f5e77470eb3de64c8849d292820698029cfa18e5d66176fe6e5ba4ed18026f90900a5b4980e2f58e39151d5cd685b10929636d4f02e7fad2a5a458249f5c0298a6d53acbe41a7fc83fa7cc01973f7a74d1237a51974e097636b6203997f921d07bc1940a6f2d0de9f5a11432946159ed6cc21df65c4ddd1115f86427259a196c7148b25b6478b0dc7766e1c4d1b1f5159f90eabc61636226244642ee148b464c9e619ee50a5e3ddc836227cad938987c4ea3c1fa7c75bbf88d89e9ada642b2b88fe8107b7ea375b1b64889a4e9e5c38a1c896ce275a5658d250e2d76e1ed3a34ce7e3a3f383d0c996d0bed106c2899ca6fc263ef0455e74bb6ac1640ea7bfedc59f03fee0e1725ea150ff4d69a7660c5542119c71de270ae7c3ecfd1af2c4ce551986949cc34a66b3e216bfe18b347e6c05fd050f85912db303a8f054ec23e38f44d1c725ab641ae929fecc8e3cefa5619df4231f5b4c009fa0c0bbc60bc75f76d06ef154fc8577077d9d6a1d2bd9bf081dc783ece60111bea7da9e5a9748069d078b2bef48de04cabe3755b197d52b32046949ecaa310274b4aac0d008b1948c1082cdfe2083e386d4fd84c0ed0666d3ee26c4515c4fee73433ac703b690a9f7bf278a77486ace44c489a0c7ac8dfe4d1a58fb3a730b993ff0f0d61b4d89557831eb4c752ffd39c10f6b9f46d8db278da624fd800e4af85548a294c1518893a8778c4f6d6d73c93df200960104e062b388ea97dcf4016bced7f62b4f062cb6c04c20693d9a0e3b74ba8fe74cc01237884f40d765ae56a51688d985cf0ceaef43045ed8c3f0c33bced08537f6882613acd3b08d665fce9dd8aa73171e2d3771a61dba2790e491d413d93d987e2745af29418e428be34941485c93447520ffe231da2304d6a0fd5d07d0837220236966159bef3cf904d722324dd852513df39ae030d8173908da6364786d3c1bfcb19ea77a63b25f1e7fc661def480c5d00d44456269ebd84efd8e3a8b2c257eec76060682848cbf5194bc99e49ee75e4d0d254bad4bfd74970c30e44b65511d4ad0e6ec7398e08e01307eeeea14e46ccd87cf36b285221254d8fc6a6765c524ded0085dca5bd688ddf722e2c0faf9d0fb2ce7a0c3f2cee19ca0ffba461ca8dc5d2c8178b0762cf67135558494d2a96f1a139f0edb42d2af89a9c9122b07acbc29e5e722df8615c343702491098478a389c9872a10b0c9875125e257c7bfdf27eef4060bd3d00f4c14fd3e3496c38d3c5d1a5668c39350effbc2d16ca17be4ce29f02ed969504dda2a8c6b9ff919e693ee79e09089316e7d1d89ec099db3b2b268725d888536a4b8bf9aee8fb43e82a4d919d4843b1ca70a2d8d3f725ead1391377dcc0");
    //LogTestBuffer("ExpectedPacket", EncryptedPacket.Data, EncryptedPacket.Length);
    //LogTestBuffer("  ActualPacket", PacketBuffer, sizeof(PacketBuffer));
    ASSERT_EQ(EncryptedPacket.Length, (uint16_t)sizeof(PacketBuffer));
    ASSERT_EQ(0, memcmp(EncryptedPacket.Data, PacketBuffer, EncryptedPacket.Length));

    //
    // Little hack to convert the initial key to a 1-RTT key for a key update test.
    //
    uint8_t PacketKeyBuffer[sizeof(QUIC_SECRET) + sizeof(QUIC_PACKET_KEY)] = {0};
    QUIC_PACKET_KEY* PacketKey = (QUIC_PACKET_KEY*)PacketKeyBuffer;
    memcpy(PacketKey, State.ReadKeys[0], sizeof(QUIC_PACKET_KEY));
    PacketKey->Type = QUIC_PACKET_KEY_1_RTT;

    QUIC_PACKET_KEY* NewPacketKey = NULL;
    VERIFY_QUIC_SUCCESS(QuicPacketKeyUpdate(PacketKey, &NewPacketKey));

    const QuicBuffer ExpectedTrafficSecret("53dd8c90e78fc6ea92864f791865be060d933be0824befcb2b59ac901f306035");
    //LogTestBuffer("ExpectedTrafficSecret", ExpectedTrafficSecret.Data, ExpectedTrafficSecret.Length);
    //LogTestBuffer("  ActualTrafficSecret", NewPacketKey->TrafficSecret[0].Secret, ExpectedTrafficSecret.Length);
    ASSERT_EQ(0, memcmp(ExpectedTrafficSecret.Data, NewPacketKey->TrafficSecret[0].Secret, ExpectedTrafficSecret.Length));

    QuicPacketKeyFree(State.ReadKeys[0]);
    QuicPacketKeyFree(State.WriteKeys[0]);
    QuicPacketKeyFree(NewPacketKey);
}

TEST_P(CryptTest, Encryption)
{

    int AEAD = GetParam();

    uint8_t RawKey[32];
    uint8_t Iv[QUIC_IV_LENGTH];
    uint8_t AuthData[12];
    uint8_t Buffer[128];

    QuicKey Key((QUIC_AEAD_TYPE)AEAD, RawKey);
    if (Key.Ptr == NULL) return;

    //
    // Positive cases
    //

    ASSERT_TRUE(Key.Encrypt(Iv, 0, NULL, sizeof(Buffer), Buffer));
    ASSERT_TRUE(Key.Decrypt(Iv, 0, NULL, sizeof(Buffer), Buffer));
    ASSERT_TRUE(Key.Encrypt(Iv, sizeof(AuthData), AuthData, sizeof(Buffer), Buffer));
    ASSERT_TRUE(Key.Decrypt(Iv, sizeof(AuthData), AuthData, sizeof(Buffer), Buffer));

    //
    // Negative cases
    //

    ASSERT_TRUE(Key.Encrypt(Iv, 0, NULL, sizeof(Buffer), Buffer));
    ASSERT_FALSE(Key.Decrypt(Iv, 0, NULL, sizeof(Buffer) - 1, Buffer));

    ASSERT_TRUE(Key.Encrypt(Iv, sizeof(AuthData), AuthData, sizeof(Buffer), Buffer));
    ASSERT_FALSE(Key.Decrypt(Iv, sizeof(AuthData), AuthData, sizeof(Buffer) - 1, Buffer));

    ASSERT_TRUE(Key.Encrypt(Iv, sizeof(AuthData), AuthData, sizeof(Buffer), Buffer));
    ASSERT_FALSE(Key.Decrypt(Iv, sizeof(AuthData) - 1, AuthData, sizeof(Buffer), Buffer));

    ASSERT_TRUE(Key.Encrypt(Iv, 0, NULL, sizeof(Buffer), Buffer));
    Buffer[0] ^= 1;
    ASSERT_FALSE(Key.Decrypt(Iv, 0, NULL, sizeof(Buffer), Buffer));

    ASSERT_TRUE(Key.Encrypt(Iv, 0, NULL, sizeof(Buffer), Buffer));
    Buffer[127] ^= 1;
    ASSERT_FALSE(Key.Decrypt(Iv, 0, NULL, sizeof(Buffer), Buffer));

    ASSERT_TRUE(Key.Encrypt(Iv, sizeof(AuthData), AuthData, sizeof(Buffer), Buffer));
    AuthData[0] ^= 1;
    ASSERT_FALSE(Key.Decrypt(Iv, sizeof(AuthData), AuthData, sizeof(Buffer), Buffer));

    ASSERT_TRUE(Key.Encrypt(Iv, sizeof(AuthData), AuthData, sizeof(Buffer), Buffer));
    Buffer[127] ^= 1;
    ASSERT_FALSE(Key.Decrypt(Iv, sizeof(AuthData), AuthData, sizeof(Buffer), Buffer));
}

TEST_P(CryptTest, HashWellKnown)
{
    int HASH = GetParam();

    const QuicBuffer WellKnownOutput0("6a2434c718a984ad38abc419e1300c066e0a61e84bf8403876cf2e32f9103938");
    const QuicBuffer WellKnownOutput1("1aa0fa65e1b94d6cf9eaeaa062d55bc643259b9f42b6750547cf325c1489ddb76e069081bc13152614a2ff4a85e920ce");
    const QuicBuffer WellKnownOutput2("a2827af996dc82f3721cfb6c5c7d3d307d088438caa77b330f105e711d2b1eadd3c0bcd5ac3498bf05c15e8ab73ac86fb9522b80e735e017db17c40d29d0e588");

    const QuicBuffer* WellKnownOutput[] = {
        &WellKnownOutput0, &WellKnownOutput1, &WellKnownOutput2
    };

    uint8_t Salt[20];
    QuicZeroMemory(Salt, sizeof(Salt));
    Salt[0] = 0xff;
    uint8_t Input[256];
    QuicZeroMemory(Input, sizeof(Input));
    Input[0] = 0xaa;

    uint8_t Output[QUIC_HASH_MAX_SIZE];
    QuicZeroMemory(Output, sizeof(Output));
    const uint16_t OutputLength = QuicHashLength((QUIC_HASH_TYPE)HASH);

    QuicHash Hash((QUIC_HASH_TYPE)HASH, Salt, sizeof(Salt));
    if (Hash.Ptr == NULL) return;

    ASSERT_TRUE(
        Hash.Compute(
            Input,
            sizeof(Input),
            OutputLength,
            Output));
    ASSERT_EQ(WellKnownOutput[HASH]->Length, OutputLength);
    ASSERT_EQ(0, memcmp(WellKnownOutput[HASH]->Data, Output, OutputLength));
}

TEST_P(CryptTest, HashRandom)
{
    int HASH = GetParam();

    uint8_t Salt[20];
    uint8_t Input[256];
    uint8_t Output[QUIC_HASH_MAX_SIZE];
    uint8_t Output2[QUIC_HASH_MAX_SIZE];
    const uint16_t OutputLength = QuicHashLength((QUIC_HASH_TYPE)HASH);

    QuicRandom(sizeof(Salt), Salt);
    QuicRandom(sizeof(Input), Input);

    QuicHash Hash((QUIC_HASH_TYPE)HASH, Salt, sizeof(Salt));
    if (Hash.Ptr == NULL) return;

    ASSERT_TRUE(
        Hash.Compute(
            Input,
            sizeof(Input),
            OutputLength,
            Output));
    ASSERT_TRUE(
        Hash.Compute(
            Input,
            sizeof(Input),
            OutputLength,
            Output2));
    ASSERT_EQ(0, memcmp(Output, Output2, OutputLength));
}

INSTANTIATE_TEST_SUITE_P(CryptTest, CryptTest, ::testing::Values(0, 1, 2));

#endif // QUIC_TLS_STUB
