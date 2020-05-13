/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#include "main.h"
#include "msquic.h"
#include "quic_tls.h"

#include "msquichelper.h"

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
    const QuicBuffer InitialSalt("c3eef712c72ebb5a11a7d2432bb46365bef9f502");
    const QuicBuffer ConnectionID("8394c8f03e515708");

    const QuicBuffer InitialPacketHeader("c3ff000017088394c8f03e5157080000449e00000002");
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

    const QuicBuffer ExpectedSample("535064a4268a0d9d7b1c9d250ae35516");
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

    const QuicBuffer ExpectedHpMask("833b343aaa");
    //LogTestBuffer("ExpectedHpMask", ExpectedHpMask.Data, ExpectedHpMask.Length);
    //LogTestBuffer("  ActualHpMask", HpMask, ExpectedHpMask.Length);
    ASSERT_EQ(0, memcmp(ExpectedHpMask.Data, HpMask, ExpectedHpMask.Length));

    PacketBuffer[0] ^= HpMask[0] & 0x0F;
    for (uint8_t i = 1; i < 5; ++i) {
        PacketBuffer[17 + i] ^= HpMask[i];
    }

    const QuicBuffer ExpectedHeader("c0ff000017088394c8f03e5157080000449e3b343aa8");
    //LogTestBuffer("ExpectedHeader", ExpectedHeader.Data, ExpectedHeader.Length);
    //LogTestBuffer("  ActualHeader", PacketBuffer, ExpectedHeader.Length);
    ASSERT_EQ(0, memcmp(ExpectedHeader.Data, PacketBuffer, ExpectedHeader.Length));

    const QuicBuffer EncryptedPacket("c0ff000017088394c8f03e5157080000449e3b343aa8535064a4268a0d9d7b1c9d250ae355162276e9b1e3011ef6bbc0ab48ad5bcc2681e953857ca62becd7524daac473e68d7405fbba4e9ee616c87038bdbe908c06d9605d9ac49030359eecb1d05a14e117db8cede2bb09d0dbbfee271cb374d8f10abec82d0f59a1dee29fe95638ed8dd41da07487468791b719c55c46968eb3b54680037102a28e53dc1d12903db0af5821794b41c4a93357fa59ce69cfe7f6bdfa629eef78616447e1d611c4baf71bf33febcb03137c2c75d25317d3e13b684370f668411c0f00304b501c8fd422bd9b9ad81d643b20da89ca0525d24d2b142041cae0af205092e430080cd8559ea4c5c6e4fa3f66082b7d303e52ce0162baa958532b0bbc2bc785681fcf37485dff6595e01e739c8ac9efba31b985d5f656cc092432d781db9522172487641c4d3ab8ece01e39bc85b15436614775a98ba8fa12d46f9b35e2a55eb72d7f85181a366663387ddc20551807e007673bd7e26bf9b29b5ab10a1ca87cbb7ad97e99eb66959c2a9bc3cbde4707ff7720b110fa95354674e395812e47a0ae53b464dcb2d1f345df360dc227270c750676f6724eb479f0d2fbb6124429990457ac6c9167f40aab739998f38b9eccb24fd47c8410131bf65a52af841275d5b3d1880b197df2b5dea3e6de56ebce3ffb6e9277a82082f8d9677a6767089b671ebd244c214f0bde95c2beb02cd1172d58bdf39dce56ff68eb35ab39b49b4eac7c815ea60451d6e6ab82119118df02a586844a9ffe162ba006d0669ef57668cab38b62f71a2523a084852cd1d079b3658dc2f3e87949b550bab3e177cfc49ed190dff0630e43077c30de8f6ae081537f1e83da537da980afa668e7b7fb25301cf741524be3c49884b42821f17552fbd1931a813017b6b6590a41ea18b6ba49cd48a440bd9a3346a7623fb4ba34a3ee571e3c731f35a7a3cf25b551a680fa68763507b7fde3aaf023c50b9d22da6876ba337eb5e9dd9ec3daf970242b6c5aab3aa4b296ad8b9f6832f686ef70fa938b31b4e5ddd7364442d3ea72e73d668fb0937796f462923a81a47e1cee7426ff6d9221269b5a62ec03d6ec94d12606cb485560bab574816009e96504249385bb61a819be04f62c2066214d8360a2022beb316240b6c7d78bbe56c13082e0ca272661210abf020bf3b5783f1426436cf9ff41840593a5d0638d32fc51c5c65ff291a3a7a52fd6775e623a4439cc08dd25582febc944ef92d8dbd329c91de3e9c9582e41f17f3d186f104ad3f90995116c682a2a14a3b4b1f547c335f0be710fc9fc03e0e587b8cda31ce65b969878a4ad4283e6d5b0373f43da86e9e0ffe1ae0fddd3516255bd74566f36a38703d5f34249ded1f66b3d9b45b9af2ccfefe984e13376b1b2c6404aa48c8026132343da3f3a33659ec1b3e95080540b28b7f3fcd35fa5d843b579a84c089121a60d8c1754915c344eeaf45a9bf27dc0c1e78416169122091313eb0e87555abd706626e557fc36a04fcd191a58829104d6075c5594f627ca506bf181daec940f4a4f3af0074eee89daacde6758312622d4fa675b39f728e062d2bee680d8f41a597c262648bb18bcfc13c8b3d97b1a77b2ac3af745d61a34cc4709865bac824a94bb19058015e4e42dc9be6c7803567321829dd85853396269");
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
