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
        CXPLAT_KEY* Ptr;
        QuicKey(CXPLAT_AEAD_TYPE AeadType, const uint8_t* const RawKey) : Ptr(NULL) {
            QUIC_STATUS Status = CxPlatKeyCreate(AeadType, RawKey, &Ptr);
            if (Status == QUIC_STATUS_NOT_SUPPORTED) {
                GTEST_SKIP_NO_RETURN_(": AEAD Type unsupported");
                return;
            }
            EXPECT_EQ(Status, QUIC_STATUS_SUCCESS);
            EXPECT_NE(Ptr, nullptr);
        }

        ~QuicKey() {
            CxPlatKeyFree(Ptr);
        }

        bool
        Encrypt(
            _In_reads_bytes_(CXPLAT_IV_LENGTH)
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
                CxPlatEncrypt(
                    Ptr,
                    Iv,
                    AuthDataLength,
                    AuthData,
                    BufferLength,
                    Buffer);
        }

        bool
        Decrypt(
            _In_reads_bytes_(CXPLAT_IV_LENGTH)
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
                CxPlatDecrypt(
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
        CXPLAT_HASH* Ptr;
        QuicHash(
            _In_ CXPLAT_HASH_TYPE HashType,
            _In_reads_(SaltLength)
                const uint8_t* const Salt,
            _In_ uint32_t SaltLength
            ) : Ptr(NULL) {
            QUIC_STATUS Status = CxPlatHashCreate(HashType, Salt, SaltLength, &Ptr);
            if (Status == QUIC_STATUS_NOT_SUPPORTED) {
                GTEST_SKIP_NO_RETURN_(": HASH Type unsupported");
                return;
            }
            EXPECT_EQ(Status, QUIC_STATUS_SUCCESS);
            EXPECT_NE(Ptr, nullptr);
        }

        ~QuicHash() {
            CxPlatHashFree(Ptr);
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
                CxPlatHashCompute(
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

    void
    TestWellKnownClientInitial(
        _In_z_ const char* const InitSaltStr,
        _In_z_ const char* const CIDStr,
        _In_z_ const char* const InitPacketHdr,
        _In_z_ const char* const InitPktPayload,
        _In_ const QUIC_HKDF_LABELS Labels,
        _In_z_ const char* const ExpectedSampleStr,
        _In_z_ const char* const ExpectedHpMaskStr,
        _In_z_ const char* const ExpectedHdrStr,
        _In_z_ const char* const EncryptedPktStr,
        _In_opt_z_ const char* const
            ExpectedTrafficSecretStr
        )
    {
        const QuicBuffer InitialSalt(InitSaltStr);
        const QuicBuffer ConnectionID(CIDStr);

        const QuicBuffer InitialPacketHeader(InitPacketHdr);
        const QuicBuffer InitialPacketPayload(InitPktPayload);
        const uint64_t InitialPacketNumber = 2;

        uint8_t PacketBuffer[1200] = {0};
        memcpy(PacketBuffer, InitialPacketHeader.Data, InitialPacketHeader.Length);
        memcpy(PacketBuffer + InitialPacketHeader.Length, InitialPacketPayload.Data, InitialPacketPayload.Length);

        CXPLAT_TLS_PROCESS_STATE State;
        CxPlatZeroMemory(&State, sizeof(State));
        VERIFY_QUIC_SUCCESS(
            QuicPacketKeyCreateInitial(
                FALSE,
                &Labels,
                InitialSalt.Data,
                (uint8_t)ConnectionID.Length,
                ConnectionID.Data,
                &State.ReadKeys[QUIC_PACKET_KEY_INITIAL],
                &State.WriteKeys[QUIC_PACKET_KEY_INITIAL]));

        uint8_t Iv[CXPLAT_IV_LENGTH];
        QuicCryptoCombineIvAndPacketNumber(State.WriteKeys[0]->Iv, (uint8_t*) &InitialPacketNumber, Iv);

        VERIFY_QUIC_SUCCESS(
            CxPlatEncrypt(
                State.WriteKeys[0]->PacketKey,
                Iv,
                InitialPacketHeader.Length,
                PacketBuffer,
                sizeof(PacketBuffer) - InitialPacketHeader.Length,
                PacketBuffer + InitialPacketHeader.Length));

        const QuicBuffer ExpectedSample(ExpectedSampleStr);
        //LogTestBuffer("ExpectedSample", ExpectedSample.Data, ExpectedSample.Length);
        //LogTestBuffer("  ActualSample", PacketBuffer + InitialPacketHeader.Length, ExpectedSample.Length);
        ASSERT_EQ(0, memcmp(ExpectedSample.Data, PacketBuffer + InitialPacketHeader.Length, ExpectedSample.Length));

        uint8_t HpMask[16];
        VERIFY_QUIC_SUCCESS(
            CxPlatHpComputeMask(
                State.WriteKeys[0]->HeaderKey,
                1,
                PacketBuffer + InitialPacketHeader.Length,
                HpMask));

        const QuicBuffer ExpectedHpMask(ExpectedHpMaskStr);
        //LogTestBuffer("ExpectedHpMask", ExpectedHpMask.Data, ExpectedHpMask.Length);
        //LogTestBuffer("  ActualHpMask", HpMask, ExpectedHpMask.Length);
        ASSERT_EQ(0, memcmp(ExpectedHpMask.Data, HpMask, ExpectedHpMask.Length));

        PacketBuffer[0] ^= HpMask[0] & 0x0F;
        for (uint8_t i = 1; i < 5; ++i) {
            PacketBuffer[17 + i] ^= HpMask[i];
        }

        const QuicBuffer ExpectedHeader(ExpectedHdrStr);
        //LogTestBuffer("ExpectedHeader", ExpectedHeader.Data, ExpectedHeader.Length);
        //LogTestBuffer("  ActualHeader", PacketBuffer, ExpectedHeader.Length);
        ASSERT_EQ(0, memcmp(ExpectedHeader.Data, PacketBuffer, ExpectedHeader.Length));

        const QuicBuffer EncryptedPacket(EncryptedPktStr);
        //LogTestBuffer("ExpectedPacket", EncryptedPacket.Data, EncryptedPacket.Length);
        //LogTestBuffer("  ActualPacket", PacketBuffer, sizeof(PacketBuffer));
        ASSERT_EQ(EncryptedPacket.Length, (uint16_t)sizeof(PacketBuffer));
        ASSERT_EQ(0, memcmp(EncryptedPacket.Data, PacketBuffer, EncryptedPacket.Length));

        //
        // Little hack to convert the initial key to a 1-RTT key for a key update test.
        //
        uint8_t PacketKeyBuffer[sizeof(CXPLAT_SECRET) + sizeof(QUIC_PACKET_KEY)] = {0};
        QUIC_PACKET_KEY* PacketKey = (QUIC_PACKET_KEY*)PacketKeyBuffer;
        memcpy(PacketKey, State.ReadKeys[0], sizeof(QUIC_PACKET_KEY));
        PacketKey->Type = QUIC_PACKET_KEY_1_RTT;

        QUIC_PACKET_KEY* NewPacketKey = NULL;
        VERIFY_QUIC_SUCCESS(QuicPacketKeyUpdate(&Labels, PacketKey, &NewPacketKey));

        if (ExpectedTrafficSecretStr) {
            const QuicBuffer ExpectedTrafficSecret(ExpectedTrafficSecretStr);
            //LogTestBuffer("ExpectedTrafficSecret", ExpectedTrafficSecret.Data, ExpectedTrafficSecret.Length);
            //LogTestBuffer("  ActualTrafficSecret", NewPacketKey->TrafficSecret[0].Secret, ExpectedTrafficSecret.Length);
            ASSERT_EQ(0, memcmp(ExpectedTrafficSecret.Data, NewPacketKey->TrafficSecret[0].Secret, ExpectedTrafficSecret.Length));
        }

        QuicPacketKeyFree(State.ReadKeys[0]);
        QuicPacketKeyFree(State.WriteKeys[0]);
        QuicPacketKeyFree(NewPacketKey);
    }

    void
    TestWellKnownChaChaPoly(
        _In_z_ const char* const SecretBufferStr,
        _In_z_ const char* const ExpectedIvStr,
        _In_z_ const char* const ExpectedNonceStr,
        _In_z_ const char* const ExpectedHeaderStr,
        _In_z_ const char* const ExpectedHpMaskStr,
        _In_z_ const char* const EncryptedPacketStr,
        _In_z_ const char* const SampleStr,
        _In_z_ const char* const EncryptedHeaderStr,
        _In_ const QUIC_HKDF_LABELS Labels
        )
    {
        const QuicBuffer SecretBuffer(SecretBufferStr);
        const QuicBuffer ExpectedIv(ExpectedIvStr);
        const QuicBuffer ExpectedNonce(ExpectedNonceStr);
        const QuicBuffer ExpectedHeader(ExpectedHeaderStr);
        const QuicBuffer ExpectedHpMask(ExpectedHpMaskStr);

        const QuicBuffer EncryptedPacket(EncryptedPacketStr);
        const QuicBuffer Sample(SampleStr);
        const QuicBuffer EncryptedHeader(EncryptedHeaderStr);
        uint8_t PacketBuffer[21];
        CXPLAT_SECRET Secret{};
        QUIC_PACKET_KEY* PacketKey;
        const uint64_t PacketNumber = 654360564ull;

        Secret.Hash = CXPLAT_HASH_SHA256;
        Secret.Aead = CXPLAT_AEAD_CHACHA20_POLY1305;
        memcpy(Secret.Secret, SecretBuffer.Data, SecretBuffer.Length);

        ASSERT_EQ(sizeof(PacketBuffer), EncryptedPacket.Length);
        memcpy(PacketBuffer, EncryptedPacket.Data, sizeof(PacketBuffer));

        VERIFY_QUIC_SUCCESS(QuicPacketKeyDerive(QUIC_PACKET_KEY_1_RTT, &Labels, &Secret, "WellKnownChaChaPoly", TRUE, &PacketKey));

        ASSERT_EQ(0, memcmp(ExpectedIv.Data, PacketKey->Iv, sizeof(PacketKey->Iv)));

        uint8_t Iv[CXPLAT_IV_LENGTH];
        QuicCryptoCombineIvAndPacketNumber(PacketKey->Iv, (uint8_t*) &PacketNumber, Iv);

        ASSERT_EQ(0, memcmp(Iv, ExpectedNonce.Data, sizeof(Iv)));

        ASSERT_EQ((size_t)ExpectedHeader.Length + 1, sizeof(PacketBuffer) - Sample.Length);
        ASSERT_EQ(0, memcmp(Sample.Data, PacketBuffer + ExpectedHeader.Length + 1, Sample.Length));

        uint8_t HpMask[16];
        VERIFY_QUIC_SUCCESS(
            CxPlatHpComputeMask(
                PacketKey->HeaderKey,
                1,
                PacketBuffer + ExpectedHeader.Length + 1,
                HpMask));

        ASSERT_EQ(0, memcmp(HpMask, ExpectedHpMask.Data, ExpectedHpMask.Length));

        PacketBuffer[0] ^= HpMask[0] & 0x1F;
        for (uint16_t i = 1; i < ExpectedHeader.Length; ++i) {
            PacketBuffer[i] ^= HpMask[i];
        }
        ASSERT_EQ(0, memcmp(PacketBuffer, ExpectedHeader.Data, ExpectedHeader.Length));

        VERIFY_QUIC_SUCCESS(
            CxPlatDecrypt(
                PacketKey->PacketKey,
                Iv,
                ExpectedHeader.Length,
                PacketBuffer,
                sizeof(PacketBuffer) - ExpectedHeader.Length,
                PacketBuffer + ExpectedHeader.Length));

        if (PacketBuffer[ExpectedHeader.Length] != 0x01) {// A single ping frame.
            LogTestBuffer("Packet Buffer After decryption", PacketBuffer, sizeof(PacketBuffer));
            GTEST_MESSAGE_AT_(__FILE__, __LINE__, "Decrypted payload is incorrect", ::testing::TestPartResult::kFatalFailure);
        }

        QuicPacketKeyFree(PacketKey);
    }

    bool
    TestKbKdfDerive(
        _In_ QuicBuffer& Key,
        _In_ const uint32_t OutputLength,
        _In_ QuicBuffer& ExpectedOutput)
    {
        uint8_t Output[CXPLAT_AEAD_MAX_SIZE];
        if (OutputLength > sizeof(Output)) {
            //
            // Ensure the test doesn't overrun the buffer.
            //
            GTEST_LOG_(ERROR) << "OutputLength is larger than buffer.";
            return false;
        }
        CxPlatZeroMemory(Output, OutputLength);
        uint64_t Context = 1752112221;
        const char* Label = "test";
        const uint32_t ContextLength = (uint32_t)sizeof(Context);

        QUIC_STATUS Status =
            CxPlatKbKdfDerive(
                Key.Data,
                Key.Length,
                Label,
                (uint8_t*)&Context,
                ContextLength,
                OutputLength,
                Output);
        if (QUIC_FAILED(Status)) {
            GTEST_LOG_(ERROR) << "CxPlatKbKdfDerive failed with " << std::hex << Status;
            return false;
        }
        
        if (memcmp(ExpectedOutput.Data, Output, ExpectedOutput.Length) != 0) {
            LogTestBuffer("Expected Output:     ", ExpectedOutput.Data, ExpectedOutput.Length);
            LogTestBuffer("Calculated Output:   ", Output, ExpectedOutput.Length);
            return false;
        }
        return true;
    }
};

TEST_F(CryptTest, WellKnownClientInitialv1)
{
    TestWellKnownClientInitial(
        "38762cf7f55934b34d179ae6a4c80cadccbb7f0a",
        "8394c8f03e515708",
        "c300000001088394c8f03e5157080000449e00000002",
        "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d0017001800100007000504616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b0003020304000d0010000e0403050306030203080408050806002d00020101001c00024001003900320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806048000ffff",
        { "quic key", "quic iv", "quic hp", "quic ku" },
        "d1b1c98dd7689fb8ec11d242b123dc9b",
        "437b9aec36",
        "c000000001088394c8f03e5157080000449e7b9aec34",
        "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f3991c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c2084dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f89937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe5896425c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ffef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009ddc324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450efc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03adea2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e72404790a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f440591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca06948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd46840647e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241e221af44860018ab0856972e194cd934",
        "53dd8c90e78fc6ea92864f791865be060d933be0824befcb2b59ac901f306035");
}

TEST_F(CryptTest, WellKnownClientInitialv2)
{
    //
    // Vectors from RFC 9369 (QUIC Version 2), Appendix A.2, with the Initial
    // salt from Section 3.3. These previously carried the values of the
    // withdrawn draft-ietf-quic-v2 (version 0x709a50c4), which the shipped
    // QuicSupportedVersionList does not use.
    //
    TestWellKnownClientInitial(
        "0dede3def700a6db819381be6e269dcbf9bd2ed9",
        "8394c8f03e515708",
        "d36b3343cf088394c8f03e5157080000449e00000002",
        "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578616d706c652e636f6dff01000100000a00080006001d0017001800100007000504616c706e000500050100000000003300260024001d00209370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b0003020304000d0010000e0403050306030203080408050806002d00020101001c00024001003900320408ffffffffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806048000ffff",
        { "quicv2 key", "quicv2 iv", "quicv2 hp", "quicv2 ku" },
        "ffe67b6abcdb4298b485dd04de806071",
        "94a0c95e80",
        "d76b3343cf088394c8f03e5157080000449ea0c95e82",
        "d76b3343cf088394c8f03e5157080000449ea0c95e82ffe67b6abcdb4298b485dd04de806071bf03dceebfa162e75d6c96058bdbfb127cdfcbf903388e99ad049f9a3dd4425ae4d0992cfff18ecf0fdb5a842d09747052f17ac2053d21f57c5d250f2c4f0e0202b70785b7946e992e58a59ac52dea6774d4f03b55545243cf1a12834e3f249a78d395e0d18f4d766004f1a2674802a747eaa901c3f10cda5500cb9122faa9f1df66c392079a1b40f0de1c6054196a11cbea40afb6ef5253cd6818f6625efce3b6def6ba7e4b37a40f7732e093daa7d52190935b8da58976ff3312ae50b187c1433c0f028edcc4c2838b6a9bfc226ca4b4530e7a4ccee1bfa2a3d396ae5a3fb512384b2fdd851f784a65e03f2c4fbe11a53c7777c023462239dd6f7521a3f6c7d5dd3ec9b3f233773d4b46d23cc375eb198c63301c21801f6520bcfb7966fc49b393f0061d974a2706df8c4a9449f11d7f3d2dcbb90c6b877045636e7c0c0fe4eb0f697545460c806910d2c355f1d253bc9d2452aaa549e27a1fac7cf4ed77f322e8fa894b6a83810a34b361901751a6f5eb65a0326e07de7c1216ccce2d0193f958bb3850a833f7ae432b65bc5a53975c155aa4bcb4f7b2c4e54df16efaf6ddea94e2c50b4cd1dfe06017e0e9d02900cffe1935e0491d77ffb4fdf85290fdd893d577b1131a610ef6a5c32b2ee0293617a37cbb08b847741c3b8017c25ca9052ca1079d8b78aebd47876d330a30f6a8c6d61dd1ab5589329de714d19d61370f8149748c72f132f0fc99f34d766c6938597040d8f9e2bb522ff99c63a344d6a2ae8aa8e51b7b90a4a806105fcbca31506c446151adfeceb51b91abfe43960977c87471cf9ad4074d30e10d6a7f03c63bd5d4317f68ff325ba3bd80bf4dc8b52a0ba031758022eb025cdd770b44d6d6cf0670f4e990b22347a7db848265e3e5eb72dfe8299ad7481a408322cac55786e52f633b2fb6b614eaed18d703dd84045a274ae8bfa73379661388d6991fe39b0d93debb41700b41f90a15c4d526250235ddcd6776fc77bc97e7a417ebcb31600d01e57f32162a8560cacc7e27a096d37a1a86952ec71bd89a3e9a30a2a26162984d7740f81193e8238e61f6b5b984d4d3dfa033c1bb7e4f0037febf406d91c0dccf32acf423cfa1e7071010d3f270121b493ce85054ef58bada42310138fe081adb04e2bd901f2f13458b3d6758158197107c14ebb193230cd1157380aa79cae1374a7c1e5bbcb80ee23e06ebfde206bfb0fcbc0edc4ebec309661bdd908d532eb0c6adc38b7ca7331dce8dfce39ab71e7c32d318d136b6100671a1ae6a6600e3899f31f0eed19e3417d134b90c9058f8632c798d4490da4987307cba922d61c39805d072b589bd52fdf1e86215c2d54e6670e07383a27bbffb5addf47d66aa85a0c6f9f32e59d85a44dd5d3b22dc2be80919b490437ae4f36a0ae55edf1d0b5cb4e9a3ecabee93dfc6e38d209d0fa6536d27a5d6fbb17641cde27525d61093f1b28072d111b2b4ae5f89d5974ee12e5cf7d5da4d6a31123041f33e61407e76cffcdcfd7e19ba58cf4b536f4c4938ae79324dc402894b44faf8afbab35282ab659d13c93f70412e85cb199a37ddec600545473cfb5a05e08d0b209973b2172b4d21fb69745a262ccde96ba18b2faa745b6fe189cf772a9f84cbfc",
        nullptr);
}

#ifndef QUIC_DISABLE_CHACHA20_TESTS
TEST_F(CryptTest, WellKnownChaChaPolyv1)
{
    TestWellKnownChaChaPoly(
        "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b",
        "e0459b3474bdd0e44a41c144",
        "e0459b3474bdd0e46d417eb0",
        "4200bff4",
        "aefefe7d03",
        "4cfe4189655e5cd55c41f69080575d7999c25a5bfb",
        "5e5cd55c41f69080575d7999c25a5bfb",
        "4cfe4189",
        { "quic key", "quic iv", "quic hp", "quic ku" });
}

TEST_F(CryptTest, WellKnownChaChaPolyv2)
{
    TestWellKnownChaChaPoly(
        "9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b",
        "a6b5bc6ab7dafce30ffff5dd",
        "a6b5bc6ab7dafce328ff4a29",
        "4200bff4",
        "97580e32bf",
        "5558b1c60ae7b6b932bc27d786f4bc2bb20f2162ba",
        "e7b6b932bc27d786f4bc2bb20f2162ba",
        "5558b1c6",
        { "quicv2 key", "quicv2 iv", "quicv2 hp", "quicv2 ku" });
}

TEST_F(CryptTest, HpMaskChaCha20)
{
    const uint8_t RawKey[] =
        {0, 1, 2, 3, 4, 5, 6, 7,
        8, 9, 10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23,
        24, 25, 26, 27, 28, 29, 30, 31};
    const uint8_t Sample[] =
        {0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t Mask[16] = {0};
    CXPLAT_HP_KEY* HpKey = nullptr;
    VERIFY_QUIC_SUCCESS(CxPlatHpKeyCreate(CXPLAT_AEAD_CHACHA20_POLY1305, RawKey, &HpKey));
    VERIFY_QUIC_SUCCESS(CxPlatHpComputeMask(HpKey, 1, Sample, Mask));

    const uint8_t ExpectedMask[] = {0x39, 0xfd, 0x2b, 0x7d, 0xd9};

    if (memcmp(ExpectedMask, Mask, sizeof(ExpectedMask)) != 0) {
        LogTestBuffer("Expected Mask:     ", ExpectedMask, sizeof(ExpectedMask));
        LogTestBuffer("Calculated Mask:   ", Mask, sizeof(ExpectedMask));
        FAIL();
    }

    CxPlatHpKeyFree(HpKey);
}
#endif // QUIC_DISABLE_CHACHA20_TESTS

TEST_F(CryptTest, HpMaskAes256)
{
    const uint8_t RawKey[] =
        {0, 1, 2, 3, 4, 5, 6, 7,
        8, 9, 10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23,
        24, 25, 26, 27, 28, 29, 30, 31};
    const uint8_t Sample[] =
        {0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t Mask[16] = {0};
    CXPLAT_HP_KEY* HpKey = nullptr;
    VERIFY_QUIC_SUCCESS(CxPlatHpKeyCreate(CXPLAT_AEAD_AES_256_GCM, RawKey, &HpKey));
    VERIFY_QUIC_SUCCESS(CxPlatHpComputeMask(HpKey, 1, Sample, Mask));

    const uint8_t ExpectedMask[] = {0xf2, 0x90, 0x00, 0xb6, 0x2a};

    if (memcmp(ExpectedMask, Mask, sizeof(ExpectedMask)) != 0) {
        LogTestBuffer("Expected Mask:     ", ExpectedMask, sizeof(ExpectedMask));
        LogTestBuffer("Calculated Mask:   ", Mask, sizeof(ExpectedMask));
        FAIL();
    }

    CxPlatHpKeyFree(HpKey);
}

TEST_F(CryptTest, HpMaskAes128)
{
    const uint8_t RawKey[] =
        {0, 1, 2, 3, 4, 5, 6, 7,
        8, 9, 10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23,
        24, 25, 26, 27, 28, 29, 30, 31};
    const uint8_t Sample[] =
        {0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t Mask[16] = {0};
    CXPLAT_HP_KEY* HpKey = nullptr;
    VERIFY_QUIC_SUCCESS(CxPlatHpKeyCreate(CXPLAT_AEAD_AES_128_GCM, RawKey, &HpKey));
    VERIFY_QUIC_SUCCESS(CxPlatHpComputeMask(HpKey, 1, Sample, Mask));

    const uint8_t ExpectedMask[] = {0xc6, 0xa1, 0x3b, 0x37, 0x87};

    if (memcmp(ExpectedMask, Mask, sizeof(ExpectedMask)) != 0) {
        LogTestBuffer("Expected Mask:     ", ExpectedMask, sizeof(ExpectedMask));
        LogTestBuffer("Calculated Mask:   ", Mask, sizeof(ExpectedMask));
        FAIL();
    }

    CxPlatHpKeyFree(HpKey);
}

TEST_F(CryptTest, KbKdfDerive)
{
    QuicBuffer Key256("3edc6b5b8f7aadbd713732b482b8f979286e1ea3b8f8f99c30c884cfe3349b83");

    QuicBuffer ExpectedOutput256_Key256("B7BFF374C8928335AA41589D41084B64211876771C459C23B06BA4A2EA89B5AE");
    if (!TestKbKdfDerive(
        Key256,
        ExpectedOutput256_Key256.Length,
        ExpectedOutput256_Key256)) {
        FAIL();
    }

    QuicBuffer ExpectedOutput128_Key256("2775BB8F82B3B5EB667C8CF548C2F06F");
    if (!TestKbKdfDerive(
        Key256,
        ExpectedOutput128_Key256.Length,
        ExpectedOutput128_Key256)) {
        FAIL();
    }

    QuicBuffer Key128("5ddd79f7b33f1f4a6dd57c34a8eec42e");
    QuicBuffer ExpectedOutput256_Key128("0D90AEEEA79D7068283FC33561277AD8B641F5D0F2C47A3360DE8BBCB2D1A6E6");
    if (!TestKbKdfDerive(
        Key128,
        ExpectedOutput256_Key128.Length,
        ExpectedOutput256_Key128)) {
        FAIL();
    }

    QuicBuffer ExpectedOutput128_Key128("3D49CD6A27AC5CA5F0F51893A755D160");
    if (!TestKbKdfDerive(
        Key128,
        ExpectedOutput128_Key128.Length,
        ExpectedOutput128_Key128)) {
        FAIL();
    }
}

TEST_P(CryptTest, Encryption)
{

    int AEAD = GetParam();

    uint8_t RawKey[32];
    uint8_t Iv[CXPLAT_IV_LENGTH];
    uint8_t AuthData[12];
    uint8_t Buffer[128];

    QuicKey Key((CXPLAT_AEAD_TYPE)AEAD, RawKey);
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
    CxPlatZeroMemory(Salt, sizeof(Salt));
    Salt[0] = 0xff;
    uint8_t Input[256];
    CxPlatZeroMemory(Input, sizeof(Input));
    Input[0] = 0xaa;

    uint8_t Output[CXPLAT_HASH_MAX_SIZE];
    CxPlatZeroMemory(Output, sizeof(Output));
    const uint16_t OutputLength = CxPlatHashLength((CXPLAT_HASH_TYPE)HASH);

    QuicHash Hash((CXPLAT_HASH_TYPE)HASH, Salt, sizeof(Salt));
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
    uint8_t Output[CXPLAT_HASH_MAX_SIZE];
    uint8_t Output2[CXPLAT_HASH_MAX_SIZE];
    const uint16_t OutputLength = CxPlatHashLength((CXPLAT_HASH_TYPE)HASH);

    CxPlatRandom(sizeof(Salt), Salt);
    CxPlatRandom(sizeof(Input), Input);

    QuicHash Hash((CXPLAT_HASH_TYPE)HASH, Salt, sizeof(Salt));
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
