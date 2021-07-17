using System;
using Microsoft.Quic;

namespace QuicChatLib
{
    public class ServerConfiguration : IDisposable
    {
        private readonly Registration registration;
        private readonly unsafe QUIC_HANDLE* confHandle;

        public unsafe QUIC_HANDLE* Handle => confHandle;

        byte DecodeHexChar(char c)
        {
            if (c >= '0' && c <= '9') return (byte)(c - '0');
            if (c >= 'A' && c <= 'F') return (byte)(10 + c - 'A');
            if (c >= 'a' && c <= 'f') return (byte)(10 + c - 'a');
            return 0;
        }

        public unsafe ServerConfiguration(Registration registration, string thumbprint)
        {
            this.registration = registration;

            if (thumbprint.Length != 40)
            {
                throw new ArgumentException("thumpbrint must be 40 hex characters");
            }

            fixed (byte* alpn = Constants.Alpn)
            {
                QUIC_BUFFER buffer;
                buffer.Buffer = alpn;
                buffer.Length = (uint)Constants.Alpn.Length;

                QUIC_SETTINGS settings = new QUIC_SETTINGS();
                settings.IsSetFlags = 0;
                settings.PeerBidiStreamCount = 1;
                settings.IsSet.PeerBidiStreamCount = 1;

                QUIC_HANDLE* handle = null;

                QUIC_CERTIFICATE_HASH hash = new();
                Span<byte> hashSpan = new Span<byte>(hash.ShaHash, 20);
                for (int i = 0; i < thumbprint.Length / 2; i++)
                {
                    ReadOnlySpan<char> chars = thumbprint.AsSpan().Slice(i * 2, 2);
                    byte n = DecodeHexChar(chars[0]);
                    byte a = (byte)((DecodeHexChar(chars[0]) & 0xF) << 4);
                    byte b = (byte)(DecodeHexChar(chars[1]) & 0xF);
                    hashSpan[i] = (byte)(a | b);
                }

                QUIC_CREDENTIAL_CONFIG credConfig = new QUIC_CREDENTIAL_CONFIG();
                credConfig.Type = QUIC_CREDENTIAL_TYPE.QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH;
                credConfig.CertificateHash = &hash;
                credConfig.Flags = 0;

                int status = registration.Table.ConfigurationOpen(registration.Handle, &buffer, 1, &settings, (uint)sizeof(QUIC_SETTINGS), null, &handle);
                MsQuic.ThrowIfFailure(status);
                status = registration.Table.ConfigurationLoadCredential(handle, &credConfig);
                MsQuic.ThrowIfFailure(status);
                confHandle = handle;
            }
        }

        public unsafe void Dispose()
        {
            registration.Table.ConfigurationClose(confHandle);
        }
    }
}
