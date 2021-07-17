using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Quic;

namespace QuicChatLib
{
    public class ClientConfiguration : IDisposable
    {
        private readonly Registration registration;
        private unsafe readonly QUIC_HANDLE* confHandle;

        public unsafe QUIC_HANDLE* Handle => confHandle;

        public unsafe ClientConfiguration(Registration registration)
        {
            this.registration = registration;

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

                QUIC_CREDENTIAL_CONFIG credConfig = new QUIC_CREDENTIAL_CONFIG();
                credConfig.Flags = QUIC_CREDENTIAL_FLAGS.QUIC_CREDENTIAL_FLAG_CLIENT | QUIC_CREDENTIAL_FLAGS.QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;

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
