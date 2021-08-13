using System;

namespace Microsoft.Quic
{
    public class QuicException : Exception
    {
        public int Status { get; }

        public QuicException(int status) : base(GetErrorCodeForStatus(status))
        {
            Status = status;
        }

        public static string GetErrorCodeForStatus(int status)
        {
            return "";
        }
    }
}
