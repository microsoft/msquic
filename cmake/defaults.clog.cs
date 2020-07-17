/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

namespace defaults.clog_config
{
    public class Types
    {
        public static string DecodePointer(ulong pointer)
        {
            return "CLOG_POINTER:" + pointer.ToString("x");
        }

        public static string DecodeUInt32(uint value)
        {
            return "CLOG_UINT32:" + value.ToString();
        }

        public static string DecodeInt32(int value)
        {
            return "CLOG_INT32:" + value.ToString();
        }

        public static string DecodeInt8(byte value)
        {
            return "CLOG_INT8:" + value.ToString();
        }
    }
}
