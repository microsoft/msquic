//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//

using System;
using System.Net;
using CtfPlayback.FieldValues;
using CtfPlayback.Metadata.Helpers;

namespace QuicTrace.DataModel.LTTng
{
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "IDE2001:Embedded statements must be on their own line", Justification = "<Pending>")]
    internal unsafe ref struct QuicLTTngDataReader
    {
        private readonly int PointerSize;
        private readonly CtfStructValue Payload;
        private int Index;

        internal QuicLTTngDataReader(CtfStructValue payload, int pointerSize)
        {
            Payload = payload;
            Index = 2; // start from 2
            PointerSize = pointerSize;
        }
        private object GetValue(string value, Type type)
        {
            return Convert.ChangeType(value, type);
        }

        internal IntegerLiteral Preprocess()
        {
            var val = (CtfIntegerValue)Payload.FieldsByName[string.Concat("_arg", Index.ToString())];
            Index++;
            return val.Value;
        }

        internal byte ReadByte()
        {
            var data = Preprocess();
            byte val;
            if (!data.TryGetUInt8(out val)) throw new InvalidCastException();
            return val;
        }

        internal ushort ReadUShort()
        {
            var data = Preprocess();
            ushort val;
            if (!data.TryGetUInt16(out val)) throw new InvalidCastException();
            return val;
        }

        internal uint ReadUInt()
        {
            var data = Preprocess();
            uint val;
            if (!data.TryGetUInt32(out val)) throw new InvalidCastException();
            return val;
        }

        internal ulong ReadULong()
        {
            var data = Preprocess();
            ulong val;
            if (!data.TryGetUInt64(out val)) throw new InvalidCastException();
            return val;
        }
        internal ulong ReadPointer()
        {
            return PointerSize == 8 ? ReadULong() : ReadUInt();
        }

        internal byte[] ReadBytes()
        {
            var argstr = string.Concat("_arg", Index.ToString());
            Index++;
            return ((CtfArrayValue)Payload.FieldsByName[argstr]).ReadAsUInt8Array();
        }

        internal string ReadString()
        {
            var val = ((CtfStringValue)Payload.FieldsByName[string.Concat("_arg", Index.ToString())]).Value;
            Index++;
            return val;
        }

        internal IPEndPoint ReadAddress()
        {
            var argstr = string.Concat("_arg", Index.ToString());
            Index++;
            var length = uint.Parse(Payload.FieldsByName[string.Concat(argstr, "_len")].GetValueAsString());
            if (length == 0)
            {
                return new IPEndPoint(IPAddress.None, 0);
            }

            var buf = ((CtfArrayValue)Payload.FieldsByName[argstr]).ReadAsUInt8Array();
            int family = buf[0] | buf[1] << 8;
            int port = buf[3] | buf[2] << 8;

            if (family == 0) // unspecified
            {
                return new IPEndPoint(IPAddress.Any, port);
            }
            else if (family == 2) // v4
            {
                return new IPEndPoint(new IPAddress(buf[4..8]), port);
            }
            else // v6
            {
                return new IPEndPoint(new IPAddress(buf[4..20]), port);
            }
        }
    }
}
