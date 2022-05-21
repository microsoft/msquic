#pragma warning disable IDE0073
//
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
#pragma warning restore IDE0073

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Microsoft.Quic.Polyfill
{
#if NETSTANDARD
    internal static class OperatingSystem
    {
        public static bool IsWindows()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
        }

        public static bool IsLinux()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Linux);
        }

        public static bool IsAndroid()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.Linux);
        }

        public static bool IsMacOS()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        }

        public static bool IsIOS()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        }

        public static bool IsMacCatalyst()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        }

        public static bool IsTvOS()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        }

        public static bool IsWatchOS()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.OSX);
        }

        public static bool IsFreeBSD()
        {
            return false;
        }
    }
#endif

#if NETSTANDARD && !NETSTANDARD2_1_OR_GREATER
    internal static class MemoryMarshal
    {
        public static ref T GetReference<T>(Span<T> span) {
            return ref span.GetPinnableReference();
        }

        public static unsafe Span<T> CreateSpan<T>(ref T reference, int length) {
            return new(Unsafe.AsPointer(ref reference), length);
        }
    }
#endif
}
