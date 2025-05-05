/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    QUIC Debugger Extension Declarations and Helpers.

    DML Output Documentation available at:
        https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/customizing-debugger-output-using-dml

--*/

#pragma once

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#define EXTCPP_EXPORTS

#include <windows.h>
#include <ws2def.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <stdint.h>

#include <engextcpp.hpp>

#include <stdio.h>

extern ULONG g_ulDebug;

#define DEBUG_LEVEL_ERROR   0
#define DEBUG_LEVEL_QUIET   1
#define DEBUG_LEVLE_INFO    2
#define DEBUG_LEVEL_TRACE   3
#define DEBUG_LEVEL_VERBOSE 4
#define DEBUG_LEVEL_LOUD    5

#define dpError(format, ...) \
    if (g_ulDebug >= DEBUG_LEVEL_ERROR) dprintf(format, ##__VA_ARGS__)

//
// Base extension class.
// Extensions derive from the provided ExtExtension class.
//
// The standard class name is "Extension". It can be overridden by providing
// an alternate definition of EXT_CLASS before including engextcpp.hpp.
//
// More documentation in minkernel/debuggers/published/engextcpp.w
//
//
class EXT_CLASS : public ExtExtension {

public:

    EXT_COMMAND_METHOD(quicanalyze);
    EXT_COMMAND_METHOD(quicbinding);
    EXT_COMMAND_METHOD(quicconfiguration);
    EXT_COMMAND_METHOD(quicconn);
    EXT_COMMAND_METHOD(quicconnection);
    EXT_COMMAND_METHOD(quicdump);
    EXT_COMMAND_METHOD(quicdumpqueue);
    EXT_COMMAND_METHOD(quichandle);
    EXT_COMMAND_METHOD(quiclib);
    EXT_COMMAND_METHOD(quiclibrary);
    EXT_COMMAND_METHOD(quiclistener);
    EXT_COMMAND_METHOD(quicpacket);
    EXT_COMMAND_METHOD(quicregistration);
    EXT_COMMAND_METHOD(quicstream);
    EXT_COMMAND_METHOD(quicworker);

    //
    // Called by a command when symbols don't seem to be resolving.
    //
    void
    OnSymbolsError(
        )
    {
        m_Control->ControlledOutput(
            DEBUG_OUTCTL_AMBIENT_DML,
            DEBUG_OUTPUT_NORMAL,
            "<b><col fg=\"ebpbg\">"
                "Can't resolve msquic symbols."
            "</col></b>\n");
    }

    void AnalyzeConnection(UINT64 Addr);
    void AnalyzeStream(UINT64 Addr);
};

extern EXT_CLASS g_ExtInstance;

inline
bool
IsEqualPointer(
    _In_ ULONG64 Address1,
    _In_ ULONG64 Address2
    )
{
    if (g_ExtInstance.m_PtrSize == 8) {
        return (Address1 == Address2);
    } else { // g_ExtInstance.m_PtrSize == 4
        return ((Address1 & 0xFFFFFFFF) == (Address2 & 0xFFFFFFFF));
    }
}

//
// Reads a non-pointer type at the given address.
//
template<typename T>
bool
ReadTypeAtAddr(
    _In_ ULONG64 Addr,
    _Out_ T* Value
    )
{
    ULONG cbRead;
    if (!ReadMemory(Addr, Value, sizeof(T), &cbRead)) {
        dpError("Error reading at %p\n", Addr);
        return false;
    }
    return true;
}

//
// Reads a pointer at the given address. The size of the pointer is
// determined by the current target.
//
inline
bool
ReadPointerAtAddr(
    _In_ ULONG64 Addr,
    _Out_ ULONG64* Value
    )
{
    ULONG cbRead;
    if (!ReadMemory(Addr, Value, g_ExtInstance.m_PtrSize, &cbRead)) {
        dpError("Error reading at %p\n", Addr);
        return false;
    }
    return true;
}

//
// Reads a null-terminated string at the given address.
//
inline
size_t
ReadStringAtAddr(
    _In_ ULONG64 Addr,
    _In_ size_t MaxLength,
    _Out_writes_bytes_(MaxLength)
        char Value[256]
    )
{
    ULONG cbRead;
    size_t offset = 0;
    while (offset + 1 < MaxLength && !CheckControlC()) {
        if (!ReadMemory(Addr + offset, Value + offset, sizeof(char), &cbRead) ||
            Value[offset] == 0) {
            break;
        }
        offset++;
    }
    Value[offset] = 0;
    return offset;
}

//
// Reads a non-pointer type from a struct at the given address.
//
template<typename T>
bool
ReadTypeFromStructAddr(
    _In_ ULONG64 StructAddr,
    _In_ PSTR StructType,
    _In_ PSTR FieldName,
    _Out_ T* Value
    )
{
    ULONG FieldOffset;
    if (0 != GetFieldOffset(StructType, FieldName, &FieldOffset)){
        dpError("GetFieldOffset failed struct=%s field=%s\n", StructType, FieldName);
        return false;
    }
    return ReadTypeAtAddr(StructAddr + FieldOffset, Value);
}

//
// Reads a pointer type from a struct at the given address. The size of
// the pointer is determined by the current target.
//
inline
bool
ReadPointerFromStructAddr(
    _In_ ULONG64 StructAddr,
    _In_ PSTR StructType,
    _In_ PSTR FieldName,
    _Out_ ULONG64* Value
    )
{
    ULONG FieldOffset;
    if (0 != GetFieldOffset(StructType, FieldName, &FieldOffset)){
        dpError("GetFieldOffset failed struct=%s field=%s\n", StructType, FieldName);
        return false;
    }
    return ReadPointerAtAddr(StructAddr + FieldOffset, Value);
}

//
// Helper for reading many fields from a single struct.
//
struct Struct {
    PSTR Type;
    ULONG64 Addr;
    Struct(PSTR type, ULONG64 addr) : Type(type), Addr(addr) { }
    ULONG
    OffsetOf(
        _In_ PSTR FieldName
        )
    {
        ULONG FieldOffset;
        if (0 != GetFieldOffset(Type, FieldName, &FieldOffset)){
            dpError("GetFieldOffset failed struct=%s field=%s\n", Type, FieldName);
        }
        return FieldOffset;
    }
    ULONG64
    AddrOf(
        _In_ PSTR FieldName
        )
    {
        ULONG FieldOffset;
        if (0 != GetFieldOffset(Type, FieldName, &FieldOffset)){
            dpError("GetFieldOffset failed struct=%s field=%s\n", Type, FieldName);
        }
        return Addr + FieldOffset;
    }
    template<typename T>
    T
    ReadType(
        _In_ PSTR FieldName
        )
    {
        T Value;
        ReadTypeFromStructAddr(Addr, Type, FieldName, &Value);
        return Value;
    }
    template<typename T>
    T
    ReadTypeAtOffset(
        _In_ ULONG Offset
        )
    {
        T Value;
        ReadTypeAtAddr(Addr + Offset, &Value);
        return Value;
    }
    ULONG64
    ReadPointer(
        _In_ PSTR FieldName
        )
    {
        ULONG64 Value;
        ReadPointerFromStructAddr(Addr, Type, FieldName, &Value);
        return Value;
    }
    ULONG64
    ReadPointerAtOffset(
        _In_ ULONG Offset
        )
    {
        ULONG64 Value;
        ReadPointerAtAddr(Addr + Offset, &Value);
        return Value;
    }
};

struct String {
    ULONG64 Addr;
    char Data[256];

    String() : Addr(0) { Data[0] = 0; }

    String(ULONG64 Addr) : Addr(Addr) {
        ReadStringAtAddr(Addr, sizeof(Data), Data);
    }

    String(ULONG64 Addr, ULONG Length) : Addr(Addr) {
        ULONG cbRead;
        ReadMemory(Addr, Data, Length, &cbRead);
        Data[Length] = 0;
    }
};

struct IpAddress {
    SOCKADDR_INET Raw;
    char IpString[256];

    IpAddress(ULONG64 Addr) {
        ReadTypeAtAddr(Addr, &Raw);
        ULONG StringLen = sizeof(String);
        if (Raw.si_family == AF_UNSPEC) {
            sprintf(IpString, "UNSPEC:%u", ntohs(Raw.Ipv4.sin_port));
        } else if (Raw.si_family == AF_INET) {
            RtlIpv4AddressToStringExA(&Raw.Ipv4.sin_addr, Raw.Ipv4.sin_port, IpString, &StringLen);
        } else {
            RtlIpv6AddressToStringExA(&Raw.Ipv6.sin6_addr, 0, Raw.Ipv6.sin6_port, IpString, &StringLen);
        }
    }
};
