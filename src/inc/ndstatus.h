/*++

Copyright (c) Microsoft Corporation.  All rights reserved.

ndstatus.h - NetworkDirect Status Codes

Status codes with a facility of System map to NTSTATUS codes
of similar names.

--*/

#ifndef _NDSTATUS_
#define _NDSTATUS_

#pragma once


//
//  Values are 32 bit values laid out as follows:
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//  +---+-+-+-----------------------+-------------------------------+
//  |Sev|C|R|     Facility          |               Code            |
//  +---+-+-+-----------------------+-------------------------------+
//
//  where
//
//      Sev - is the severity code
//
//          00 - Success
//          01 - Informational
//          10 - Warning
//          11 - Error
//
//      C - is the Customer code flag
//
//      R - is a reserved bit
//
//      Facility - is the facility code
//
//      Code - is the facility's status code
//
//
// Define the facility codes
//


//
// Define the severity codes
//
#define STATUS_SEVERITY_SUCCESS          0x0
#define STATUS_SEVERITY_INFORMATIONAL    0x1
#define STATUS_SEVERITY_WARNING          0x2
#define STATUS_SEVERITY_ERROR            0x3


//
// MessageId: ND_SUCCESS
//
// MessageText:
//
//  ND_SUCCESS
//
#define ND_SUCCESS                       ((HRESULT)0x00000000L)

//
// MessageId: ND_TIMEOUT
//
// MessageText:
//
//  ND_TIMEOUT
//
#define ND_TIMEOUT                       ((HRESULT)0x00000102L)

//
// MessageId: ND_PENDING
//
// MessageText:
//
//  ND_PENDING
//
#define ND_PENDING                       ((HRESULT)0x00000103L)

//
// MessageId: ND_BUFFER_OVERFLOW
//
// MessageText:
//
//  ND_BUFFER_OVERFLOW
//
#define ND_BUFFER_OVERFLOW               ((HRESULT)0x80000005L)

//
// MessageId: ND_DEVICE_BUSY
//
// MessageText:
//
//  ND_DEVICE_BUSY
//
#define ND_DEVICE_BUSY                   ((HRESULT)0x80000011L)

//
// MessageId: ND_NO_MORE_ENTRIES
//
// MessageText:
//
//  ND_NO_MORE_ENTRIES
//
#define ND_NO_MORE_ENTRIES               ((HRESULT)0x8000001AL)

//
// MessageId: ND_UNSUCCESSFUL
//
// MessageText:
//
//  ND_UNSUCCESSFUL
//
#define ND_UNSUCCESSFUL                  ((HRESULT)0xC0000001L)

//
// MessageId: ND_ACCESS_VIOLATION
//
// MessageText:
//
//  ND_ACCESS_VIOLATION
//
#define ND_ACCESS_VIOLATION              ((HRESULT)0xC0000005L)

//
// MessageId: ND_INVALID_HANDLE
//
// MessageText:
//
//  ND_INVALID_HANDLE
//
#define ND_INVALID_HANDLE                ((HRESULT)0xC0000008L)

//
// MessageId: ND_INVALID_DEVICE_REQUEST
//
// MessageText:
//
//  ND_INVALID_DEVICE_REQUEST
//
#define ND_INVALID_DEVICE_REQUEST        ((HRESULT)0xC0000010L)

//
// MessageId: ND_INVALID_PARAMETER
//
// MessageText:
//
//  ND_INVALID_PARAMETER
//
#define ND_INVALID_PARAMETER             ((HRESULT)0xC000000DL)

//
// MessageId: ND_NO_MEMORY
//
// MessageText:
//
//  ND_NO_MEMORY
//
#define ND_NO_MEMORY                     ((HRESULT)0xC0000017L)

//
// MessageId: ND_INVALID_PARAMETER_MIX
//
// MessageText:
//
//  ND_INVALID_PARAMETER_MIX
//
#define ND_INVALID_PARAMETER_MIX         ((HRESULT)0xC0000030L)

//
// MessageId: ND_DATA_OVERRUN
//
// MessageText:
//
//  ND_DATA_OVERRUN
//
#define ND_DATA_OVERRUN                  ((HRESULT)0xC000003CL)

//
// MessageId: ND_SHARING_VIOLATION
//
// MessageText:
//
//  ND_SHARING_VIOLATION
//
#define ND_SHARING_VIOLATION             ((HRESULT)0xC0000043L)

//
// MessageId: ND_INSUFFICIENT_RESOURCES
//
// MessageText:
//
//  ND_INSUFFICIENT_RESOURCES
//
#define ND_INSUFFICIENT_RESOURCES        ((HRESULT)0xC000009AL)

//
// MessageId: ND_DEVICE_NOT_READY
//
// MessageText:
//
//  ND_DEVICE_NOT_READY
//
#define ND_DEVICE_NOT_READY              ((HRESULT)0xC00000A3L)

//
// MessageId: ND_IO_TIMEOUT
//
// MessageText:
//
//  ND_IO_TIMEOUT
//
#define ND_IO_TIMEOUT                    ((HRESULT)0xC00000B5L)

//
// MessageId: ND_NOT_SUPPORTED
//
// MessageText:
//
//  ND_NOT_SUPPORTED
//
#define ND_NOT_SUPPORTED                 ((HRESULT)0xC00000BBL)

//
// MessageId: ND_INTERNAL_ERROR
//
// MessageText:
//
//  ND_INTERNAL_ERROR
//
#define ND_INTERNAL_ERROR                ((HRESULT)0xC00000E5L)

//
// MessageId: ND_INVALID_PARAMETER_1
//
// MessageText:
//
//  ND_INVALID_PARAMETER_1
//
#define ND_INVALID_PARAMETER_1           ((HRESULT)0xC00000EFL)

//
// MessageId: ND_INVALID_PARAMETER_2
//
// MessageText:
//
//  ND_INVALID_PARAMETER_2
//
#define ND_INVALID_PARAMETER_2           ((HRESULT)0xC00000F0L)

//
// MessageId: ND_INVALID_PARAMETER_3
//
// MessageText:
//
//  ND_INVALID_PARAMETER_3
//
#define ND_INVALID_PARAMETER_3           ((HRESULT)0xC00000F1L)

//
// MessageId: ND_INVALID_PARAMETER_4
//
// MessageText:
//
//  ND_INVALID_PARAMETER_4
//
#define ND_INVALID_PARAMETER_4           ((HRESULT)0xC00000F2L)

//
// MessageId: ND_INVALID_PARAMETER_5
//
// MessageText:
//
//  ND_INVALID_PARAMETER_5
//
#define ND_INVALID_PARAMETER_5           ((HRESULT)0xC00000F3L)

//
// MessageId: ND_INVALID_PARAMETER_6
//
// MessageText:
//
//  ND_INVALID_PARAMETER_6
//
#define ND_INVALID_PARAMETER_6           ((HRESULT)0xC00000F4L)

//
// MessageId: ND_INVALID_PARAMETER_7
//
// MessageText:
//
//  ND_INVALID_PARAMETER_7
//
#define ND_INVALID_PARAMETER_7           ((HRESULT)0xC00000F5L)

//
// MessageId: ND_INVALID_PARAMETER_8
//
// MessageText:
//
//  ND_INVALID_PARAMETER_8
//
#define ND_INVALID_PARAMETER_8           ((HRESULT)0xC00000F6L)

//
// MessageId: ND_INVALID_PARAMETER_9
//
// MessageText:
//
//  ND_INVALID_PARAMETER_9
//
#define ND_INVALID_PARAMETER_9           ((HRESULT)0xC00000F7L)

//
// MessageId: ND_INVALID_PARAMETER_10
//
// MessageText:
//
//  ND_INVALID_PARAMETER_10
//
#define ND_INVALID_PARAMETER_10          ((HRESULT)0xC00000F8L)

//
// MessageId: ND_CANCELED
//
// MessageText:
//
//  ND_CANCELED
//
#define ND_CANCELED                      ((HRESULT)0xC0000120L)

//
// MessageId: ND_REMOTE_ERROR
//
// MessageText:
//
//  ND_REMOTE_ERROR
//
#define ND_REMOTE_ERROR                  ((HRESULT)0xC000013DL)

//
// MessageId: ND_INVALID_ADDRESS
//
// MessageText:
//
//  ND_INVALID_ADDRESS
//
#define ND_INVALID_ADDRESS               ((HRESULT)0xC0000141L)

//
// MessageId: ND_INVALID_DEVICE_STATE
//
// MessageText:
//
//  ND_INVALID_DEVICE_STATE
//
#define ND_INVALID_DEVICE_STATE          ((HRESULT)0xC0000184L)

//
// MessageId: ND_INVALID_BUFFER_SIZE
//
// MessageText:
//
//  ND_INVALID_BUFFER_SIZE
//
#define ND_INVALID_BUFFER_SIZE           ((HRESULT)0xC0000206L)

//
// MessageId: ND_TOO_MANY_ADDRESSES
//
// MessageText:
//
//  ND_TOO_MANY_ADDRESSES
//
#define ND_TOO_MANY_ADDRESSES            ((HRESULT)0xC0000209L)

//
// MessageId: ND_ADDRESS_ALREADY_EXISTS
//
// MessageText:
//
//  ND_ADDRESS_ALREADY_EXISTS
//
#define ND_ADDRESS_ALREADY_EXISTS        ((HRESULT)0xC000020AL)

//
// MessageId: ND_CONNECTION_REFUSED
//
// MessageText:
//
//  ND_CONNECTION_REFUSED
//
#define ND_CONNECTION_REFUSED            ((HRESULT)0xC0000236L)

//
// MessageId: ND_CONNECTION_INVALID
//
// MessageText:
//
//  ND_CONNECTION_INVALID
//
#define ND_CONNECTION_INVALID            ((HRESULT)0xC000023AL)

//
// MessageId: ND_CONNECTION_ACTIVE
//
// MessageText:
//
//  ND_CONNECTION_ACTIVE
//
#define ND_CONNECTION_ACTIVE             ((HRESULT)0xC000023BL)

//
// MessageId: ND_NETWORK_UNREACHABLE
//
// MessageText:
//
//  ND_NETWORK_UNREACHABLE
//
#define ND_NETWORK_UNREACHABLE           ((HRESULT)0xC000023CL)

//
// MessageId: ND_HOST_UNREACHABLE
//
// MessageText:
//
//  ND_HOST_UNREACHABLE
//
#define ND_HOST_UNREACHABLE              ((HRESULT)0xC000023DL)

//
// MessageId: ND_CONNECTION_ABORTED
//
// MessageText:
//
//  ND_CONNECTION_ABORTED
//
#define ND_CONNECTION_ABORTED            ((HRESULT)0xC0000241L)

//
// MessageId: ND_DEVICE_REMOVED
//
// MessageText:
//
//  ND_DEVICE_REMOVED
//
#define ND_DEVICE_REMOVED                ((HRESULT)0xC00002B6L)

#endif // _NDSTATUS_
