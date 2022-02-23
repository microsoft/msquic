/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

--*/

#pragma warning(disable:4100)  // unreferenced formal parameter
#pragma warning(disable:4189)  // local variable is initialized but not referenced
#pragma warning(disable:4200)  // nonstandard extension used: bit field types other than int
#pragma warning(disable:4201)  // nonstandard extension used: nameless struct/union
#pragma warning(disable:4204)  // nonstandard extension used: non-constant aggregate initializer
#pragma warning(disable:4214)  // nonstandard extension used: zero-sized array in struct/union
#pragma warning(disable:4324)  // structure was padded due to alignment specifier
#pragma warning(disable:26035) // Precondition Nulltermination Violation
#pragma warning(disable:26451) // Arithmetic overflow: Using operator '+' on a 4 byte value and then casting the result to a 8 byte value.
#pragma warning(disable:28931) // Unused Assignment

#define QUIC_API_ENABLE_INSECURE_FEATURES 1
#define QUIC_API_ENABLE_PREVIEW_FEATURES 1

//
// Platform or Public Headers.
//
#include "quic_platform.h"
#include "quic_datapath.h"
#include "quic_storage.h"
#include "quic_tls.h"
#include "quic_versions.h"
#include "quic_var_int.h"
#include "quic_trace.h"

#include "msquic.h"
#include "msquicp.h"

#define QUIC_VERSION_ONLY 1
#include "msquic.ver"

//
// Internal Core Headers.
//
#include "quicdef.h"
#include "cid.h"
#include "mtu_discovery.h"
#include "path.h"
#include "transport_params.h"
#include "lookup.h"
#include "timer_wheel.h"
#include "settings.h"
#include "library.h"
#include "operation.h"
#include "binding.h"
#include "api.h"
#include "registration.h"
#include "configuration.h"
#include "range.h"
#include "recv_buffer.h"
#include "send_buffer.h"
#include "frame.h"
#include "packet.h"
#include "sent_packet_metadata.h"
#include "worker.h"
#include "ack_tracker.h"
#include "packet_space.h"
#include "congestion_control.h"
#include "loss_detection.h"
#include "send.h"
#include "crypto.h"
#include "stream.h"
#include "stream_set.h"
#include "datagram.h"
#include "version_neg.h"
#include "connection.h"
#include "packet_builder.h"
#include "listener.h"
#include "cubic.h"
