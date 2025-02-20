# Receive Buffer Architecture

The receive buffer interface, `QUIC_RECV_BUFFER` in [recv_buffer.c](../src/core/recv_buffer.c), manages the crypto or stream data received from the peer.
It is generally responsible for memory management and reassembly of the data.
Since this is core to much of the data path for QUIC, the interface is highly optimized for performance, often trading complexity for perf.
As a result, the inner workings of the interface is quite complex and requires this document to help explain it.

## Interface

The `QUIC_RECV_BUFFER` provides a fairly simple external interface to callers, in [recv_buffer.h](../src/core/recv_buffer.h):

- **QuicRecvBufferWrite** - Writes received data to the receive buffer.
- **QuicRecvBufferRead** - Reads the available data from the front of the receive buffer.
- **QuicRecvBufferDrain** - Drains a length of data from the front of the receive buffer.

There are also initialization, cleanup and a few helper functions, but the above functions consistute the bulk of the logic (and complexity).

### General Usage

Using the above functions a caller takes received data and 'writes' it to the receive buffer, which then **copies** the data locally.
Internally, the receive buffer manages the memory dynamically to ensure the appropriate amount of space is available to store the data.
The receive buffer also manages the reassembly logic, tracking which offsets and lengths have been received.
As an output of the write, the receive buffer indicates to the caller if there is now new data that should be read from the front of the buffer.
The caller may make multiple writes before any call to read.
By doing so, this will improve the performance of the read call because all the written data may be batched into a single read.

When the app is ready to read, it passes an array of `QUIC_BUFFER` objects (which hold a pointer a length) to the receive buffer to read out any data available at the front of the logical buffer.
It is a logical buffer in the sense that internally it may be represented by one or more physical buffers (details later).
The receive buffer gathers the **pointers to its internal buffers** and returns them to the caller, internally marking them as now having an external reference.

The caller then does whatever processing it needs on the read data. 
**In the meantime, additional write calls may be made.**
Once the caller is done with the data it drains the amount of data it processed, **which may be less than the amount of data it read**.
There may be cases where a caller cannot currently process all the read data, so this is why it may not drain all the data.

Throughout the lifetime of the receive buffer, the circle of write, read, drain calls continues until the caller is done with the receive buffer.

### Different Modes of Operation

To augment the above usage, the receive buffer has 3 different modes of operation:

- **QUIC_RECV_BUF_MODE_SINGLE** - Only one read with a single contiguous buffer at a time.
- **QUIC_RECV_BUF_MODE_CIRCULAR** - Only one read that may indicate two contiguous buffers at a time.
- **QUIC_RECV_BUF_MODE_MULTIPLE** - Multiple independent reads that may indicate up to three contiguous buffers at a time.

There are multiple different modes because there are different types of callers in QUIC.

The crypto layer that manages received TLS payload uses the **QUIC_RECV_BUF_MODE_SINGLE** mode because the TLS libraries that the data is eventually passed to do not support 'gather' read semantics, and expect single, contiguous buffers each time.

The stream layer supports 'gather' reads and indicates arrays of `QUIC_BUFFER` objects up to the application layer; but the apps only expect a single outstanding receive event at any one time.
So, the stream layer uses the **QUIC_RECV_BUF_MODE_CIRCULAR** mode.

Finally, applications may opt in to receiving multiple outstanding receive events at once for their streams.
For these scenarios, the stream will change to use the **QUIC_RECV_BUF_MODE_MULTIPLE** mode.

## Memory Management

As mentioned above, the receive buffer interface manages memory itself, and doesn't employ the common socket `recv` model of requiring the app the pre-post a buffer to copy into.
The goal is to eliminate the cost and complexity of memory management for all applications built on top.
This way the code is developed, tested and maintained in one place so that all may benefit.

Internally, the receive buffer tries to minimize total memory usage, both in terms of bytes and number of unique buffers to keep at once.
It will prefer one larger allocation over managing two smaller, separate buffers, even if this means data must be copied from one buffer to another (larger) one.
The goal is the minimize the complexity of managing multiple buffer, as much as possible, for both the receive buffer internally as well as the caller on top.

Because the receive buffer gives out pointers to the internal buffers, it must also keep track of these external references so as to not delete (to allocate additional space) those buffers out from underneath the caller.
This means that while the receive buffer tries to keep only one internal buffer, it might have multiple while apps have outstanding read data.

Another aspect of memory management is balancing what is advertised (in terms of flow control) to the peer, as the amount of memory we're willing to allocate, compared to how much we try to keep allocated.
The caller controls both the advertised, maximum allocation size, as well as the initial buffer size to allocate.
The receive buffer takes these values and dynamically allocates memory (doubling in size as necessary) up to the maximum size. Finally, it exposes the ability for the app to dynamically increase the max as necessary.

## Design

TODO

