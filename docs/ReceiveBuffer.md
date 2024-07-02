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

