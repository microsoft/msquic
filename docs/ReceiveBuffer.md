# Receive Buffer Architecture

The receive buffer, `QUIC_RECV_BUFFER` in [recv_buffer.c](../src/core/recv_buffer.c), manages the buffering and reassembly
of the crypto or stream data received from a peer. It abstracts the buffer memory management and the data reassembly logic.
Since this is core to much of the data path for QUIC, the receive buffer is highly optimized for performance, often at the price of more complexity.

## Interface

The `QUIC_RECV_BUFFER` provides a fairly simple interface to callers, in [recv_buffer.h](../src/core/recv_buffer.h).
It uses 3 main verbs:

- **Write**, `QuicRecvBufferWrite` - Writes received data to the receive buffer.
- **Read**, `QuicRecvBufferRead` - Reads the available data from the front of the receive buffer.
- **Drain**, `QuicRecvBufferDrain` - Drains a length of data from the front of the receive buffer.

Initialization, cleanup and various helper functions complete the interface, but are mainly supporting the three actions above.

### General Usage

A caller first 'writes' received data to the receive buffer, which **copies** the data locally.
Internally, the receive buffer manages the memory dynamically to ensure the appropriate amount of space is available to store the data (up to its virtual size, more on this below).
The receive buffer also manages the reassembly logic, tracking which offsets and lengths have been received.
As an output of the 'write', the receive buffer indicates if data can be read from the front of the buffer.
The caller may make multiple writes before any call to read (which improves performances by allowing several 'writes' to be batched into a single 'read').

The caller then 'reads' data. The receive buffer reads as much contiguous data as possible starting from its current reading head position.
It will populate the array of `QUIC_BUFFER` provided by the caller with pointers and length, as a **view of its internal buffers**.

Finally, the caller 'drains' data from the receive buffer. The receive buffer discards the drained data, moving its reading head by the number of drained bytes.
The receive buffer ensures that the `QUIC_BUFFER`s provided for a 'read' are valid until the data is drained (more details on this when discussing the buffer modes).
The caller doesn't necessarily drain all the data indicated by a 'read'.

Throughout the lifetime of the receive buffer, the cycle of write, read, drain calls continues until the caller is done with the receive buffer.

### Different Modes of Operation

Different modes of operation are supported by the receive buffer.

- **Single**, `QUIC_RECV_BUF_MODE_SINGLE` - Ensures a 'reads' always indicates a single contiguous buffer;
- **Circular**, `QUIC_RECV_BUF_MODE_CIRCULAR` - Default receive buffer mode, balances performances and ease of use;
- **Multiple**, `QUIC_RECV_BUF_MODE_MULTIPLE` - Allows multiple independent pending reads;
- **AppOwned**, `QUIC_RECV_BUF_MODE_APP_OWNED` - Uses memory buffers provided by the caller to write data;

The 'write' operation is similar for all modes, but the behavior of 'read' and 'drain' operations change.

#### Contiguous data buffering

The Single mode guarantees that all data indicated on a 'read' is contiguous in memory: it always returns a single `QUIC_BUFFER`.
However, Single mode needs additional data copy to implement this behavior and is less performant.
This mode is used because the TLS libraries do not support 'gather' semantics and expect to operate on single, contiguous buffers.

Other modes can indicate multiple `QUIC_BUFFER` pointing to non-continuous memory:
the number of `QUIC_BUFFER` reported on a 'read' is not fixed and is subject to change (the caller should not assume an upper bound).
In practice, Circular mode can currently use up to 2 buffers, Multiple mode up to 3 and AppOwned mode up to the number of buffers provided by the application.

#### Number of pending 'read'

For Single, Circular and AppOwned modes, only a single 'read' can be pending at a time.
Each 'read' must be paired with a 'drain' (for up to the size of the 'read', but potentially less),
before another 'read' can be done.

For the Multiple mode, multiple 'reads' can be pending simultaneously.
The number of 'drains' can differ from the number of 'read' (higher or smaller)
as long as the total number of bytes drained stays lower than the total number of bytes read at all time.

#### Partial 'drain'

For Single, Circular and AppOwned modes, the data indicated during a 'read' that is not drained will be
indicated again in the next 'read'.

For the Multiple mode, each byte of data is only indicated once.
A 'read' will always indicate data starting from the end of the previous 'read'.

#### Memory ownership

For Single, Circular and Multiple modes, the receive buffer owns the memory buffers
and gives out pointer to its internal buffers on a 'read'.

A pre-allocated buffer can be provided by the caller to optimize the receive buffer initialization,
this pre-allocated buffer is owned by the caller.

For the AppOwned mode, buffers are owned by the application and provided to the receive buffer.
The caller must ensure buffers stay valid until they are fully drained or the receive buffer is deinitialized
(more precisely, a buffer can be released by the caller as soon as all its bytes have been 'read' as long as
the matching 'drain' drains all the buffer bytes - the receive buffer ).
This allows to avoid a copy but increases the application memory management complexity.

## Internal Design

In very few words, the receive buffers does the following:

- It tracks all bytes written during the lifetime of the buffer, from byte index 0.
- It maintains a reading head pointing to the first byte that has not been drained yet,
    and the offset of that byte in the stream.
- It manages buffer allocations to store bytes written to the buffer
    - It grows the allocated buffer space as needed
    - It copies bytes to the appropriate buffer index based on their stream offset to re-order them.
- It references buffers while they are shared with the client to ensure they aren't freed.

### Data structures

`QUIC_RECV_BUFFER` store information in two main data structures, with other variables helping to manage them.

- A `WrittenRanges`, a `QUIC_RANGE` which stores which byte numbers that have been written to the receive buffer.
    It maps directly to the byte offsets from the Quic stream and stores the offsets for all bytes written to the buffer since its creation (not only the one currently stored).
- A list of `Chunks`. `QUIC_RECV_CHUNK`s are essentially memory buffers associated with control
    variables (size, list link, ...). They contain the memory allocated in the receive buffer.
    Data is read and written there.

The logic surrounding `WrittenRanges` is pretty straightforward: when data is written to the receive buffer,
the new byte offsets are inserted in `WrittenRanges`. At any time, the first contiguous segment of `WrittenRanges` is the data that has been, or can be read by the client.

The interesting logic is largely about managing the list of `Chunks`.

### Active and retired chunks

Chunks can be "active" or "retired". An active chunk data can be used by a new 'read' or 'write' operation.
A retired chunk is a chunk that is waiting to be deleted but is currently referenced by the application.
All its data has either been drained or has been copied to an active chunk, it will be deleted as soon as it isn't referenced anymore.

Currently, the single and circular can have up to one retired chunk and one active chunk.
The multiple and app-owned modes do not use retired chunks and can have multiple active chunks.

### A special chunk: the first active chunk

'Read' and 'write' operations are generally performed linearly on chunks, starting from the buffer start,
progressing through it linearly and, if more data needs to be read / written, continuing on the next chunk.

However, the first **active** chunk has a special behavior:
- it is treated as a circular buffer, starting from the reading head position (see `ReadStart` below).
- it can be shrunk, reducing the amount of buffer space that can be used (see `Capacity` below).

Once the index `(ReadStart + Capacity) % FirstChunkLength` is reached, wrapping around if needed,
the processing continues with the next chunk and progress linerarly from there.

This circular behavior allows the receive buffer to minimize copy and re-allocations.

### Control variables and invariants

`BaseOffset`
: The stream byte index of the byte at the reading head position.

`VirtualBufferLength`
: The size of the receive buffer as indicated to the client code. It doesn't necessarily correspond to the amount of memory currently allocated in the receive buffer.

**Invariant**:
- `BaseOffset` and `BaseOffset + VirtualBufferLength` must only increase through time. However, `VirtualBufferLength` can decrease.

**Invariant**: A 'write' operation must only write bytes with offset lower than `BaseOffset` + `VirtualBufferLength`. Bytes offset lower than `BaseOffset` are ignored.

`ReadPendingLength`
: The number of bytes that have been indicated to the client through a 'read' and not released by 'drain' yet.

**Invariant**:
- `BaseOffset + ReadPendingLength` is smaller than the size of the first range in `WrittenRanges`.
- For modes other than "Multiple", a 'read' is allowed if and only if `ReadPendingLength == 0` and a drain reset `ReadPendingLength` to 0.

The variables below are tracking properties of the first *active* chunk in the `Chunks` list to handle its special behavior.

`ReadStart`
: The offset of the reading head in the first active chunk.

**Invariant**: For Single mode, `ReadStart == 0`.

`Capacity`
: The usable size of the first active chunk. Only bytes in `[ReadStart, ReadStart + Capacity)` (seen in a circular way) should be accessed.
  It is used to progressively shrink the size of the first active chunk when data is 'read' and the buffer space should not be re-used (App-owned and Multiple modes).

**Invariant**: For Single and AppOwned modes, `ReadStart + Capacity` is smaller than the first active chunk size.
This implies that the chunk will never be used in a circular fashion in these modes.

`ReadLength`
: The number of bytes that can be 'read' from the first active chunk.

**Invariant**:
- `ReadLength` is the minimum between `Capacity` and `FirstRangeSize - BaseOffset` (where `FirstRangeSize` is the size of the first range in `WrittenRanges`).

### Memory Management

As mentioned above, the receive buffer generally manages memory itself and doesn't follow the common socket `recv` model of requiring the app the pre-post a buffer.
The AppOwned mode is the exception, with memory being managed by the caller. 

Internally, the receive buffer tries to minimize total memory usage, both in terms of bytes and number of unique buffers to keep at once.
It generally prefers one large chunk over multiple smaller chunks, even if this means data must be copied from one buffer to another (larger) one.
This aims to reduce the complexity of both the internal implementation and the caller implementation.

Since the receive buffer gives out pointers to its internal buffers, it must keep track of these external references and
extend the lifetimes of chunks so that they are not deleted from underneath the caller.
This means the receive buffer might keep a "retired" buffer for some time, or decide to have multiple active chunks for a while.

Another aspect of memory management is balancing the amount of memory we advertised to the peer we are willing to allocate and how much we actually allocate.
The caller controls both the advertised, maximum allocation size, as well as the initial buffer size to allocate.
The caller can dynamically increase the maximum size as necessary.

The receive buffer takes these values and dynamically allocates memory (doubling in size as necessary) up to the maximum
size - except in AppOwned mode, where the application must provide memory to match the maximum size advertised to the peer.

### Less words, more ASCII art!!

- `x`, `+`: A 'write' put data here
- `.`: No data here yet
- ` `: Bytes that should no longer be accessed

A very generic view of the receive buffer could be:

```
   Retired                                         Chunk 1                            Chunk 2              Chunk 3       
┌──────────────┐   ┌───────────────────────────────────────────────────────────┐   ┌────────────────┐   ┌──────────────┐ 
│              │   │xxx.......xxxxxxxx                   xxxxxxxxxxxxxxxxxxxxxx├──►│xxxxxxxx........├──►│xxxxxxxxxxx...│ 
└──────────────┘   └───▲──────────────▲──────────────────▲───────────────▲─────┘   └────────────────┘   └──────────────┘ 
                       │              │                  │               │                                               
                   ReadStart +      ReadStart +       ReadStart       ReadStart +                                        
                    ReadLength       Capacity                          ReadPendingLength                                 
```

This receive buffer has 1 retired chunk and 3 active chunks.
`WrittenRanges` contains 3 data segments:
- `[0, ReadStart + ReadLength]`, cycling through the end of Chunk 1;
- The second segment goes over the end of Chunk 1 and the start of Chunk 2;
- The third segment is at the start of chunk3

However, the state of the receive buffer presented above is so generic it will actually never happen:
For instance, single and circular modes would only have a single active chunk at a time.
Multiple and app-owned would not have a retired chunk.

Still, this is the model to keep in mind for code that must be compatible with all modes.

#### Circular mode

```
                                Chunk 1                              
┌───────────────────────────────────────────────────────────┐        
│xxx.......xxxxxxxx...................xxxxxxxxxxxxxxxxxxxxxx│        
└───▲─────────────────────────────────▲───────────────▲─────┘        
    │                                 │               │              
ReadStart +                        ReadStart       ReadStart +       
 ReadLength                           │             ReadPendingLength
                                      │                              
                                  ReadStart +                        
                                   Capacity                          
```

In circular mode, the data can wrap around the end. There is always a single active chunk
and the capacity is always the full buffer size. A "retired" chunk can be present in a similar way
as in the Single mode exemple below.

#### Single mode

```
   Retired                                         Chunk 1                            
┌──────────────┐   ┌───────────────────────────────────────────────────────────┐      
│xxxxxxxxxx....│   │xxxxxxxxxx+++++++...++++...................................│      
└──────────────┘   └▲─────────▲──────▲─────────────────────────────────────────▲      
                    │         │      │                                         │      
                 ReadStart    │  ReadStart +                               ReadStart +
                              │   ReadLength                                Capacity  
                              │                                                       
                          ReadStart +                                                 
                           ReadPendingLength                                          
```

In single mode, `ReadStart` is always at the front of the buffer.
A 'read' was pending and data `+` could not fit in the initial chunk: the old chunk had to be retired
until it isn't referenced anymore and data `x` was copied to the new chunk front.

#### Multiple mode

```
                                Chunk 1                            Chunk 2       
┌───────────────────────────────────────────────────────────┐   ┌────────────────┐
│xxx.......xxxxxxxx                   ++++++++++++++++xxxxxx├──►│xxxxxxxx........│
└───▲──────────────▲──────────────────▲───────────────▲─────┘   └────────────────┘
    │              │                  │               │                           
ReadStart +      ReadStart +       ReadStart       ReadStart +                    
 ReadLength       Capacity                          ReadPendingLength             
```

In multiple mode, several chunks can be active at the same time.
It took several steps to arrive to the situation above:
- Data `+` was written to the buffer
- A 'read' was performed for all the data `+`
- More data `x` was written to the buffer, causing the creation of Chunk 2 once Chunk 1 was full
    - Note that if a read was not pending on Chunk 1, data would have been copied instead to Chunk 2.
- A 'drain' was performed for part of the data `+`
    - Since a second chunk is present, the `Capacity` was shrunk as part of the drain

#### App-owned mode

```
                                Chunk 1                            Chunk 2              Chunk 3      
┌───────────────────────────────────────────────────────────┐   ┌────────────────┐   ┌──────────────┐
│                     xxxxxxxxxxxxxxxxxxxxxxxx..............├──►│xxxxxxxx........├──►│....xxxxxxx...│
└─────────────────────▲───────────────────────▲─────────────▲   └────────────────┘   └──────────────┘
                      │                       │             │                                        
                   ReadStart              ReadStart +     ReadStart +                                
                                           ReadLength      Capacity                                  
```

In app-owned mode, `ReadStart + Capacity` always point to the end of the first chunk, no wrap around ever happen.
Bytes from the start of the first chunk up to `ReadStart` should no longer be accessed:
we need to write in the provided buffer only once and in order.
Many active chunks can be present at the same time.