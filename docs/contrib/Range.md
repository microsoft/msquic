# Range Architecture

The range, `QUIC_RANGE` in [range.h](../../src/core/range.h) and
[range.c](../../src/core/range.c), tracks a set of unique 64-bit values as an
ordered list of contiguous subranges. It is used for packet numbers,
acknowledged stream or crypto offsets, and received byte offsets.

For example, the values `1, 2, 3, 7, 8, 20` are stored as three records:

```text
Index 0: Low = 1,  Count = 3  -> 1, 2, 3
Index 1: Low = 7,  Count = 2  -> 7, 8
Index 2: Low = 20, Count = 1  -> 20
```

The common range logic owns ordering, searching, merging, trimming, and the
public interface. The records can be stored by either a contiguous array or a
tiered collection of fixed-size blocks. Callers see the same logical sequence
regardless of the active storage representation.

## Interface

The `QUIC_RANGE` interface is declared in
[range.h](../../src/core/range.h). Callers interact with it through:

- **Add**, `QuicRangeAddValue` and `QuicRangeAddRange` - Inserts values and
  merges overlapping or adjacent subranges.
- **Query**, `QuicRangeGetRange`, `QuicRangeGetMin`, `QuicRangeGetMax`,
  `QuicRangeSize`, and `QuicRangeGet` - Searches or enumerates the normalized
  subranges.
- **Discard**, `QuicRangeSetMin` and `QuicRangeRemoveSubranges` - Trims values
  from the front or removes logical subrange records.

Initialization, reset, and cleanup complete the interface.

### General Usage

A caller initializes a range with:

- `MaxAllocSize`, the byte budget for its active storage representation.
- `AllowedModes`, the storage representations that the caller permits.

Every range starts in array mode. A caller can allow:

- `QUIC_RANGE_MODE_ARRAY`
- `QUIC_RANGE_MODE_ARRAY | QUIC_RANGE_MODE_TIERED`

Tiered-only initialization is not supported. `Mode` identifies the active
representation, while `AllowedModes` records the policy chosen at
initialization. These values are intentionally separate: a tiered-capable range
still begins in array mode and promotes only when necessary.

The caller normally adds values or ranges and lets `QUIC_RANGE` normalize them.
Adding a value already present does not create another record. Adding a range
that overlaps or touches existing records expands the first matching record and
removes any later records that it subsumes.

`QuicRangeSize` returns the number of `QUIC_SUBRANGE` records, not the number of
individual 64-bit values represented by those records.

Pointers returned by `QuicRangeGet` or `QuicRangeAddRange` refer to internal
storage. A later mutation can move records or replace the active
representation, so callers must not assume those pointers remain valid across
mutations.

### Subrange Representation

Each logical record is a `QUIC_SUBRANGE`, declared in
[range_subrange.h](../../src/core/range_subrange.h):

`Low`
: The smallest value represented by the record.

`Count`
: The number of consecutive values represented by the record.

The inclusive high value is:

```text
High = Low + Count - 1
```

The common logical invariants are:

- Every record has a nonzero `Count`.
- Records are ordered by increasing `Low`.
- Records do not overlap.
- Adjacent records are merged, so there is at least one missing value between
  consecutive records.
- Logical indexes identify subrange records, not individual values.
- The first record contains the minimum value.
- The final record contains the maximum value.

## Storage Modes

The two backends trade simple contiguous storage for scalable mutation without
reallocating one very large array.

| Mode | Storage | Normal use |
|---|---|---|
| Array | Embedded records, then one contiguous heap allocation | All ranges and all small range sets |
| Tiered | A directory of independent 256-record blocks | Large range sets whose callers explicitly opt in |

The following current callers opt in to tiered storage:

- Stream sparse acknowledgement ranges.
- Crypto sparse acknowledgement ranges.
- Receive-buffer written ranges.

Packet-number ACK tracking, duplicate detection, and decoded ACK workspaces
remain array-only because their bounded behavior is part of their existing
policy.

## Internal Design

At a high level, the implementation:

- Stores a sorted logical vector of normalized `QUIC_SUBRANGE` records.
- Uses binary search to locate overlapping records or insertion positions.
- Keeps interval semantics independent of the storage backend.
- Starts with eight embedded array records.
- Grows the array geometrically while the range is small.
- Optionally promotes a full 256-record array to tiered storage.
- Demotes a tiered range back to its embedded array when it becomes small.
- Keeps mutations transactional when new tiered blocks are required.

### Data Structures

The implementation is split across several files:

- [range.h](../../src/core/range.h) and
  [range.c](../../src/core/range.c) own the facade, shared semantics, searching,
  promotion, and demotion.
- [range_array.h](../../src/core/range_array.h) and
  [range_array.c](../../src/core/range_array.c) own contiguous array storage.
- [range_tiered.h](../../src/core/range_tiered.h) and
  [range_tiered.c](../../src/core/range_tiered.c) own block-based storage.
- [range_subrange.h](../../src/core/range_subrange.h) owns the common
  `QUIC_SUBRANGE` record.

#### `QUIC_RANGE`

`QUIC_RANGE` is the public facade used by core callers.

`Array` / `Tiered`
: A union containing either the array descriptor by value or a pointer to an
  opaque tiered descriptor. `Mode` determines which member is valid.

`MaxAllocSize`
: The maximum number of bytes the active representation may allocate.

`Mode`
: The currently active representation.

`AllowedModes`
: The representations the caller permits for the lifetime of this range.

**Invariant**: `Mode` must be one of the representations in `AllowedModes`.

**Invariant**: Only the union member selected by `Mode` may be interpreted.

#### `QUIC_RANGE_ARRAY`

`SubRanges`
: Points either to the embedded `PreAllocSubRanges` array or to a heap
  allocation.

`UsedLength`
: The number of live logical records.

`AllocLength`
: The number of records that fit in `SubRanges`.

`PreAllocSubRanges`
: Eight records embedded directly in the descriptor.

**Invariant**: `UsedLength <= AllocLength`.

**Invariant**: Records in `[0, UsedLength)` are stored in logical order.

#### `QUIC_RANGE_TIERED`

The tiered descriptor is opaque outside
[range_tiered.c](../../src/core/range_tiered.c).

`Blocks`
: A 256-entry directory of independently allocated record blocks. Each block
  contains 256 `QUIC_SUBRANGE` records and occupies 4,096 bytes.

`Starts`
: The physical slot in each circular block that contains logical slot zero.

`UsedLength`
: The total number of live logical records across active blocks.

`ActiveBlockCount`
: The number of blocks currently needed to represent `UsedLength`.

`AllocatedBlockCount`
: The number of blocks currently allocated. Inactive allocations can be
  retained for reuse.

`MaxBlockCount`
: The maximum number of blocks permitted by both `MaxAllocSize` and the
  directory capacity.

The important tiered invariants are:

- Allocated blocks occupy the contiguous directory prefix
  `[0, AllocatedBlockCount)`.
- Active blocks occupy the prefix `[0, ActiveBlockCount)`.
- `ActiveBlockCount <= AllocatedBlockCount <= MaxBlockCount`.
- Every non-final active block is full.
- The final active block contains the remaining records.
- Each block's logical order begins at `Starts[BlockIndex]` and wraps modulo
  256.
- A stable, nonempty tiered range requires
  `ceil(UsedLength / 256)` active blocks.
- Logical record order is continuous across block boundaries.

The final active block can temporarily be empty while insertion reserves all
required storage before moving records. The new logical length is published
only after the insertion has completed.

### Searching and Normalization

`QuicRangeSearch` performs a binary search over the logical subrange sequence.
The backend does not affect the search:

- Array mode indexes directly into `SubRanges`.
- Tiered mode maps the logical index to a block and block-local slot.

A nonnegative search result is a matching record index. A negative result
encodes the position where a new record would be inserted.

`QuicRangeAddRange` uses that result to:

1. Find the first overlapping or adjacent record.
2. Insert a new record if no record can be expanded.
3. Expand the selected record to include the new values.
4. Remove later records now covered by the expanded record.
5. Reacquire its record pointer if removal moved storage.

The common code therefore preserves the same normalized set semantics for both
backends.

### Array Storage

Array mode is optimized for the common case of a small number of subranges.
Initialization points `SubRanges` at the eight embedded records, so an empty or
small range requires no separate allocation.

When the array fills, it doubles its record capacity:

```text
8 -> 16 -> 32 -> 64 -> 128 -> 256 -> ...
```

Tiered-capable ranges intercept growth when a full 256-record array needs
another record. Otherwise, array growth can continue while its byte budget
allows.

Growth allocates a new contiguous array and copies records around the new
insertion slot. The old heap allocation is then released. Because growth moves
all records, pointers into the old array become invalid.

Removal shifts the tail with `memmove`. If a heap-backed array is less than
one-quarter full, one removal call can halve its allocation. When the halved
allocation reaches eight slots, storage returns to the embedded array.

An active array representation whose budget differs from
`QUIC_MAX_RANGE_ALLOC_SIZE` preserves the existing aging behavior. If a full
array cannot grow and a record above the current minimum is being inserted, the
lowest record can be discarded to make room. Insertion at the front cannot age
out an older record and fails instead.

`QuicRangeArrayReset` removes all logical records but retains the current
allocation for reuse.

### Tiered Storage

Tiered storage keeps a logical vector while splitting its records into
independent fixed-size blocks. Adding a block does not relocate the directory's
existing blocks.

The constants are:

```text
Records per block:       256
Bytes per block:         4,096
Directory slots:         256
Theoretical records:     65,536
```

The byte budget also includes the tiered directory. With the standard 1-MiB
range budget, 255 data blocks fit, giving an effective capacity of 65,280
subranges.

#### Logical Index Mapping

A logical record index maps to a block and a block-local logical slot:

```text
BlockIndex = Index / 256
LocalIndex = Index % 256
```

The physical slot then accounts for the block's circular start:

```text
PhysicalSlot = (Starts[BlockIndex] + LocalIndex) % 256
```

This extra mapping allows insertion or removal near the front of a block to
move the prefix instead of always moving the suffix.

#### Local Block Mutation

For a block-local insertion or removal, the backend computes:

- The number of records before the mutation.
- The number of records after the mutation.
- Whether each side is physically contiguous in the circular block.

It normally moves the shorter contiguous side. If the shorter side wraps, it
moves the other side. Zero-length moves skip `memmove`.

This bounds a local movement to one block rather than shifting every later
record in one large allocation.

#### Cross-Block Insertion

Tiered insertion first calculates the number of blocks required by the
post-insertion length. All missing blocks are allocated before any record is
moved.

If allocation fails:

- Newly allocated blocks from this attempt are released.
- Existing records remain unchanged.
- The insertion returns failure.

After storage is ready, insertion opens a slot in the target block. If that
block was full, its final record is saved and carried into the front of the
next block. The carry continues until it reaches a block with space.
`UsedLength` is incremented only after the final carried record is stored.

When configured capacity is full, tiered storage applies the same budget and
insertion-position rule as the array's full-capacity path:

- A range whose budget differs from `QUIC_MAX_RANGE_ALLOC_SIZE` can discard its
  lowest subrange when inserting above the current minimum.
- Insertion at the front fails because discarding the minimum cannot make room
  for a new lower record.
- A `QUIC_MAX_RANGE_ALLOC_SIZE` range never silently discards data and fails
  insertion instead.

This equivalence applies only when configured capacity is full. The array can
also age after an attempted growth allocation fails; a tiered block allocation
failure before configured capacity is reached remains atomic and does not
trigger aging.

#### Cross-Block Removal

A single-record removal closes the local slot, then carries the first record of
each later block backward to keep every earlier active block full.

For a multi-record removal, the backend estimates two approaches:

- Repeated bounded local removals and backward carries.
- One forward copy of the surviving logical tail.

It chooses the cheaper estimate. After removal, unused trailing allocations
can be reclaimed when active utilization falls below one quarter. Some
capacity is retained for later regrowth; the exact amount is an allocation
policy, not a structural invariant.

### Promotion and Demotion

Promotion and demotion are facade policies in
[range.c](../../src/core/range.c), not backend responsibilities.

#### Promotion

Promotion is considered only when:

- The active representation is array mode.
- `AllowedModes` includes tiered mode.
- The array has exactly 256 used and allocated records.
- The byte budget can hold the tiered directory and the first two blocks.
- A new disjoint subrange requires a 257th record.

An addition that merely merges with existing records does not promote.

Promotion reuses the full 256-record array allocation as tiered block zero:

1. Allocate and zero the tiered directory.
2. Temporarily reference the array allocation as block zero.
3. Allocate block one.
4. Insert the new record.
5. Publish the tiered pointer and change `Mode`.

The embedded array holds only eight records, which is below the 256-record
promotion threshold. A debug assertion verifies that promotion transfers a
heap-backed allocation rather than embedded storage.

The original allocation remains owned by the array backend until every
required allocation succeeds. If directory or block allocation fails, any new
tiered state is discarded and the original array representation remains
unchanged.

#### Demotion

After tiered removal, the facade demotes when eight or fewer records remain:

1. Copy records in logical order into the embedded array.
2. Free the tiered directory and every allocated block.
3. Initialize the array descriptor.
4. Publish array mode with the copied logical length.

Public `QuicRangeReset` frees tiered storage and returns the range directly to
an empty embedded array.

### Memory Management and Ownership

Array storage has two ownership states:

- `PreAllocSubRanges` is part of the array descriptor and is never freed.
- A heap-backed `SubRanges` allocation is owned by the array backend.

Tiered storage owns:

- The tiered directory.
- Every non-NULL block in its allocated directory prefix.

Promotion is the ownership transition. Before promotion succeeds, the original
array still owns block zero. After the new record is inserted and the tiered
representation is published, the tiered backend owns that allocation.

Tiered blocks are independent allocations, so allocating a later block does not
relocate an earlier block. Mutations can still move records within or between
blocks, so record pointers must not be treated as stable across mutations.

`QuicRangeRemoveSubranges` returns a pointer-invalidation indication, not a
success indication:

- Array mode returns `TRUE` when shrinking changed the backing allocation.
- Tiered mode returns `TRUE` because removal can move records physically even
  when no allocation is released.

### Complexity

Let `n` be the number of stored subrange records.

| Operation | Complexity |
|---|---|
| Get by logical index | O(1) |
| Get minimum or maximum | O(1) |
| Search | O(log n) |
| Array insertion or removal | O(n) worst case |
| Tiered local mutation | Bounded by one 256-record block |
| Tiered cross-block insertion or removal | O(n) worst case |

Tiered storage does not change the worst-case complexity of arbitrary
insertion. Its benefit is that growth does not copy one increasingly large
contiguous allocation and local mutations can move only part of a fixed-size
block.

## Storage Layout Diagrams

The following diagrams show how the facade, backends, and representation
transitions relate to one another.

### Facade and Active Backend

```text
+--------------------------- QUIC_RANGE ----------------------------+
| MaxAllocSize | Mode | AllowedModes                                |
|                                                                    |
| Active union member:                                               |
|                                                                    |
|   ARRAY                              TIERED                         |
|   +-----------------------+          +--------------------------+  |
|   | QUIC_RANGE_ARRAY      |          | QUIC_RANGE_TIERED*       |  |
|   | stored by value       |          | opaque allocated object  |  |
|   +-----------------------+          +--------------------------+  |
+--------------------------------------------------------------------+
```

`Mode` selects the valid union member. `AllowedModes` determines whether the
array representation is permitted to promote to tiered storage.

### Array Storage

An empty or small range uses the records embedded in `QUIC_RANGE_ARRAY`:

```text
QUIC_RANGE_ARRAY

SubRanges ------------------------------------+
                                               |
                                               v
PreAllocSubRanges: [ R0 ][ R1 ][ R2 ][ ... ][ R7 ]
                    <------ UsedLength ------>
                    <--------- 8 slots --------->
```

After growth, `SubRanges` points to a separate contiguous allocation:

```text
PreAllocSubRanges: [ unused embedded storage ]

SubRanges ---> [ R0 ][ R1 ][ R2 ] ... [ Rn ][ unused ... ]
                <--------- UsedLength -------->
                <------------- AllocLength ---------------->
```

### Tiered Directory

This example has three active blocks and two additional allocations retained
for reuse:

```text
QUIC_RANGE_TIERED

Directory index:          0          1          2          3          4
                     +----------+----------+----------+----------+----------+
Blocks[] ----------> | Block 0  | Block 1  | Block 2  | Block 3  | Block 4  |
                     +----+-----+----+-----+----+-----+----+-----+----+-----+
                          |          |          |          |          |
                          v          v          v          v          v
                     [256 recs] [256 recs] [partial]  [retained] [retained]

                     <------ ActiveBlockCount ------->
                     <------------- AllocatedBlockCount ------------>
```

All non-final active blocks are full. Logical enumeration continues from the
end of one active block to logical slot zero of the next.

### Circular Block Mapping

Suppose a block contains five logical records and
`Starts[BlockIndex] == 253`:

```text
Physical slot:   0    1    2  ...  252   253  254  255
Stored record:  [L3] [L4] [ ] ...  [ ]  [L0] [L1] [L2]
                                            ^
                                            |
                                         Starts

Logical order:  L0 -> L1 -> L2 -> L3 -> L4
```

Changing `Starts` lets a short prefix move across the physical end of the block
without first normalizing every record back to slot zero.

### Promotion

```text
Array mode:

[ R0 ][ R1 ] ... [ R255 ]       new disjoint record
          full 256-record array           |
                                          v

Prepare tiered storage:

Directory
Blocks[0] --------------------> existing array allocation
Blocks[1] --------------------> newly allocated block

                                          |
                                          | insertion succeeds
                                          v

Publish:

Range->Tiered = Directory
Range->Mode = QUIC_RANGE_MODE_TIERED
```

Until publication, `Blocks[0]` is only a borrowed reference. If preparation
fails, the range continues to own and use the original array.

### Demotion

```text
Tiered mode with eight or fewer records:

Block 0 -------> [ R0 ][ R1 ] ... [ R7 ]
                         |
                         | copy in logical order
                         v

Embedded array -> [ R0 ][ R1 ] ... [ R7 ]

Free the tiered blocks and directory
Set Mode = QUIC_RANGE_MODE_ARRAY
```

Promotion and demotion preserve the same ordered logical subranges. Only their
physical storage changes.
