/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file contains code for a dynamic hash table (adapted from Windows
    RTL hash implementation).

Notes:

    This code uses linear-hashing to increase the table size
    smoothly as the number of elements in the table increases,
    while rehashing a portion of the elements. This is in
    contrast to doubling-based schemes which double the
    size of the hash table periodically and rehash *all*
    the elements in the hash table.

    Note that the hash table size (in terms of the total number of buckets)
    is independent from the size of memory allocated for backing the table.
    This implementation doubles up the memory size for each higher-indexed 
    second level bucket directory (which the first level directory points to).
    This is so that we can scale up the maximum supported table size
    exponentially by the size of the first level directory. But, we still
    increment the table size by only one bucket during table expansion, 
    i.e., each expansion iteration rehashes only a single bucket (the
    pivot bucket) as opposed to the whole table.

    This module contains the "basic" hash table, referred below
    as just the hash table. This hash table is intended to
    be protected by a single lock, which can be a reader-writer
    lock if the caller desires. Locking is supposed to be
    handled by the user. This API is designed for users
    who really care about performance and would like to
    retain explicit control of locking.

    APIs support the concept of transactions -- if the
    caller wishes to make a series of operations, for e.g, a
    lookup followed by an insertion, the APIs allow the user
    to mark the position where the last operation occurred
    using a place-holder called a Context. So if a user
    performs a lookup and passes in a Context, the Context
    will store the place in the hash table where the lookup
    ended. If the caller wants to follow it up with an
    insertion, the hash table now has information about
    the location, and does not have to traverse the hash
    table chains again.

--*/

#include "platform_internal.h"

#ifdef QUIC_LOGS_WPP
#include "hashtable.tmh"
#endif

#define QUIC_HASH_RESERVED_SIGNATURE 0

//
// Inserts with hash = QUIC_HASH_RESERVED_SIGNATURE aren't allowed.
//
#define QUIC_HASH_ALT_SIGNATURE (QUIC_HASH_RESERVED_SIGNATURE + 1)

//
// Define table sizes.
//

#define HT_FIRST_LEVEL_DIR_SIZE   16
#define HT_SECOND_LEVEL_DIR_SHIFT  7
#define HT_SECOND_LEVEL_DIR_MIN_SIZE (1 << HT_SECOND_LEVEL_DIR_SHIFT)

//
// First level dir[0] covers a mininum-size 2nd-level dir.
// First level dir[1] covers a 2*minimum-size 2nd-level dir.
// First level dir[2] covers a 4*minimum-size 2nd-level dirs. So on...
// Hence, we can have at most (2^HT_FIRST_LEVEL_DIR_SIZE)-1
// minimum-size hash bucket directories.
// With a first-level directory size of 16 and a 2nd-level directory 
// minimum-size of 128, we get a max hash table size of 8,388,480 buckets.
//
#define MAX_HASH_TABLE_SIZE \
    (((1 << HT_FIRST_LEVEL_DIR_SIZE) - 1) \
        * HT_SECOND_LEVEL_DIR_MIN_SIZE)

#define BASE_HASH_TABLE_SIZE HT_SECOND_LEVEL_DIR_MIN_SIZE

QUIC_STATIC_ASSERT(
    QUIC_HASH_MIN_SIZE == BASE_HASH_TABLE_SIZE,
    "Hash table sizes should match!");

#ifndef BitScanReverse
static
uint8_t
QuicBitScanReverse(
    _Out_ uint32_t *Index,
    _In_ uint32_t Mask
    )
/*++

Routine Description:

    Find the most significant set bit.

Arguments:

    Index - Returns the most significant set bit.

    Mask - Mask to find most signifcant set bit in.

Return Value:

    1 if most significant set bit is found, 0 if no bit is set.

--*/
{
    int ii = 0;
    uint32_t TempMask = 0;

    if (Mask == 0 || Index == 0) {
        return 0;
    }

    for (ii = (sizeof(uint32_t) * 8); ii >= 0; --ii) {
        TempMask = 1 << ii;

        if ((Mask & TempMask) != 0) {
            *Index = ii;
            break;
        }
    }

    return (ii >= 0 ? (uint8_t)1 : (uint8_t)0);
}
#else
#define QuicBitScanReverse(A, B) BitScanReverse((ULONG*)A, (ULONG)B)
#endif // BitScanReverse

static
void
QuicComputeDirIndices(
    _In_range_(<, MAX_HASH_TABLE_SIZE)
    uint32_t BucketIndex,
    _Out_range_(<, HT_FIRST_LEVEL_DIR_SIZE)
    uint32_t* FirstLevelIndex,
    _Out_range_(<, (1 << (*FirstLevelIndex+HT_SECOND_LEVEL_DIR_SHIFT)))
    uint32_t* SecondLevelIndex
    )
/*++

Routine Description:

    Given a bucket index, computes the first level dir index that points to
    the corresponding second level dir, and the second level dir index that
    points to the hash bucket.

Arguments:

    BucketIndex - [0, MAX_HASH_TABLE_SIZE-1]

    FirstLevelIndex - Pointer to a uint32_t that will be assigned the first
        level index upon return.

    SecondLevelIndex - Pointer to a uint32_t that will be assigned the second
        level index upon return.

--*/
{
    uint32_t AbsoluteIndex = BucketIndex + HT_SECOND_LEVEL_DIR_MIN_SIZE;

    QUIC_DBG_ASSERT(BucketIndex < MAX_HASH_TABLE_SIZE);

    //
    // Find the most significant set bit. Since AbsoluteIndex
    // is always nonzero, we don't need to check the return value.
    //

    QuicBitScanReverse(FirstLevelIndex, AbsoluteIndex);

    //
    // The second level index is the absolute index with the most significant
    // bit cleared.
    //

    *SecondLevelIndex = (AbsoluteIndex ^ (1 << *FirstLevelIndex));

    //
    // The first level index is the position of the most significant bit
    // adjusted for the size of the minimum second level dir size.
    //

    *FirstLevelIndex -= HT_SECOND_LEVEL_DIR_SHIFT;

    QUIC_DBG_ASSERT(*FirstLevelIndex < HT_FIRST_LEVEL_DIR_SIZE);
}

static
uint32_t
QuicComputeSecondLevelDirSize(
    _In_range_(<, HT_FIRST_LEVEL_DIR_SIZE) uint32_t FirstLevelIndex
    )
/*++

Routine Description:

    Computes size of 2nd level directory. The size of the second level dir
    is determined by its position in the first level dir.

Arguments:

    FirstLevelIndex - The first level index.

Return Value:

    The directory size.

--*/
{
    return (1 << (FirstLevelIndex + HT_SECOND_LEVEL_DIR_SHIFT));
}

static
_Ret_maybenull_
_Must_inspect_result_
__ecount_opt(1 << (FirstLevelIndex + HT_SECOND_LEVEL_DIR_SHIFT))
QUIC_LIST_ENTRY*
QuicAllocateSecondLevelDir(
    _In_range_(<, HT_FIRST_LEVEL_DIR_SIZE) uint32_t FirstLevelIndex
    )
/*++

Routine Description:

    This routine allocates a second level dir. The size of the second level dir
    is determined by its position in the first level dir. 

Arguments:

    FirstLevelIndex - [0, HT_FIRST_LEVEL_DIR_SIZE-1]

Return Value:

    QUIC_LIST_ENTRY* Head of a second-level directory.

--*/
{
    return
        QUIC_ALLOC_NONPAGED(
            QuicComputeSecondLevelDirSize(FirstLevelIndex) * sizeof(QUIC_LIST_ENTRY));
}

static
void
QuicInitializeSecondLevelDir(
    _Out_writes_all_(NumberOfBucketsToInitialize) QUIC_LIST_ENTRY* SecondLevelDir,
    _In_ uint32_t NumberOfBucketsToInitialize
    )
/*++

Routine Description:

    Initializes a second level dir. 

Arguments:

    SecondLevelDir - The 2nd level dir to initialize.

    NumberOfBucketsToInitialize - Number of buckets to initialize.

--*/
{
    for (uint32_t i = 0; i < NumberOfBucketsToInitialize; i += 1) {
        QuicListInitializeHead(&SecondLevelDir[i]);
    }
}

static
void
QuicSecondLevelDirFree(
    _In_ __drv_freesMem(Mem) _Post_invalid_ void* MemPtr
    )
/*++

Routine Description:

    Frees second level dir

Arguments:

    MemPtr - supplies the pointer to the second level page dir

--*/
{
    QUIC_FREE(MemPtr);
}

static
QUIC_HASHTABLE_ENTRY*
QuicFlinkToHashEntry(
    _In_ QUIC_LIST_ENTRY* *FlinkPtr
    )
/*++

Routine Description:

    Converts the pointer to the Flink in LIST_ENTRY
    into a RTL_DYNAMIC_HASH_TABLE_ENTRY structure.

Arguments:

    FlinkPtr - supplies the pointer to the Flink field
        in LIST_ENTRY

Return Value:

    Returns the RTL_DYNAMIC_HASH_TABLE_ENTRY that contains the
    LIST_ENTRY which contains the Flink whose pointer
    was passed above.

--*/
{
    return QUIC_CONTAINING_RECORD(FlinkPtr, QUIC_HASHTABLE_ENTRY, Linkage);
}


static
QUIC_LIST_ENTRY*
QuicGetChainHead(
    _In_ const QUIC_HASHTABLE* HashTable,
    _In_range_(<, HashTable->TableSize) uint32_t BucketIndex
    )
/*++

Routine Description:

    Given a table index, it retrieves the pointer to
    the head of the hash chain. This routine expects
    that the index passed will be less than the table
    size.
    I thought of adding functionality such that if the
    index asked for is greater than table size, this
    routine should just increase the table size so that
    the index asked for exists. But that increases the
    path length for the regular callers, and so I chucked
    that functionality out.

Arguments:

    HashTable - Pointer to hash table to operate on.

    BucketIndex - Index of chain to be returned.

Synchronization:

    Hash table lock should be held in shared mode by caller.

Return Value:

    Returns the pointer to the head of the hash chain.

--*/
{
    uint32_t SecondLevelIndex;
    QUIC_LIST_ENTRY* SecondLevelDir;

    QUIC_DBG_ASSERT(BucketIndex < HashTable->TableSize);

    //
    // 'Directory' field of the hash table points either
    // to the first level directory or to the second-level directory
    // itself depending to the allocated size..
    //

    if (HashTable->TableSize <= HT_SECOND_LEVEL_DIR_MIN_SIZE) {
        SecondLevelDir = (QUIC_LIST_ENTRY*)HashTable->Directory;
        SecondLevelIndex = BucketIndex;

    } else {
        uint32_t FirstLevelIndex = 0;
        QuicComputeDirIndices(BucketIndex, &FirstLevelIndex, &SecondLevelIndex);
        SecondLevelDir = *((QUIC_LIST_ENTRY**)HashTable->Directory + FirstLevelIndex);
    }

    QUIC_DBG_ASSERT(SecondLevelDir != NULL);

    return SecondLevelDir + SecondLevelIndex;
}

static
uint32_t
QuicRandomizeBits(
    _In_ const QUIC_HASHTABLE* HashTable,
    _In_ uint64_t Signature
    )
/*++

Routine Description:

    Mix up the Signature bits in order to generate a more unified distribution
    of bits. The intent is to avoid clustering the keys in the hash table for
    better performance.
    Hash Function came from CLKRHashTable see bug#349459

Arguments:

    HashTable - Pointer to hash table to operate on.

    Signature - The signature to mix.

Synchronization:
    none

Return Value:

    Returns the mixed set of bits

--*/
{
    uint32_t Hash = (uint32_t)Signature >> HashTable->Shift;

    Hash = (((Hash * 1103515245 + 12345) >> 16)
            | ((Hash * 69069 + 1) & 0xffff0000));

    return Hash;
}

static
uint32_t
QuicGetBucketIndex(
    _In_ const QUIC_HASHTABLE* HashTable,
    _In_ uint64_t Signature
    )
/*++

Routine Description:

    Returns a bucket index of a Signature within a given HashTable

Arguments:

    HashTable - Pointer to hash table to operate on.

    Signature - The signature.

Synchronization:
    none

Return Value:

    Returns the index of the bucket within the HashTable

--*/

{
    uint32_t MixedBits = QuicRandomizeBits(HashTable, Signature);

    uint32_t BucketIndex = MixedBits & HashTable->DivisorMask;
    if (BucketIndex < HashTable->Pivot) {
        BucketIndex = MixedBits & ((HashTable->DivisorMask << 1) | 1);
    }

    return BucketIndex;
}


static
void
QuicPopulateContext(
    _In_ QUIC_HASHTABLE* HashTable,
    _Out_ QUIC_HASHTABLE_LOOKUP_CONTEXT* Context,
    _In_ uint64_t Signature
    )
/*++

Routine Description:

    Does the basic hashing and lookup and returns a pointer
    to either the entry before the entry with the queried
    signature, or to the entry after which such a entry would
    exist (if it doesn't exist).

Arguments:

    HashTable - Pointer to hash table to operate on.

    Context - The context structure that is to be filled.

    Signature - The signature to be looked up.

Synchronization:

    Hash Table lock should be held in shared mode by caller.

Return Value:

    Returns nothing, but fills the Context structure with
    the relevant information.

--*/
{
    QUIC_HASHTABLE_ENTRY* NextHashEntry = NULL;
    QUIC_LIST_ENTRY* BucketPtr;
    QUIC_LIST_ENTRY* NextEntry;
    QUIC_LIST_ENTRY* CurEntry;
    uint32_t BucketIndex;

    //
    // Compute the hash.
    //
    BucketIndex = QuicGetBucketIndex(HashTable, Signature);

    BucketPtr = QuicGetChainHead(HashTable, BucketIndex);
    QUIC_DBG_ASSERT(NULL != BucketPtr);

    CurEntry = BucketPtr;

    while (CurEntry->Flink != BucketPtr) {

        NextEntry = CurEntry->Flink;
        NextHashEntry = QuicFlinkToHashEntry(&NextEntry->Flink);

        if ((QUIC_HASH_RESERVED_SIGNATURE == NextHashEntry->Signature) ||
            (NextHashEntry->Signature < Signature)) {

            CurEntry = NextEntry;
            continue;
        }

        break;
    }

    //
    // At this point, the signature is either equal or greater, or the
    // end of the chain. Either way, this is where we want to
    // be.
    //
    Context->ChainHead = BucketPtr;
    Context->PrevLinkage = CurEntry;
    Context->Signature = Signature;
}

_Must_inspect_result_
_Success_(return != 0)
BOOLEAN
QuicHashtableInitialize(
    _Inout_ _When_(NULL == *HashTable, _At_(*HashTable, __drv_allocatesMem(Mem)))
        QUIC_HASHTABLE* *HashTable,
    _In_ uint32_t InitialSize
    )
/*++

Routine Description:

    Creates a hash table. Takes a pointer to a pointer to
    RTL_DYNAMIC_HASH_TABLE, just so that the caller can pass a
    pre-allocated RTL_DYNAMIC_HASH_TABLE structure to be initialized,
    which the partitioned hash table does.

Synchronization:

    None.

Arguments:

    HashTable - Pointer to a pointer to a hash Table to be initialized.
        This argument must be non-null, but it can
        contain either a NULL value (in which case
        a RTL_DYNAMIC_HASH_TABLE will be allocated, or can
        contain a pre-allocated RTL_DYNAMIC_HASH_TABLE.

    InitialSize - The initial size of the hash table in number of buckets.

Return Value:

    TRUE if creation and initialization succeeded, FALSE otherwise.

--*/
{
    QUIC_HASHTABLE* Table;
    QUIC_LIST_ENTRY* SecondLevelDir;
    QUIC_LIST_ENTRY** FirstLevelDir;
    uint32_t LocalFlags;

    //
    // Initial size must be a power of two and within the allowed range.
    //

    if (((InitialSize & (InitialSize - 1)) != 0) ||
        (InitialSize > MAX_HASH_TABLE_SIZE) ||
        (InitialSize < BASE_HASH_TABLE_SIZE)) {
        return FALSE;
    }

    //
    // First allocate the hash Table header.
    //

    LocalFlags = 0;
    if (*HashTable == NULL) {
        Table = QUIC_ALLOC_NONPAGED(sizeof(QUIC_HASHTABLE));
        if (Table == NULL) {
            LogError("[ pal] Hashtable allocation failed.");
            return FALSE;
        }

        LocalFlags = QUIC_HASH_ALLOCATED_HEADER;

    } else {
        Table = *HashTable;
    }

    //
    // Zero out all the fields.
    //

    QuicZeroMemory(Table, sizeof(QUIC_HASHTABLE));

    Table->Flags = LocalFlags;
    Table->TableSize = InitialSize;
    Table->DivisorMask = Table->TableSize - 1;
    Table->Shift = 0;
    Table->Pivot = 0;

    //
    // Now we allocate the second level entries.
    //

    if (Table->TableSize <= HT_SECOND_LEVEL_DIR_MIN_SIZE) {

        //
        // Directory pointer in the Table header structure
        // points directly to the single second-level directory.
        //

        SecondLevelDir = QuicAllocateSecondLevelDir(0);
        if (SecondLevelDir == NULL) {
            LogError("[ pal] SecondLevelDir allocation failure.");
            QuicHashtableUninitialize(Table);
            return FALSE;
        }

        QuicInitializeSecondLevelDir(SecondLevelDir, Table->TableSize);

        Table->Directory = SecondLevelDir;

    } else {

        //
        // Allocate and initialize the first-level directory
        // entries required to fit upper bound.
        //
        uint32_t FirstLevelIndex;
        uint32_t SecondLevelIndex;
        uint32_t i;

        QuicComputeDirIndices(
            (Table->TableSize - 1), &FirstLevelIndex, &SecondLevelIndex);

        FirstLevelDir = (QUIC_LIST_ENTRY**)
            QUIC_ALLOC_NONPAGED(sizeof(QUIC_LIST_ENTRY*) * HT_FIRST_LEVEL_DIR_SIZE);

        if (FirstLevelDir == NULL) {
            QuicHashtableUninitialize(Table);
            return FALSE;
        }

        QuicZeroMemory(FirstLevelDir,
                       sizeof(QUIC_LIST_ENTRY*) * HT_FIRST_LEVEL_DIR_SIZE);
        Table->Directory = FirstLevelDir;

        for (i = 0; i <= FirstLevelIndex; i++) {

            SecondLevelDir = QuicAllocateSecondLevelDir(i);

            if (SecondLevelDir == NULL) {
                QuicHashtableUninitialize(Table);
                return FALSE;
            }

            QuicInitializeSecondLevelDir(
                SecondLevelDir,
                (i < FirstLevelIndex)
                    ? QuicComputeSecondLevelDirSize(i) 
                    : (SecondLevelIndex+1));

            FirstLevelDir[i] = SecondLevelDir;
        }
    }

    //
    // Return the initialized hash Table via the supplied pointer.
    //

    *HashTable = Table;

    return TRUE;
}

void
QuicHashtableUninitialize(
    _In_ _When_((HashTable->Flags & QUIC_HASH_ALLOCATED_HEADER), __drv_freesMem(Mem) _Post_invalid_)
        QUIC_HASHTABLE* HashTable
    )
/*++

Routine Description:

    Called to remove all resources allocated either in
    RtlCreateHashTable, or later while expanding the
    table. This function just walks the entire table
    checking that all hash buckets are null, and then
    removing all the memory allocated for the directories
    behind it. This function is also called from
    RtlCreateHashTable to cleanup the allocations
    just in case, an error occurs (like failed memory
    allocation).

Synchronization:

    None

Arguments:

    HashTable - Pointer to hash Table to be deleted.

--*/
{
    uint32_t FirstLevelIndex, SecondLevelIndex;
    QUIC_LIST_ENTRY* SecondLevelDir;
    QUIC_LIST_ENTRY** FirstLevelDir;

    QUIC_DBG_ASSERT(HashTable->NumEnumerators == 0);
    QUIC_DBG_ASSERT(HashTable->NumEntries == 0);

    if (HashTable->TableSize <= HT_SECOND_LEVEL_DIR_MIN_SIZE) {

        SecondLevelDir = (QUIC_LIST_ENTRY*)HashTable->Directory;

        if (SecondLevelDir != NULL) {

            QuicSecondLevelDirFree(SecondLevelDir);

        }

    } else {

        FirstLevelDir = (QUIC_LIST_ENTRY**)HashTable->Directory;

        if (FirstLevelDir != NULL) {

            uint32_t largestFirstLevelIndex;
            uint32_t largestSecondLevelIndex;
            uint32_t initializedBucketCountInSecondLevelDir;
            
            QuicComputeDirIndices(
                (HashTable->TableSize - 1), &largestFirstLevelIndex, &largestSecondLevelIndex);

            for (FirstLevelIndex = 0;
                 FirstLevelIndex < HT_FIRST_LEVEL_DIR_SIZE;
                 FirstLevelIndex++) {

                SecondLevelDir = FirstLevelDir[FirstLevelIndex];

                if (NULL == SecondLevelDir) {
                    break;
                }

                initializedBucketCountInSecondLevelDir = 
                    (FirstLevelIndex < largestFirstLevelIndex) 
                    ? QuicComputeSecondLevelDirSize(FirstLevelIndex)
                    : largestSecondLevelIndex+1;
                
                for(SecondLevelIndex = 0;
                    SecondLevelIndex < initializedBucketCountInSecondLevelDir;
                    SecondLevelIndex ++) {
                    QUIC_DBG_ASSERT(QuicListIsEmpty(&SecondLevelDir[SecondLevelIndex]));
                }

                QuicSecondLevelDirFree(SecondLevelDir);

            }

            for(; FirstLevelIndex < HT_FIRST_LEVEL_DIR_SIZE; FirstLevelIndex++) {
                QUIC_DBG_ASSERT(NULL == FirstLevelDir[FirstLevelIndex]);
            }

            QUIC_FREE(FirstLevelDir);
        }
    }

    if (HashTable->Flags & QUIC_HASH_ALLOCATED_HEADER) {
        QUIC_FREE(HashTable);
    }
}

void
QuicHashtableInsert(
    _In_ QUIC_HASHTABLE* HashTable,
    _In_ __drv_aliasesMem QUIC_HASHTABLE_ENTRY* Entry,
    _In_ uint64_t Signature,
    _Inout_opt_ QUIC_HASHTABLE_LOOKUP_CONTEXT* Context
    )
/*++

Routine Description:

    Inserts an entry into a hash table, given the pointer to
    a RTL_DYNAMIC_HASH_TABLE_ENTRY and a signature. An optional context
    can be passed in which, if possible, will be used to
    quickly get to the relevant bucket chain. This routine
    will not take the contents of the Context structure passed
    in on blind faith -- it will check if the signature in
    the Context structure matches the signature of the entry
    that needs to be inserted. This adds an extra check
    on the hot path, but I deemed it necessary.

    This routine strictly requires that the signature is not
    QUIC_HASH_RESERVED_SIGNATURE.

Synchronization:

    Hash lock has to be held by caller in exclusive mode.

Arguments:

    HashTable - Pointer to hash table in which we wish to insert entry

    Entry - Pointer to entry to be inserted.

    Signature - Signature of the entry to be inserted.

    Context - Pointer to optional context that can be passed in.

--*/
{
    QUIC_HASHTABLE_LOOKUP_CONTEXT LocalContext = {0};
    QUIC_HASHTABLE_LOOKUP_CONTEXT* ContextPtr = NULL;

    if (Signature == QUIC_HASH_RESERVED_SIGNATURE) {
        Signature = QUIC_HASH_ALT_SIGNATURE;
    }

    Entry->Signature = Signature;

    HashTable->NumEntries++;

    if (Context == NULL) {

        QuicPopulateContext(HashTable, &LocalContext, Signature);
        ContextPtr = &LocalContext;

    } else {

        if (Context->ChainHead == NULL) {
            QuicPopulateContext(HashTable, Context, Signature);
        }

        QUIC_DBG_ASSERT(Signature == Context->Signature);
        ContextPtr = Context;
    }

    if (QuicListIsEmpty(ContextPtr->ChainHead)) {
        HashTable->NonEmptyBuckets++;
    }

    QuicListInsertHead(ContextPtr->PrevLinkage, &Entry->Linkage);
}

void
QuicHashtableRemove(
    _In_ QUIC_HASHTABLE* HashTable,
    _In_ QUIC_HASHTABLE_ENTRY* Entry,
    _Inout_opt_ QUIC_HASHTABLE_LOOKUP_CONTEXT* Context
    )
/*++

Routine Description:

    This function will remove an entry from the hash table.
    Since the bucket chains are doubly-linked lists, removal
    does not require identification of the bucket, and is a
    local operation.

    If a Context is specified, the function takes care of
    both possibilities -- if the Context is already filled,
    it remains untouched, otherwise, it is filled appropriately.

Synchronization:

    Requires the caller to hold the lock protecting the
    hash table in exclusive-mode

Arguments:

    HashTable - Pointer to hash table from which the entry is to be removed.

    Entry - Pointer to the entry that is to be removed.

    Context - Optional pointer which stores information
        about the location in the hash table where
        that particular signature resides. This is
        NOT used in this function currently -- it
        is there just in case we decide to go with
        singly-linked lists in the future.

--*/
{
    uint64_t Signature = Entry->Signature;

    QUIC_DBG_ASSERT(HashTable->NumEntries > 0);
    HashTable->NumEntries--;

    if (Entry->Linkage.Flink == Entry->Linkage.Blink) {
        //
        // This is the last element in this chain.
        //
        QUIC_DBG_ASSERT (HashTable->NonEmptyBuckets > 0);
        HashTable->NonEmptyBuckets--;
    }

    QuicListEntryRemove(&Entry->Linkage);

    if (Context != NULL) {
        if (Context->ChainHead == NULL) {
            QuicPopulateContext(HashTable, Context, Signature);
        } else {
            QUIC_DBG_ASSERT(Signature == Context->Signature);
        }
    }
}

_Must_inspect_result_
QUIC_HASHTABLE_ENTRY*
QuicHashtableLookup(
    _In_ QUIC_HASHTABLE* HashTable,
    _In_ uint64_t Signature,
    _Out_opt_ QUIC_HASHTABLE_LOOKUP_CONTEXT* Context
    )
/*++

Routine Description:

    This function will lookup an entry in the hash table.
    Since our hash table only recognizes signatures, lookups
    need to generate all possible matches for the requested
    signature. This is achieved by storing all entries with
    the same signature in a contiguous subsequence, and
    returning the subsequence. The caller can walk this
    subsequence by calling RtlLookupNextEntryHashTable.
    If specified, the context is always initialized in
    this operation.

    This routine strictly requires that the signature is not
    QUIC_HASH_RESERVED_SIGNATURE.

Arguments:

    HashTable - Pointer to the hash table in which the
        signature is to be looked up.

    Signature - Signature to be looked up.

    Context - Optional pointer which stores information
        about the location in the hash table where
        that particular signature resides.

Return Value:

    Returns the first hash entry found that matches the
    signature. All the other hash entries with the same
    signature are linked behind this value.

--*/
{
    QUIC_HASHTABLE_LOOKUP_CONTEXT LocalContext;
    QUIC_HASHTABLE_LOOKUP_CONTEXT* ContextPtr;
    QUIC_HASHTABLE_ENTRY* CurHashEntry ;
    QUIC_LIST_ENTRY* CurEntry;

    if (Signature == QUIC_HASH_RESERVED_SIGNATURE) {
        Signature = QUIC_HASH_ALT_SIGNATURE;
    }

    if (Context != NULL) {
        ContextPtr = Context;
    } else {
        ContextPtr = &LocalContext;
    }

    QuicPopulateContext(HashTable, ContextPtr, Signature);

    CurEntry = ContextPtr->PrevLinkage->Flink;
    if (ContextPtr->ChainHead == CurEntry) {
        return NULL;
    }

    CurHashEntry = QuicFlinkToHashEntry(&(CurEntry->Flink));

    //
    // QuicPopulateContext will never return a PrevLinkage whose next
    // points to a enumerator.
    //
    QUIC_DBG_ASSERT(QUIC_HASH_RESERVED_SIGNATURE != CurHashEntry->Signature);

    if (CurHashEntry->Signature == Signature) {
        return CurHashEntry;
    }

    return NULL;
}

_Must_inspect_result_
QUIC_HASHTABLE_ENTRY*
QuicHashtableLookupNext(
    _In_ QUIC_HASHTABLE* HashTable,
    _Inout_ QUIC_HASHTABLE_LOOKUP_CONTEXT* Context
    )
/*++

Routine Description:

    This function will continue a lookup on a hash table.
    See comments for QuicHashtableLookupStrict. We assume
    that the user is not stupid and will call it only
    after Lookup has returned a non-NULL entry.

    Also note that this function has the responsibility
    to skip through any enumerators that may be in the
    chain. In such a case, the Context structure's
    PrevLinkage will *still* point to the last entry
    WHICH IS NOT A ENUMERATOR.

Arguments:

    HashTable - Pointer to the hash table in which the
        lookup is to be performed

    Context - Pointer to context which remains untouched
        during this operation. However that entry
        must be non-NULL so that we can figure out
        whether we have reached the end of the
        list.

Return Value:

    Returns the next entry with the same signature as the
    entry passed in, or NULL if no such entry exists.

--*/
{
    QUIC_HASHTABLE_ENTRY* NextHashEntry = NULL;
    QUIC_LIST_ENTRY* CurEntry, *NextEntry;

    QUIC_DBG_ASSERT(NULL != Context);
    QUIC_DBG_ASSERT(NULL != Context->ChainHead);
    QUIC_DBG_ASSERT(Context->PrevLinkage->Flink != Context->ChainHead);

    //
    // We know that the next entry is a valid, kosher entry,
    //
    CurEntry = Context->PrevLinkage->Flink;

    QUIC_DBG_ASSERT(CurEntry != Context->ChainHead);
    QUIC_DBG_ASSERT(QUIC_HASH_RESERVED_SIGNATURE !=
           (QuicFlinkToHashEntry(&(CurEntry->Flink))->Signature));

    //
    // Is this the end of the chain?
    //
    if (CurEntry->Flink == Context->ChainHead) {
        return NULL;
    }

    //
    // Good, so there is a following entry.
    //
    if (HashTable->NumEnumerators == 0) {
        NextEntry = CurEntry->Flink;
        NextHashEntry = QuicFlinkToHashEntry(&(NextEntry->Flink));
    } else {
        QUIC_DBG_ASSERT(CurEntry->Flink != Context->ChainHead);
        while (CurEntry->Flink != Context->ChainHead) {
            NextEntry = CurEntry->Flink;
            NextHashEntry = QuicFlinkToHashEntry(&(NextEntry->Flink));

            if (QUIC_HASH_RESERVED_SIGNATURE != (NextHashEntry->Signature)) {
                break;
            }

            CurEntry = NextEntry;
        }
    }

    QUIC_DBG_ASSERT(NextHashEntry != NULL);
    if (NextHashEntry->Signature == Context->Signature) {
        Context->PrevLinkage = CurEntry;
        return NextHashEntry;
    }

    //
    // If we have found no other entry matching that signature,
    // the Context remains untouched, free for the caller to
    // use for other insertions and removals.
    //
    return NULL;
}

void
QuicHashtableEnumerateBegin(
    _In_ QUIC_HASHTABLE* HashTable,
    _Out_ QUIC_HASHTABLE_ENUMERATOR* Enumerator
    )
/*++

Routine Description:

    This routine initializes state for the main type
    of enumeration supported -- in which the lock is
    held during the entire duration of the enumeration.

    Currently, the enumeration always starts from the
    start of the table and proceeds till the end, but
    we leave open the possibility that the Context
    passed in will be used to initialize the place
    from which the enumeration starts.

    This routine also increments the counter in the
    hash table tracking the number of enumerators
    active on the hash table -- as long as this
    number is positive, no hash table restructuring
    is possible.

Synchronization:

    The lock protecting the hash table must be
    acquired in exclusive mode.

Arguments:

    HashTable - Pointer to hash Table on which the enumeration
        will take place.

    Enumerator - Pointer to RTL_DYNAMIC_HASH_TABLE_ENUMERATOR structure that
        stores enumeration state.

--*/
{
    QUIC_HASHTABLE_LOOKUP_CONTEXT LocalContext;

    QUIC_DBG_ASSERT(Enumerator != NULL);

    QuicPopulateContext(HashTable, &LocalContext, 0);
    HashTable->NumEnumerators ++;

    if (QuicListIsEmpty(LocalContext.ChainHead)) {
        HashTable->NonEmptyBuckets ++;
    }

    QuicListInsertHead(LocalContext.ChainHead, &(Enumerator->HashEntry.Linkage));
    Enumerator->BucketIndex = 0;
    Enumerator->ChainHead = LocalContext.ChainHead;
    Enumerator->HashEntry.Signature = QUIC_HASH_RESERVED_SIGNATURE;
}

_Must_inspect_result_
QUIC_HASHTABLE_ENTRY*
QuicHashtableEnumerateNext(
    _In_ QUIC_HASHTABLE* HashTable,
    _Inout_ QUIC_HASHTABLE_ENUMERATOR* Enumerator
    )
/*++

Routine Description

    Get the next entry to be enumerated. If the hash chain
    still has entries that haven't been given to the user,
    the next such entry in the hash chain is returned. If
    the hash chain has ended, this function searches for
    the next non-empty hash chain and returns the first
    element in that chain. If no more non-empty hash chains
    exists, the function returns NULL. The caller must call
    RtlEndEnumeration() to explicitly end the enumeration
    and cleanup state.

    This call is robust in the sense, that if this function
    returns NULL, subsequent calls to this function will
    not fail, and will still return NULL.

Synchronization:

    The hash lock must be held in exclusive mode.

Arguments:

    Hash Table - Pointer to the hash table to be enumerated.

    Enumerator - Pointer to RTL_DYNAMIC_HASH_TABLE_ENUMERATOR structure that
        stores enumeration state.

Return Value:

    Pointer to RTL_DYNAMIC_HASH_TABLE_ENTRY if one can be enumerated, and NULL
    other wise.

--*/
{
    QUIC_LIST_ENTRY* CurEntry, *NextEntry, *ChainHead;
    uint32_t i;
    QUIC_HASHTABLE_ENTRY* NextHashEntry;

    QUIC_DBG_ASSERT(Enumerator != NULL);

    //
    // Make sure that Enumerator is initialized.
    //
    QUIC_DBG_ASSERT(Enumerator->ChainHead != NULL);
    QUIC_DBG_ASSERT(QUIC_HASH_RESERVED_SIGNATURE == Enumerator->HashEntry.Signature);

    //
    // We are trying to find the next valid entry. We need
    // to skip over other enumerators AND empty buckets.
    //
    for (i = Enumerator->BucketIndex; i < HashTable->TableSize; i++) {
        if (i == Enumerator->BucketIndex) {
            //
            // If this is the first bucket, start searching from enumerator.
            //
            CurEntry = &(Enumerator->HashEntry.Linkage);
            ChainHead = Enumerator->ChainHead;
        } else {
            //
            // Otherwise start searching from the head of the chain.
            //
            ChainHead = QuicGetChainHead(HashTable, i);
            CurEntry = ChainHead;
        }

        while (CurEntry->Flink != ChainHead) {
            NextEntry = CurEntry->Flink;
            NextHashEntry = QuicFlinkToHashEntry(&(NextEntry->Flink));

            if (QUIC_HASH_RESERVED_SIGNATURE != NextHashEntry->Signature) {
                QuicListEntryRemove(&(Enumerator->HashEntry.Linkage));

                QUIC_DBG_ASSERT(Enumerator->ChainHead != NULL);

                if (Enumerator->ChainHead != ChainHead) {
                    if (QuicListIsEmpty(Enumerator->ChainHead)) {
                        HashTable->NonEmptyBuckets --;
                    }

                    if (QuicListIsEmpty(ChainHead)) {
                        HashTable->NonEmptyBuckets ++;
                    }
                }

                Enumerator->BucketIndex = i;
                Enumerator->ChainHead = ChainHead;

                QuicListInsertHead(NextEntry, &(Enumerator->HashEntry.Linkage));
                return NextHashEntry;
            }

            CurEntry = NextEntry;
        }
    }

    return NULL;
}

void
QuicHashtableEnumerateEnd(
    _In_ QUIC_HASHTABLE* HashTable,
    _Inout_ QUIC_HASHTABLE_ENUMERATOR* Enumerator
    )
/*++

Routine Description:

    This routine reverses the effect of InitEnumeration. It
    decrements the NumEnumerators counter in HashTable and
    cleans up Enumerator state.

Synchronization:

    The hash table lock must be held in exclusive mode.

Arguments:

    HashTable - Pointer to hash table on which enumerator was operating.

    Enumerator - Pointer to enumerator representing the enumeration that
        needs to be ended.

--*/
{
    QUIC_DBG_ASSERT(Enumerator != NULL);
    QUIC_DBG_ASSERT(HashTable->NumEnumerators > 0);
    HashTable->NumEnumerators--;

    if (!QuicListIsEmpty(&(Enumerator->HashEntry.Linkage))) {
        QUIC_DBG_ASSERT(Enumerator->ChainHead != NULL);

        QuicListEntryRemove(&(Enumerator->HashEntry.Linkage));

        if (QuicListIsEmpty(Enumerator->ChainHead)) {
            QUIC_DBG_ASSERT(HashTable->NonEmptyBuckets > 0);
            HashTable->NonEmptyBuckets--;
        }
    }

    Enumerator->ChainHead = FALSE;
}

#if 0 // Currently unused

BOOLEAN
QuicHashTableExpand(
    _Inout_ QUIC_HASHTABLE* HashTable
    )
{
    QUIC_HASHTABLE_ENTRY* NextHashEntry;
    QUIC_LIST_ENTRY* ChainToBeSplit, *NewChain;
    QUIC_LIST_ENTRY* NextEntry, *CurEntry;
    uint32_t BucketIndex;
    uint32_t FirstLevelIndex, SecondLevelIndex;
    QUIC_LIST_ENTRY*  SecondLevelDir;
    QUIC_LIST_ENTRY* *FirstLevelDir;

    //
    // Can't expand if we've reached the maximum.
    //
    if (HashTable->TableSize == MAX_HASH_TABLE_SIZE) {
        return FALSE;
    }

    if (HashTable->NumEnumerators > 0) {
        return FALSE;
    }

    QUIC_DBG_ASSERT(HashTable->TableSize < MAX_HASH_TABLE_SIZE);

    //
    // First see if increasing the table size will mean
    // new allocations. After the hash table is increased by
    // one, the highest bucket index will be the current table
    // size, which is what we use in the calculations below
    //
    QuicComputeDirIndices(
        HashTable->TableSize, &FirstLevelIndex, &SecondLevelIndex);

    //
    // Switch to the multi-dir mode in case of
    // the only second-level directory is about to be expanded.
    //

    if (HT_SECOND_LEVEL_DIR_MIN_SIZE == HashTable->TableSize) {

        SecondLevelDir = (QUIC_LIST_ENTRY*)HashTable->Directory;
        FirstLevelDir = QUIC_ALLOC_NONPAGED(sizeof(QUIC_LIST_ENTRY*) * HT_FIRST_LEVEL_DIR_SIZE);

        if (FirstLevelDir == NULL) {
            return FALSE;
        }

        QuicZeroMemory(FirstLevelDir,
                      sizeof(QUIC_LIST_ENTRY*) * HT_FIRST_LEVEL_DIR_SIZE);

        FirstLevelDir[0] = SecondLevelDir;

        HashTable->Directory = FirstLevelDir;
    }

    FirstLevelDir = (QUIC_LIST_ENTRY* *)HashTable->Directory;
    QUIC_DBG_ASSERT(FirstLevelDir != NULL);
    SecondLevelDir = FirstLevelDir[FirstLevelIndex];

    if (SecondLevelDir == NULL) {
        //
        // Allocate second level directory.
        //
        SecondLevelDir = QuicAllocateSecondLevelDir(FirstLevelIndex);

        if (NULL == SecondLevelDir) {

            //
            // If allocation failure happened on attempt to restructure
            // the table, switch it back to direct mode.
            //

            if (HT_SECOND_LEVEL_DIR_MIN_SIZE == HashTable->TableSize) {

                QUIC_DBG_ASSERT(FirstLevelIndex == 1);

                HashTable->Directory = FirstLevelDir[0];
                QUIC_FREE(FirstLevelDir);
            }

            return FALSE;
        }

        FirstLevelDir[FirstLevelIndex] = SecondLevelDir;
    }

    HashTable->TableSize ++;

    //
    // The allocations are out of the way. Now actually increase
    // the Table size and split the pivot bucket.
    //
    ChainToBeSplit = QuicGetChainHead(HashTable, HashTable->Pivot);
    HashTable->Pivot ++;

    NewChain = &(SecondLevelDir[SecondLevelIndex]);
    QuicListInitializeHead(NewChain);

    if (!QuicListIsEmpty(ChainToBeSplit)) {
        CurEntry = ChainToBeSplit;

        while (CurEntry->Flink != ChainToBeSplit) {
            NextEntry = CurEntry->Flink;
            NextHashEntry = QuicFlinkToHashEntry(&(NextEntry->Flink));

            BucketIndex = QuicRandomizeBits(HashTable, NextHashEntry->Signature) &
                ((HashTable->DivisorMask << 1) | 1);

            QUIC_DBG_ASSERT((BucketIndex == (HashTable->Pivot - 1)) ||
                   (BucketIndex == (HashTable->TableSize - 1)));

            if (BucketIndex == (HashTable->TableSize - 1)) {
                QuicListEntryRemove(NextEntry);
                QuicListInsertTail(NewChain, NextEntry);
                continue;
            }

            //
            // If the NextEntry falls in the same bucket, move on.
            //
            CurEntry = NextEntry;
        }

        if (!QuicListIsEmpty(NewChain)) {
            HashTable->NonEmptyBuckets ++;
        }

        if (QuicListIsEmpty(ChainToBeSplit)) {
            QUIC_DBG_ASSERT(HashTable->NonEmptyBuckets > 0);
            HashTable->NonEmptyBuckets --;
        }
    }

    if (HashTable->Pivot == (HashTable->DivisorMask + 1)) {
        HashTable->DivisorMask = (HashTable->DivisorMask << 1) | 1;
        HashTable->Pivot = 0;

        //
        // Assert that at this point, TableSize is a power of 2.
        //
        QUIC_DBG_ASSERT(0 == (HashTable->TableSize & (HashTable->TableSize - 1)));
    }

    return TRUE;
}

BOOLEAN
QuicHashTableContract(
    _Inout_ QUIC_HASHTABLE* HashTable
    )
{
    uint32_t FirstLevelIndex, SecondLevelIndex;
    QUIC_LIST_ENTRY* ChainToBeMoved, *CombinedChain;
    QUIC_LIST_ENTRY* CurEntry, *NextEntry, *EntryToBeMoved;
    QUIC_LIST_ENTRY* SecondLevelDir;
    QUIC_LIST_ENTRY** FirstLevelDir;
    QUIC_HASHTABLE_ENTRY* NextHashEntry, *HashEntryToBeMoved;

    //
    // Can't take table size lower than BASE_DYNAMIC_HASH_TABLE_SIZE.
    //
    QUIC_DBG_ASSERT(HashTable->TableSize >= BASE_HASH_TABLE_SIZE);

    if (HashTable->TableSize == BASE_HASH_TABLE_SIZE) {
        return FALSE;
    }

    if (HashTable->NumEnumerators > 0) {
        return FALSE;
    }

    //
    // Bring the table size down by 1 bucket, and change all
    // state variables accordingly.
    //
    if (HashTable->Pivot == 0) {
        HashTable->DivisorMask = HashTable->DivisorMask >> 1;
        HashTable->Pivot = HashTable->DivisorMask;
    } else {
        HashTable->Pivot --;
    }

    //
    // Need to combine two buckets. Since table-size is down by 1
    // and we need the bucket that was the last bucket before table
    // size was lowered, the index of the last bucket is exactly
    // equal to the current table size.
    //
    ChainToBeMoved = QuicGetChainHead(HashTable, HashTable->TableSize - 1);
    CombinedChain = QuicGetChainHead(HashTable, HashTable->Pivot);

    HashTable->TableSize--;

    QUIC_DBG_ASSERT(ChainToBeMoved != NULL);
    QUIC_DBG_ASSERT(CombinedChain != NULL);

    if (!QuicListIsEmpty(ChainToBeMoved) && !QuicListIsEmpty(CombinedChain)) {
        //
        // Both lists are non-empty.
        //

        QUIC_DBG_ASSERT(HashTable->NonEmptyBuckets > 0);
        HashTable->NonEmptyBuckets--;
    }

    CurEntry = CombinedChain;

    while (!QuicListIsEmpty(ChainToBeMoved)) {
        EntryToBeMoved = QuicListRemoveHead(ChainToBeMoved);
        HashEntryToBeMoved = QuicFlinkToHashEntry(&(EntryToBeMoved->Flink));

        while (CurEntry->Flink != CombinedChain) {
            NextEntry = CurEntry->Flink;
            NextHashEntry = QuicFlinkToHashEntry(&(NextEntry->Flink));

            if (NextHashEntry->Signature >= HashEntryToBeMoved->Signature) {
                break;
            }

            CurEntry = NextEntry;
        }

        QuicListInsertHead(CurEntry, &(HashEntryToBeMoved->Linkage));
    }

    //
    // Finally free any extra memory if possible.
    //

    QuicComputeDirIndices(
        HashTable->TableSize, &FirstLevelIndex, &SecondLevelIndex);

    if (SecondLevelIndex == 0) {

        FirstLevelDir = (QUIC_LIST_ENTRY**)HashTable->Directory;

        SecondLevelDir = FirstLevelDir[FirstLevelIndex];

        QuicSecondLevelDirFree(SecondLevelDir);

        FirstLevelDir[FirstLevelIndex] = NULL;

        //
        // Switch to a single-dir mode if fits within a single second-level.
        //

        if (HT_SECOND_LEVEL_DIR_MIN_SIZE == HashTable->TableSize) {
            HashTable->Directory = FirstLevelDir[0];
            QUIC_FREE(FirstLevelDir);
        }
    }

    return TRUE;
}

#endif // 0
