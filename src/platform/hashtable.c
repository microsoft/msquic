/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file contains code for a dynamic hash table (adapted from Windows
    RTL hash implementation).

Notes:

    This code uses linear hashing to increase the table size smoothly as the
    number of elements in the table increases, while rehashing a portion of the
    elements. This is in contrast to doubling-based schemes which double the
    size of the hash table periodically and rehash *all* the elements in the
    hash table.

    Note that the hash table size (in terms of the total number of buckets) is
    independent from the size of memory allocated for backing the table. This
    implementation doubles up the memory size for each higher-indexed second
    level bucket directory (which the first level directory points to). This is
    so that we can scale up the maximum supported table size exponentially by
    the size of the first level directory. But, we still increment the table
    size by only one bucket during table expansion, i.e., each expansion
    iteration rehashes only a single bucket (the pivot bucket) as opposed to the
    whole table.

    This hash table is intended to be protected by a single lock, which can be a
    reader-writer lock if the caller desires. Locking is supposed to be handled
    by the user. This API is designed for users who really care about
    performance and would like to retain explicit control of locking.

    APIs support the concept of transactions -- if the caller wishes to make a
    series of operations, for e.g, a lookup followed by an insertion, the APIs
    allow the user to mark the position where the last operation occurred using
    a place-holder called a Context. So if a user performs a lookup and passes
    in a Context, the Context will store the place in the hash table where the
    lookup ended. If the caller wants to follow it up with an insertion, the
    hash table now has information about the location, and does not have to
    traverse the hash table chains again.

--*/

#include "platform_internal.h"
#ifdef QUIC_CLOG
#include "hashtable.c.clog.h"
#endif

#define CXPLAT_HASH_RESERVED_SIGNATURE 0

//
// Inserts with hash = CXPLAT_HASH_RESERVED_SIGNATURE aren't allowed.
//
#define CXPLAT_HASH_ALT_SIGNATURE (CXPLAT_HASH_RESERVED_SIGNATURE + 1)

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

CXPLAT_STATIC_ASSERT(
    CXPLAT_HASH_MIN_SIZE == BASE_HASH_TABLE_SIZE,
    "Hash table sizes should match!");

#ifndef BitScanReverse
static
uint8_t
CxPlatBitScanReverse(
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

    if (Mask == 0 || Index == 0) {
        return 0;
    }

    for (ii = (sizeof(uint32_t) * 8); ii >= 0; --ii) {
        uint32_t TempMask = 1UL << ii;

        if ((Mask & TempMask) != 0) {
            *Index = ii;
            break;
        }
    }

    return (ii >= 0 ? (uint8_t)1 : (uint8_t)0);
}
#else
#define CxPlatBitScanReverse(A, B) BitScanReverse((ULONG*)A, (ULONG)B)
#endif // BitScanReverse

static
void
CxPlatComputeDirIndices(
    _In_range_(<, MAX_HASH_TABLE_SIZE)
    uint32_t BucketIndex,
    _Out_range_(<, HT_FIRST_LEVEL_DIR_SIZE)
    uint32_t* FirstLevelIndex,
    _Out_range_(<, (1 << (*FirstLevelIndex + HT_SECOND_LEVEL_DIR_SHIFT)))
    uint32_t* SecondLevelIndex
    )
/*++

Routine Description:

    Given a bucket index, computes the first level dir index that points to the
    corresponding second level dir, and the second level dir index that points
    to the hash bucket.

Arguments:

    BucketIndex - [0, MAX_HASH_TABLE_SIZE-1]

    FirstLevelIndex - Pointer to a uint32_t that will be assigned the first
        level index upon return.

    SecondLevelIndex - Pointer to a uint32_t that will be assigned the second
        level index upon return.

--*/
{
    CXPLAT_DBG_ASSERT(BucketIndex < MAX_HASH_TABLE_SIZE);

    uint32_t AbsoluteIndex = BucketIndex + HT_SECOND_LEVEL_DIR_MIN_SIZE;

    //
    // Find the most significant set bit. Since AbsoluteIndex is always nonzero,
    // we don't need to check the return value.
    //

    CxPlatBitScanReverse(FirstLevelIndex, AbsoluteIndex);

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

    CXPLAT_DBG_ASSERT(*FirstLevelIndex < HT_FIRST_LEVEL_DIR_SIZE);
}

_Ret_range_(>=, CXPLAT_HASH_MIN_SIZE)
static
uint32_t
CxPlatComputeSecondLevelDirSize(
    _In_range_(<, HT_FIRST_LEVEL_DIR_SIZE) uint32_t FirstLevelIndex
    )
/*++

Routine Description:

    Computes size of 2nd level directory. The size of the second level dir is
    determined by its position in the first level dir.

Arguments:

    FirstLevelIndex - The first level index.

Return Value:

    The directory size.

--*/
{
    return (1 << (FirstLevelIndex + HT_SECOND_LEVEL_DIR_SHIFT));
}

static
void
CxPlatInitializeSecondLevelDir(
    _Out_writes_all_(NumberOfBucketsToInitialize) CXPLAT_LIST_ENTRY* SecondLevelDir,
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
        CxPlatListInitializeHead(&SecondLevelDir[i]);
    }
}

static
CXPLAT_HASHTABLE_ENTRY*
CxPlatFlinkToHashEntry(
    _In_ CXPLAT_LIST_ENTRY* *FlinkPtr
    )
/*++

Routine Description:

    Converts the pointer to the Flink in LIST_ENTRY into a CXPLAT_HASHTABLE_ENTRY
    structure.

Arguments:

    FlinkPtr - supplies the pointer to the Flink field in LIST_ENTRY

Return Value:

    Returns the CXPLAT_HASHTABLE_ENTRY that contains the LIST_ENTRY which contains
    the Flink whose pointer was passed above.

--*/
{
    return CXPLAT_CONTAINING_RECORD(FlinkPtr, CXPLAT_HASHTABLE_ENTRY, Linkage);
}

static
CXPLAT_LIST_ENTRY*
CxPlatGetChainHead(
    _In_ const CXPLAT_HASHTABLE* HashTable,
    _In_range_(<, HashTable->TableSize) uint32_t BucketIndex
    )
/*++

Routine Description:

    Given a table index, it retrieves the pointer to the head of the hash chain.
    This routine expects that the index passed will be less than the table size.

    N.B. It was initially designed such that if the index asked for is greater
    than table size, this routine should just increase the table size so that
    the index asked for exists. But that increases the path length for the
    regular callers, and so that functionality was removed.

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
    CXPLAT_LIST_ENTRY* SecondLevelDir;

    CXPLAT_DBG_ASSERT(BucketIndex < HashTable->TableSize);

    //
    // 'Directory' field of the hash table points either
    // to the first level directory or to the second-level directory
    // itself depending to the allocated size..
    //

    if (HashTable->TableSize <= HT_SECOND_LEVEL_DIR_MIN_SIZE) {
        SecondLevelDir = HashTable->SecondLevelDir;
        SecondLevelIndex = BucketIndex;

    } else {
        uint32_t FirstLevelIndex = 0;
        CxPlatComputeDirIndices(BucketIndex, &FirstLevelIndex, &SecondLevelIndex);
        SecondLevelDir = *(HashTable->FirstLevelDir + FirstLevelIndex);
    }

    CXPLAT_DBG_ASSERT(SecondLevelDir != NULL);

    return SecondLevelDir + SecondLevelIndex;
}

static
uint32_t
CxPlatGetBucketIndex(
    _In_ const CXPLAT_HASHTABLE* HashTable,
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
#ifdef CXPLAT_HASHTABLE_RESIZE_SUPPORT
    uint32_t BucketIndex = ((uint32_t)Signature) & HashTable->DivisorMask;
    if (BucketIndex < HashTable->Pivot) {
        BucketIndex = ((uint32_t)Signature) & ((HashTable->DivisorMask << 1) | 1);
    }
#else
    uint32_t BucketIndex = ((uint32_t)Signature) & (HashTable->TableSize - 1);
#endif

    return BucketIndex;
}

static
void
CxPlatPopulateContext(
    _In_ const CXPLAT_HASHTABLE* HashTable,
    _Out_ CXPLAT_HASHTABLE_LOOKUP_CONTEXT* Context,
    _In_ uint64_t Signature
    )
/*++

Routine Description:

    Does the basic hashing and lookup and returns a pointer to either the entry
    before the entry with the queried signature, or to the entry after which
    such a entry would exist (if it doesn't exist).

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
    //
    // Compute the hash.
    //
    uint32_t BucketIndex = CxPlatGetBucketIndex(HashTable, Signature);

    CXPLAT_LIST_ENTRY* BucketPtr = CxPlatGetChainHead(HashTable, BucketIndex);
    CXPLAT_DBG_ASSERT(NULL != BucketPtr);

    CXPLAT_LIST_ENTRY* CurEntry = BucketPtr;
    while (CurEntry->Flink != BucketPtr) {

        CXPLAT_LIST_ENTRY* NextEntry = CurEntry->Flink;
        CXPLAT_HASHTABLE_ENTRY* NextHashEntry = CxPlatFlinkToHashEntry(&NextEntry->Flink);

        if ((CXPLAT_HASH_RESERVED_SIGNATURE == NextHashEntry->Signature) ||
            (NextHashEntry->Signature < Signature)) {

            CurEntry = NextEntry;
            continue;
        }

        break;
    }

    //
    // At this point, the signature is either equal or greater, or the end of
    // the chain. Either way, this is where we want to be.
    //
    Context->ChainHead = BucketPtr;
    Context->PrevLinkage = CurEntry;
    Context->Signature = Signature;
}

_Must_inspect_result_
_Success_(return != FALSE)
BOOLEAN
CxPlatHashtableInitialize(
    _Inout_ _When_(NULL == *HashTable, _At_(*HashTable, __drv_allocatesMem(Mem) _Post_notnull_))
        CXPLAT_HASHTABLE* *HashTable,
    _In_ uint32_t InitialSize
    )
/*++

Routine Description:

    Creates a hash table. Takes a pointer to a pointer to CXPLAT_HASHTABLE, just
    so that the caller can pass a pre-allocated CXPLAT_HASHTABLE structure to be
    initialized, which the partitioned hash table does.

Synchronization:

    None.

Arguments:

    HashTable - Pointer to a pointer to a hash Table to be initialized. This
        argument must be non-null, but it can contain either a NULL value (in
        which case a CXPLAT_HASHTABLE will be allocated, or can contain a
        pre-allocated CXPLAT_HASHTABLE.

    InitialSize - The initial size of the hash table in number of buckets.

Return Value:

    TRUE if creation and initialization succeeded, FALSE otherwise.

--*/
{
    //
    // Initial size must be a power of two and within the allowed range.
    //
    if (!IS_POWER_OF_TWO(InitialSize) ||
        (InitialSize > MAX_HASH_TABLE_SIZE) ||
        (InitialSize < BASE_HASH_TABLE_SIZE)) {
        return FALSE;
    }

    //
    // First allocate the hash Table header.
    //
    uint32_t LocalFlags = 0;
    CXPLAT_HASHTABLE* Table;
    if (*HashTable == NULL) {
        Table = CXPLAT_ALLOC_NONPAGED(sizeof(CXPLAT_HASHTABLE), QUIC_POOL_HASHTABLE);
        if (Table == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "CXPLAT_HASHTABLE",
                sizeof(CXPLAT_HASHTABLE));
            return FALSE;
        }

        LocalFlags = CXPLAT_HASH_ALLOCATED_HEADER;

    } else {
        Table = *HashTable;
    }

    CxPlatZeroMemory(Table, sizeof(CXPLAT_HASHTABLE));
    Table->Flags = LocalFlags;
    Table->TableSize = InitialSize;
#ifdef CXPLAT_HASHTABLE_RESIZE_SUPPORT
    Table->DivisorMask = Table->TableSize - 1;
    Table->Pivot = 0;
#endif

    //
    // Now we allocate the second level entries.
    //

    if (Table->TableSize <= HT_SECOND_LEVEL_DIR_MIN_SIZE) {

        //
        // Directory pointer in the Table header structure points points directly
        // directly points directly to the single second-level directory.
        //

        Table->SecondLevelDir =
            CXPLAT_ALLOC_NONPAGED(
                CxPlatComputeSecondLevelDirSize(0) * sizeof(CXPLAT_LIST_ENTRY),
                QUIC_POOL_HASHTABLE_MEMBER);
        if (Table->SecondLevelDir == NULL) {
            QuicTraceEvent(
                AllocFailure,
                "Allocation of '%s' failed. (%llu bytes)",
                "second level dir (0)",
                CxPlatComputeSecondLevelDirSize(0) * sizeof(CXPLAT_LIST_ENTRY));
            CxPlatHashtableUninitialize(Table);
            return FALSE;
        }

        CxPlatInitializeSecondLevelDir(Table->SecondLevelDir, Table->TableSize);

    } else {

        //
        // Allocate and initialize the first-level directory entries required to
        // fit upper bound.
        //
        uint32_t FirstLevelIndex = 0, SecondLevelIndex = 0;
        CxPlatComputeDirIndices(
            (Table->TableSize - 1), &FirstLevelIndex, &SecondLevelIndex);

        Table->FirstLevelDir =
            CXPLAT_ALLOC_NONPAGED(
                sizeof(CXPLAT_LIST_ENTRY*) * HT_FIRST_LEVEL_DIR_SIZE,
                QUIC_POOL_HASHTABLE_MEMBER);
        if (Table->FirstLevelDir == NULL) {
            CxPlatHashtableUninitialize(Table);
            return FALSE;
        }

        CxPlatZeroMemory(Table->FirstLevelDir,
            sizeof(CXPLAT_LIST_ENTRY*) * HT_FIRST_LEVEL_DIR_SIZE);

        for (uint32_t i = 0; i <= FirstLevelIndex; i++) {

            Table->FirstLevelDir[i] =
                CXPLAT_ALLOC_NONPAGED(
                    CxPlatComputeSecondLevelDirSize(i) * sizeof(CXPLAT_LIST_ENTRY),
                    QUIC_POOL_HASHTABLE_MEMBER);
            if (Table->FirstLevelDir[i] == NULL) {
                QuicTraceEvent(
                    AllocFailure,
                    "Allocation of '%s' failed. (%llu bytes)",
                    "second level dir (i)",
                    CxPlatComputeSecondLevelDirSize(i) * sizeof(CXPLAT_LIST_ENTRY));
                CxPlatHashtableUninitialize(Table);
                return FALSE;
            }

            CxPlatInitializeSecondLevelDir(
                Table->FirstLevelDir[i],
                (i < FirstLevelIndex)
                    ? CxPlatComputeSecondLevelDirSize(i)
                    : (SecondLevelIndex + 1));
        }
    }

    *HashTable = Table;

    return TRUE;
}

void
CxPlatHashtableUninitialize(
    _In_
    _When_((HashTable->Flags & CXPLAT_HASH_ALLOCATED_HEADER), __drv_freesMem(Mem) _Post_invalid_)
    _At_(HashTable->Directory, __drv_freesMem(Mem) _Post_invalid_)
        CXPLAT_HASHTABLE* HashTable
    )
/*++

Routine Description:

    Called to remove all resources allocated either in CxPlatHashtableInitialize,
    or later while expanding the table. This function just walks the entire
    table checking that all hash buckets are null, and then removing all the
    memory allocated for the directories behind it. This function is also called
    from CxPlatHashtableInitialize to cleanup the allocations just in case, an
    error occurs (like failed memory allocation).

Synchronization:

    None

Arguments:

    HashTable - Pointer to hash Table to be deleted.

--*/
{
    CXPLAT_DBG_ASSERT(HashTable->NumEnumerators == 0);
    CXPLAT_DBG_ASSERT(HashTable->NumEntries == 0);

    if (HashTable->TableSize <= HT_SECOND_LEVEL_DIR_MIN_SIZE) {

        if (HashTable->SecondLevelDir != NULL) {
            CXPLAT_FREE(HashTable->SecondLevelDir, QUIC_POOL_HASHTABLE_MEMBER);
            HashTable->SecondLevelDir = NULL;
        }

    } else {

        if (HashTable->FirstLevelDir != NULL) {

#if DEBUG
            uint32_t largestFirstLevelIndex = 0, largestSecondLevelIndex = 0;
            CxPlatComputeDirIndices(
                (HashTable->TableSize - 1), &largestFirstLevelIndex, &largestSecondLevelIndex);
#endif

            uint32_t FirstLevelIndex;
            for (FirstLevelIndex = 0;
                 FirstLevelIndex < HT_FIRST_LEVEL_DIR_SIZE;
                 FirstLevelIndex++) {

                CXPLAT_LIST_ENTRY* SecondLevelDir =
                    HashTable->FirstLevelDir[FirstLevelIndex];
                if (NULL == SecondLevelDir) {
                    break;
                }

#if DEBUG
                uint32_t initializedBucketCountInSecondLevelDir =
                    (FirstLevelIndex < largestFirstLevelIndex)
                        ? CxPlatComputeSecondLevelDirSize(FirstLevelIndex)
                        : largestSecondLevelIndex+1;

                for (uint32_t SecondLevelIndex = 0;
                     SecondLevelIndex < initializedBucketCountInSecondLevelDir;
                     SecondLevelIndex++) {
                    CXPLAT_DBG_ASSERT(CxPlatListIsEmpty(&SecondLevelDir[SecondLevelIndex]));
                }
#endif

                CXPLAT_FREE(SecondLevelDir, QUIC_POOL_HASHTABLE_MEMBER);
            }

#if DEBUG
            for (; FirstLevelIndex < HT_FIRST_LEVEL_DIR_SIZE; FirstLevelIndex++) {
                CXPLAT_DBG_ASSERT(NULL == HashTable->FirstLevelDir[FirstLevelIndex]);
            }
#endif

            CXPLAT_FREE(HashTable->FirstLevelDir, QUIC_POOL_HASHTABLE_MEMBER);
            HashTable->FirstLevelDir = NULL;
        }
    }

    if (HashTable->Flags & CXPLAT_HASH_ALLOCATED_HEADER) {
        CXPLAT_FREE(HashTable, QUIC_POOL_HASHTABLE);
    }
}

void
CxPlatHashtableInsert(
    _In_ CXPLAT_HASHTABLE* HashTable,
    _In_ __drv_aliasesMem CXPLAT_HASHTABLE_ENTRY* Entry,
    _In_ uint64_t Signature,
    _Inout_opt_ CXPLAT_HASHTABLE_LOOKUP_CONTEXT* Context
    )
/*++

Routine Description:

    Inserts an entry into a hash table, given the pointer to a
    CXPLAT_HASHTABLE_ENTRY and a signature. An optional context can be passed in
    which, if possible, will be used to quickly get to the relevant bucket chain.
    This routine will not take the contents of the Context structure passed in
    on blind faith -- it will check if the signature in the Context structure
    matches the signature of the entry that needs to be inserted. This adds an
    extra check on the hot path, but I deemed it necessary.

Synchronization:

    Hash lock has to be held by caller in exclusive mode.

Arguments:

    HashTable - Pointer to hash table in which we wish to insert entry

    Entry - Pointer to entry to be inserted.

    Signature - Signature of the entry to be inserted.

    Context - Pointer to optional context that can be passed in.

--*/
{
    CXPLAT_HASHTABLE_LOOKUP_CONTEXT LocalContext = {0};
    CXPLAT_HASHTABLE_LOOKUP_CONTEXT* ContextPtr = NULL;

    if (Signature == CXPLAT_HASH_RESERVED_SIGNATURE) {
        Signature = CXPLAT_HASH_ALT_SIGNATURE;
    }

    Entry->Signature = Signature;

    HashTable->NumEntries++;

    if (Context == NULL) {

        CxPlatPopulateContext(HashTable, &LocalContext, Signature);
        ContextPtr = &LocalContext;

    } else {

        if (Context->ChainHead == NULL) {
            CxPlatPopulateContext(HashTable, Context, Signature);
        }

        CXPLAT_DBG_ASSERT(Signature == Context->Signature);
        ContextPtr = Context;
    }

    CXPLAT_DBG_ASSERT(ContextPtr->ChainHead != NULL);

    if (CxPlatListIsEmpty(ContextPtr->ChainHead)) {
        HashTable->NonEmptyBuckets++;
    }

    CxPlatListInsertHead(ContextPtr->PrevLinkage, &Entry->Linkage);
}

void
CxPlatHashtableRemove(
    _In_ CXPLAT_HASHTABLE* HashTable,
    _In_ CXPLAT_HASHTABLE_ENTRY* Entry,
    _Inout_opt_ CXPLAT_HASHTABLE_LOOKUP_CONTEXT* Context
    )
/*++

Routine Description:

    This function will remove an entry from the hash table. Since the bucket
    chains are doubly-linked lists, removal does not require identification of
    the bucket, and is a local operation.

    If a Context is specified, the function takes care of both possibilities --
    if the Context is already filled, it remains untouched, otherwise, it is
    filled appropriately.

Synchronization:

    Requires the caller to hold the lock protecting the hash table in
    exclusive-mode

Arguments:

    HashTable - Pointer to hash table from which the entry is to be removed.

    Entry - Pointer to the entry that is to be removed.

    Context - Optional pointer which stores information about the location in
        about the location in the hash table where that particular signature
        resides.

--*/
{
    uint64_t Signature = Entry->Signature;

    CXPLAT_DBG_ASSERT(HashTable->NumEntries > 0);
    HashTable->NumEntries--;

    if (Entry->Linkage.Flink == Entry->Linkage.Blink) {
        //
        // This is the last element in this chain.
        //
        CXPLAT_DBG_ASSERT (HashTable->NonEmptyBuckets > 0);
        HashTable->NonEmptyBuckets--;
    }

    CxPlatListEntryRemove(&Entry->Linkage);

    if (Context != NULL) {
        if (Context->ChainHead == NULL) {
            CxPlatPopulateContext(HashTable, Context, Signature);
        } else {
            CXPLAT_DBG_ASSERT(Signature == Context->Signature);
        }
    }
}

_Must_inspect_result_
CXPLAT_HASHTABLE_ENTRY*
CxPlatHashtableLookup(
    _In_ const CXPLAT_HASHTABLE* HashTable,
    _In_ uint64_t Signature,
    _Out_opt_ CXPLAT_HASHTABLE_LOOKUP_CONTEXT* Context
    )
/*++

Routine Description:

    This function will look up an entry in the hash table. Since our hash table
    only recognizes signatures, lookups need to generate all possible matches
    for the requested signature. This is achieved by storing all entries with
    the same signature in a contiguous subsequence, and returning the
    subsequence. The caller can walk this subsequence by calling
    CxPlatHashtableLookupNext. If specified, the context is always initialized in
    this operation.

Arguments:

    HashTable - Pointer to the hash table in which the signature is to be looked
        up.

    Signature - Signature to be looked up.

    Context - Optional pointer which stores information about the location in
        the hash table where that particular signature resides.

Return Value:

    Returns the first hash entry found that matches the signature. All the other
    hash entries with the same signature are linked behind this value.

--*/
{
    if (Signature == CXPLAT_HASH_RESERVED_SIGNATURE) {
        Signature = CXPLAT_HASH_ALT_SIGNATURE;
    }

    CXPLAT_HASHTABLE_LOOKUP_CONTEXT LocalContext;
    CXPLAT_HASHTABLE_LOOKUP_CONTEXT* ContextPtr =
        (Context != NULL) ? Context : &LocalContext;

    CxPlatPopulateContext(HashTable, ContextPtr, Signature);

    CXPLAT_LIST_ENTRY* CurEntry = ContextPtr->PrevLinkage->Flink;
    if (ContextPtr->ChainHead == CurEntry) {
        return NULL;
    }

    CXPLAT_HASHTABLE_ENTRY* CurHashEntry = CxPlatFlinkToHashEntry(&CurEntry->Flink);

    //
    // CxPlatPopulateContext will never return a PrevLinkage whose next points to
    // an enumerator.
    //
    CXPLAT_DBG_ASSERT(CXPLAT_HASH_RESERVED_SIGNATURE != CurHashEntry->Signature);

    if (CurHashEntry->Signature == Signature) {
        return CurHashEntry;
    }

    return NULL;
}

_Must_inspect_result_
CXPLAT_HASHTABLE_ENTRY*
CxPlatHashtableLookupNext(
    _In_ const CXPLAT_HASHTABLE* HashTable,
    _Inout_ CXPLAT_HASHTABLE_LOOKUP_CONTEXT* Context
    )
/*++

Routine Description:

    This function will continue a lookup on a hash table. We assume that the
    user is not stupid and will call it only after Lookup has returned a
    non-NULL entry.

    Also note that this function has the responsibility to skip through any
    enumerators that may be in the chain. In such a case, the Context structure's
    PrevLinkage will *still* point to the last entry WHICH IS NOT A ENUMERATOR.

Arguments:

    HashTable - Pointer to the hash table in which the lookup is to be performed

    Context - Pointer to context which remains untouched during this operation.
        However that entry must be non-NULL so that we can figure out whether we
        have reached the end of the list.

Return Value:

    Returns the next entry with the same signature as the entry passed in, or
    NULL if no such entry exists.

--*/
{
    CXPLAT_DBG_ASSERT(NULL != Context);
    CXPLAT_DBG_ASSERT(NULL != Context->ChainHead);
    CXPLAT_DBG_ASSERT(Context->PrevLinkage->Flink != Context->ChainHead);

    //
    // We know that the next entry is a valid, kosher entry,
    //
    CXPLAT_LIST_ENTRY* CurEntry = Context->PrevLinkage->Flink;
    CXPLAT_DBG_ASSERT(CurEntry != Context->ChainHead);
    CXPLAT_DBG_ASSERT(CXPLAT_HASH_RESERVED_SIGNATURE !=
           (CxPlatFlinkToHashEntry(&CurEntry->Flink)->Signature));

    //
    // Is this the end of the chain?
    //
    if (CurEntry->Flink == Context->ChainHead) {
        return NULL;
    }

    CXPLAT_LIST_ENTRY* NextEntry;
    CXPLAT_HASHTABLE_ENTRY* NextHashEntry;
    if (HashTable->NumEnumerators == 0) {
        NextEntry = CurEntry->Flink;
        NextHashEntry = CxPlatFlinkToHashEntry(&NextEntry->Flink);
    } else {
        CXPLAT_DBG_ASSERT(CurEntry->Flink != Context->ChainHead);
        NextHashEntry = NULL;
        while (CurEntry->Flink != Context->ChainHead) {
            NextEntry = CurEntry->Flink;
            NextHashEntry = CxPlatFlinkToHashEntry(&NextEntry->Flink);

            if (CXPLAT_HASH_RESERVED_SIGNATURE != NextHashEntry->Signature) {
                break;
            }

            CurEntry = NextEntry;
        }
    }

    CXPLAT_DBG_ASSERT(NextHashEntry != NULL);
    if (NextHashEntry->Signature == Context->Signature) {
        Context->PrevLinkage = CurEntry;
        return NextHashEntry;
    }

    //
    // If we have found no other entry matching that signature, the Context
    // remains untouched, free for the caller to use for other insertions and
    // removals.
    //
    return NULL;
}

void
CxPlatHashtableEnumerateBegin(
    _In_ CXPLAT_HASHTABLE* HashTable,
    _Out_ CXPLAT_HASHTABLE_ENUMERATOR* Enumerator
    )
/*++

Routine Description:

    This routine initializes state for the main type of enumeration supported --
    in which the lock is held during the entire duration of the enumeration.

    Currently, the enumeration always starts from the start of the table and
    proceeds till the end, but we leave open the possibility that the Context
    passed in will be used to initialize the place from which the enumeration
    starts.

    This routine also increments the counter in the hash table tracking the
    number of enumerators active on the hash table -- as long as this number is
    positive, no hash table restructuring is possible.

Synchronization:

    The lock protecting the hash table must be acquired in exclusive mode.

Arguments:

    HashTable - Pointer to hash Table on which the enumeration will take place.

    Enumerator - Pointer to CXPLAT_HASHTABLE_ENUMERATOR structure that stores
        enumeration state.

--*/
{
    CXPLAT_DBG_ASSERT(Enumerator != NULL);

    CXPLAT_HASHTABLE_LOOKUP_CONTEXT LocalContext;
    CxPlatPopulateContext(HashTable, &LocalContext, 0);
    HashTable->NumEnumerators++;

    if (CxPlatListIsEmpty(LocalContext.ChainHead)) {
        HashTable->NonEmptyBuckets++;
    }

    CxPlatListInsertHead(LocalContext.ChainHead, &(Enumerator->HashEntry.Linkage));
    Enumerator->BucketIndex = 0;
    Enumerator->ChainHead = LocalContext.ChainHead;
    Enumerator->HashEntry.Signature = CXPLAT_HASH_RESERVED_SIGNATURE;
}

_Must_inspect_result_
CXPLAT_HASHTABLE_ENTRY*
CxPlatHashtableEnumerateNext(
    _In_ CXPLAT_HASHTABLE* HashTable,
    _Inout_ CXPLAT_HASHTABLE_ENUMERATOR* Enumerator
    )
/*++

Routine Description

    Get the next entry to be enumerated. If the hash chain still has entries
    that haven't been given to the user, the next such entry in the hash chain
    is returned. If the hash chain has ended, this function searches for the
    next non-empty hash chain and returns the first element in that chain. If no
    more non-empty hash chains exists, the function returns NULL. The caller
    must call CxPlatHashtableEnumerateEnd() to explicitly end the enumeration and
    cleanup state.

    This call is robust in the sense, that if this function returns NULL,
    subsequent calls to this function will not fail, and will still return NULL.

Synchronization:

    The hash lock must be held in exclusive mode.

Arguments:

    Hash Table - Pointer to the hash table to be enumerated.

    Enumerator - Pointer to CXPLAT_HASHTABLE_ENUMERATOR structure that stores
        enumeration state.

Return Value:

    Pointer to CXPLAT_HASHTABLE_ENTRY if one can be enumerated, and NULL other
    wise.

--*/
{
    CXPLAT_DBG_ASSERT(Enumerator != NULL);
    CXPLAT_DBG_ASSERT(Enumerator->ChainHead != NULL);
    CXPLAT_DBG_ASSERT(CXPLAT_HASH_RESERVED_SIGNATURE == Enumerator->HashEntry.Signature);

    //
    // We are trying to find the next valid entry. We need
    // to skip over other enumerators AND empty buckets.
    //
    for (uint32_t i = Enumerator->BucketIndex; i < HashTable->TableSize; i++) {

        CXPLAT_LIST_ENTRY* CurEntry, *ChainHead;
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
            ChainHead = CxPlatGetChainHead(HashTable, i);
            CurEntry = ChainHead;
        }

        while (CurEntry->Flink != ChainHead) {

            CXPLAT_LIST_ENTRY* NextEntry = CurEntry->Flink;
            CXPLAT_HASHTABLE_ENTRY* NextHashEntry = CxPlatFlinkToHashEntry(&NextEntry->Flink);
            if (CXPLAT_HASH_RESERVED_SIGNATURE != NextHashEntry->Signature) {
                CxPlatListEntryRemove(&(Enumerator->HashEntry.Linkage));

                CXPLAT_DBG_ASSERT(Enumerator->ChainHead != NULL);

                if (Enumerator->ChainHead != ChainHead) {
                    if (CxPlatListIsEmpty(Enumerator->ChainHead)) {
                        HashTable->NonEmptyBuckets--;
                    }

                    if (CxPlatListIsEmpty(ChainHead)) {
                        HashTable->NonEmptyBuckets++;
                    }
                }

                Enumerator->BucketIndex = i;
                Enumerator->ChainHead = ChainHead;

                CxPlatListInsertHead(NextEntry, &(Enumerator->HashEntry.Linkage));
                return NextHashEntry;
            }

            CurEntry = NextEntry;
        }
    }

    return NULL;
}

void
CxPlatHashtableEnumerateEnd(
    _In_ CXPLAT_HASHTABLE* HashTable,
    _Inout_ CXPLAT_HASHTABLE_ENUMERATOR* Enumerator
    )
/*++

Routine Description:

    This routine reverses the effect of InitEnumeration. It decrements the
    NumEnumerators counter in HashTable and cleans up Enumerator state.

Synchronization:

    The hash table lock must be held in exclusive mode.

Arguments:

    HashTable - Pointer to hash table on which enumerator was operating.

    Enumerator - Pointer to enumerator representing the enumeration that needs
        to be ended.

--*/
{
    CXPLAT_DBG_ASSERT(Enumerator != NULL);
    CXPLAT_DBG_ASSERT(HashTable->NumEnumerators > 0);
    HashTable->NumEnumerators--;

    if (!CxPlatListIsEmpty(&(Enumerator->HashEntry.Linkage))) {
        CXPLAT_DBG_ASSERT(Enumerator->ChainHead != NULL);

        CxPlatListEntryRemove(&(Enumerator->HashEntry.Linkage));

        if (CxPlatListIsEmpty(Enumerator->ChainHead)) {
            CXPLAT_DBG_ASSERT(HashTable->NonEmptyBuckets > 0);
            HashTable->NonEmptyBuckets--;
        }
    }

    Enumerator->ChainHead = FALSE;
}

#ifdef CXPLAT_HASHTABLE_RESIZE_SUPPORT

BOOLEAN
CxPlatHashTableExpand(
    _Inout_ CXPLAT_HASHTABLE* HashTable
    )
{
    //
    // Can't expand if we've reached the maximum.
    //
    if (HashTable->TableSize == MAX_HASH_TABLE_SIZE) {
        return FALSE;
    }

    if (HashTable->NumEnumerators > 0) {
        return FALSE;
    }

    CXPLAT_DBG_ASSERT(HashTable->TableSize < MAX_HASH_TABLE_SIZE);

    //
    // First see if increasing the table size will mean new allocations. After
    // the hash table is increased by one, the highest bucket index will be the
    // current table size, which is what we use in the calculations below
    //
    uint32_t FirstLevelIndex, SecondLevelIndex;
    CxPlatComputeDirIndices(
        HashTable->TableSize, &FirstLevelIndex, &SecondLevelIndex);

    //
    // Switch to the multi-dir mode in case of the only second-level directory
    // is about to be expanded.
    //

    CXPLAT_LIST_ENTRY* SecondLevelDir;
    CXPLAT_LIST_ENTRY** FirstLevelDir;
    if (HT_SECOND_LEVEL_DIR_MIN_SIZE == HashTable->TableSize) {

        SecondLevelDir = (CXPLAT_LIST_ENTRY*)HashTable->SecondLevelDir;
        FirstLevelDir = CXPLAT_ALLOC_NONPAGED(sizeof(CXPLAT_LIST_ENTRY*) * HT_FIRST_LEVEL_DIR_SIZE);

        if (FirstLevelDir == NULL) {
            return FALSE;
        }

        CxPlatZeroMemory(FirstLevelDir,
                      sizeof(CXPLAT_LIST_ENTRY*) * HT_FIRST_LEVEL_DIR_SIZE);

        FirstLevelDir[0] = SecondLevelDir;

        HashTable->FirstLevelDir = FirstLevelDir;
    }

    CXPLAT_DBG_ASSERT(HashTable->FirstLevelDir != NULL);
    FirstLevelDir = HashTable->FirstLevelDir;
    SecondLevelDir = FirstLevelDir[FirstLevelIndex];

    if (SecondLevelDir == NULL) {

        //
        // Allocate second level directory.
        //
        SecondLevelDir =
            CXPLAT_ALLOC_NONPAGED(
                CxPlatComputeSecondLevelDirSize(FirstLevelIndex) * sizeof(CXPLAT_LIST_ENTRY));
        if (NULL == SecondLevelDir) {

            //
            // If allocation failure happened on attempt to restructure the
            // table, switch it back to direct mode.
            //

            if (HT_SECOND_LEVEL_DIR_MIN_SIZE == HashTable->TableSize) {

                CXPLAT_DBG_ASSERT(FirstLevelIndex == 1);

                HashTable->SecondLevelDir = FirstLevelDir[0];
                CXPLAT_FREE(FirstLevelDir);
            }

            return FALSE;
        }

        FirstLevelDir[FirstLevelIndex] = SecondLevelDir;
    }

    HashTable->TableSize++;

    //
    // The allocations are out of the way. Now actually increase
    // the Table size and split the pivot bucket.
    //
    CXPLAT_LIST_ENTRY* ChainToBeSplit =
        CxPlatGetChainHead(HashTable, HashTable->Pivot);
    HashTable->Pivot++;

    CXPLAT_LIST_ENTRY* NewChain = &(SecondLevelDir[SecondLevelIndex]);
    CxPlatListInitializeHead(NewChain);

    if (!CxPlatListIsEmpty(ChainToBeSplit)) {

        CXPLAT_LIST_ENTRY* CurEntry = ChainToBeSplit;
        while (CurEntry->Flink != ChainToBeSplit) {

            CXPLAT_LIST_ENTRY* NextEntry = CurEntry->Flink;
            CXPLAT_HASHTABLE_ENTRY* NextHashEntry =
                CxPlatFlinkToHashEntry(&NextEntry->Flink);

            uint32_t BucketIndex =
                ((uint32_t)NextHashEntry->Signature) &
                ((HashTable->DivisorMask << 1) | 1);

            CXPLAT_DBG_ASSERT((BucketIndex == (HashTable->Pivot - 1)) ||
                   (BucketIndex == (HashTable->TableSize - 1)));

            if (BucketIndex == (HashTable->TableSize - 1)) {
                CxPlatListEntryRemove(NextEntry);
                CxPlatListInsertTail(NewChain, NextEntry);
                continue;
            }

            //
            // If the NextEntry falls in the same bucket, move on.
            //
            CurEntry = NextEntry;
        }

        if (!CxPlatListIsEmpty(NewChain)) {
            HashTable->NonEmptyBuckets++;
        }

        if (CxPlatListIsEmpty(ChainToBeSplit)) {
            CXPLAT_DBG_ASSERT(HashTable->NonEmptyBuckets > 0);
            HashTable->NonEmptyBuckets--;
        }
    }

    if (HashTable->Pivot == (HashTable->DivisorMask + 1)) {
        HashTable->DivisorMask = (HashTable->DivisorMask << 1) | 1;
        HashTable->Pivot = 0;

        //
        // Assert that at this point, TableSize is a power of 2.
        //
        CXPLAT_DBG_ASSERT(0 == (HashTable->TableSize & (HashTable->TableSize - 1)));
    }

    return TRUE;
}

BOOLEAN
CxPlatHashTableContract(
    _Inout_ CXPLAT_HASHTABLE* HashTable
    )
{
    //
    // Can't take table size lower than BASE_DYNAMIC_HASH_TABLE_SIZE.
    //
    CXPLAT_DBG_ASSERT(HashTable->TableSize >= BASE_HASH_TABLE_SIZE);

    if (HashTable->TableSize == BASE_HASH_TABLE_SIZE) {
        return FALSE;
    }

    if (HashTable->NumEnumerators > 0) {
        return FALSE;
    }

    //
    // Bring the table size down by 1 bucket, and change all state variables
    // accordingly.
    //
    if (HashTable->Pivot == 0) {
        HashTable->DivisorMask = HashTable->DivisorMask >> 1;
        HashTable->Pivot = HashTable->DivisorMask;
    } else {
        HashTable->Pivot--;
    }

    //
    // Need to combine two buckets. Since table-size is down by 1 and we need
    // the bucket that was the last bucket before table size was lowered, the
    // index of the last bucket is exactly equal to the current table size.
    //
    CXPLAT_LIST_ENTRY* ChainToBeMoved = CxPlatGetChainHead(HashTable, HashTable->TableSize - 1);
    CXPLAT_LIST_ENTRY* CombinedChain = CxPlatGetChainHead(HashTable, HashTable->Pivot);

    HashTable->TableSize--;

    CXPLAT_DBG_ASSERT(ChainToBeMoved != NULL);
    CXPLAT_DBG_ASSERT(CombinedChain != NULL);

    if (!CxPlatListIsEmpty(ChainToBeMoved) && !CxPlatListIsEmpty(CombinedChain)) {
        //
        // Both lists are non-empty.
        //

        CXPLAT_DBG_ASSERT(HashTable->NonEmptyBuckets > 0);
        HashTable->NonEmptyBuckets--;
    }

    CXPLAT_LIST_ENTRY* CurEntry = CombinedChain;
    while (!CxPlatListIsEmpty(ChainToBeMoved)) {

        CXPLAT_LIST_ENTRY* EntryToBeMoved = CxPlatListRemoveHead(ChainToBeMoved);
        CXPLAT_HASHTABLE_ENTRY* HashEntryToBeMoved =
            CxPlatFlinkToHashEntry(&EntryToBeMoved->Flink);

        while (CurEntry->Flink != CombinedChain) {

            CXPLAT_LIST_ENTRY* NextEntry = CurEntry->Flink;
            CXPLAT_HASHTABLE_ENTRY* NextHashEntry =
                CxPlatFlinkToHashEntry(&NextEntry->Flink);

            if (NextHashEntry->Signature >= HashEntryToBeMoved->Signature) {
                break;
            }

            CurEntry = NextEntry;
        }

        CxPlatListInsertHead(CurEntry, &(HashEntryToBeMoved->Linkage));
    }

    //
    // Finally free any extra memory if possible.
    //

    uint32_t FirstLevelIndex, SecondLevelIndex;
    CxPlatComputeDirIndices(
        HashTable->TableSize, &FirstLevelIndex, &SecondLevelIndex);

    if (SecondLevelIndex == 0) {

        CXPLAT_LIST_ENTRY** FirstLevelDir = HashTable->FirstLevelDir;
        CXPLAT_LIST_ENTRY* SecondLevelDir = FirstLevelDir[FirstLevelIndex];

        CXPLAT_FREE(SecondLevelDir);
        FirstLevelDir[FirstLevelIndex] = NULL;

        //
        // Switch to a single-dir mode if fits within a single second-level.
        //

        if (HT_SECOND_LEVEL_DIR_MIN_SIZE == HashTable->TableSize) {
            HashTable->SecondLevelDir = FirstLevelDir[0];
            CXPLAT_FREE(FirstLevelDir);
        }
    }

    return TRUE;
}

#endif // CXPLAT_HASHTABLE_RESIZE_SUPPORT
