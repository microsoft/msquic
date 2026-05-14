/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    A dynamically resizing hash table implementation.

    Currently CXPLAT_HASH_TABLE only supports "weak" enumeration. "Weak"
    enumeration means enumeration that requires exclusive access to the table
    during the entire enumeration.

Usage examples:

    void
    ExampleInsert(
        CXPLAT_HASHTABLE* Table,
        PEXAMPLE_OBJECT Obj
        )
    {
        CxPlatHashtableInsert(
            Table, &Obj->HashtableEntry, ExampleAttribHash(Obj->Attrib));
    }

    void
    ExampleRemove(
        CXPLAT_HASHTABLE* Table,
        PEXAMPLE_OBJECT Obj
        )
    {
        CxPlatHashtableRemove(Table, &Obj->HashtableEntry);
    }

    PEXAMPLE_OBJECT
    ExampleLookup(
        CXPLAT_HASHTABLE* Table,
        EXAMPLE_OBJECT_ATTRIBUTE Attrib
        )
    {
        CXPLAT_HASHTABLE_LOOKUP_CONTEXT Context;
        CXPLAT_HASHTABLE_ENTRY* Entry;

        Entry = CxPlatHashtableLookup(Table, ExampleAttribHash(Attrib), &Context);
        while (Entry != NULL) {
            PEXAMPLE_OBJECT Obj =
                CONTAINING_RECORD(Entry, EXAMPLE_OBJECT, HashTableEntry);
            if (Obj->Attrib == Attrib) {
                return Obj;
            }
            Entry = CxPlatHashtableLookupNext(Table, &Context);
        }
        return NULL;
    }

    void
    ExampleEnumeration(
        CXPLAT_HASHTABLE* Table
        )
    {
        CXPLAT_HASHTABLE_ENTRY* Entry;
        CXPLAT_HASHTABLE_ENUMERATOR Enumerator;

        CxPlatHashtableEnumerateBegin(Table, &Enumerator);
        for (;;) {
            Entry = CxPlatHashtableEnumerateNext(Table, &Enumerator);
            if (Entry == NULL) {
                break;
            }
            PEXAMPLE_OBJECT Obj =
                CONTAINING_RECORD(Entry, EXAMPLE_OBJECT, HashTableEntry);
            ExampleVisitObject(Obj);
        }
        CxPlatHashtableEnumerateEnd(Table, &Enumerator);
    }

--*/

#pragma once

#if defined(__cplusplus)
extern "C" {
#endif

#pragma warning(disable:4201)  // nonstandard extension used: nameless struct/union

#define CXPLAT_HASH_ALLOCATED_HEADER 0x00000001

#define CXPLAT_HASH_MIN_SIZE 128

typedef struct CXPLAT_HASHTABLE_ENTRY {
    CXPLAT_LIST_ENTRY Linkage;
    uint64_t Signature;
} CXPLAT_HASHTABLE_ENTRY;

typedef struct CXPLAT_HASHTABLE_LOOKUP_CONTEXT {
    //
    // Brief background on each of the parameters and their justification:
    // 1. ChainHead stores the pointer to a bucket. This is needed since our
    //    hash chains are doubly-linked circular lists, and there is no way to
    //    determine whether we've reached the end of the chain unless we store
    //    the pointer to the bucket itself. This is particularly used in walking
    //    the sub-list of entries returned by a lookup. We need to know when the
    //    sub-list has been completely returned.
    // 2. PrevLinkage stores a pointer to the entry before the entry under
    //    consideration. The reason for storing the previous entry instead of
    //    the entry itself is for cases where a lookup fails and PrevLinkage
    //    actually stores the entry that would have been the previous entry, had
    //    the looked up entry existed. This can then be used to actually insert
    //    the entry at that place.
    // 3. Signature is used primarily as a safety check in insertion. This field
    //    must match the Signature of the entry being inserted.
    //
    CXPLAT_LIST_ENTRY* ChainHead;
    CXPLAT_LIST_ENTRY* PrevLinkage;
    uint64_t Signature;
} CXPLAT_HASHTABLE_LOOKUP_CONTEXT;

typedef struct CXPLAT_HASHTABLE_ENUMERATOR {
    union {
       CXPLAT_HASHTABLE_ENTRY HashEntry;
       CXPLAT_LIST_ENTRY* CurEntry;
    };
    CXPLAT_LIST_ENTRY* ChainHead;
    uint32_t BucketIndex;
} CXPLAT_HASHTABLE_ENUMERATOR;

typedef struct CXPLAT_HASHTABLE {

    // Entries initialized at creation
    uint32_t Flags;

    // Entries used in bucket computation.
    uint32_t TableSize;
    uint32_t Pivot;
    uint32_t DivisorMask;

    // Counters
    uint32_t NumEntries;
    uint32_t NonEmptyBuckets;
    uint32_t NumEnumerators;

    // For internal use only.
    union {
        void* Directory;
        CXPLAT_LIST_ENTRY* SecondLevelDir; // When TableSize <= HT_SECOND_LEVEL_DIR_MIN_SIZE
        CXPLAT_LIST_ENTRY** FirstLevelDir; // When TableSize > HT_SECOND_LEVEL_DIR_MIN_SIZE
    };

} CXPLAT_HASHTABLE;

_Must_inspect_result_
_Success_(return != FALSE)
BOOLEAN
CxPlatHashtableInitialize(
    _Inout_ _When_(NULL == *HashTable, _At_(*HashTable, __drv_allocatesMem(Mem) _Post_notnull_))
        CXPLAT_HASHTABLE** HashTable,
    _In_ uint32_t InitialSize
    );

QUIC_INLINE
_Must_inspect_result_
_Success_(return != FALSE)
BOOLEAN
CxPlatHashtableInitializeEx(
    _Inout_ CXPLAT_HASHTABLE* HashTable,
    _In_ uint32_t InitialSize
    )
{
    return CxPlatHashtableInitialize(&HashTable, InitialSize);
}

void
CxPlatHashtableUninitialize(
    _In_
    _When_((HashTable->Flags & CXPLAT_HASH_ALLOCATED_HEADER), __drv_freesMem(Mem) _Post_invalid_)
    _At_(HashTable->Directory, __drv_freesMem(Mem) _Post_invalid_)
        CXPLAT_HASHTABLE* HashTable
    );

void
CxPlatHashtableInsert(
    _In_ CXPLAT_HASHTABLE* HashTable,
    _In_ __drv_aliasesMem CXPLAT_HASHTABLE_ENTRY* Entry,
    _In_ uint64_t Signature,
    _Inout_opt_ CXPLAT_HASHTABLE_LOOKUP_CONTEXT* Context
    );

void
CxPlatHashtableRemove(
    _In_ CXPLAT_HASHTABLE* HashTable,
    _In_ CXPLAT_HASHTABLE_ENTRY* Entry,
    _Inout_opt_ CXPLAT_HASHTABLE_LOOKUP_CONTEXT* Context
    );

_Must_inspect_result_
CXPLAT_HASHTABLE_ENTRY*
CxPlatHashtableLookup(
    _In_ const CXPLAT_HASHTABLE* HashTable,
    _In_ uint64_t Signature,
    _Out_opt_ CXPLAT_HASHTABLE_LOOKUP_CONTEXT* Context
    );

_Must_inspect_result_
CXPLAT_HASHTABLE_ENTRY*
CxPlatHashtableLookupNext(
    _In_ const CXPLAT_HASHTABLE* HashTable,
    _Inout_ CXPLAT_HASHTABLE_LOOKUP_CONTEXT* Context
    );

void
CxPlatHashtableEnumerateBegin(
    _In_ CXPLAT_HASHTABLE* HashTable,
    _Out_ CXPLAT_HASHTABLE_ENUMERATOR* Enumerator
    );

_Must_inspect_result_
CXPLAT_HASHTABLE_ENTRY*
CxPlatHashtableEnumerateNext(
    _In_ CXPLAT_HASHTABLE* HashTable,
    _Inout_ CXPLAT_HASHTABLE_ENUMERATOR* Enumerator
    );

void
CxPlatHashtableEnumerateEnd(
    _In_ CXPLAT_HASHTABLE* HashTable,
    _Inout_ CXPLAT_HASHTABLE_ENUMERATOR* Enumerator
    );

//
// Simple helper hash function.
//
QUIC_INLINE
QUIC_NO_SANITIZE("unsigned-integer-overflow")
uint32_t
CxPlatHashSimple(
    _In_ uint16_t Length,
    _In_reads_(Length)
        const uint8_t* const Buffer
    )
{
    uint32_t Hash = 5387; // A random prime number.
    for (uint16_t i = 0; i < Length; ++i) {
        Hash = ((Hash << 5) - Hash) + Buffer[i];
    }
    return Hash;
}

#if defined(__cplusplus)
}
#endif
