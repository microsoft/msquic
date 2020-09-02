/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    A dynamically resizing hash table implementation.

    Currently QUIC_HASH_TABLE only supports "weak" enumeration. "Weak"
    enumeration means enumeration that requires exclusive access to the table
    during the entire enumeration.

Usage examples:

    void
    ExampleInsert(
        QUIC_HASHTABLE* Table,
        PEXAMPLE_OBJECT Obj
        )
    {
        QuicHashtableInsert(
            Table, &Obj->HashtableEntry, ExampleAttribHash(Obj->Attrib));
    }

    void
    ExampleRemove(
        QUIC_HASHTABLE* Table,
        PEXAMPLE_OBJECT Obj
        )
    {
        QuicHashtableRemove(Table, &Obj->HashtableEntry);
    }

    PEXAMPLE_OBJECT
    ExampleLookup(
        QUIC_HASHTABLE* Table,
        EXAMPLE_OBJECT_ATTRIBUTE Attrib
        )
    {
        QUIC_HASHTABLE_LOOKUP_CONTEXT Context;
        QUIC_HASHTABLE_ENTRY* Entry;

        Entry = QuicHashtableLookup(Table, ExampleAttribHash(Attrib), &Context);
        while (Entry != NULL) {
            PEXAMPLE_OBJECT Obj =
                CONTAINING_RECORD(Entry, EXAMPLE_OBJECT, HashTableEntry);
            if (Obj->Attrib == Attrib) {
                return Obj;
            }
            Entry = QuicHashtableLookupNext(Table, &Context);
        }
        return NULL;
    }

    void
    ExampleEnumeration(
        QUIC_HASHTABLE* Table
        )
    {
        QUIC_HASHTABLE_ENTRY* Entry;
        QUIC_HASHTABLE_ENUMERATOR Enumerator;

        QuicHashtableEnumerateBegin(Table, &Enumerator);
        for (;;) {
            Entry = QuicHashtableEnumerateNext(Table, &Enumerator);
            if (Entry == NULL) {
                break;
            }
            PEXAMPLE_OBJECT Obj =
                CONTAINING_RECORD(Entry, EXAMPLE_OBJECT, HashTableEntry);
            ExampleVisitObject(Obj);
        }
        QuicHashtableEnumerateEnd(Table, &Enumerator);
    }

--*/

#pragma once

#pragma warning(disable:4201)  // nonstandard extension used: nameless struct/union

#define QUIC_HASH_ALLOCATED_HEADER 0x00000001

#define QUIC_HASH_MIN_SIZE 128

typedef struct QUIC_HASHTABLE_ENTRY {
    QUIC_LIST_ENTRY Linkage;
    uint64_t Signature;
} QUIC_HASHTABLE_ENTRY;

typedef struct QUIC_HASHTABLE_LOOKUP_CONTEXT {
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
    QUIC_LIST_ENTRY* ChainHead;
    QUIC_LIST_ENTRY* PrevLinkage;
    uint64_t Signature;
} QUIC_HASHTABLE_LOOKUP_CONTEXT;

typedef struct QUIC_HASHTABLE_ENUMERATOR {
    union {
       QUIC_HASHTABLE_ENTRY HashEntry;
       QUIC_LIST_ENTRY* CurEntry;
    };
    QUIC_LIST_ENTRY* ChainHead;
    uint32_t BucketIndex;
} QUIC_HASHTABLE_ENUMERATOR;

typedef struct QUIC_HASHTABLE {

    // Entries initialized at creation
    uint32_t Flags;

    // Entries used in bucket computation.
    uint32_t TableSize;
#ifdef QUIC_HASHTABLE_RESIZE_SUPPORT
    uint32_t Pivot;
    uint32_t DivisorMask;
#endif

    // Counters
    uint32_t NumEntries;
    uint32_t NonEmptyBuckets;
    uint32_t NumEnumerators;

    // For internal use only.
    union {
        void* Directory;
        QUIC_LIST_ENTRY* SecondLevelDir; // When TableSize <= HT_SECOND_LEVEL_DIR_MIN_SIZE
        QUIC_LIST_ENTRY** FirstLevelDir; // When TableSize > HT_SECOND_LEVEL_DIR_MIN_SIZE
    };

} QUIC_HASHTABLE;

_Must_inspect_result_
_Success_(return != FALSE)
BOOLEAN
QuicHashtableInitialize(
    _Inout_ _When_(NULL == *HashTable, _At_(*HashTable, __drv_allocatesMem(Mem) _Post_notnull_))
        QUIC_HASHTABLE** HashTable,
    _In_ uint32_t InitialSize
    );

inline
_Must_inspect_result_
_Success_(return != FALSE)
BOOLEAN
QuicHashtableInitializeEx(
    _Inout_ QUIC_HASHTABLE* HashTable,
    _In_ uint32_t InitialSize
    )
{
    return QuicHashtableInitialize(&HashTable, InitialSize);
}

void
QuicHashtableUninitialize(
    _In_
    _When_((HashTable->Flags & QUIC_HASH_ALLOCATED_HEADER), __drv_freesMem(Mem) _Post_invalid_)
    _At_(HashTable->Directory, __drv_freesMem(Mem) _Post_invalid_)
        QUIC_HASHTABLE* HashTable
    );

void
QuicHashtableInsert(
    _In_ QUIC_HASHTABLE* HashTable,
    _In_ __drv_aliasesMem QUIC_HASHTABLE_ENTRY* Entry,
    _In_ uint64_t Signature,
    _Inout_opt_ QUIC_HASHTABLE_LOOKUP_CONTEXT* Context
    );

void
QuicHashtableRemove(
    _In_ QUIC_HASHTABLE* HashTable,
    _In_ QUIC_HASHTABLE_ENTRY* Entry,
    _Inout_opt_ QUIC_HASHTABLE_LOOKUP_CONTEXT* Context
    );

_Must_inspect_result_
QUIC_HASHTABLE_ENTRY*
QuicHashtableLookup(
    _In_ QUIC_HASHTABLE* HashTable,
    _In_ uint64_t Signature,
    _Out_opt_ QUIC_HASHTABLE_LOOKUP_CONTEXT* Context
    );

_Must_inspect_result_
QUIC_HASHTABLE_ENTRY*
QuicHashtableLookupNext(
    _In_ QUIC_HASHTABLE* HashTable,
    _Inout_ QUIC_HASHTABLE_LOOKUP_CONTEXT* Context
    );

void
QuicHashtableEnumerateBegin(
    _In_ QUIC_HASHTABLE* HashTable,
    _Out_ QUIC_HASHTABLE_ENUMERATOR* Enumerator
    );

_Must_inspect_result_
QUIC_HASHTABLE_ENTRY*
QuicHashtableEnumerateNext(
    _In_ QUIC_HASHTABLE* HashTable,
    _Inout_ QUIC_HASHTABLE_ENUMERATOR* Enumerator
    );

void
QuicHashtableEnumerateEnd(
    _In_ QUIC_HASHTABLE* HashTable,
    _Inout_ QUIC_HASHTABLE_ENUMERATOR* Enumerator
    );

#ifdef QUIC_HASHTABLE_RESIZE_SUPPORT

BOOLEAN
QuicHashTableExpand(
    _Inout_ QUIC_HASHTABLE* HashTable
    );

BOOLEAN
QuicHashTableContract(
    _Inout_ QUIC_HASHTABLE* HashTable
    );

#endif // QUIC_HASHTABLE_RESIZE_SUPPORT

//
// Simple helper hash function.
//
inline
QUIC_NO_SANITIZE("unsigned-integer-overflow")
uint32_t
QuicHashSimple(
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
