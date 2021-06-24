/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file respresents a generic way to store objects that are represented
    by non-unique pointers. An object has a lifetime and after that, its
    pointer may be reused for a new object. An object is 'active' if it's
    currently using the pointer address; otherwise it's 'inactive' meaning it is
    no longer using that pointer (because it was freed).

--*/

#include "quic_platform.h"
#include <stdio.h>

inline ULONG HashPtr(ULONG64 ObjPtr)
{
    ULONG H = 0;
    for (ULONG i = 0; i < sizeof(ObjPtr); i++) {
        H = (H<<5) + (H<<2) + H + ((ObjPtr>>i)&0xff); // H*37 + NextByte
    }
    return H|0x80000000;
}

typedef struct _OBJECT {
    CXPLAT_HASHTABLE_ENTRY ActiveEntry;
    struct _OBJECT* InactiveNext;
    ULONG Id;
    ULONG64 Ptr;
} OBJECT;

typedef
void
(__cdecl * OBJECT_FREE_FN)(
    _In_opt_ void* Mem
    );

typedef struct _OBJECT_SET {
    OBJECT_FREE_FN FreeFn;
    CXPLAT_HASHTABLE* Active;
    OBJECT* Inactive;
    ULONG NextId;
} OBJECT_SET;

inline void ObjectSetCreate(_Inout_ OBJECT_SET* Set)
{
    if (Set->NextId != 0) return;
    if (Set->FreeFn == NULL) {
        Set->FreeFn = free;
    }
    Set->NextId = 1; // 0 is a sentinel
    Set->Inactive = NULL;
    if (!CxPlatHashtableInitialize(&Set->Active, 65536)) {
        printf("RtlCreateHashTableEx failed!\n");
        exit(1);
    }
}

inline void ObjectSetDestroy(_Inout_ OBJECT_SET* Set)
{
    if (Set->NextId == 0) return;

    CXPLAT_HASHTABLE_ENUMERATOR Enumerator;
    CXPLAT_HASHTABLE_ENTRY* Entry;
    OBJECT* Obj;

    CxPlatHashtableEnumerateBegin(Set->Active, &Enumerator);
    for (;;) {
        Entry = CxPlatHashtableEnumerateNext(Set->Active, &Enumerator);
        if (Entry == NULL) {
            CxPlatHashtableEnumerateEnd(Set->Active, &Enumerator);
            break;
        }
        Obj = CONTAINING_RECORD(Entry, OBJECT, ActiveEntry);
        CxPlatHashtableRemove(Set->Active, &Obj->ActiveEntry, NULL);
        Set->FreeFn(Obj);
    }

    while (Set->Inactive) {
        Obj = Set->Inactive;
        Set->Inactive = Obj->InactiveNext;
        Set->FreeFn(Obj);
    }

    ZeroMemory(Set, sizeof(*Set));
}

inline void ObjectSetReset(_Inout_ OBJECT_SET* Set)
{
    ObjectSetDestroy(Set);
    ObjectSetCreate(Set);
}

inline OBJECT* ObjectSetGetActive(_Inout_ OBJECT_SET* Set, ULONG64 ObjPtr)
{
    CXPLAT_HASHTABLE_ENTRY* Entry;
    CXPLAT_HASHTABLE_LOOKUP_CONTEXT Ctx;
    OBJECT* Obj = NULL;

    Entry = CxPlatHashtableLookup(Set->Active, HashPtr(ObjPtr), &Ctx);
    while (Entry != NULL) {
        OBJECT* o = CONTAINING_RECORD(Entry, OBJECT, ActiveEntry);
        if (o->Ptr == ObjPtr) {
            Obj = o;
            break;
        }
        Entry = CxPlatHashtableLookupNext(Set->Active, &Ctx);
    }
    return Obj;
}

inline void ObjectSetAddActive(_Inout_ OBJECT_SET* Set, _In_ OBJECT* Obj)
{
    CxPlatHashtableInsert(Set->Active, &Obj->ActiveEntry, HashPtr(Obj->Ptr), NULL);
}

inline OBJECT* ObjectSetRemoveActive(_Inout_ OBJECT_SET* Set, ULONG64 ObjPtr)
{
    OBJECT* Obj = ObjectSetGetActive(Set, ObjPtr);
    if (Obj != NULL) {
        CxPlatHashtableRemove(Set->Active, &Obj->ActiveEntry, NULL);
        Obj->InactiveNext = Set->Inactive;
        Set->Inactive = Obj;
    }
    return Obj;
}

inline OBJECT* ObjectSetGetId(_Inout_ OBJECT_SET* Set, ULONG Id)
{
    CXPLAT_HASHTABLE_ENUMERATOR Enumerator;
    CXPLAT_HASHTABLE_ENTRY* Entry;

    CxPlatHashtableEnumerateBegin(Set->Active, &Enumerator);
    for (;;) {
        Entry = CxPlatHashtableEnumerateNext(Set->Active, &Enumerator);
        if (Entry == NULL) {
            CxPlatHashtableEnumerateEnd(Set->Active, &Enumerator);
            break;
        }
        OBJECT* Obj = CONTAINING_RECORD(Entry, OBJECT, ActiveEntry);
        if (Obj->Id == Id) {
            CxPlatHashtableEnumerateEnd(Set->Active, &Enumerator);
            return Obj;
        }
    }

    OBJECT* Obj = Set->Inactive;
    while (Obj != NULL) {
        if (Obj->Id == Id) {
            return Obj;
        }
        Obj = Obj->InactiveNext;
    }

    return NULL;
}

inline OBJECT** ObjectSetSort(_Inout_ OBJECT_SET* Set, _In_opt_ int (__cdecl * CompareFn)(const void *, const void *))
{
    CXPLAT_HASHTABLE_ENUMERATOR Enumerator;
    CXPLAT_HASHTABLE_ENTRY* Entry;
    OBJECT** ObjArray;
    OBJECT* Obj;

    // Now we have a hashtable of objects which were active at the end of the
    // trace, and a list of inactive objects. Sort them into a single array. The
    // default sort is by ID, which is cheap (O(n)), and then we re-sort if the
    // user requested a different sort order.

    ObjArray = malloc(Set->NextId * sizeof(OBJECT*));
    if (ObjArray == NULL) {
        printf("Out of memory\n");
        exit(1);
    }

    CxPlatHashtableEnumerateBegin(Set->Active, &Enumerator);
    for (;;) {
        Entry = CxPlatHashtableEnumerateNext(Set->Active, &Enumerator);
        if (Entry == NULL) {
            CxPlatHashtableEnumerateEnd(Set->Active, &Enumerator);
            break;
        }
        Obj = CONTAINING_RECORD(Entry, OBJECT, ActiveEntry);
        ObjArray[Obj->Id] = Obj;
    }

    Obj = Set->Inactive;
    while (Obj) {
        ObjArray[Obj->Id] = Obj;
        Obj = Obj->InactiveNext;
    }

    if (CompareFn != NULL) {
        qsort(&ObjArray[1], Set->NextId - 1, sizeof(OBJECT*), CompareFn);
    }

    return ObjArray;
}
