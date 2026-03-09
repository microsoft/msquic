/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Tests to verify that memory allocations are zero-initialized by default.

--*/

#include "main.h"

#ifdef QUIC_CLOG
#include "AllocTest.cpp.clog.h"
#endif

#ifndef _KERNEL_MODE

//
// Size large enough to avoid small-allocation optimizations that might
// coincidentally return zeroed memory.
//
#define TEST_ALLOC_SIZE 256

static bool
IsZeroMemory(
    _In_reads_(Size) const uint8_t* Buffer,
    _In_ size_t Size
    )
{
    for (size_t i = 0; i < Size; i++) {
        if (Buffer[i] != 0) {
            return false;
        }
    }
    return true;
}

//
// Allocates memory, fills it with non-zero data, frees it, then reallocates
// the same size and checks whether the new allocation is zero-initialized.
//
// If the allocator does NOT zero-initialize, the recycled block will likely
// still contain the 0xDE pattern, causing the test to fail.
//
TEST(AllocTest, NonPagedAllocIsZeroInitialized)
{
    //
    // Phase 1: Allocate and poison memory so the heap has a dirty free block.
    //
    uint8_t* First =
        (uint8_t*)CXPLAT_ALLOC_NONPAGED(TEST_ALLOC_SIZE, QUIC_POOL_TEST);
    ASSERT_NE(nullptr, First);

    memset(First, 0xDE, TEST_ALLOC_SIZE);
    CXPLAT_FREE(First, QUIC_POOL_TEST);

    //
    // Phase 2: Reallocate the same size. A non-zeroing allocator will likely
    // hand back the same (still dirty) block.
    //
    uint8_t* Second =
        (uint8_t*)CXPLAT_ALLOC_NONPAGED(TEST_ALLOC_SIZE, QUIC_POOL_TEST);
    ASSERT_NE(nullptr, Second);

    EXPECT_TRUE(IsZeroMemory(Second, TEST_ALLOC_SIZE))
        << "CXPLAT_ALLOC_NONPAGED returned non-zero-initialized memory. ";

    CXPLAT_FREE(Second, QUIC_POOL_TEST);
}

TEST(AllocTest, PagedAllocIsZeroInitialized)
{
    uint8_t* First =
        (uint8_t*)CXPLAT_ALLOC_PAGED(TEST_ALLOC_SIZE, QUIC_POOL_TEST);
    ASSERT_NE(nullptr, First);

    memset(First, 0xDE, TEST_ALLOC_SIZE);
    CXPLAT_FREE(First, QUIC_POOL_TEST);

    uint8_t* Second =
        (uint8_t*)CXPLAT_ALLOC_PAGED(TEST_ALLOC_SIZE, QUIC_POOL_TEST);
    ASSERT_NE(nullptr, Second);

    EXPECT_TRUE(IsZeroMemory(Second, TEST_ALLOC_SIZE))
        << "CXPLAT_ALLOC_PAGED returned non-zero-initialized memory. ";

    CXPLAT_FREE(Second, QUIC_POOL_TEST);
}

//
// CxPlatPoolAlloc can return a previously-used
// object from its free list, and that object will contain stale data unless
// the allocator explicitly zeroes it.
//
TEST(AllocTest, PoolAllocIsZeroInitializedOnReuse)
{
    CXPLAT_POOL Pool;
    CxPlatPoolInitialize(FALSE, TEST_ALLOC_SIZE, QUIC_POOL_TEST, &Pool);

    //
    // Phase 1: Allocate from pool, poison, return to pool.
    //
    uint8_t* First = (uint8_t*)CxPlatPoolAlloc(&Pool);
    ASSERT_NE(nullptr, First);

    memset(First, 0xDE, TEST_ALLOC_SIZE);
    CxPlatPoolFree(First);

    //
    // Phase 2: Re-allocate from pool. The pool will return the same object
    // from its free list. If pool alloc doesn't zero-init, it will still
    // contain the 0xDE poison bytes.
    //
    uint8_t* Second = (uint8_t*)CxPlatPoolAlloc(&Pool);
    ASSERT_NE(nullptr, Second);

    EXPECT_TRUE(IsZeroMemory(Second, TEST_ALLOC_SIZE))
        << "CxPlatPoolAlloc returned non-zero-initialized memory on reuse. ";

    CxPlatPoolFree(Second);
    CxPlatPoolUninitialize(&Pool);
}

TEST(AllocTest, PoolAllocIsZeroInitializedFresh)
{
    CXPLAT_POOL Pool;
    CxPlatPoolInitialize(FALSE, TEST_ALLOC_SIZE, QUIC_POOL_TEST, &Pool);

    uint8_t* Mem = (uint8_t*)CxPlatPoolAlloc(&Pool);
    ASSERT_NE(nullptr, Mem);

    EXPECT_TRUE(IsZeroMemory(Mem, TEST_ALLOC_SIZE))
        << "CxPlatPoolAlloc returned non-zero-initialized memory on fresh alloc. ";

    CxPlatPoolFree(Mem);
    CxPlatPoolUninitialize(&Pool);
}

#endif // _KERNEL_MODE
