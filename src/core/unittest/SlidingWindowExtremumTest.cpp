/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Unit test for SlidingWindowExtremum

--*/

#include "main.h"
#ifdef QUIC_CLOG
#include "SlidingWindowExtremumTest.cpp.clog.h"
#endif

TEST(SlidingWindowExtremumTest, EmptyWindow)
{
    const int kWindowCapacity = 3;
    QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY Entries[kWindowCapacity];
    QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY Extremum;
    QUIC_SLIDING_WINDOW_EXTREMUM Window = QuicSlidingWindowExtremumInitialize(100, kWindowCapacity, Entries);
    
    // newly created instance is empty
    QUIC_STATUS Status = QuicSlidingWindowExtremumGet(&Window, &Extremum);
    ASSERT_EQ(QUIC_STATUS_NOT_FOUND, Status);
    
    // adding a new value to the window
    QuicSlidingWindowExtremumUpdateMin(&Window, 100, 100);
    Status = QuicSlidingWindowExtremumGet(&Window, &Extremum);
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Status);
    
    // instance is empty after reset
    QuicSlidingWindowExtremumReset(&Window);
    Status = QuicSlidingWindowExtremumGet(&Window, &Extremum);
    ASSERT_EQ(QUIC_STATUS_NOT_FOUND, Status);
}

TEST(SlidingWindowExtremumTest, SlidingWindowMinima)
{
    const int kWindowCapacity = 3;
    QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY Entries[kWindowCapacity];
    QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY Extremum;
    QUIC_SLIDING_WINDOW_EXTREMUM Window = QuicSlidingWindowExtremumInitialize(100, kWindowCapacity, Entries);

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    
    // adding the first value to the window, current we have [(V:200, T:200)]
    QuicSlidingWindowExtremumUpdateMin(&Window, 200, 200);
    Status = QuicSlidingWindowExtremumGet(&Window, &Extremum);
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Status);
    ASSERT_EQ(200, Extremum.Value);
    ASSERT_EQ(200, Extremum.Time);

    // adding stale values to the window as noise, the window will ignore this
    QuicSlidingWindowExtremumUpdateMin(&Window, 0, 0);
    QuicSlidingWindowExtremumUpdateMin(&Window, 1000, 0);
    Status = QuicSlidingWindowExtremumGet(&Window, &Extremum);
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Status);
    ASSERT_EQ(200, Extremum.Value);
    ASSERT_EQ(200, Extremum.Time);

    // adding other 2 values to the window, now we have [(V:200, T:200), (V:201, T:200), (V:202, T:201)]
    QuicSlidingWindowExtremumUpdateMin(&Window, 201, 200);
    QuicSlidingWindowExtremumUpdateMin(&Window, 202, 201);
    Status = QuicSlidingWindowExtremumGet(&Window, &Extremum);
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Status);
    ASSERT_EQ(200, Extremum.Value);
    ASSERT_EQ(200, Extremum.Time);
    
    // adding a large new value to the window, but as the window is full, this value will be ignored
    // now the window is still: [(V:200, T:200), (V:201, T:200), (V:202, T:201)]
    QuicSlidingWindowExtremumUpdateMin(&Window, 1000, 202);
    Status = QuicSlidingWindowExtremumGet(&Window, &Extremum);
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Status);
    ASSERT_EQ(200, Extremum.Value);
    ASSERT_EQ(200, Extremum.Time);

    // adding another large value to expire the old values
    // now the window is: [(V:202, T:201), (V:1000, T: 301)]
    QuicSlidingWindowExtremumUpdateMin(&Window, 1000, 301);
    Status = QuicSlidingWindowExtremumGet(&Window, &Extremum);
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Status);
    ASSERT_EQ(202, Extremum.Value);
    ASSERT_EQ(201, Extremum.Time);

    // adding new minima to sweep out all
    // now the window is: [(V:1, T:302)]
    QuicSlidingWindowExtremumUpdateMin(&Window, 1, 302);
    Status = QuicSlidingWindowExtremumGet(&Window, &Extremum);
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Status);
    ASSERT_EQ(1, Extremum.Value);
    ASSERT_EQ(302, Extremum.Time);
    
    // adding one duplicate value which will be ignored
    // now the window is still: [(V:1, T:302)]
    QuicSlidingWindowExtremumUpdateMin(&Window, 1, 302);
    Status = QuicSlidingWindowExtremumGet(&Window, &Extremum);
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Status);
    ASSERT_EQ(1, Extremum.Value);
    ASSERT_EQ(302, Extremum.Time);
}

TEST(SlidingWindowExtremumTest, SlidingWindowMaxima)
{
    const int kWindowCapacity = 3;
    QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY Entries[kWindowCapacity];
    QUIC_SLIDING_WINDOW_EXTREMUM_ENTRY Extremum;
    QUIC_SLIDING_WINDOW_EXTREMUM Window = QuicSlidingWindowExtremumInitialize(100, kWindowCapacity, Entries);

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    
    // adding the first value to the window, current we have [(V:200, T:200)]
    QuicSlidingWindowExtremumUpdateMax(&Window, 200, 200);
    Status = QuicSlidingWindowExtremumGet(&Window, &Extremum);
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Status);
    ASSERT_EQ(200, Extremum.Value);
    ASSERT_EQ(200, Extremum.Time);

    // adding stale values to the window as noise, the window will ignore this
    QuicSlidingWindowExtremumUpdateMax(&Window, 0, 0);
    QuicSlidingWindowExtremumUpdateMax(&Window, 1000, 0);
    Status = QuicSlidingWindowExtremumGet(&Window, &Extremum);
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Status);
    ASSERT_EQ(200, Extremum.Value);
    ASSERT_EQ(200, Extremum.Time);

    // adding other 2 values to the window, now we have [(V:200, T:200), (V:199, T:200), (V:198, T:201)]
    QuicSlidingWindowExtremumUpdateMax(&Window, 199, 200);
    QuicSlidingWindowExtremumUpdateMax(&Window, 198, 201);
    Status = QuicSlidingWindowExtremumGet(&Window, &Extremum);
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Status);
    ASSERT_EQ(200, Extremum.Value);
    ASSERT_EQ(200, Extremum.Time);
    
    // adding a large small to the window, but as the window is full, this value will be ignored
    // now the window is still: [(V:200, T:200), (V:199, T:200), (V:198, T:201)]
    QuicSlidingWindowExtremumUpdateMax(&Window, 0, 202);
    Status = QuicSlidingWindowExtremumGet(&Window, &Extremum);
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Status);
    ASSERT_EQ(200, Extremum.Value);
    ASSERT_EQ(200, Extremum.Time);

    // adding another small value to expire the old values
    // now the window is: [(V:198, T:201), (V:0, T: 301)]
    QuicSlidingWindowExtremumUpdateMax(&Window, 0, 301);
    Status = QuicSlidingWindowExtremumGet(&Window, &Extremum);
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Status);
    ASSERT_EQ(198, Extremum.Value);
    ASSERT_EQ(201, Extremum.Time);

    // adding new maxima to sweep out all
    // now the window is: [(V:1000, T:302)]
    QuicSlidingWindowExtremumUpdateMax(&Window, 1000, 302);
    Status = QuicSlidingWindowExtremumGet(&Window, &Extremum);
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Status);
    ASSERT_EQ(1000, Extremum.Value);
    ASSERT_EQ(302, Extremum.Time);
    
    // adding one duplicate value which will be ignored
    // now the window is still: [(V:1000, T:302)]
    QuicSlidingWindowExtremumUpdateMax(&Window, 1000, 302);
    Status = QuicSlidingWindowExtremumGet(&Window, &Extremum);
    ASSERT_EQ(QUIC_STATUS_SUCCESS, Status);
    ASSERT_EQ(1000, Extremum.Value);
    ASSERT_EQ(302, Extremum.Time);
}
