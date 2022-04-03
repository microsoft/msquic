#include "TokenBucket.h"
#include <chrono>

using namespace std::chrono;

TokenBucket::TokenBucket(uint64_t rate, uint64_t burst)
    : _time(0),
      _time_per_token(1'000'000'000ULL / rate),
      _time_per_burst(burst * _time_per_token)
{

}

inline TokenBucket::TokenBucket(const TokenBucket& tb)
    : _time(tb._time.load()),
      _time_per_token(tb._time_per_token.load()),
      _time_per_burst(tb._time_per_burst.load())
{
}

inline TokenBucket& TokenBucket::operator=(const TokenBucket& tb)
{
    _time = tb._time.load();
    _time_per_token = tb._time_per_token.load();
    _time_per_burst = tb._time_per_burst.load();
    return *this;
}

bool TokenBucket::Consume(uint64_t tokens)
{
    uint64_t now = time_point_cast<nanoseconds>(system_clock::now()).time_since_epoch().count();
    uint64_t delay = tokens * _time_per_token.load(std::memory_order_relaxed);
    uint64_t minTime = now - _time_per_burst.load(std::memory_order_relaxed);
    uint64_t oldTime = _time.load(std::memory_order_relaxed);
    uint64_t newTime = oldTime;

    // Previous consume performed long time ago... Shift the new time to the start of a new burst.
    if (minTime > oldTime)
        newTime = minTime;

    // Lock-free token consume loop
    for (;;)
    {
        // Consume tokens
        newTime += delay;

        // No more tokens left in the bucket
        if (newTime > now)
            return false;

        // Try to update the current time atomically
        if (_time.compare_exchange_weak(oldTime, newTime, std::memory_order_relaxed, std::memory_order_relaxed))
            return true;

        // Failed... Then retry consume tokens with a new time value
        newTime = oldTime;
    }
}
