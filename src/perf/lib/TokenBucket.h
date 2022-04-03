#pragma once

#include "quic_platform.h"
#include <atomic>

// ref: chronoxor/CppCommon
class TokenBucket
{
public:
    TokenBucket(uint64_t rate, uint64_t burst);
    TokenBucket(const TokenBucket &tb);
    TokenBucket(TokenBucket &&) = delete;
    ~TokenBucket() = default;

    TokenBucket &operator=(const TokenBucket &tb);
    TokenBucket &operator=(TokenBucket &&) = delete;

    bool Consume(uint64_t tokens = 1);

private:
    std::atomic<uint64_t> _time;
    std::atomic<uint64_t> _time_per_token;
    std::atomic<uint64_t> _time_per_burst;
};
