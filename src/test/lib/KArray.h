/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Module Name:

    KArray.h

Abstract:

    Implements a C++ container analogous to std::vector

Environment:

    Kernel mode or user mode unittest

Notes:

    Because kernel C++ doesn't support exceptions, we can't use the STL
    directly in kernel mode. Therefore, this class provides a limited and
    slightly modified subset of the STL's std::vector.

    If you're not familiar with std::vector, you should go read up on it
    first: https://docs.microsoft.com/en-us/cpp/standard-library/vector-class

    This file was originally copied from the following location and then
    modified to reduce dependencies:

    https://github.com/microsoft/Network-Adapter-Class-Extension/blob/windows_10.0.19541/ndis/rtl/inc/karray.h

--*/

#pragma once

#include <new.h>
#include <ntintsafe.h>

namespace wistd     // ("Windows Implementation" std)
{

//
// WIL implementation of wistd::addressof
//

template <class _Tp>
inline constexpr
_Tp*
addressof(_Tp& __x) noexcept
{
    return __builtin_addressof(__x);
}

//
// WIL implementation of wistd::move
//

template <class _Tp> struct remove_reference { typedef _Tp type; };
template <class _Tp> struct remove_reference<_Tp&&> { typedef _Tp type; };

template <class _Tp>
inline constexpr
typename remove_reference<_Tp>::type&&
move(_Tp&& __t) noexcept
{
    typedef typename remove_reference<_Tp>::type _Up;
    return static_cast<_Up&&>(__t);
}

//
// WIL dependencies for is_trivially_destructable and is_trivially_constructible
//

template <class _Tp, _Tp __v>
struct integral_constant
{
    static constexpr const _Tp      value = __v;
    typedef _Tp               value_type;
    typedef integral_constant type;
        constexpr operator value_type() const noexcept { return value; }
        constexpr value_type operator ()() const noexcept { return value; }
};

template <class _Tp, _Tp __v>
    constexpr const _Tp integral_constant<_Tp, __v>::value;

//
// WIL implementation for is_trivially_constructible
//

template <class _Tp, class ..._Args>
    struct is_constructible
        : public integral_constant<bool, __is_constructible(_Tp, _Args...)>
    {};

template <class _Tp, class... _Args>
    struct is_trivially_constructible
        : integral_constant<bool, __is_trivially_constructible(_Tp, _Args...)>
    {};

template <class _Tp>
struct is_trivially_default_constructible
    : public is_trivially_constructible<_Tp>
{};

template <class _Tp>
    constexpr bool is_trivially_default_constructible_v
        = is_trivially_default_constructible<_Tp>::value;

//
// WIL implementation for is_trivially_destructible
//

template <class _Tp>
struct is_destructible
    : public integral_constant<bool, __is_destructible(_Tp)> {};

template <class _Tp> struct is_trivially_destructible
    : public integral_constant<bool, is_destructible<_Tp>::value&& __has_trivial_destructor(_Tp)> {};

template <class _Tp>
constexpr bool is_trivially_destructible_v
    = is_trivially_destructible<_Tp>::value;

} // end namespace wistd

#define CODE_SEG(segment) __declspec(code_seg(segment))

#ifndef KRTL_PAGE_SEGMENT
#  define KRTL_PAGE_SEGMENT "PAGE"
#endif

// Use on classes or structs.  Class member functions & compiler-generated code
// will default to the PAGE segment.  You can override any member function with `NONPAGED`.
#define KRTL_CLASS CODE_SEG(KRTL_PAGE_SEGMENT) __declspec(empty_bases)

// Use on pageable functions.
#define PAGED CODE_SEG(KRTL_PAGE_SEGMENT) _IRQL_always_function_max_(PASSIVE_LEVEL)

// Use on code that must always be locked in memory.
#define NONPAGED CODE_SEG(KRTL_NONPAGED_SEGMENT) _IRQL_requires_max_(DISPATCH_LEVEL)

template<ULONG SIGNATURE>
struct KRTL_CLASS QuicDebugBlock
{
#if _DEBUG
    PAGED ~QuicDebugBlock()
    {
        ASSERT_VALID();
        Signature |= 0x80;
    }
#endif

    NONPAGED void ASSERT_VALID() const
    {
#if _DEBUG
        WIN_ASSERT(Signature == SIGNATURE);
#endif
    }

private:
#if _DEBUG
    uint32_t Signature = SIGNATURE;
#endif
};

template <uint32_t TAG, POOL_FLAGS ARENA = POOL_FLAG_PAGED>
struct KRTL_CLASS KALLOCATION_TAG
{
    static const uint32_t AllocationTag = TAG;
    static const POOL_FLAGS AllocationArena = ARENA;
};

template <uint32_t TAG, POOL_FLAGS ARENA = POOL_FLAG_PAGED>
struct KRTL_CLASS KALLOCATOR : public KALLOCATION_TAG<TAG, ARENA>
{
    // Scalar new & delete

    PAGED void *operator new(size_t cb, std::nothrow_t const &)
    {
        PAGED_CODE();
        return ExAllocatePool2(static_cast<POOL_FLAGS>(ARENA), (SIZE_T)cb, TAG);
    }

    PAGED void operator delete(void *p)
    {
        PAGED_CODE();

        if (p != nullptr)
        {
            ExFreePoolWithTag(p, TAG);
        }
    }

    // Scalar new with bonus bytes

    PAGED void *operator new(size_t cb, std::nothrow_t const &, size_t extraBytes)
    {
        PAGED_CODE();

        auto size = cb + extraBytes;

        // Overflow check
        if (size < cb)
            return nullptr;

        return ExAllocatePool2(static_cast<POOL_FLAGS>(ARENA), (SIZE_T)size, TAG);
    }

    // Array new & delete

    PAGED void *operator new[](size_t cb, std::nothrow_t const &)
    {
        PAGED_CODE();
        return ExAllocatePool2(static_cast<POOL_FLAGS>(ARENA), (SIZE_T)cb, TAG);
    }

    PAGED void operator delete[](void *p)
    {
        PAGED_CODE();

        if (p != nullptr)
        {
            ExFreePoolWithTag(p, TAG);
        }
    }

    // Placement new & delete

    PAGED void *operator new(size_t n, void * p)
    {
        PAGED_CODE();
        UNREFERENCED_PARAMETER((n));
        return p;
    }

    PAGED void operator delete(void *p1, void *p2)
    {
        PAGED_CODE();
        UNREFERENCED_PARAMETER((p1, p2));
    }
};

template <uint32_t TAG>
struct KRTL_CLASS PAGED_OBJECT :
    public KALLOCATOR<TAG, PagedPool>,
    public QuicDebugBlock<TAG>
{

};

namespace Rtl
{

template<typename T, POOL_FLAGS PoolType = POOL_FLAG_PAGED>
class KRTL_CLASS KArray :
    public PAGED_OBJECT<'rrAK'>
{
public:

    CXPLAT_STATIC_ASSERT(
        ((PoolType == (POOL_FLAG_NON_PAGED | POOL_FLAG_CACHE_ALIGNED)) &&
         (alignof(T) <= SYSTEM_CACHE_ALIGNMENT_SIZE)) ||
        (alignof(T) <= MEMORY_ALLOCATION_ALIGNMENT),
        "This container allocates items with a fixed alignment");

    // This iterator is not a full implementation of a STL-style iterator.
    // Mostly this is only here to get C++'s syntax "for(x : y)" to work.
    class const_iterator
    {
    friend class KArray;
    protected:

        PAGED const_iterator(KArray const *a, size_t i) : _a{ const_cast<KArray*>(a) }, _i{ i } { ensure_valid(); }

    public:

        const_iterator() = delete;
        PAGED const_iterator(const_iterator const &rhs) : _a { rhs._a }, _i{ rhs._i } { }
        PAGED ~const_iterator() = default;

        PAGED const_iterator &operator=(const_iterator const &rhs) { _a = rhs._a; _i = rhs._i; return *this; }

        PAGED const_iterator &operator++() { _i++; return *this; }
        PAGED const_iterator operator++(int) { auto result = *this; ++(*this); return result; }

        PAGED const_iterator &operator+=(size_t offset) { _i += offset; return *this;}

        PAGED T const &operator*() const { return (*_a)[_i]; }
        PAGED T const *operator->() const { return &(*_a)[_i]; }

        PAGED bool operator==(const_iterator const &rhs) const { return rhs._i == _i; }
        PAGED bool operator!=(const_iterator const &rhs) const { return !(rhs == *this); }

    protected:

        PAGED void ensure_valid() const { if (_i > _a->count()) RtlFailFast(FAST_FAIL_RANGE_CHECK_FAILURE); }

        KArray *_a;
        size_t _i;
    };

    class iterator : public const_iterator
    {
    friend class KArray;
    protected:

        PAGED iterator(KArray *a, size_t i) : const_iterator{ a, i } {}

    public:

        PAGED T &operator*() const { return (*_a)[_i]; }
        PAGED T *operator->() const { return &(*_a)[_i]; }
    };

    PAGED KArray(size_t sizeHint = 0) noexcept
    {
        if (sizeHint)
            (void)grow(sizeHint);
    }

    NONPAGED ~KArray()
    {
        reset();
    }

    PAGED KArray(
        _In_ KArray &&rhs) noexcept :
            _p(rhs._p),
            m_numElements(rhs.m_numElements),
            m_bufferSize(rhs.m_bufferSize)
    {
        rhs._p = nullptr;
        rhs.m_numElements = 0;
        rhs.m_bufferSize = 0;
    }

    KArray(KArray &) = delete;

    KArray &operator=(KArray &) = delete;

    PAGED KArray &operator=(
        _In_ KArray &&rhs)
    {
        reset();

        this->_p = rhs._p;
        this->m_numElements = rhs.m_numElements;
        this->m_bufferSize = rhs.m_bufferSize;

        rhs._p = nullptr;
        rhs.m_numElements = 0;
        rhs.m_bufferSize = 0;

        return *this;
    }

    NONPAGED size_t count() const
    {
        return m_numElements;
    }

    PAGED bool reserve(size_t count)
    {
        if (m_bufferSize >= count)
            return true;

        if (count >= (uint32_t)(-1))
            return false;

        ULONGLONG bytesNeeded;
        if (!NT_SUCCESS(RtlULongLongMult(sizeof(T), count, &bytesNeeded)) ||
            bytesNeeded > SIZE_T_MAX)
            return false;

        T * p = (T*)ExAllocatePool2(PoolType, (SIZE_T)bytesNeeded, 'rrAK');
        if (!p)
            return false;

        if (__is_trivially_copyable(T))
        {
            memcpy(p, _p, m_numElements * sizeof(T));
        }
        else
        {
            for (uint32_t i = 0; i < m_numElements; i++)
                new (wistd::addressof(p[i])) T(wistd::move(_p[i]));
        }

        if (_p)
        {
            for (uint32_t i = 0; i < m_numElements; i++)
                _p[i].~T();

            ExFreePoolWithTag(_p, 'rrAK');
        }

        m_bufferSize = static_cast<uint32_t>(count);
        _p = p;

        return true;
    }

    PAGED bool resize(size_t count)
    {
        if (!reserve(count))
            return false;

        if (wistd::is_trivially_default_constructible_v<T>)
        {
            if (count > m_numElements)
            {
                memset(wistd::addressof(_p[m_numElements]), 0, (count - m_numElements) * sizeof(T));
            }
        }
        else
        {
            for (size_t i = m_numElements; i < count; i++)
            {
                new(wistd::addressof(_p[i])) T();
            }
        }

        if (!wistd::is_trivially_destructible_v<T>)
        {
            for (size_t i = count; i < m_numElements; i++)
            {
                _p[i].~T();
            }
        }

        m_numElements = static_cast<uint32_t>(count);
        return true;
    }

    PAGED void clear(void)
    {
        (void)resize(0);
    }

    PAGED bool append(T const &t)
    {
        if (!grow(m_numElements+1))
            return false;

        new(wistd::addressof(_p[m_numElements])) T(t);
        ++m_numElements;
        return true;
    }

    PAGED bool append(T &&t)
    {
        if (!grow(m_numElements+1))
            return false;

        new(wistd::addressof(_p[m_numElements])) T(wistd::move(t));
        ++m_numElements;
        return true;
    }

    PAGED bool insertAt(size_t index, T &t)
    {
        if (index > m_numElements)
            return false;

        if (!grow(m_numElements+1))
            return false;

        if (index < m_numElements)
            moveElements((uint32_t)index, (uint32_t)(index+1), (uint32_t)(m_numElements - index));

        new(wistd::addressof(_p[index])) T(t);
        ++m_numElements;
        return true;
    }

    PAGED bool insertAt(const iterator &destination, const const_iterator &start, const const_iterator &end)
    {
        if (end._i < start._i || destination._a != this)
            RtlFailFast(FAST_FAIL_INVALID_ARG);
        if (end._i == start._i)
            return true;

        const size_t countToInsert = end._i - start._i;

        size_t countToGrow;
        if (!NT_SUCCESS(RtlULongLongAdd(m_numElements, countToInsert, reinterpret_cast<ULONGLONG*>(&countToGrow))))
            return false;

        if (!grow(countToGrow))
            return false;

        moveElements((uint32_t)destination._i, (uint32_t)(destination._i+countToInsert), (uint32_t)(m_numElements - destination._i));

        if (__is_trivially_copyable(T))
        {
            memcpy(_p + destination._i, wistd::addressof((*start._a)[start._i]), countToInsert * sizeof(T));
        }
        else
        {
            const_iterator readCursor(start);
            iterator writeCursor(destination);
            while (readCursor != end)
            {
                new(wistd::addressof(_p[writeCursor._i])) T(wistd::move((*readCursor._a)[readCursor._i]));
                writeCursor++;
                readCursor++;
            }
        }

        m_numElements += static_cast<uint32_t>(countToInsert);
        return true;
    }

    PAGED bool insertAt(size_t index, T &&t)
    {
        if (index > m_numElements)
            return false;

        if (!grow(m_numElements+1))
            return false;

        if (index < m_numElements)
            moveElements((uint32_t)index, (uint32_t)(index+1), (uint32_t)(m_numElements - index));

        new(wistd::addressof(_p[index])) T(wistd::move(t));
        ++m_numElements;
        return true;
    }

    PAGED bool insertSorted(T &t, bool (*lessThanPredicate)(T const&, T const&))
    {
        for (size_t i = 0; i < m_numElements; i++)
        {
            if (!lessThanPredicate(_p[i], t))
            {
                return insertAt(i, t);
            }
        }

        return append(t);
    }

    PAGED bool insertSorted(T &&t, bool (*lessThanPredicate)(T const&, T const&))
    {
        for (size_t i = 0; i < m_numElements; i++)
        {
            if (!lessThanPredicate(_p[i], t))
            {
                return insertAt(i, wistd::move(t));
            }
        }

        return append(wistd::move(t));
    }

    PAGED bool insertSortedUnique(T &t, bool (*lessThanPredicate)(T const&, T const&))
    {
        for (size_t i = 0; i < m_numElements; i++)
        {
            if (!lessThanPredicate(_p[i], t))
            {
                if (lessThanPredicate(t, _p[i]))
                    return insertAt(i, t);
                else
                    return true;
            }
        }

        return append(t);
    }

    PAGED bool insertSortedUnique(T &&t, bool (*lessThanPredicate)(T const&, T const&))
    {
        for (size_t i = 0; i < m_numElements; i++)
        {
            if (!lessThanPredicate(_p[i], t))
            {
                if (lessThanPredicate(t, _p[i]))
                    return insertAt(i, wistd::move(t));
                else
                    return true;
            }
        }

        return append(wistd::move(t));
    }

    PAGED void eraseAt(size_t index)
    {
        if (index >= m_numElements)
            RtlFailFast(FAST_FAIL_INVALID_ARG);

        _p[index].~T();
        moveElements((uint32_t)(index+1), (uint32_t)index, (uint32_t)(m_numElements - index - 1));
        --m_numElements;
    }

    NONPAGED T &operator[](size_t index)
    {
        if (index >= m_numElements)
            RtlFailFast(FAST_FAIL_INVALID_ARG);

        return _p[index];
    }

    NONPAGED T const &operator[](size_t index) const
    {
        if (index >= m_numElements)
            RtlFailFast(FAST_FAIL_INVALID_ARG);

        return _p[index];
    }

    PAGED iterator begin()
    {
        return { this, 0 };
    }

    PAGED const_iterator begin() const
    {
        return { this, 0 };
    }

    PAGED iterator end()
    {
        return { this, m_numElements };
    }

    PAGED const_iterator end() const
    {
        return { this, m_numElements };
    }

private:

    NONPAGED void reset()
    {
        if (_p)
        {
            if (!wistd::is_trivially_destructible_v<T>)
            {
                for (auto i = m_numElements; i > 0; i--)
                {
                    _p[i-1].~T();
                }
            }

            ExFreePoolWithTag(_p, 'rrAK');
            _p = nullptr;
            m_numElements = 0;
            m_bufferSize = 0;
        }
    }

    PAGED void moveElements(uint32_t from, uint32_t to, uint32_t number)
    {
        if (from == to || number == 0)
        {
            // Do nothing in this case.
        }
        else if (__is_trivially_copyable(T))
        {
            memmove(_p + to, _p + from, number * sizeof(T));
        }
        else if (from < to)
        {
            CXPLAT_FRE_ASSERT(m_numElements == from + number);

            uint32_t delta = to - from;
            uint32_t i;

            for (i = to + number; i - 1 >= m_numElements; i--)
            {
                new (wistd::addressof(_p[i - 1])) T(wistd::move(_p[i - delta - 1]));
            }

            for (; i > to; i--)
            {
                _p[i - 1].~T();
                new (wistd::addressof(_p[i - 1])) T(wistd::move(_p[i - delta - 1]));
            }

            for (; i > from; i--)
            {
                _p[i - 1].~T();
            }
        }
        else
        {
            CXPLAT_FRE_ASSERT(m_numElements == from + number);

            uint32_t delta = from - to;
            uint32_t i;

            for (i = to; i < from; i++)
            {
                new (wistd::addressof(_p[i])) T(wistd::move(_p[i + delta]));
            }

            for (; i < to + number; i++)
            {
                _p[i].~T();
                new (wistd::addressof(_p[i])) T(wistd::move(_p[i + delta]));
            }

            for (; i < from + number; i++)
            {
                _p[i].~T();
            }
        }
    }

    PAGED bool grow(size_t count)
    {
        if (m_bufferSize >= count)
            return true;

        if (count < 4)
            count = 4;

        size_t exponentialGrowth = m_bufferSize + m_bufferSize / 2;
        if (count < exponentialGrowth)
            count = exponentialGrowth;

        return reserve(count);
    }

    uint32_t m_bufferSize = 0;
    uint32_t m_numElements = 0;
    T *_p = nullptr;
};

}
