/*
Copyright (C) 1999-2007 The Botan Project. All rights reserved.

Redistribution and use in source and binary forms, for any use, with or without
modification, is permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions, and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions, and the following disclaimer in the documentation
and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) "AS IS" AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ARE DISCLAIMED.

IN NO EVENT SHALL THE AUTHOR(S) OR CONTRIBUTOR(S) BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
// LICENSEHEADER_END
namespace QCA { // WRAPNS_LINE
/*************************************************
 * Secure Memory Buffers Header File              *
 * (C) 1999-2007 The Botan Project                *
 *************************************************/

#ifndef BOTAN_SECURE_MEMORY_BUFFERS_H__
#define BOTAN_SECURE_MEMORY_BUFFERS_H__

} // WRAPNS_LINE
#include <botan/allocate.h>
namespace QCA { // WRAPNS_LINE
} // WRAPNS_LINE
#include <botan/mem_ops.h>
namespace QCA { // WRAPNS_LINE

namespace Botan {

/*************************************************
 * Variable Length Memory Buffer                  *
 *************************************************/
template<typename T> class MemoryRegion // clazy:exclude=rule-of-three
{
public:
    u32bit size() const
    {
        return used;
    }
    u32bit is_empty() const
    {
        return (used == 0);
    }
    u32bit has_items() const
    {
        return (used != 0);
    }

    operator T *()
    {
        return buf;
    }
    operator const T *() const
    {
        return buf;
    }

    T *begin()
    {
        return buf;
    }
    const T *begin() const
    {
        return buf;
    }

    T *end()
    {
        return (buf + size());
    }
    const T *end() const
    {
        return (buf + size());
    }

    bool operator==(const MemoryRegion<T> &other) const
    {
        return (size() == other.size() && same_mem(buf, other.buf, size()));
    }

    bool operator<(const MemoryRegion<T> &) const;

    bool operator!=(const MemoryRegion<T> &in) const
    {
        return (!(*this == in));
    }
    MemoryRegion<T> &operator=(const MemoryRegion<T> &in)
    {
        if (this != &in)
            set(in);
        return (*this);
    }

    void copy(const T in[], u32bit n)
    {
        copy(0, in, n);
    }
    void copy(u32bit off, const T in[], u32bit n)
    {
        copy_mem(buf + off, in, (n > size() - off) ? (size() - off) : n);
    }

    void set(const T in[], u32bit n)
    {
        create(n);
        copy(in, n);
    }
    void set(const MemoryRegion<T> &in)
    {
        set(in.begin(), in.size());
    }

    void append(const T data[], u32bit n)
    {
        grow_to(size() + n);
        copy(size() - n, data, n);
    }
    void append(T x)
    {
        append(&x, 1);
    }
    void append(const MemoryRegion<T> &x)
    {
        append(x.begin(), x.size());
    }

    void clear()
    {
        clear_mem(buf, allocated);
    }
    void destroy()
    {
        create(0);
    }

    void create(u32bit);
    void grow_to(u32bit) const;
    void swap(MemoryRegion<T> &);

    ~MemoryRegion()
    {
        deallocate(buf, allocated);
    }

protected:
    MemoryRegion()
    {
        buf   = nullptr;
        alloc = nullptr;
        used = allocated = 0;
    }
    MemoryRegion(const MemoryRegion<T> &copy)
    {
        buf  = nullptr;
        used = allocated = 0;
        alloc            = copy.alloc;
        set(copy.buf, copy.used);
    }

    void init(bool locking, u32bit size = 0)
    {
        alloc = Allocator::get(locking);
        create(size);
    }

private:
    T *allocate(u32bit n) const
    {
        return (T *)alloc->allocate(sizeof(T) * n);
    }
    void deallocate(T *p, u32bit n) const
    {
        alloc->deallocate(p, sizeof(T) * n);
    }

    mutable T         *buf;
    mutable u32bit     used;
    mutable u32bit     allocated;
    mutable Allocator *alloc;
};

/*************************************************
 * Create a new buffer                            *
 *************************************************/
template<typename T> void MemoryRegion<T>::create(u32bit n)
{
    if (n <= allocated) {
        clear();
        used = n;
        return;
    }
    deallocate(buf, allocated);
    buf       = allocate(n);
    allocated = used = n;
}

/*************************************************
 * Increase the size of the buffer                *
 *************************************************/
template<typename T> void MemoryRegion<T>::grow_to(u32bit n) const
{
    if (n > used && n <= allocated) {
        clear_mem(buf + used, n - used);
        used = n;
        return;
    } else if (n > allocated) {
        T *new_buf = allocate(n);
        copy_mem(new_buf, buf, used);
        deallocate(buf, allocated);
        buf       = new_buf;
        allocated = used = n;
    }
}

/*************************************************
 * Compare this buffer with another one           *
 *************************************************/
template<typename T> bool MemoryRegion<T>::operator<(const MemoryRegion<T> &in) const
{
    if (size() < in.size())
        return true;
    if (size() > in.size())
        return false;

    for (u32bit j = 0; j != size(); j++) {
        if (buf[j] < in[j])
            return true;
        if (buf[j] > in[j])
            return false;
    }

    return false;
}

/*************************************************
 * Swap this buffer with another one              *
 *************************************************/
template<typename T> void MemoryRegion<T>::swap(MemoryRegion<T> &x)
{
    std::swap(buf, x.buf);
    std::swap(used, x.used);
    std::swap(allocated, x.allocated);
    std::swap(alloc, x.alloc);
}

/*************************************************
 * Unlocked Variable Length Buffer                *
 *************************************************/
template<typename T> class MemoryVector : public MemoryRegion<T>
{
public:
    MemoryVector<T> &operator=(const MemoryRegion<T> &in)
    {
        if (this != &in)
            this->set(in);
        return (*this);
    }

    MemoryVector(u32bit n = 0)
    {
        MemoryRegion<T>::init(false, n);
    }
    MemoryVector(const T in[], u32bit n)
    {
        MemoryRegion<T>::init(false);
        this->set(in, n);
    }
    MemoryVector(const MemoryRegion<T> &in)
    {
        MemoryRegion<T>::init(false);
        this->set(in);
    }
    MemoryVector(const MemoryRegion<T> &in1, const MemoryRegion<T> &in2)
    {
        MemoryRegion<T>::init(false);
        this->set(in1);
        append(in2);
    }
};

/*************************************************
 * Locked Variable Length Buffer                  *
 *************************************************/
template<typename T> class SecureVector : public MemoryRegion<T>
{
public:
    SecureVector<T> &operator=(const MemoryRegion<T> &in)
    {
        if (this != &in)
            this->set(in);
        return (*this);
    }

    SecureVector(u32bit n = 0)
    {
        MemoryRegion<T>::init(true, n);
    }
    SecureVector(const T in[], u32bit n)
    {
        MemoryRegion<T>::init(true);
        this->set(in, n);
    }
    SecureVector(const MemoryRegion<T> &in)
    {
        MemoryRegion<T>::init(true);
        this->set(in);
    }
    SecureVector(const MemoryRegion<T> &in1, const MemoryRegion<T> &in2)
    {
        MemoryRegion<T>::init(true);
        this->set(in1);
        append(in2);
    }
};

/*************************************************
 * Locked Fixed Length Buffer                     *
 *************************************************/
template<typename T, u32bit L>
class SecureBuffer : public MemoryRegion<T> // clazy:exclude=rule-of-three TODO Needs checking if a real bug or not
{
public:
    SecureBuffer<T, L> &operator=(const SecureBuffer<T, L> &in)
    {
        if (this != &in)
            this->set(in);
        return (*this);
    }

    SecureBuffer()
    {
        MemoryRegion<T>::init(true, L);
    }
    SecureBuffer(const T in[], u32bit n)
    {
        MemoryRegion<T>::init(true, L);
        copy(in, n);
    }

private:
    SecureBuffer<T, L> &operator=(const MemoryRegion<T> &in)
    {
        if (this != &in)
            this->set(in);
        return (*this);
    }
};

}

#endif
} // WRAPNS_LINE
