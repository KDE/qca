/*************************************************
* Basic Allocators Header File                   *
* (C) 1999-2004 The Botan Project                *
*************************************************/

#ifndef BOTAN_BASIC_ALLOC_H__
#define BOTAN_BASIC_ALLOC_H__

#include <botan/secalloc.h>

namespace Botan {

/*************************************************
* Malloc Allocator                              *
*************************************************/
class Malloc_Allocator : public SecureAllocator
   {
   private:
      void* alloc_block(u32bit) const;
      void dealloc_block(void*, u32bit) const;
   };

/*************************************************
* Locking Allocator                              *
*************************************************/
class Locking_Allocator : public SecureAllocator
   {
   private:
      void* alloc_block(u32bit) const;
      void dealloc_block(void*, u32bit) const;
      bool should_prealloc() const { return true; }
   };

}

#endif
