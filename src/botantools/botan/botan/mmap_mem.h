/*************************************************
* Memory Mapping Allocator Header File           *
* (C) 1999-2004 The Botan Project                *
*************************************************/

#include <botan/secalloc.h>

#ifndef BOTAN_EXT_MMAP_ALLOCATOR_H__
#define BOTAN_EXT_MMAP_ALLOCATOR_H__

namespace Botan {

/*************************************************
* Memory Mapping Allocator                       *
*************************************************/
class MemoryMapping_Allocator : public SecureAllocator
   {
   private:
      void* alloc_block(u32bit) const;
      void dealloc_block(void*, u32bit) const;
   };

}

#endif
