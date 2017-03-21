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
* Pooling Allocator Header File                  *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_POOLING_ALLOCATOR_H__
#define BOTAN_POOLING_ALLOCATOR_H__

} // WRAPNS_LINE
#include <botan/allocate.h>
namespace QCA { // WRAPNS_LINE
} // WRAPNS_LINE
#include <botan/exceptn.h>
namespace QCA { // WRAPNS_LINE
} // WRAPNS_LINE
#include <botan/mutex.h>
namespace QCA { // WRAPNS_LINE
} // WRAPNS_LINE
#include <utility>
namespace QCA { // WRAPNS_LINE
} // WRAPNS_LINE
#include <vector>
namespace QCA { // WRAPNS_LINE

namespace Botan {

/*************************************************
* Pooling Allocator                              *
*************************************************/
class Pooling_Allocator : public Allocator
   {
   public:
      void* allocate(u32bit);
      void deallocate(void*, u32bit);

      void destroy();

      Pooling_Allocator(u32bit, bool);
      ~Pooling_Allocator() NOEXCEPT;
   private:
      void get_more_core(u32bit);
      byte* allocate_blocks(u32bit);

      virtual void* alloc_block(u32bit) = 0;
      virtual void dealloc_block(void*, u32bit) = 0;

      class Memory_Block
         {
         public:
            Memory_Block(void*);

            static u32bit bitmap_size() { return BITMAP_SIZE; }
            static u32bit block_size() { return BLOCK_SIZE; }

            bool contains(void*, u32bit) const throw();
            byte* alloc(u32bit) throw();
            void free(void*, u32bit) throw();

            bool operator<(const Memory_Block& other) const
               {
               if(buffer < other.buffer && other.buffer < buffer_end)
                  return false;
               return (buffer < other.buffer);
               }

         private:
            typedef u64bit bitmap_type;
            static const u32bit BITMAP_SIZE;
            static const u32bit BLOCK_SIZE;

            bitmap_type bitmap;
            byte* buffer, *buffer_end;
         };

      const u32bit PREF_SIZE;

      std::vector<Memory_Block> blocks;
      std::vector<Memory_Block>::iterator last_used;
      std::vector<std::pair<void*, u32bit> > allocated;
      Mutex* mutex;
   };

}

#endif
} // WRAPNS_LINE
