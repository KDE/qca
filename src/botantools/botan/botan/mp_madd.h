/*************************************************
* MPI Multiply-Add Core Header File              *
* (C) 1999-2004 The Botan Project                *
*************************************************/

#ifndef BOTAN_MP_MADD_H__
#define BOTAN_MP_MADD_H__

#include <botan/mp_core.h>

namespace Botan {

/*************************************************
* Multiply-Add Operation                         *
*************************************************/
inline void bigint_madd(word a, word b, word c, word d,
                        word* out_low, word* out_high)
   {
#if (BOTAN_MP_WORD_BITS == 8)
  typedef Botan::u16bit dword;
#elif (BOTAN_MP_WORD_BITS == 16)
  typedef Botan::u32bit dword;
#elif (BOTAN_MP_WORD_BITS == 32)
  typedef Botan::u64bit dword;
#elif (BOTAN_MP_WORD_BITS == 64)
  #error BOTAN_MP_WORD_BITS can only be 64 with the mp_asm64 module
#else
  #error BOTAN_MP_WORD_BITS must be 8, 16, 32, or 64
#endif

   dword z = (dword)a * b + c + d;
   *out_low =  (word)((z                      ) & MP_WORD_MAX);
   *out_high = (word)((z >> BOTAN_MP_WORD_BITS) & MP_WORD_MAX);
   }

}

#endif
