/*************************************************
* MPI Algorithms Header File                     *
* (C) 1999-2004 The Botan Project                *
*************************************************/

#ifndef BOTAN_MP_CORE_H__
#define BOTAN_MP_CORE_H__

#include <botan/mp_types.h>

namespace Botan {

/*************************************************
* The size of the word type, in bits             *
*************************************************/
const u32bit MP_WORD_BITS = BOTAN_MP_WORD_BITS;

/*************************************************
* Two Argument MP Core                           *
*************************************************/
void bigint_add2(word[], u32bit, const word[], u32bit);
void bigint_sub2(word[], u32bit, const word[], u32bit);
void bigint_linmul2(word[], u32bit, word);

/*************************************************
* Three Argument MP Core                         *
*************************************************/
void bigint_add3(word[], const word[], u32bit, const word[], u32bit);
void bigint_sub3(word[] , const word[], u32bit, const word[], u32bit);
void bigint_linmul3(word[], const word[], u32bit, word);

/*************************************************
* MP Shifting                                    *
*************************************************/
void bigint_shl1(word[], u32bit, u32bit, u32bit);
void bigint_shl2(word[], const word[], u32bit, u32bit, u32bit);
void bigint_shr1(word[], u32bit, u32bit, u32bit);
void bigint_shr2(word[], const word[], u32bit, u32bit, u32bit);

/*************************************************
* Comba Multiplication                           *
*************************************************/
void bigint_comba4(word[8], const word[4], const word[4]);
void bigint_comba6(word[12], const word[6], const word[6]);
void bigint_comba8(word[16], const word[8], const word[8]);

/*************************************************
* Karatsuba Multiplication                       *
*************************************************/
void bigint_karat16(word[32], const word[16], const word[16]);
void bigint_karat32(word[64], const word[32], const word[32]);
void bigint_karat64(word[128], const word[64], const word[64]);
void bigint_karat128(word[256], const word[128], const word[128]);

void bigint_karat12(word[24], const word[12], const word[12]);
void bigint_karat24(word[48], const word[24], const word[24]);
void bigint_karat48(word[96], const word[48], const word[48]);
void bigint_karat96(word[192], const word[96], const word[96]);

/*************************************************
* Simple O(N^2) Multiplication                   *
*************************************************/
void bigint_smul(word[], const word[], u32bit, const word[], u32bit);

/*************************************************
* MP Multiplication                              *
*************************************************/
void bigint_mul3(word[], u32bit, const word[], u32bit, u32bit,
                                 const word[], u32bit, u32bit);

/*************************************************
* Misc MP Algorithms                             *
*************************************************/
u32bit bigint_divcore(word, word, word, word, word, word);
s32bit bigint_cmp(const word[], u32bit, const word[], u32bit);
word bigint_divop(word, word, word);
word bigint_modop(word, word, word);


}

#endif
