/*************************************************
* Comba Multiplication Source File               *
* (C) 1999-2004 The Botan Project                *
*************************************************/

#include <botan/mp_core.h>
#include <botan/mp_madd.h>

namespace Botan {

namespace {

/*************************************************
* Multiply-Add Accumulator                       *
*************************************************/
void word3_muladd(word* w2, word* w1, word* w0, word x, word y)
   {
   word temp = 0;
   bigint_madd(x, y, *w0, 0, w0, &temp);
   *w1 += temp;
   *w2 += (*w1 < temp) ? 1 : 0;
   }

}

/*************************************************
* Comba 4x4 Multiplication                       *
*************************************************/
void bigint_comba4(word z[8], const word x[4], const word y[4])
   {
   word w2 = 0, w1 = 0, w0 = 0;

   word3_muladd(&w2, &w1, &w0, x[0], y[0]);
   z[0] = w0; w0 = w1; w1 = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[0], y[1]);
   word3_muladd(&w2, &w1, &w0, x[1], y[0]);
   z[1] = w0; w0 = w1; w1 = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[0], y[2]);
   word3_muladd(&w2, &w1, &w0, x[1], y[1]);
   word3_muladd(&w2, &w1, &w0, x[2], y[0]);
   z[2] = w0; w0 = w1; w1 = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[0], y[3]);
   word3_muladd(&w2, &w1, &w0, x[1], y[2]);
   word3_muladd(&w2, &w1, &w0, x[2], y[1]);
   word3_muladd(&w2, &w1, &w0, x[3], y[0]);
   z[3] = w0; w0 = w1; w1 = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[1], y[3]);
   word3_muladd(&w2, &w1, &w0, x[2], y[2]);
   word3_muladd(&w2, &w1, &w0, x[3], y[1]);
   z[4] = w0; w0 = w1; w1 = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[2], y[3]);
   word3_muladd(&w2, &w1, &w0, x[3], y[2]);
   z[5] = w0; w0 = w1; w1 = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[3], y[3]);
   z[6] = w0;
   z[7] = w1;
   }

/*************************************************
* Comba 6x6 Multiplication                       *
*************************************************/
void bigint_comba6(word z[12], const word x[6], const word y[6])
   {
   word w2 = 0, w1 = 0, w0 = 0;

   word3_muladd(&w2, &w1, &w0, x[0], y[0]);
   z[0] = w0; w0 = w1; w1 = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[0], y[1]);
   word3_muladd(&w2, &w1, &w0, x[1], y[0]);
   z[1] = w0; w0 = w1; w1 = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[0], y[2]);
   word3_muladd(&w2, &w1, &w0, x[1], y[1]);
   word3_muladd(&w2, &w1, &w0, x[2], y[0]);
   z[2] = w0; w0 = w1; w1 = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[0], y[3]);
   word3_muladd(&w2, &w1, &w0, x[1], y[2]);
   word3_muladd(&w2, &w1, &w0, x[2], y[1]);
   word3_muladd(&w2, &w1, &w0, x[3], y[0]);
   z[3] = w0; w0 = w1; w1 = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[0], y[4]);
   word3_muladd(&w2, &w1, &w0, x[1], y[3]);
   word3_muladd(&w2, &w1, &w0, x[2], y[2]);
   word3_muladd(&w2, &w1, &w0, x[3], y[1]);
   word3_muladd(&w2, &w1, &w0, x[4], y[0]);
   z[4] = w0; w0 = w1; w1 = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[0], y[5]);
   word3_muladd(&w2, &w1, &w0, x[1], y[4]);
   word3_muladd(&w2, &w1, &w0, x[2], y[3]);
   word3_muladd(&w2, &w1, &w0, x[3], y[2]);
   word3_muladd(&w2, &w1, &w0, x[4], y[1]);
   word3_muladd(&w2, &w1, &w0, x[5], y[0]);
   z[5] = w0; w0 = w1; w1 = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[1], y[5]);
   word3_muladd(&w2, &w1, &w0, x[2], y[4]);
   word3_muladd(&w2, &w1, &w0, x[3], y[3]);
   word3_muladd(&w2, &w1, &w0, x[4], y[2]);
   word3_muladd(&w2, &w1, &w0, x[5], y[1]);
   z[6] = w0; w0 = w1; w1 = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[2], y[5]);
   word3_muladd(&w2, &w1, &w0, x[3], y[4]);
   word3_muladd(&w2, &w1, &w0, x[4], y[3]);
   word3_muladd(&w2, &w1, &w0, x[5], y[2]);
   z[7] = w0; w0 = w1; w1 = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[3], y[5]);
   word3_muladd(&w2, &w1, &w0, x[4], y[4]);
   word3_muladd(&w2, &w1, &w0, x[5], y[3]);
   z[8] = w0; w0 = w1; w1 = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[4], y[5]);
   word3_muladd(&w2, &w1, &w0, x[5], y[4]);
   z[9] = w0; w0 = w1; w1 = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[5], y[5]);
   z[10] = w0;
   z[11] = w1;
   }

/*************************************************
* Comba 8x8 Multiplication                       *
*************************************************/
void bigint_comba8(word z[16], const word x[8], const word y[8])
   {
   word w2 = 0, w1 = 0, w0 = 0;

   word3_muladd(&w2, &w1, &w0, x[0], y[0]);
   z[0] = w0; w0 = w1; w1 = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[0], y[1]);
   word3_muladd(&w2, &w1, &w0, x[1], y[0]);
   z[1] = w0; w0 = w1; w1 = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[0], y[2]);
   word3_muladd(&w2, &w1, &w0, x[1], y[1]);
   word3_muladd(&w2, &w1, &w0, x[2], y[0]);
   z[2] = w0; w0 = w1; w1 = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[0], y[3]);
   word3_muladd(&w2, &w1, &w0, x[1], y[2]);
   word3_muladd(&w2, &w1, &w0, x[2], y[1]);
   word3_muladd(&w2, &w1, &w0, x[3], y[0]);
   z[3] = w0; w0 = w1; w1 = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[0], y[4]);
   word3_muladd(&w2, &w1, &w0, x[1], y[3]);
   word3_muladd(&w2, &w1, &w0, x[2], y[2]);
   word3_muladd(&w2, &w1, &w0, x[3], y[1]);
   word3_muladd(&w2, &w1, &w0, x[4], y[0]);
   z[4] = w0; w0 = w1; w1 = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[0], y[5]);
   word3_muladd(&w2, &w1, &w0, x[1], y[4]);
   word3_muladd(&w2, &w1, &w0, x[2], y[3]);
   word3_muladd(&w2, &w1, &w0, x[3], y[2]);
   word3_muladd(&w2, &w1, &w0, x[4], y[1]);
   word3_muladd(&w2, &w1, &w0, x[5], y[0]);
   z[5] = w0; w0 = w1; w1 = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[0], y[6]);
   word3_muladd(&w2, &w1, &w0, x[1], y[5]);
   word3_muladd(&w2, &w1, &w0, x[2], y[4]);
   word3_muladd(&w2, &w1, &w0, x[3], y[3]);
   word3_muladd(&w2, &w1, &w0, x[4], y[2]);
   word3_muladd(&w2, &w1, &w0, x[5], y[1]);
   word3_muladd(&w2, &w1, &w0, x[6], y[0]);
   z[6] = w0; w0 = w1; w1 = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[0], y[7]);
   word3_muladd(&w2, &w1, &w0, x[1], y[6]);
   word3_muladd(&w2, &w1, &w0, x[2], y[5]);
   word3_muladd(&w2, &w1, &w0, x[3], y[4]);
   word3_muladd(&w2, &w1, &w0, x[4], y[3]);
   word3_muladd(&w2, &w1, &w0, x[5], y[2]);
   word3_muladd(&w2, &w1, &w0, x[6], y[1]);
   word3_muladd(&w2, &w1, &w0, x[7], y[0]);
   z[7] = w0; w0 = w1; w1 = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[1], y[7]);
   word3_muladd(&w2, &w1, &w0, x[2], y[6]);
   word3_muladd(&w2, &w1, &w0, x[3], y[5]);
   word3_muladd(&w2, &w1, &w0, x[4], y[4]);
   word3_muladd(&w2, &w1, &w0, x[5], y[3]);
   word3_muladd(&w2, &w1, &w0, x[6], y[2]);
   word3_muladd(&w2, &w1, &w0, x[7], y[1]);
   z[8] = w0; w0 = w1; w1 = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[2], y[7]);
   word3_muladd(&w2, &w1, &w0, x[3], y[6]);
   word3_muladd(&w2, &w1, &w0, x[4], y[5]);
   word3_muladd(&w2, &w1, &w0, x[5], y[4]);
   word3_muladd(&w2, &w1, &w0, x[6], y[3]);
   word3_muladd(&w2, &w1, &w0, x[7], y[2]);
   z[9] = w0; w0 = w1; w1 = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[3], y[7]);
   word3_muladd(&w2, &w1, &w0, x[4], y[6]);
   word3_muladd(&w2, &w1, &w0, x[5], y[5]);
   word3_muladd(&w2, &w1, &w0, x[6], y[4]);
   word3_muladd(&w2, &w1, &w0, x[7], y[3]);
   z[10] = w0; w0 = w1; w1 = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[4], y[7]);
   word3_muladd(&w2, &w1, &w0, x[5], y[6]);
   word3_muladd(&w2, &w1, &w0, x[6], y[5]);
   word3_muladd(&w2, &w1, &w0, x[7], y[4]);
   z[11] = w0; w0 = w1; w1 = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[5], y[7]);
   word3_muladd(&w2, &w1, &w0, x[6], y[6]);
   word3_muladd(&w2, &w1, &w0, x[7], y[5]);
   z[12] = w0; w0 = w1; w1 = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[6], y[7]);
   word3_muladd(&w2, &w1, &w0, x[7], y[6]);
   z[13] = w0; w0 = w1; w1 = w2; w2 = 0;

   word3_muladd(&w2, &w1, &w0, x[7], y[7]);
   z[14] = w0;
   z[15] = w1;
   }

}
