/*************************************************
* MPI Addition/Subtraction Source File           *
* (C) 1999-2004 The Botan Project                *
*************************************************/

#include <botan/mp_core.h>

namespace Botan {

/*************************************************
* Two Operand Addition                           *
*************************************************/
void bigint_add2(word x[], u32bit x_size, const word y[], u32bit y_size)
   {
   word carry = 0;

   for(u32bit j = 0; j != y_size; j++)
      {
      word z = x[j] + y[j] + carry;

      const u32bit top_x = x[j] >> (MP_WORD_BITS - 1);
      const u32bit top_y = y[j] >> (MP_WORD_BITS - 1);
      const u32bit top_z = z >> (MP_WORD_BITS - 1);

      x[j] = z;
      carry = ((top_x | top_y) & !top_z) | (top_x & top_y);
      }

   if(!carry) return;

   for(u32bit j = y_size; j != x_size; j++)
      {
      x[j]++;
      if(x[j]) return;
      }
   x[x_size]++;
   }

/*************************************************
* Three Operand Addition                         *
*************************************************/
void bigint_add3(word z[], const word x[], u32bit x_size,
                           const word y[], u32bit y_size)
   {
   if(x_size < y_size)
      { bigint_add3(z, y, y_size, x, x_size); return; }

   word carry = 0;
   for(u32bit j = 0; j != y_size; j++)
      {
      z[j] = x[j] + y[j] + carry;

      const u32bit top_x = x[j] >> (MP_WORD_BITS - 1);
      const u32bit top_y = y[j] >> (MP_WORD_BITS - 1);
      const u32bit top_z = z[j] >> (MP_WORD_BITS - 1);

      carry = ((top_x | top_y) & !top_z) | (top_x & top_y);
      }

   for(u32bit j = y_size; j != x_size; j++)
      z[j] = x[j];

   if(!carry) return;

   for(u32bit j = y_size; j != x_size; j++)
      {
      z[j]++;
      if(z[j]) return;
      }
   z[x_size]++;
   }

/*************************************************
* Two Operand Subtraction                        *
*************************************************/
void bigint_sub2(word x[], u32bit x_size, const word y[], u32bit y_size)
   {
   word borrow = 0;
   for(u32bit j = 0; j != y_size; j++)
      {
      word r = x[j] - y[j];
      word next = ((x[j] < r) ? 1 : 0);
      r -= borrow;
      borrow = next | ((r == MP_WORD_MAX) ? borrow : 0);
      x[j] = r;
      }

   if(!borrow) return;

   for(u32bit j = y_size; j != x_size; j++)
      {
      x[j]--;
      if(x[j] != MP_WORD_MAX) return;
      }
   }

/*************************************************
* Three Operand Subtraction                      *
*************************************************/
void bigint_sub3(word z[], const word x[], u32bit x_size,
                           const word y[], u32bit y_size)
   {
   word borrow = 0;
   for(u32bit j = 0; j != y_size; j++)
      {
      z[j] = x[j] - y[j];
      word next = ((x[j] < z[j]) ? 1 : 0);
      z[j] -= borrow;
      borrow = next | ((z[j] == MP_WORD_MAX) ? borrow : 0);
      }

   for(u32bit j = y_size; j != x_size; j++)
      z[j] = x[j];

   if(!borrow) return;

   for(u32bit j = y_size; j != x_size; j++)
      {
      z[j]--;
      if(z[j] != MP_WORD_MAX) return;
      }
   }

}
