/*************************************************
* BigInt Binary Operators Source File            *
* (C) 1999-2004 The Botan Project                *
*************************************************/

#include <botan/bigint.h>
#include <botan/numthry.h>
#include <botan/mp_core.h>

namespace Botan {

/*************************************************
* Addition Operator                              *
*************************************************/
BigInt operator+(const BigInt& x, const BigInt& y)
   {
   if((x.sign() == y.sign()))
      {
      BigInt z(x.sign(), std::max(x.sig_words(), y.sig_words()) + 1);
      bigint_add3(z.get_reg(), x.data(), x.sig_words(),
                               y.data(), y.sig_words());
      return z;
      }
   else if(x.is_positive())
      return (x - y.abs());
   else
      return (y - x.abs());
   }

/*************************************************
* Subtraction Operator                           *
*************************************************/
BigInt operator-(const BigInt& x, const BigInt& y)
   {
   s32bit relative_size = bigint_cmp(x.data(), x.sig_words(),
                                     y.data(), y.sig_words());
   if(relative_size == 0 && (x.sign() == y.sign())) return 0;
   if(relative_size == 0 && (x.sign() != y.sign())) return (x << 1);

   BigInt z(BigInt::Positive, std::max(x.sig_words(), y.sig_words()) + 1);

   if(relative_size == -1)
      {
      if(x.sign() == y.sign())
         bigint_sub3(z.get_reg(), y.data(), y.sig_words(),
                                  x.data(), x.sig_words());
      else
         bigint_add3(z.get_reg(), x.data(), x.sig_words(),
                                  y.data(), y.sig_words());
      z.set_sign(y.reverse_sign());
      }
   if(relative_size == 1)
      {
      if(x.sign() == y.sign())
         bigint_sub3(z.get_reg(), x.data(), x.sig_words(),
                                  y.data(), y.sig_words());
      else
         bigint_add3(z.get_reg(), x.data(), x.sig_words(),
                                  y.data(), y.sig_words());
      z.set_sign(x.sign());
      }
   return z;
   }

/*************************************************
* Multiplication Operator                        *
*************************************************/
BigInt operator*(const BigInt& x, const BigInt& y)
   {
   if(x.is_zero() || y.is_zero())
      return 0;

   BigInt::Sign sign = BigInt::Positive;
   if(x.sign() != y.sign())
      sign = BigInt::Negative;

   const u32bit x_sw = x.sig_words();
   const u32bit y_sw = y.sig_words();

   if(x_sw == 1 || y_sw == 1)
      {
      BigInt z(sign, x_sw + y_sw);
      if(x_sw == 1)
         bigint_linmul3(z.get_reg(), y.data(), y_sw, x.word_at(0));
      else
         bigint_linmul3(z.get_reg(), x.data(), x_sw, y.word_at(0));
      return z;
      }

   BigInt z(sign, x.size() + y.size());
   bigint_mul3(z.get_reg(), z.size(),
               x.data(), x.size(), x_sw,
               y.data(), y.size(), y_sw);
   return z;
   }

/*************************************************
* Division Operator                              *
*************************************************/
BigInt operator/(const BigInt& x, const BigInt& y)
   {
   BigInt q, r;
   divide(x, y, q, r);
   return q;
   }

/*************************************************
* Modulo Operator                                *
*************************************************/
BigInt operator%(const BigInt& n, const BigInt& mod)
   {
   if(mod.is_zero())
      throw BigInt::DivideByZero();
   if(mod.is_negative())
      throw Invalid_Argument("BigInt::operator%: modulus must be > 0");
   if(n.is_positive() && mod.is_positive() && n < mod)
      return n;

   BigInt q, r;
   divide(n, mod, q, r);
   return r;
   }

/*************************************************
* Modulo Operator                                *
*************************************************/
word operator%(const BigInt& n, word mod)
   {
   if(mod == 0)
      throw BigInt::DivideByZero();

   if(power_of_2(mod))
      return (n.word_at(0) & (mod - 1));

   word remainder = 0;
   u32bit size = n.sig_words();

   for(u32bit j = size; j > 0; j--)
      remainder = bigint_modop(remainder, n.word_at(j-1), mod);
   return remainder;
   }

/*************************************************
* Left Shift Operator                            *
*************************************************/
BigInt operator<<(const BigInt& x, u32bit shift)
   {
   if(shift == 0) return x;
   const u32bit shift_words = shift / MP_WORD_BITS,
                shift_bits  = shift % MP_WORD_BITS;

   BigInt y(x.sign(), x.sig_words() + shift_words + (shift_bits ? 1 : 0));
   bigint_shl2(y.get_reg(), x.data(), x.sig_words(), shift_words, shift_bits);
   return y;
   }

/*************************************************
* Right Shift Operator                           *
*************************************************/
BigInt operator>>(const BigInt& x, u32bit shift)
   {
   if(shift == 0)        return x;
   if(x.bits() <= shift) return 0;

   const u32bit shift_words = shift / MP_WORD_BITS,
                shift_bits  = shift % MP_WORD_BITS;
   BigInt y(x.sign(), x.sig_words() - shift_words);
   bigint_shr2(y.get_reg(), x.data(), x.sig_words(), shift_words, shift_bits);
   return y;
   }

}
