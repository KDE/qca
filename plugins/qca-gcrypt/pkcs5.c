/* pkcs5.c     Partial Password-Based Cryptography (PKCS#5) implementation
 * Copyright (C) 2002 Free Software Foundation, Inc.
 *
 * This file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This file is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this file; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 *
 */

#include "gcrypt.h"

/*
 * 5.2 PBKDF2
 *
 *  PBKDF2 applies a pseudorandom function (see Appendix B.1 for an
 *  example) to derive keys. The length of the derived key is essentially
 *  unbounded. (However, the maximum effective search space for the
 *  derived key may be limited by the structure of the underlying
 *  pseudorandom function. See Appendix B.1 for further discussion.)
 *  PBKDF2 is recommended for new applications.
 *
 *  PBKDF2 (P, S, c, dkLen)
 *
 *  Options:        PRF        underlying pseudorandom function (hLen
 *                             denotes the length in octets of the
 *                             pseudorandom function output)
 *
 *  Input:          P          password, an octet string
 *                  S          salt, an octet string
 *                  c          iteration count, a positive integer
 *                  dkLen      intended length in octets of the derived
 *                             key, a positive integer, at most
 *                             (2^32 - 1) * hLen
 *
 *  Output:         DK         derived key, a dkLen-octet string
 */

static gcry_error_t gcry_pbkdf2(int          PRF,
                                const char * P,
                                size_t       Plen,
                                const char * S,
                                size_t       Slen,
                                unsigned int c,
                                unsigned int dkLen,
                                char *       DK)
{
    gcry_md_hd_t   prf;
    gcry_error_t   rc;
    char *         U;
    unsigned int   u;
    unsigned int   hLen;
    unsigned int   l;
    unsigned int   r;
    unsigned char *p;
    unsigned int   i;
    unsigned int   k;

    hLen = gcry_md_get_algo_dlen(PRF);
    if (hLen == 0)
        return GPG_ERR_UNSUPPORTED_ALGORITHM;

    if (c == 0)
        return GPG_ERR_INV_ARG;

    if (dkLen == 0)
        return GPG_ERR_TOO_SHORT;

    /*
     *
     *  Steps:
     *
     *     1. If dkLen > (2^32 - 1) * hLen, output "derived key too long" and
     *        stop.
     */

    if (dkLen > 4294967295U)
        return GPG_ERR_TOO_LARGE;

    /*
     *     2. Let l be the number of hLen-octet blocks in the derived key,
     *        rounding up, and let r be the number of octets in the last
     *        block:
     *
     *                  l = CEIL (dkLen / hLen) ,
     *                  r = dkLen - (l - 1) * hLen .
     *
     *        Here, CEIL (x) is the "ceiling" function, i.e. the smallest
     *        integer greater than, or equal to, x.
     */

    l = dkLen / hLen;
    if (dkLen % hLen)
        l++;
    r = dkLen - (l - 1) * hLen;

    /*
     *     3. For each block of the derived key apply the function F defined
     *        below to the password P, the salt S, the iteration count c, and
     *        the block index to compute the block:
     *
     *                  T_1 = F (P, S, c, 1) ,
     *                  T_2 = F (P, S, c, 2) ,
     *                  ...
     *                  T_l = F (P, S, c, l) ,
     *
     *        where the function F is defined as the exclusive-or sum of the
     *        first c iterates of the underlying pseudorandom function PRF
     *        applied to the password P and the concatenation of the salt S
     *        and the block index i:
     *
     *                  F (P, S, c, i) = U_1 \xor U_2 \xor ... \xor U_c
     *
     *        where
     *
     *                  U_1 = PRF (P, S || INT (i)) ,
     *                  U_2 = PRF (P, U_1) ,
     *                  ...
     *                  U_c = PRF (P, U_{c-1}) .
     *
     *        Here, INT (i) is a four-octet encoding of the integer i, most
     *        significant octet first.
     *
     *     4. Concatenate the blocks and extract the first dkLen octets to
     *        produce a derived key DK:
     *
     *                  DK = T_1 || T_2 ||  ...  || T_l<0..r-1>
     *
     *     5. Output the derived key DK.
     *
     *  Note. The construction of the function F follows a "belt-and-
     *  suspenders" approach. The iterates U_i are computed recursively to
     *  remove a degree of parallelism from an opponent; they are exclusive-
     *  ored together to reduce concerns about the recursion degenerating
     *  into a small set of values.
     *
     */
    rc = gcry_md_open(&prf, PRF, GCRY_MD_FLAG_HMAC | GCRY_MD_FLAG_SECURE);
    if (rc != GPG_ERR_NO_ERROR)
        return rc;

    U = (char *)gcry_malloc(hLen);
    if (!U) {
        rc = GPG_ERR_ENOMEM;
        goto done;
    }

    for (i = 1; i <= l; i++) {
        memset(DK + (i - 1) * hLen, 0, i == l ? r : hLen);

        for (u = 1; u <= c; u++) {
            gcry_md_reset(prf);

            rc = gcry_md_setkey(prf, P, Plen);
            if (rc != GPG_ERR_NO_ERROR) {
                goto done;
            }
            if (u == 1) {
                char tmp[4];
                gcry_md_write(prf, S, Slen);
                tmp[0] = (i & 0xff000000) >> 24;
                tmp[1] = (i & 0x00ff0000) >> 16;
                tmp[2] = (i & 0x0000ff00) >> 8;
                tmp[3] = (i & 0x000000ff) >> 0;
                gcry_md_write(prf, tmp, 4);
            } else
                gcry_md_write(prf, U, hLen);

            p = gcry_md_read(prf, PRF);
            if (p == nullptr) {
                rc = GPG_ERR_CONFIGURATION;
                goto done;
            }

            memcpy(U, p, hLen);
            for (k = 0; k < (i == l ? r : hLen); k++)
                DK[(i - 1) * hLen + k] ^= U[k];
        }
    }

    rc = GPG_ERR_NO_ERROR;
done:
    gcry_md_close(prf);
    gcry_free(U);
    return rc;
}
