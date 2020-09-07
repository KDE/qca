/*
 * Copyright (C) 2011 Collabora Ltd.
 * Copyright (C) 2018 Alexander Volkov <a.volkov@rusbitech.ru>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301 USA
 *
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#include <gcrypt.h>

static gcry_error_t gcry_hkdf(int         algo,
                              const char *input,
                              size_t      n_input,
                              const char *salt,
                              size_t      n_salt,
                              const char *info,
                              size_t      n_info,
                              char *      output,
                              size_t      n_output)
{
    void *       alloc  = nullptr;
    void *       buffer = nullptr;
    gcry_md_hd_t md1, md2;
    unsigned int hash_len;
    int          i;
    size_t       step, n_buffer;
    char *       at;
    gcry_error_t gcry;

    hash_len = gcry_md_get_algo_dlen(algo);
    if (hash_len == 0) {
        return GPG_ERR_UNSUPPORTED_ALGORITHM;
    }

    if (n_output > 255 * hash_len) {
        return GPG_ERR_TOO_LARGE;
    }

    /* Buffer we need to for intermediate stuff */
    buffer = gcry_malloc_secure(hash_len);
    if (!buffer) {
        return GPG_ERR_ENOMEM;
    }
    n_buffer = 0;

    /* Salt defaults to hash_len zeros */
    if (!salt) {
        alloc = gcry_calloc_secure(hash_len, 1);
        if (!alloc) {
            return GPG_ERR_ENOMEM;
        }
        salt   = (const char *)alloc;
        n_salt = hash_len;
    }

    /* Step 1: Extract */
    gcry = gcry_md_open(&md1, algo, GCRY_MD_FLAG_HMAC | GCRY_MD_FLAG_SECURE);
    if (gcry != GPG_ERR_NO_ERROR) {
        goto done;
    }
    gcry = gcry_md_setkey(md1, salt, n_salt);
    if (gcry != GPG_ERR_NO_ERROR) {
        gcry_md_close(md1);
        goto done;
    }
    gcry_md_write(md1, input, n_input);

    /* Step 2: Expand */
    gcry = gcry_md_open(&md2, algo, GCRY_MD_FLAG_HMAC | GCRY_MD_FLAG_SECURE);
    if (gcry != GPG_ERR_NO_ERROR) {
        gcry_md_close(md1);
        goto done;
    }
    gcry = gcry_md_setkey(md2, gcry_md_read(md1, algo), hash_len);
    if (gcry != GPG_ERR_NO_ERROR) {
        gcry_md_close(md2);
        gcry_md_close(md1);
        goto done;
    }
    gcry_md_close(md1);

    at = output;
    for (i = 1; i < 256; ++i) {
        gcry_md_reset(md2);
        gcry_md_write(md2, buffer, n_buffer);
        gcry_md_write(md2, info, n_info);
        gcry_md_putc(md2, i);

        n_buffer = hash_len;
        memcpy(buffer, gcry_md_read(md2, algo), n_buffer);

        step = n_buffer < n_output ? n_buffer : n_output;
        memcpy(at, buffer, step);
        n_output -= step;
        at += step;

        if (!n_output)
            break;
    }
    gcry_md_close(md2);

done:
    gcry_free(alloc);
    gcry_free(buffer);
    return gcry;
}
