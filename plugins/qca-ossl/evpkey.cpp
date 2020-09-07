/*
 * Copyright (C) 2004-2007  Justin Karneges <justin@affinix.com>
 * Copyright (C) 2004-2006  Brad Hards <bradh@frogmouth.net>
 * Copyright (C) 2013-2016  Ivan Romanov <drizt@land.ru>
 * Copyright (C) 2017       Fabian Vogt <fabian@ritter-vogt.de>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 *
 */

#include "evpkey.h"

#include <openssl/rsa.h>

namespace opensslQCAPlugin {

EVPKey::EVPKey()
{
    pkey     = nullptr;
    raw_type = false;
    state    = Idle;
    mdctx    = EVP_MD_CTX_new();
}

EVPKey::EVPKey(const EVPKey &from)
{
    pkey = from.pkey;
    EVP_PKEY_up_ref(pkey);
    raw_type = false;
    state    = Idle;
    mdctx    = EVP_MD_CTX_new();
    EVP_MD_CTX_copy(mdctx, from.mdctx);
}

EVPKey::~EVPKey()
{
    reset();
    EVP_MD_CTX_free(mdctx);
}

void EVPKey::reset()
{
    if (pkey)
        EVP_PKEY_free(pkey);
    pkey = nullptr;
    raw.clear();
    raw_type = false;
}

void EVPKey::startSign(const EVP_MD *type)
{
    state = SignActive;
    if (!type) {
        raw_type = true;
        raw.clear();
    } else {
        raw_type = false;
        EVP_MD_CTX_init(mdctx);
        if (!EVP_SignInit_ex(mdctx, type, nullptr))
            state = SignError;
    }
}

void EVPKey::startVerify(const EVP_MD *type)
{
    state = VerifyActive;
    if (!type) {
        raw_type = true;
        raw.clear();
    } else {
        raw_type = false;
        EVP_MD_CTX_init(mdctx);
        if (!EVP_VerifyInit_ex(mdctx, type, nullptr))
            state = VerifyError;
    }
}

void EVPKey::update(const MemoryRegion &in)
{
    if (state == SignActive) {
        if (raw_type)
            raw += in;
        else if (!EVP_SignUpdate(mdctx, in.data(), (unsigned int)in.size()))
            state = SignError;
    } else if (state == VerifyActive) {
        if (raw_type)
            raw += in;
        else if (!EVP_VerifyUpdate(mdctx, in.data(), (unsigned int)in.size()))
            state = VerifyError;
    }
}

SecureArray EVPKey::endSign()
{
    if (state == SignActive) {
        SecureArray  out(EVP_PKEY_size(pkey));
        unsigned int len = out.size();
        if (raw_type) {
            int type = EVP_PKEY_id(pkey);

            if (type == EVP_PKEY_RSA) {
                RSA *rsa = EVP_PKEY_get0_RSA(pkey);
                if (RSA_private_encrypt(
                        raw.size(), (unsigned char *)raw.data(), (unsigned char *)out.data(), rsa, RSA_PKCS1_PADDING) ==
                    -1) {
                    state = SignError;
                    return SecureArray();
                }
            } else if (type == EVP_PKEY_DSA) {
                state = SignError;
                return SecureArray();
            } else {
                state = SignError;
                return SecureArray();
            }
        } else {
            if (!EVP_SignFinal(mdctx, (unsigned char *)out.data(), &len, pkey)) {
                state = SignError;
                return SecureArray();
            }
        }
        out.resize(len);
        state = Idle;
        return out;
    } else
        return SecureArray();
}

bool EVPKey::endVerify(const SecureArray &sig)
{
    if (state == VerifyActive) {
        if (raw_type) {
            SecureArray out(EVP_PKEY_size(pkey));
            int         len = 0;

            int type = EVP_PKEY_id(pkey);

            if (type == EVP_PKEY_RSA) {
                RSA *rsa = EVP_PKEY_get0_RSA(pkey);
                if ((len = RSA_public_decrypt(sig.size(),
                                              (unsigned char *)sig.data(),
                                              (unsigned char *)out.data(),
                                              rsa,
                                              RSA_PKCS1_PADDING)) == -1) {
                    state = VerifyError;
                    return false;
                }
            } else if (type == EVP_PKEY_DSA) {
                state = VerifyError;
                return false;
            } else {
                state = VerifyError;
                return false;
            }

            out.resize(len);

            if (out != raw) {
                state = VerifyError;
                return false;
            }
        } else {
            if (EVP_VerifyFinal(mdctx, (unsigned char *)sig.data(), (unsigned int)sig.size(), pkey) != 1) {
                state = VerifyError;
                return false;
            }
        }
        state = Idle;
        return true;
    } else
        return false;
}

}
