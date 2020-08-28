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

#pragma once

#include "qca_tools.h"

#include <openssl/evp.h>

using namespace QCA;

namespace opensslQCAPlugin {

// note: this class squelches processing errors, since QCA doesn't care about them
class EVPKey
{
public:
    enum State
    {
        Idle,
        SignActive,
        SignError,
        VerifyActive,
        VerifyError
    };
    EVP_PKEY *  pkey;
    EVP_MD_CTX *mdctx;
    State       state;
    bool        raw_type;
    SecureArray raw;

    EVPKey();
    EVPKey(const EVPKey &from);
    EVPKey &operator=(const EVPKey &from) = delete;
    ~EVPKey();

    void        reset();
    void        startSign(const EVP_MD *type);
    void        startVerify(const EVP_MD *type);
    void        update(const MemoryRegion &in);
    SecureArray endSign();
    bool        endVerify(const SecureArray &sig);
};

}
