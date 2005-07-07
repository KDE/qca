/**
 * Copyright (C)  2004  Brad Hards <bradh@frogmouth.net>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "keylengthunittest.h"
#include <QtCrypto>

#include <limits>

KeyLengthUnitTest::KeyLengthUnitTest()
    : Tester()
{

}

void KeyLengthUnitTest::allTests()
{
    QCA::Initializer init;

    QCA::KeyLength keylen1( 0, 0, 0 );
    CHECK( keylen1.minimum(), 0 );
    CHECK( keylen1.maximum(), 0 );
    CHECK( keylen1.multiple(), 0 );

    QCA::KeyLength keylen2( 3, 40, 1 );
    CHECK( keylen2.minimum(), 3 );
    CHECK( keylen2.maximum(), 40 );
    CHECK( keylen2.multiple(), 1 );

    QCA::KeyLength keylen3( 1, INT_MAX, 1 );
    CHECK( keylen3.minimum(), 1 );
    CHECK( keylen3.maximum(), INT_MAX );
    CHECK( keylen3.multiple(), 1 );

}

