/**
 * Copyright (C)  2005  Brad Hards <bradh@frogmouth.net>
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
#include "keygenunittest.h"
#include <QtCrypto>
#include <QList>

KeyGenUnitTest::KeyGenUnitTest()
    : Tester()
{

}

void KeyGenUnitTest::allTests()
{
    QCA::Initializer init;

    QCA::KeyGenerator keygen;
    CHECK( keygen.isBusy(), false );
    CHECK( keygen.blocking(), true );

    QCA::PrivateKey priv1 = keygen.createRSA( 1024, 65537 );
    QCA::RSAPrivateKey rsa1 = priv1.toRSA();
    CHECK( rsa1.isNull(), false );
    CHECK( rsa1.e(), QBigInteger(65537) );

    priv1 = keygen.createRSA( 512, 17 );
    rsa1 = priv1.toRSA();
    CHECK( rsa1.isNull(), false );
    CHECK( rsa1.e(), QBigInteger(17) );

    priv1 = keygen.createRSA( 512, 3 );
    rsa1 = priv1.toRSA();
    CHECK( rsa1.isNull(), false );
    CHECK( rsa1.e(), QBigInteger(3) );

}

