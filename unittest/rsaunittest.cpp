/**
 * rsaunittest.cpp
 *
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
#include "rsaunittest.h"
#include <QtCrypto>
#include <QList>

RSAUnitTest::RSAUnitTest()
    : Tester()
{

}

void RSAUnitTest::allTests()
{
    QCA::Initializer init;

    if(!QCA::isSupported("pkey") ||
       !QCA::PKey::supportedTypes().contains(QCA::PKey::RSA) ||
       !QCA::PKey::supportedIOTypes().contains(QCA::PKey::RSA))
        printf("RSA not supported!\n");
    else {
	QCA::KeyGenerator keygen;
	CHECK( keygen.isBusy(), false );
	CHECK( keygen.blocking(), true );

	QCA::PrivateKey rsaKey = keygen.createRSA(512);
	CHECK( rsaKey.isNull(), false );
	CHECK( rsaKey.isRSA(), true );
	CHECK( rsaKey.isDSA(), false );
	CHECK( rsaKey.isDH(), false );
	CHECK( rsaKey.isPrivate(), true );
	CHECK( rsaKey.isPublic(), false );
	CHECK( rsaKey.canSign(), true);
	CHECK( rsaKey.canDecrypt(), true);
	QCA::RSAPrivateKey rsaPrivKey = rsaKey.toRSA();
	CHECK( rsaPrivKey.bitSize(), 1024 );
#if 0
	QSecureArray rsaDER = rsaKey.toDER();
	QCA::ConvertResult checkResult;
	QCA::PrivateKey fromDERkey = QCA::PrivateKey::fromDER(rsaDER, QSecureArray(), &checkResult);
	CHECK( rsaKey == fromDERkey, true );
	CHECK( checkResult, QCA::ConvertGood );
#endif
    }
}

