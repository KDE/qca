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
#include "dsaunittest.h"
#include <QtCrypto>
#include <QList>

DSAUnitTest::DSAUnitTest()
    : Tester()
{

}

void DSAUnitTest::allTests()
{
    QCA::Initializer init;

    if(!QCA::isSupported("pkey") ||
       !QCA::PKey::supportedTypes().contains(QCA::PKey::DSA) ||
       !QCA::PKey::supportedIOTypes().contains(QCA::PKey::DSA))
        SKIP("DSA not supported");
    else {
	QCA::KeyGenerator keygen;
	CHECK( keygen.isBusy(), false );
	CHECK( keygen.blocking(), true );
	QCA::DLGroup group = keygen.createDLGroup(QCA::DSA_512);
	CHECK( group.isNull(), false );

	QCA::PrivateKey dsaKey = keygen.createDSA( group );
	CHECK( dsaKey.isNull(), false );
	CHECK( dsaKey.isRSA(), false );
	CHECK( dsaKey.isDSA(), true );
	CHECK( dsaKey.isDH(), false );
	CHECK( dsaKey.isPrivate(), true );
	CHECK( dsaKey.isPublic(), false );
	CHECK( dsaKey.canSign(), true );
	CHECK( dsaKey.canDecrypt(), false );

	QCA::DSAPrivateKey dsaPrivKey = dsaKey.toDSA();
	XFAIL( dsaPrivKey.bitSize(), 512 );

	QSecureArray dsaDER = dsaKey.toDER();
	CHECK( dsaDER.isEmpty(), false );

	QString dsaPEM = dsaKey.toPEM();
	CHECK( dsaPEM.isEmpty(), false );

	QCA::ConvertResult checkResult;
	QCA::PrivateKey fromPEMkey = QCA::PrivateKey::fromPEM(dsaPEM, QSecureArray(), &checkResult);
	CHECK( checkResult, QCA::ConvertGood );
	CHECK( fromPEMkey.isNull(), false );
	CHECK( fromPEMkey.isRSA(), false );
	CHECK( fromPEMkey.isDSA(), true );
	CHECK( fromPEMkey.isDH(), false );
	CHECK( fromPEMkey.isPrivate(), true );
	CHECK( fromPEMkey.isPublic(), false );
	CHECK( dsaKey == fromPEMkey, true );
	
	QCA::PrivateKey fromDERkey = QCA::PrivateKey::fromDER(dsaDER, QSecureArray(), &checkResult);
	CHECK( checkResult, QCA::ConvertGood );
	CHECK( fromDERkey.isNull(), false );
	CHECK( fromDERkey.isRSA(), false );
	CHECK( fromDERkey.isDSA(), true );
	CHECK( fromDERkey.isDH(), false );
	CHECK( fromDERkey.isPrivate(), true );
	CHECK( fromDERkey.isPublic(), false );
#if 0
	CHECK( dsaKey == fromDERkey, true );
#endif
    }
}

