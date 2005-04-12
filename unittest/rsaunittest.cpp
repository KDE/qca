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
        SKIP("RSA not supported!");
    else {
	QCA::KeyGenerator keygen;
	CHECK( keygen.isBusy(), false );
	CHECK( keygen.blocking(), true );

	QList<int> keySizes;
	keySizes << 512 << 1024 << 768 << 2048;
	foreach( int keysize, keySizes ) {
	    QCA::PrivateKey rsaKey = keygen.createRSA(keysize);
	    CHECK( rsaKey.isNull(), false );
	    CHECK( rsaKey.isRSA(), true );
	    CHECK( rsaKey.isDSA(), false );
	    CHECK( rsaKey.isDH(), false );
	    CHECK( rsaKey.isPrivate(), true );
	    CHECK( rsaKey.isPublic(), false );
	    CHECK( rsaKey.canSign(), true);
	    CHECK( rsaKey.canDecrypt(), true);
	    
	    QCA::RSAPrivateKey rsaPrivKey = rsaKey.toRSA();
	    CHECK( rsaPrivKey.bitSize(), keysize );
	    
	    QString rsaPEM = rsaKey.toPEM();
	    CHECK( rsaPEM.isEmpty(), false );
	    
	    QCA::ConvertResult checkResult;
	    QCA::PrivateKey fromPEMkey = QCA::PrivateKey::fromPEM(rsaPEM, QSecureArray(), &checkResult);
	    CHECK( checkResult, QCA::ConvertGood );
	    CHECK( fromPEMkey.isNull(), false );
	    CHECK( fromPEMkey.isRSA(), true );
	    CHECK( fromPEMkey.isDSA(), false );
	    CHECK( fromPEMkey.isDH(), false );
	    CHECK( fromPEMkey.isPrivate(), true );
	    CHECK( fromPEMkey.isPublic(), false );
	    CHECK( rsaKey == fromPEMkey, true );
	
	    QSecureArray rsaDER = rsaKey.toDER(QSecureArray("foo"));
	    CHECK( rsaDER.isEmpty(), false );
	    
	    QCA::PrivateKey fromDERkey = QCA::PrivateKey::fromDER(rsaDER, QSecureArray("foo"), &checkResult);
	    CHECK( checkResult, QCA::ConvertGood );
	    CHECK( fromDERkey.isNull(), false );
	    CHECK( fromDERkey.isRSA(), true );
	    CHECK( fromDERkey.isDSA(), false );
	    CHECK( fromDERkey.isDH(), false );
	    CHECK( fromDERkey.isPrivate(), true );
	    CHECK( fromDERkey.isPublic(), false );
	    CHECK( rsaKey == fromDERkey, true );

	    // same test, without passphrase
	    rsaDER = rsaKey.toDER();
	    CHECK( rsaDER.isEmpty(), false );
	    
	    fromDERkey = QCA::PrivateKey::fromDER(rsaDER, QSecureArray(), &checkResult);
	    CHECK( checkResult, QCA::ConvertGood );
	    CHECK( fromDERkey.isNull(), false );
	    CHECK( fromDERkey.isRSA(), true );
	    CHECK( fromDERkey.isDSA(), false );
	    CHECK( fromDERkey.isDH(), false );
	    CHECK( fromDERkey.isPrivate(), true );
	    CHECK( fromDERkey.isPublic(), false );
	    CHECK( rsaKey == fromDERkey, true );

	    QCA::PublicKey pubKey = rsaKey.toPublicKey();
	    CHECK( pubKey.isNull(), false );
	    CHECK( pubKey.isRSA(), true );
	    CHECK( pubKey.isDSA(), false );
	    CHECK( pubKey.isDH(), false );
	    CHECK( pubKey.isPrivate(), false );
	    CHECK( pubKey.isPublic(), true );

	    QCA::RSAPublicKey RSApubKey = pubKey.toRSA();
	    CHECK( RSApubKey.e(), QBigInteger(65537) );
	    CHECK( RSApubKey.isNull(), false );
	    CHECK( RSApubKey.isRSA(), true );
	    CHECK( RSApubKey.isDSA(), false );
	    CHECK( RSApubKey.isDH(), false );
	    CHECK( RSApubKey.isPrivate(), false );
	    CHECK( RSApubKey.isPublic(), true );
	}
    }
}

