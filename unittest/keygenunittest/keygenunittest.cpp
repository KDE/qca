/**
 * Copyright (C)  2004-2006  Brad Hards <bradh@frogmouth.net>
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

#include <QtCrypto>
#include <QtTest/QtTest>

#ifdef QT_STATICPLUGIN
#include "import_plugins.h"
#endif

class KeyGenUnitTest : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void cleanupTestCase();
    void testRSA();
    void testDSA();
    void testDH();
private:
    QCA::Initializer* m_init;
};

void KeyGenUnitTest::initTestCase()
{
    m_init = new QCA::Initializer;
}

void KeyGenUnitTest::cleanupTestCase()
{
    delete m_init;
}


void KeyGenUnitTest::testRSA()
{
    QCA::KeyGenerator keygen;
    QCOMPARE( keygen.isBusy(), false );
    QCOMPARE( keygen.blockingEnabled(), true );

    if(!QCA::isSupported("pkey") ||
       !QCA::PKey::supportedTypes().contains(QCA::PKey::RSA) ||
       !QCA::PKey::supportedIOTypes().contains(QCA::PKey::RSA))
#if QT_VERSION >= 0x050000
        QSKIP("RSA not supported!");
#else
        QSKIP("RSA not supported!", SkipAll);
#endif

    QCA::PrivateKey priv1 = keygen.createRSA( 1024, 65537 );
    QCA::RSAPrivateKey rsa1 = priv1.toRSA();
    QCOMPARE( rsa1.isNull(), false );
    QCOMPARE( rsa1.e(), QCA::BigInteger(65537) );
    QCOMPARE( rsa1.bitSize(), 1024);

    priv1 = keygen.createRSA( 512, 17 );
    rsa1 = priv1.toRSA();
    QCOMPARE( rsa1.isNull(), false );
    QCOMPARE( rsa1.e(), QCA::BigInteger(17) );
    QCOMPARE( rsa1.bitSize(), 512);

    priv1 = keygen.createRSA( 512, 3 );
    rsa1 = priv1.toRSA();
    QCOMPARE( rsa1.isNull(), false );
    QCOMPARE( rsa1.e(), QCA::BigInteger(3) );
    QCOMPARE( rsa1.bitSize(), 512);
}

void KeyGenUnitTest::testDSA()
{
    QCA::KeyGenerator keygen;
    QCOMPARE( keygen.isBusy(), false );
    QCOMPARE( keygen.blockingEnabled(), true );

    if(!QCA::isSupported("pkey") ||
       !QCA::PKey::supportedTypes().contains(QCA::PKey::DSA) ||
       !QCA::PKey::supportedIOTypes().contains(QCA::PKey::DSA))
#if QT_VERSION >= 0x050000
	QSKIP("DSA not supported!");
#else
	QSKIP("DSA not supported!", SkipAll);
#endif

	QCA::DLGroup group;
	QCA::PrivateKey priv2;
	QCA::DSAPrivateKey dsa1;

	if (QCA::DLGroup::supportedGroupSets().contains(QCA::DSA_512))
	{
		group = keygen.createDLGroup( QCA::DSA_512 );
		priv2 = keygen.createDSA( group );
		dsa1 = priv2.toDSA();
		QCOMPARE( dsa1.isNull(), false );
		QCOMPARE( dsa1.bitSize(), 512 );
	}

	if (QCA::DLGroup::supportedGroupSets().contains(QCA::DSA_768))
	{
		group = keygen.createDLGroup( QCA::DSA_768 );
		priv2 = keygen.createDSA( group );
		dsa1 = priv2.toDSA();
		QCOMPARE( dsa1.isNull(), false );
		QCOMPARE( dsa1.bitSize(), 768 );
	}

	if (QCA::DLGroup::supportedGroupSets().contains(QCA::DSA_1024))
	{
		group = keygen.createDLGroup( QCA::DSA_1024 );
		priv2 = keygen.createDSA( group );
		dsa1 = priv2.toDSA();
		QCOMPARE( dsa1.isNull(), false );
		QCOMPARE( dsa1.bitSize(), 1024 );
	}
}

void KeyGenUnitTest::testDH()
{
    QCA::KeyGenerator keygen;
    QCOMPARE( keygen.isBusy(), false );
    QCOMPARE( keygen.blockingEnabled(), true );

    if(!QCA::isSupported("pkey") ||
       !QCA::PKey::supportedTypes().contains(QCA::PKey::DH) ||
       !QCA::PKey::supportedIOTypes().contains(QCA::PKey::DH))
#if QT_VERSION >= 0x050000
	QSKIP("DH not supported!");
#else
	QSKIP("DH not supported!", SkipAll);
#endif

    QCA::DLGroup group = keygen.createDLGroup( QCA::IETF_1024 );
    QCA::PrivateKey priv3 = keygen.createDH( group );
    QCA::DHPrivateKey dh1 = priv3.toDH();
    QCOMPARE( dh1.isNull(), false );
    QCOMPARE( dh1.bitSize(), 1024 );

    group = keygen.createDLGroup( QCA::IETF_2048 );
    priv3 = keygen.createDH( group );
    dh1 = priv3.toDH();
    QCOMPARE( dh1.isNull(), false );
    QCOMPARE( dh1.bitSize(), 2048 );
}

QTEST_MAIN(KeyGenUnitTest)

#include "keygenunittest.moc"

