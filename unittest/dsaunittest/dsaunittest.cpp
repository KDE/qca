/**
 * Copyright (C)  2005, 2006  Brad Hards <bradh@frogmouth.net>
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

class DSAUnitTest : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void initTestCase();
    void cleanupTestCase();
    void testdsa();

private:
    QCA::Initializer* m_init;

};

void DSAUnitTest::initTestCase()
{
    m_init = new QCA::Initializer;
}

void DSAUnitTest::cleanupTestCase()
{
    delete m_init;
}

void DSAUnitTest::testdsa()
{
	if(!QCA::isSupported("pkey") ||
	   !QCA::PKey::supportedTypes().contains(QCA::PKey::DSA) ||
	   !QCA::PKey::supportedIOTypes().contains(QCA::PKey::DSA))
	{
		QSKIP("DSA not supported!");
	}

	if (!QCA::DLGroup::supportedGroupSets().contains(QCA::DSA_1024))
	{
		QSKIP("DSA_1024 discrete logarithm group sets not supported!");
	}

	QCA::KeyGenerator keygen;
	QCOMPARE( keygen.isBusy(), false );
	QCOMPARE( keygen.blockingEnabled(), true );
	QCA::DLGroup group = keygen.createDLGroup(QCA::DSA_1024);
	QCOMPARE( group.isNull(), false );

	QCA::PrivateKey dsaKey = keygen.createDSA( group );
	QCOMPARE( dsaKey.isNull(), false );
	QCOMPARE( dsaKey.isRSA(), false );
	QCOMPARE( dsaKey.isDSA(), true );
	QCOMPARE( dsaKey.isDH(), false );
	QCOMPARE( dsaKey.isPrivate(), true );
	QCOMPARE( dsaKey.isPublic(), false );
	QCOMPARE( dsaKey.canSign(), true );
	QCOMPARE( dsaKey.canDecrypt(), false );

	QCOMPARE( dsaKey.bitSize(), 1024 );
	QCA::DSAPrivateKey dsaPrivKey = dsaKey.toDSA();
	QCOMPARE( dsaPrivKey.bitSize(), 1024 );

	QCA::SecureArray dsaDER = dsaKey.toDER();
	QCOMPARE( dsaDER.isEmpty(), false );

	QString dsaPEM = dsaKey.toPEM();
	QCOMPARE( dsaPEM.isEmpty(), false );

	QCA::ConvertResult checkResult;
	QCA::PrivateKey fromPEMkey = QCA::PrivateKey::fromPEM(dsaPEM, QCA::SecureArray(), &checkResult);
	QCOMPARE( checkResult, QCA::ConvertGood );
	QCOMPARE( fromPEMkey.isNull(), false );
	QCOMPARE( fromPEMkey.isRSA(), false );
	QCOMPARE( fromPEMkey.isDSA(), true );
	QCOMPARE( fromPEMkey.isDH(), false );
	QCOMPARE( fromPEMkey.isPrivate(), true );
	QCOMPARE( fromPEMkey.isPublic(), false );
	QVERIFY( dsaKey == fromPEMkey );

	QCA::PrivateKey fromDERkey = QCA::PrivateKey::fromDER(dsaDER, QCA::SecureArray(), &checkResult);
	QCOMPARE( checkResult, QCA::ConvertGood );
	QCOMPARE( fromDERkey.isNull(), false );
	QCOMPARE( fromDERkey.isRSA(), false );
	QCOMPARE( fromDERkey.isDSA(), true );
	QCOMPARE( fromDERkey.isDH(), false );
	QCOMPARE( fromDERkey.isPrivate(), true );
	QCOMPARE( fromDERkey.isPublic(), false );
	QVERIFY( dsaKey == fromDERkey );
}

QTEST_MAIN(DSAUnitTest)

#include "dsaunittest.moc"

