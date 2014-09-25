/**
 * Copyright (C)  2005-2006  Brad Hards <bradh@frogmouth.net>
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

class RSAUnitTest : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void initTestCase();
    void cleanupTestCase();
    void testrsa();
    void testAsymmetricEncryption();

private:
    QCA::Initializer* m_init;
};

void RSAUnitTest::initTestCase()
{
    m_init = new QCA::Initializer;
}

void RSAUnitTest::cleanupTestCase()
{
    delete m_init;
}

void RSAUnitTest::testrsa()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");
    // providersToTest.append("qca-gcrypt");

    foreach(const QString provider, providersToTest) {
	if(!QCA::isSupported("pkey", provider) ||
	   !QCA::PKey::supportedTypes(provider).contains(QCA::PKey::RSA) ||
	   !QCA::PKey::supportedIOTypes(provider).contains(QCA::PKey::RSA))
	    QWARN(QString("RSA not supported for "+provider).toLocal8Bit());
	else {
	    QCA::KeyGenerator keygen;
	    QCOMPARE( keygen.isBusy(), false );
	    QCOMPARE( keygen.blockingEnabled(), true );

	    QList<int> keySizes;
	    keySizes << 512 << 1024 << 768 << 2048;
	    foreach( int keysize, keySizes ) {
		QCA::PrivateKey rsaKey = keygen.createRSA(keysize, 65537, provider);
		QCOMPARE( rsaKey.isNull(), false );
		QCOMPARE( rsaKey.isRSA(), true );
		QCOMPARE( rsaKey.isDSA(), false );
		QCOMPARE( rsaKey.isDH(), false );
		QCOMPARE( rsaKey.isPrivate(), true );
		QCOMPARE( rsaKey.isPublic(), false );
		QCOMPARE( rsaKey.canSign(), true);
		QCOMPARE( rsaKey.canDecrypt(), true);
		QCOMPARE( rsaKey.canEncrypt(), true);

		QCA::RSAPrivateKey rsaPrivKey = rsaKey.toRSA();
		QCOMPARE( rsaPrivKey.bitSize(), keysize );

		QString rsaPEM = rsaKey.toPEM();
		QCOMPARE( rsaPEM.isEmpty(), false );

		QCA::ConvertResult checkResult;
		QCA::PrivateKey fromPEMkey = QCA::PrivateKey::fromPEM(rsaPEM, QCA::SecureArray(), &checkResult);
		QCOMPARE( checkResult, QCA::ConvertGood );
		QCOMPARE( fromPEMkey.isNull(), false );
		QCOMPARE( fromPEMkey.isRSA(), true );
		QCOMPARE( fromPEMkey.isDSA(), false );
		QCOMPARE( fromPEMkey.isDH(), false );
		QCOMPARE( fromPEMkey.isPrivate(), true );
		QCOMPARE( fromPEMkey.isPublic(), false );
		QCOMPARE( rsaKey == fromPEMkey, true );

		QCA::SecureArray rsaDER = rsaKey.toDER(QCA::SecureArray("foo"));
		QCOMPARE( rsaDER.isEmpty(), false );

		QCA::PrivateKey fromDERkey = QCA::PrivateKey::fromDER(rsaDER, QCA::SecureArray("foo"), &checkResult);
		QCOMPARE( checkResult, QCA::ConvertGood );
		QCOMPARE( fromDERkey.isNull(), false );
		QCOMPARE( fromDERkey.isRSA(), true );
		QCOMPARE( fromDERkey.isDSA(), false );
		QCOMPARE( fromDERkey.isDH(), false );
		QCOMPARE( fromDERkey.isPrivate(), true );
		QCOMPARE( fromDERkey.isPublic(), false );
		QCOMPARE( rsaKey == fromDERkey, true );

		// same test, without passphrase
		rsaDER = rsaKey.toDER();
		QCOMPARE( rsaDER.isEmpty(), false );

		fromDERkey = QCA::PrivateKey::fromDER(rsaDER, QCA::SecureArray(), &checkResult);
		QCOMPARE( checkResult, QCA::ConvertGood );
		QCOMPARE( fromDERkey.isNull(), false );
		QCOMPARE( fromDERkey.isRSA(), true );
		QCOMPARE( fromDERkey.isDSA(), false );
		QCOMPARE( fromDERkey.isDH(), false );
		QCOMPARE( fromDERkey.isPrivate(), true );
		QCOMPARE( fromDERkey.isPublic(), false );
		QCOMPARE( rsaKey == fromDERkey, true );

		QCA::PublicKey pubKey = rsaKey.toPublicKey();
		QCOMPARE( pubKey.isNull(), false );
		QCOMPARE( pubKey.isRSA(), true );
		QCOMPARE( pubKey.isDSA(), false );
		QCOMPARE( pubKey.isDH(), false );
		QCOMPARE( pubKey.isPrivate(), false );
		QCOMPARE( pubKey.isPublic(), true );

		QCA::RSAPublicKey RSApubKey = pubKey.toRSA();
		QCOMPARE( RSApubKey.e(), QCA::BigInteger(65537) );
		QCOMPARE( RSApubKey.isNull(), false );
		QCOMPARE( RSApubKey.isRSA(), true );
		QCOMPARE( RSApubKey.isDSA(), false );
		QCOMPARE( RSApubKey.isDH(), false );
		QCOMPARE( RSApubKey.isPrivate(), false );
		QCOMPARE( RSApubKey.isPublic(), true );
	    }
	}
    }
}

void RSAUnitTest::testAsymmetricEncryption()
{
	if(!QCA::isSupported("pkey", "qca-ossl") ||
	   !QCA::PKey::supportedTypes("qca-ossl").contains(QCA::PKey::RSA) ||
	   !QCA::PKey::supportedIOTypes("qca-ossl").contains(QCA::PKey::RSA)) {
	    QWARN(QString("RSA not supported").toLocal8Bit());
#if QT_VERSION >= 0x050000
	    QSKIP("RSA not supported. skipping");
#else
	    QSKIP("RSA not supported. skipping",SkipAll);
#endif
	}
	QCA::RSAPrivateKey rsaPrivKey1 = QCA::KeyGenerator().createRSA(512, 65537, "qca-ossl").toRSA();
	QCA::RSAPublicKey rsaPubKey1 = rsaPrivKey1.toPublicKey().toRSA();

	QCA::RSAPrivateKey rsaPrivKey2 = QCA::KeyGenerator().createRSA(512, 65537, "qca-ossl").toRSA();
	// QCA::RSAPublicKey rsaPubKey2 = rsaPrivKey2.toPublicKey().toRSA();

	const QCA::SecureArray clearText = "Hello World !";
	QCA::SecureArray testText;
	QCA::SecureArray cipherText;

	// Test keys #1: Enc with public, dec with private
	QVERIFY( rsaPubKey1.maximumEncryptSize(QCA::EME_PKCS1v15) >=  clearText.size() );
	cipherText = rsaPubKey1.encrypt(clearText, QCA::EME_PKCS1v15);
	QVERIFY( rsaPrivKey1.decrypt(cipherText, &testText, QCA::EME_PKCS1v15) );
	QCOMPARE( clearText, testText );
	testText.clear();
	// ---

	// Test keys #2 to decipher key #1
	QVERIFY( !rsaPrivKey2.decrypt(cipherText, &testText, QCA::EME_PKCS1v15) );
	QVERIFY( testText.isEmpty() );
	// ---

	// Test keys #2: Enc with private, dec with public
	cipherText.clear();
	QVERIFY( rsaPrivKey1.maximumEncryptSize(QCA::EME_PKCS1v15) >=  clearText.size() );
	cipherText = rsaPrivKey1.encrypt(clearText, QCA::EME_PKCS1v15);
	QVERIFY( rsaPubKey1.decrypt(cipherText, &testText, QCA::EME_PKCS1v15) );
	QCOMPARE( clearText, testText );
	testText.clear();
	// ---
}

QTEST_MAIN(RSAUnitTest)

#include "rsaunittest.moc"
