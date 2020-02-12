/**
 * Copyright (C)  2006  Brad Hards <bradh@frogmouth.net>
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

class CMSut : public QObject
{

  Q_OBJECT

private Q_SLOTS:
    void initTestCase();
    void cleanupTestCase();
    void xcrypt_data();
    void xcrypt();
    void signverify_data();
    void signverify();
    void signverify_message_data();
    void signverify_message();
    void signverify_message_invalid_data();
    void signverify_message_invalid();
private:
    QCA::Initializer* m_init;

};


void CMSut::initTestCase()
{
    m_init = new QCA::Initializer;
}

void CMSut::cleanupTestCase()
{
    delete m_init;
}

void CMSut::xcrypt_data()
{
    QTest::addColumn<QByteArray>("testText");

    QTest::newRow("empty") << QByteArray("");
    QTest::newRow("0") << QByteArray("0");
    QTest::newRow("07") << QByteArray("07899847jkjjfasjaJKJLJkljklj&kjlj;/**-+.01");
    QTest::newRow("dubious") << QByteArray("~!#**$#&&%^@#^&()");
}

void CMSut::xcrypt()
{
    QStringList providersToTest;
    providersToTest.append(QStringLiteral("qca-ossl"));

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( (QStringLiteral( "Certificate not supported for ")+provider).toLocal8Bit().constData() );
        else if( !QCA::isSupported( "cms", provider ) )
	    QWARN( (QStringLiteral( "CMS not supported for ")+provider).toLocal8Bit().constData() );
	else {
	    QCA::Certificate pubCert = QCA::Certificate::fromPEMFile( QStringLiteral("QcaTestClientCert.pem"),nullptr, provider );
	    QCOMPARE( pubCert.isNull(), false );

	    QCA::SecureMessageKey secMsgKey;
	    QCA::CertificateChain chain;
	    chain += pubCert;
	    secMsgKey.setX509CertificateChain( chain );

	    QCA::CMS cms;
	    QCA::SecureMessage msg(&cms);
	    QCOMPARE( msg.canClearsign(), false );
	    QCOMPARE( msg.canSignAndEncrypt(), false );
	    QCOMPARE( msg.type(), QCA::SecureMessage::CMS );

	    msg.setRecipient(secMsgKey);

	    QFETCH( QByteArray, testText );

	    msg.startEncrypt();
	    msg.update(testText);
	    msg.end();

	    msg.waitForFinished(-1);

	    QByteArray encryptedResult1 = msg.read();
	    QCOMPARE( encryptedResult1.isEmpty(), false );

	    msg.reset();
	    msg.setRecipient(secMsgKey);
	    msg.startEncrypt();
	    msg.update( testText );
	    msg.end();

	    msg.waitForFinished(-1);
	    QVERIFY( msg.success() );

	    QByteArray encryptedResult2 = msg.read();
	    QCOMPARE( encryptedResult2.isEmpty(), false );

	    QCA::ConvertResult res;
	    QCA::SecureArray passPhrase = "start";
	    QCA::PrivateKey privKey = QCA::PrivateKey::fromPEMFile( QStringLiteral("QcaTestClientKey.pem"), passPhrase, &res );
	    QCOMPARE( res, QCA::ConvertGood );

	    secMsgKey.setX509PrivateKey( privKey );
	    QCA::SecureMessageKeyList privKeyList;
	    privKeyList += secMsgKey;
	    QCA::CMS cms2;
	    cms2.setPrivateKeys( privKeyList );

	    QCA::SecureMessage msg2( &cms2 );

	    msg2.startDecrypt();
	    msg2.update( encryptedResult1 );
	    msg2.end();
	    msg2.waitForFinished(-1);
	    QVERIFY( msg2.success() );
	    QByteArray decryptedResult1 = msg2.read();
	    QCOMPARE( decryptedResult1, testText );

	    msg2.reset();
	    msg2.startDecrypt();
	    msg2.update( encryptedResult1 );
	    msg2.end();
	    msg2.waitForFinished(-1);
	    QVERIFY( msg2.success() );
	    QByteArray decryptedResult2 = msg2.read();

	    QCOMPARE( decryptedResult1, decryptedResult2 );

	    QCOMPARE( msg2.canClearsign(), false );
	    QCOMPARE( msg2.canSignAndEncrypt(), false );
	    QCOMPARE( msg2.type(), QCA::SecureMessage::CMS );
	}
    }
}

void CMSut::signverify_data()
{
    QTest::addColumn<QByteArray>("testText");

    QTest::newRow("empty") << QByteArray("");
    QTest::newRow("0") << QByteArray("0");
    QTest::newRow("07") << QByteArray("07899847jkjjfasjaJKJLJkljklj&kjlj;/**-+.01");
    QTest::newRow("dubious") << QByteArray("~!#**$#&&%^@#^&()");
}

// This one tests Detached format.
void CMSut::signverify()
{
    QStringList providersToTest;
    providersToTest.append(QStringLiteral("qca-ossl"));

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( (QStringLiteral( "Certificate not supported for ")+provider).toLocal8Bit().constData() );
        else if( !QCA::isSupported( "cms", provider ) )
	    QWARN( (QStringLiteral( "CMS not supported for ")+provider).toLocal8Bit().constData() );
	else {
	    QCA::ConvertResult res;
	    QCA::SecureArray passPhrase = "start";
	    QCA::PrivateKey privKey = QCA::PrivateKey::fromPEMFile( QStringLiteral("QcaTestClientKey.pem"), passPhrase, &res, provider );
	    QCOMPARE( res, QCA::ConvertGood );

	    QCA::Certificate pubCert = QCA::Certificate::fromPEMFile( QStringLiteral("QcaTestClientCert.pem"), &res, provider);
	    QCOMPARE( res, QCA::ConvertGood );
	    QCOMPARE( pubCert.isNull(), false );

	    QCA::CertificateChain chain;
	    chain += pubCert;
	    QCA::SecureMessageKey secMsgKey;
	    secMsgKey.setX509CertificateChain( chain );
	    secMsgKey.setX509PrivateKey( privKey );

	    QCA::SecureMessageKeyList privKeyList;
	    privKeyList += secMsgKey;
	    QCA::CMS cms2;
	    cms2.setPrivateKeys( privKeyList );

	    QCA::SecureMessage msg2( &cms2 );
	    msg2.setSigners( privKeyList );
	    QCOMPARE( msg2.canClearsign(), false );
	    QCOMPARE( msg2.canSignAndEncrypt(), false );
	    QCOMPARE( msg2.type(), QCA::SecureMessage::CMS );

	    QFETCH( QByteArray, testText );

	    msg2.startSign(QCA::SecureMessage::Detached);
	    msg2.update( testText );
	    msg2.end();
	    msg2.waitForFinished(-1);
	    QVERIFY( msg2.success() );
	    QByteArray signedResult1 = msg2.signature();
	    QCOMPARE( signedResult1.isEmpty(), false );

	    msg2.reset();

	    msg2.setSigners( privKeyList );
	    msg2.startSign(QCA::SecureMessage::Detached);
	    msg2.update( testText );
	    msg2.end();
	    msg2.waitForFinished(-1);
	    QVERIFY( msg2.success() );
	    QByteArray signedResult2 = msg2.signature();

	    QCOMPARE( signedResult2.isEmpty(), false );

	    QCA::CMS cms;
	    QCA::Certificate caCert = QCA::Certificate::fromPEMFile( QStringLiteral("QcaTestRootCert.pem"), &res, provider );
	    QCOMPARE( res, QCA::ConvertGood );
	    QCA::CertificateCollection caCertCollection;
	    caCertCollection.addCertificate(caCert);

	    cms.setTrustedCertificates( caCertCollection );
	    QCA::SecureMessage msg( &cms );
	    QCOMPARE( msg.canClearsign(), false );
	    QCOMPARE( msg.canSignAndEncrypt(), false );
	    QCOMPARE( msg.type(), QCA::SecureMessage::CMS );

	    msg.startVerify( signedResult1 );
	    msg.update( testText );
	    msg.end();

	    msg.waitForFinished(-1);
	    QVERIFY( msg.wasSigned() );
	    QVERIFY( msg.success() );
	    QEXPECT_FAIL( "empty", "We don't seem to be able to verify signature of a zero length message", Continue);
	    QVERIFY( msg.verifySuccess() );

	    msg.reset();

	    msg.startVerify( signedResult2);
	    msg.update( testText );
	    msg.end();

	    msg.waitForFinished(-1);
	    QVERIFY( msg.wasSigned() );
	    QVERIFY( msg.success() );
	    QEXPECT_FAIL( "empty", "We don't seem to be able to verify signature of a zero length message", Continue);
	    QVERIFY( msg.verifySuccess() );

	    msg.reset();

	    // This tests junk on the end of the signature - should fail
	    msg.startVerify( signedResult2 + "junk");
	    msg.update( testText );
	    msg.end();

	    msg.waitForFinished(-1);
	    QVERIFY( msg.wasSigned() );
	    QVERIFY( msg.success() );
	    QCOMPARE( msg.verifySuccess(), false );

	    msg.reset();

	    // This tests junk on the end of the message - should fail
	    msg.startVerify( signedResult2 );
	    msg.update( testText+"junk" );
	    msg.end();

	    msg.waitForFinished(-1);
	    QVERIFY( msg.wasSigned() );
	    QVERIFY( msg.success() );
	    QCOMPARE( msg.verifySuccess(), false );
	}
    }
}


void CMSut::signverify_message_data()
{
    QTest::addColumn<QByteArray>("testText");

    QTest::newRow("empty") << QByteArray("");
    QTest::newRow("0") << QByteArray("0");
    QTest::newRow("07") << QByteArray("07899847jkjjfasjaJKJLJkljklj&kjlj;/**-+.01");
    QTest::newRow("dubious") << QByteArray("~!#**$#&&%^@#^&()");
}

// This one tests Message format
void CMSut::signverify_message()
{
    QStringList providersToTest;
    providersToTest.append(QStringLiteral("qca-ossl"));

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( (QStringLiteral( "Certificate not supported for ")+provider).toLocal8Bit().constData() );
        else if( !QCA::isSupported( "cms", provider ) )
	    QWARN( (QStringLiteral( "CMS not supported for ")+provider).toLocal8Bit().constData() );
	else {
	    QCA::ConvertResult res;
	    QCA::SecureArray passPhrase = "start";
	    QCA::PrivateKey privKey = QCA::PrivateKey::fromPEMFile( QStringLiteral("QcaTestClientKey.pem"), passPhrase, &res, provider );
	    QCOMPARE( res, QCA::ConvertGood );

	    QCA::Certificate pubCert = QCA::Certificate::fromPEMFile( QStringLiteral("QcaTestClientCert.pem"), &res, provider );
	    QCOMPARE( res, QCA::ConvertGood );
	    QCOMPARE( pubCert.isNull(), false );

	    QCA::CertificateChain chain;
	    chain += pubCert;
	    QCA::SecureMessageKey secMsgKey;
	    secMsgKey.setX509CertificateChain( chain );
	    secMsgKey.setX509PrivateKey( privKey );

	    QCA::SecureMessageKeyList privKeyList;
	    privKeyList += secMsgKey;
	    QCA::CMS cms2;
	    cms2.setPrivateKeys( privKeyList );

	    QCA::SecureMessage msg2( &cms2 );
	    msg2.setSigners( privKeyList );
	    QCOMPARE( msg2.canClearsign(), false );
	    QCOMPARE( msg2.canSignAndEncrypt(), false );
	    QCOMPARE( msg2.type(), QCA::SecureMessage::CMS );

	    QFETCH( QByteArray, testText );

	    msg2.startSign( QCA::SecureMessage::Message );
	    msg2.update( testText );
	    msg2.end();
	    msg2.waitForFinished(-1);
	    QVERIFY( msg2.success() );
	    QByteArray signedResult1 = msg2.read();
	    QCOMPARE( signedResult1.isEmpty(), false );

	    msg2.reset();

	    msg2.setSigners( privKeyList );
	    msg2.startSign(QCA::SecureMessage::Message);
	    msg2.update( testText );
	    msg2.end();
	    msg2.waitForFinished(-1);
	    QVERIFY( msg2.success() );
	    QByteArray signedResult2 = msg2.read();

	    QCOMPARE( signedResult2.isEmpty(), false );

	    QCA::CMS cms;
	    QCA::Certificate caCert = QCA::Certificate::fromPEMFile( QStringLiteral("QcaTestRootCert.pem"), &res, provider );
	    QCOMPARE( res, QCA::ConvertGood );

	    QCA::CertificateCollection caCertCollection;
	    caCertCollection.addCertificate(caCert);

	    cms.setTrustedCertificates( caCertCollection );
	    QCA::SecureMessage msg( &cms );
	    QCOMPARE( msg.canClearsign(), false );
	    QCOMPARE( msg.canSignAndEncrypt(), false );
	    QCOMPARE( msg.type(), QCA::SecureMessage::CMS );

	    msg.startVerify( );
	    msg.update( signedResult1 );
	    msg.end();

	    msg.waitForFinished(-1);
	    QVERIFY( msg.wasSigned() );
	    QVERIFY( msg.success() );
	    QVERIFY( msg.verifySuccess() );

	    msg.reset();

	    msg.startVerify( );
	    msg.update( signedResult2 );
	    msg.end();

	    msg.waitForFinished(-1);
	    QVERIFY( msg.wasSigned() );
	    QVERIFY( msg.success() );
	    QVERIFY( msg.verifySuccess() );

	    msg.reset();

	    msg.startVerify( );
	    msg.update( signedResult2 );
	    msg.end();

	    msg.waitForFinished(-1);
	    QVERIFY( msg.wasSigned() );
	    QVERIFY( msg.success() );
	    QCOMPARE( msg.verifySuccess(), true );
	}
    }
}

void CMSut::signverify_message_invalid_data()
{
    QTest::addColumn<QByteArray>("testText");

    QTest::newRow("empty") << QByteArray("");
    QTest::newRow("0") << QByteArray("0");
    QTest::newRow("07") << QByteArray("07899847jkjjfasjaJKJLJkljklj&kjlj;/**-+.01");
    QTest::newRow("dubious") << QByteArray("~!#**$#&&%^@#^&()");
}


// This one tests Message format
void CMSut::signverify_message_invalid()
{
    QStringList providersToTest;
    providersToTest.append(QStringLiteral("qca-ossl"));

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( (QStringLiteral( "Certificate not supported for ")+provider).toLocal8Bit().constData() );
        else if( !QCA::isSupported( "cms", provider ) )
	    QWARN( (QStringLiteral( "CMS not supported for ")+provider).toLocal8Bit().constData() );
	else {
	    QCA::ConvertResult res;
	    QCA::SecureArray passPhrase = "start";
	    QCA::PrivateKey privKey = QCA::PrivateKey::fromPEMFile( QStringLiteral("QcaTestClientKey.pem"), passPhrase, &res, provider );
	    QCOMPARE( res, QCA::ConvertGood );

	    QCA::Certificate pubCert = QCA::Certificate::fromPEMFile( QStringLiteral("QcaTestClientCert.pem"), &res, provider );
	    QCOMPARE( res, QCA::ConvertGood );
	    QCOMPARE( pubCert.isNull(), false );

	    QCA::CertificateChain chain;
	    chain += pubCert;
	    QCA::SecureMessageKey secMsgKey;
	    secMsgKey.setX509CertificateChain( chain );
	    secMsgKey.setX509PrivateKey( privKey );

	    QCA::SecureMessageKeyList privKeyList;
	    privKeyList += secMsgKey;
	    QCA::CMS cms2;
	    cms2.setPrivateKeys( privKeyList );

	    QCA::SecureMessage msg2( &cms2 );
	    msg2.setSigners( privKeyList );
	    QCOMPARE( msg2.canClearsign(), false );
	    QCOMPARE( msg2.canSignAndEncrypt(), false );
	    QCOMPARE( msg2.type(), QCA::SecureMessage::CMS );

	    QFETCH( QByteArray, testText );

	    msg2.startSign( QCA::SecureMessage::Message );
	    msg2.update( testText );
	    msg2.end();
	    msg2.waitForFinished(-1);
	    QVERIFY( msg2.success() );
	    QByteArray signedResult1 = msg2.read();
	    QCOMPARE( signedResult1.isEmpty(), false );

	    QCA::CMS cms;
	    QCA::Certificate caCert = QCA::Certificate::fromPEMFile( QStringLiteral("QcaTestRootCert.pem"), &res, provider );
	    QCOMPARE( res, QCA::ConvertGood );

	    QCA::CertificateCollection caCertCollection;
	    caCertCollection.addCertificate(caCert);

	    cms.setTrustedCertificates( caCertCollection );
	    QCA::SecureMessage msg( &cms );
	    QCOMPARE( msg.canClearsign(), false );
	    QCOMPARE( msg.canSignAndEncrypt(), false );
	    QCOMPARE( msg.type(), QCA::SecureMessage::CMS );

	    // This is just to break things
	    // signedResult1[30] = signedResult1[30] + 1;
	    signedResult1[signedResult1.size()-2] = 0x00;

	    msg.startVerify( );
	    msg.update( signedResult1 );
	    msg.end();

	    msg.waitForFinished(-1);
	    QVERIFY( msg.wasSigned() );
	    QVERIFY( msg.success() );
	    QCOMPARE( msg.verifySuccess(), false );
	}
    }
}


QTEST_MAIN(CMSut)

#include "cms.moc"

