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

class StaticUnitTest : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void cleanupTestCase();
    void hexConversions();
    void providers();
    void capabilities();
    void secureMemory();
private:
    QCA::Initializer* m_init;
};

void StaticUnitTest::initTestCase()
{
    m_init = new QCA::Initializer;
#include "../fixpaths.include"
}

void StaticUnitTest::cleanupTestCase()
{
    delete m_init;
}

void StaticUnitTest::hexConversions()
{
    QByteArray test(10, 'a');

    QCOMPARE( QCA::arrayToHex(test), QString("61616161616161616161") );

    test.fill('b');
    test[7] = 0x00;

    QCOMPARE( test == QCA::hexToArray(QString("62626262626262006262")), true );

    QCA::SecureArray testArray(10);
    //testArray.fill( 'a' );
    for (int i = 0; i < testArray.size(); i++) {
	testArray[ i ] = 0x61;
    }
    QCOMPARE( QCA::arrayToHex( testArray.toByteArray() ), QString( "61616161616161616161" ) );
    //testArray.fill( 'b' );
    for (int i = 0; i < testArray.size(); i++) {
	testArray[ i ] = 0x62;
    }
    testArray[6] = 0x00;
    QCOMPARE( testArray == QCA::hexToArray(QString("62626262626200626262")), true );

    QCOMPARE( testArray == QCA::hexToArray( QCA::arrayToHex( testArray.toByteArray() ) ), true );

    testArray[9] = 0x00;
    QCOMPARE( testArray == QCA::hexToArray( QCA::arrayToHex( testArray.toByteArray() ) ), true );
}


void StaticUnitTest::capabilities()
{
   // capabilities are reported as a list - that is a problem for
    // doing a direct comparison, since they change
    // We try to work around that using contains()
    QStringList supportedCapabilities = QCA::supportedFeatures();
    QCOMPARE( supportedCapabilities.contains("random"), (QBool)true );
    QCOMPARE( supportedCapabilities.contains("sha1"), (QBool)true );
    QCOMPARE( supportedCapabilities.contains("sha0"), (QBool)true );
    QCOMPARE( supportedCapabilities.contains("md2"),(QBool) true );
    QCOMPARE( supportedCapabilities.contains("md4"), (QBool)true );
    QCOMPARE( supportedCapabilities.contains("md5"), (QBool)true );
    QCOMPARE( supportedCapabilities.contains("ripemd160"), (QBool)true );

    QStringList defaultCapabilities = QCA::defaultFeatures();
    QCOMPARE( defaultCapabilities.contains("random"), (QBool)true );

    QCOMPARE( QCA::isSupported("random"), true );
    QCOMPARE( QCA::isSupported("sha0"), true );
    QCOMPARE( QCA::isSupported("sha0,sha1"), true );
    QCOMPARE( QCA::isSupported("md2,md4,md5"), true );
    QCOMPARE( QCA::isSupported("md5"), true );
    QCOMPARE( QCA::isSupported("ripemd160"), true );
    QCOMPARE( QCA::isSupported("sha256,sha384,sha512"), true );
    QCOMPARE( QCA::isSupported("nosuchfeature"), false );

    QString caps( "random,sha1,md5,ripemd160");
    QStringList capList;
    capList = caps.split( "," );
    QCOMPARE( QCA::isSupported(capList), true );
    capList.append("noSuch");
    QCOMPARE( QCA::isSupported(capList), false );
    capList.clear();
    capList.append("noSuch");
    QCOMPARE( QCA::isSupported(capList), false );
}

void StaticUnitTest::secureMemory()
{
    // this should be reliably true
    QCOMPARE( QCA::haveSecureMemory(), true );
}

void StaticUnitTest::providers()
{
    // providers are obviously variable, this might be a bit brittle
    QStringList providerNames;
    QCA::scanForPlugins();
    QCA::ProviderList qcaProviders = QCA::providers();
    for (int i = 0; i < qcaProviders.size(); ++i) {
	providerNames.append( qcaProviders[i]->name() );
    }
    QCOMPARE( providerNames.contains("qca-ossl"), (QBool)true );
    QCOMPARE( providerNames.contains("qca-gcrypt"), (QBool)true );
    QCOMPARE( providerNames.contains("qca-nss"), (QBool)true );
    QCOMPARE( providerNames.contains("qca-pkcs11"), (QBool)true );
    QCOMPARE( providerNames.contains("qca-gnupg"), (QBool)true );
    QCOMPARE( providerNames.contains("qca-botan"), (QBool)true );

    QCA::setProviderPriority("qca-ossl", 4);
    QCA::setProviderPriority("qca-botan", 2);
    QCOMPARE( QCA::providerPriority( "qca-ossl"), 4 );
    QCOMPARE( QCA::providerPriority( "qca-gcrypt"), 0 );
    QCOMPARE( QCA::providerPriority( "qca-botan"), 2 );
    QCA::setProviderPriority("qca-ossl", 3);
    // reuse last
    QCA::setProviderPriority("qca-botan", -1);
    QCOMPARE( QCA::providerPriority( "qca-botan"), 3 );

    QCA::unloadAllPlugins();
}

QTEST_MAIN(StaticUnitTest)

#include "staticunittest.moc"

