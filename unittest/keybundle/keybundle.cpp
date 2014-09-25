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

class KeyBundleTest : public QObject
{
  Q_OBJECT

private slots:
    void initTestCase();
    void cleanupTestCase();
    void nullBundle();
    void fromFile();
    void names();
    void certChain();
    void privKey();
    void createBundle();
private:
    QCA::Initializer* m_init;
};

void KeyBundleTest::initTestCase()
{
    m_init = new QCA::Initializer;
}

void KeyBundleTest::cleanupTestCase()
{
    QCA::unloadAllPlugins();
    delete m_init;
}

void KeyBundleTest::nullBundle()
{
    QCA::KeyBundle nullBundle;
    QVERIFY( nullBundle.isNull() );
    QCOMPARE( nullBundle.name(), QString() );
    QVERIFY( nullBundle.certificateChain().isEmpty() );
    QVERIFY( nullBundle.privateKey().isNull() );

    QCA::KeyBundle nullCopy = nullBundle;
    QVERIFY( nullCopy.isNull() );
    QCOMPARE( nullCopy.name(), QString() );
    QVERIFY( nullCopy.certificateChain().isEmpty() );
    QVERIFY( nullCopy.privateKey().isNull() );

    QCA::KeyBundle nullAssigned( nullCopy );
    QVERIFY( nullAssigned.isNull() );
    QCOMPARE( nullAssigned.name(), QString() );
    QVERIFY( nullAssigned.certificateChain().isEmpty() );
    QVERIFY( nullAssigned.privateKey().isNull() );
}

void KeyBundleTest::fromFile()
{
    if ( QCA::isSupported("pkcs12") ) {
	// "start" is the passphrase, but you wouldn't normally
	// code it in like this
	QCA::KeyBundle userBundle( "user2good.p12", "start" );
	QCOMPARE( userBundle.isNull(), false );
	QCOMPARE( userBundle.name(), QString() );
	QCOMPARE( userBundle.certificateChain().isEmpty(), false );
	QCOMPARE( userBundle.privateKey().isNull(), false );

	QCA::KeyBundle userBundleCopy = userBundle;
	QCOMPARE( userBundleCopy.isNull(), false );
	QCOMPARE( userBundleCopy.name(), QString() );
	QCOMPARE( userBundleCopy.certificateChain().isEmpty(), false );
	QCOMPARE( userBundleCopy.privateKey().isNull(), false );

	QCA::KeyBundle userBundleAssign( userBundleCopy );
	QCOMPARE( userBundleAssign.isNull(), false );
	QCOMPARE( userBundleAssign.name(), QString() );
	QCOMPARE( userBundleAssign.certificateChain().isEmpty(), false );
	QCOMPARE( userBundleAssign.privateKey().isNull(), false );
    }
}

void KeyBundleTest::names()
{
    if ( QCA::isSupported("pkcs12") ) {
	QCA::KeyBundle serverBundle( "servergood2.p12", "start" );
	QCOMPARE( serverBundle.isNull(), false );
	QCOMPARE( serverBundle.name(), QString() );

	serverBundle.setName( "Some Server Bundle" );
	QCOMPARE( serverBundle.name(), QString( "Some Server Bundle" ) );
    }
}

void KeyBundleTest::certChain()
{
    if ( QCA::isSupported("pkcs12") ) {
	QCA::KeyBundle serverBundle( "servergood2.p12", "start" );
	QCOMPARE( serverBundle.isNull(), false );
	QCOMPARE( serverBundle.certificateChain().size(), 1 );
    }
}

void KeyBundleTest::privKey()
{
    if ( QCA::isSupported("pkcs12") ) {
	QCA::KeyBundle serverBundle( "servergood2.p12", "start" );
	QCOMPARE( serverBundle.isNull(), false );
	QCOMPARE( serverBundle.privateKey().isNull(), false );
    }
}
void KeyBundleTest::createBundle()
{
    QCA::KeyBundle *newBundle = new QCA::KeyBundle;

    QVERIFY( newBundle->isNull() );

    if ( !QCA::isSupported( "certificate" ) )
        return;

    QCA::Certificate ca( "RootCA2cert.pem" );
    QCOMPARE( ca.isNull(), false );

    QCA::Certificate primary( "user2goodcert.pem" );
    QCOMPARE( primary.isNull(), false );

    QCA::PrivateKey key( "user2goodkey.pem" );
    QCOMPARE( key.isNull(), false );

    QCA::CertificateChain chain( primary );
    chain.append( ca );

    newBundle->setCertificateChainAndKey( chain, key );
    newBundle->setName( "My New Key Bundle" );

    QCOMPARE( newBundle->certificateChain(), chain );
    QCOMPARE( newBundle->privateKey(), key );
    QCOMPARE( newBundle->name(), QString( "My New Key Bundle" ) );

    // Try round tripping the bundle
    foreach( const QCA::Provider *thisProvider, QCA::providers() ) {
	QString provider = thisProvider->name();
	if (QCA::isSupported( "pkcs12", provider ) ) {
	    qDebug() << "Testing " << provider;
	    QByteArray bundleArray = newBundle->toArray( "reel secrut", provider );
	    QCOMPARE( bundleArray.isNull(), false );

	    QCA::ConvertResult res;
	    QCA::KeyBundle bundleFromArray = QCA::KeyBundle::fromArray( bundleArray, "reel secrut", &res, provider );
	    QCOMPARE( res, QCA::ConvertGood );
	    QCOMPARE( bundleFromArray.isNull(), false );
	    QCOMPARE( bundleFromArray.name(), QString( "My New Key Bundle" ) );
	    QCOMPARE( bundleFromArray.certificateChain(), chain );
	    QCOMPARE( bundleFromArray.privateKey(), key );

	    QTemporaryFile tempFile;
	    QVERIFY( tempFile.open() );

	    bool result = newBundle->toFile( tempFile.fileName(), "file passphrase", provider );
	    QVERIFY( result );

	    QCA::KeyBundle bundleFromFile = QCA::KeyBundle::fromFile( tempFile.fileName(), "file passphrase", &res, provider );
	    QCOMPARE( res, QCA::ConvertGood );
	    QCOMPARE( bundleFromFile.isNull(), false );
	    QCOMPARE( bundleFromFile.name(), QString( "My New Key Bundle" ) );
	    QCOMPARE( bundleFromFile.certificateChain(), chain );
	    QCOMPARE( bundleFromFile.privateKey(), key );
	}
    }
}

QTEST_MAIN(KeyBundleTest)

#include "keybundle.moc"
