/**
 * Copyright (C)  2006-2007 Brad Hards <bradh@frogmouth.net>
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

#include <stdlib.h>

#ifdef Q_OS_WIN
static int setenv(const char *name, const char *value, int overwrite)
{
    int i, iRet;
    char * a;

    if (!overwrite && getenv(name)) return 0;

    i = strlen(name) + strlen(value) + 2;
    a = (char*)malloc(i);
    if (!a) return 1;

    strcpy(a, name);
    strcat(a, "=");
    strcat(a, value);

    iRet = putenv(a);
    free(a);
    return iRet;
}
#endif

// Note; in a real application you get this from a user, but this
// is a useful trick for a unit test.
// See the qcatool application or keyloader and eventhandler examples
// for how to do this properly.
class PGPPassphraseProvider: public QObject
{
    Q_OBJECT
public:
    PGPPassphraseProvider(QObject *parent = 0) : QObject(parent)
    {
        connect(&m_handler, SIGNAL(eventReady(int, const QCA::Event &)),
		SLOT(eh_eventReady(int, const QCA::Event &)));
	m_handler.start();
    }

private slots:
    void eh_eventReady(int id, const QCA::Event &event)
    {
        qDebug() << "got event: " << id;
        if(event.type() == QCA::Event::Password)
	{
	    QCA::SecureArray pass("start");
	    m_handler.submitPassword(id, pass);
	}
	else
	{
	    m_handler.reject(id);
        }
    }

private:
    QCA::EventHandler m_handler;
};

class PgpUnitTest : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void cleanupTestCase();
    void testKeyRing();
    void testClearsign();
private:
    QCA::Initializer* m_init;
};

void PgpUnitTest::initTestCase()
{
    m_init = new QCA::Initializer;
#include "../fixpaths.include"
}

void PgpUnitTest::cleanupTestCase()
{
    delete m_init;
}

void PgpUnitTest::testKeyRing()
{
    // activate the KeyStoreManager
    QCA::KeyStoreManager::start();

    if ( QCA::isSupported( QStringList( QString( "keystorelist" ) ),
                            QString( "qca-gnupg" ) ) )
    {
        QCA::KeyStoreManager keyManager(this);
	keyManager.waitForBusyFinished();
	QStringList storeIds = keyManager.keyStores();
	QVERIFY( storeIds.contains( "qca-gnupg" ) );

        QCA::KeyStore pgpStore( QString("qca-gnupg"), &keyManager );
        QVERIFY( pgpStore.isValid() );
        QCOMPARE( pgpStore.name(), QString( "GnuPG Keyring" ) );
        QCOMPARE( pgpStore.type(), QCA::KeyStore::PGPKeyring );
        QCOMPARE( pgpStore.id(), QString( "qca-gnupg" ) );
	QEXPECT_FAIL( "", "Write support not yet implemented", Continue );
        QCOMPARE( pgpStore.isReadOnly(), false );
        QCOMPARE( pgpStore.holdsTrustedCertificates(), false );
        QCOMPARE( pgpStore.holdsIdentities(), true );
        QCOMPARE( pgpStore.holdsPGPPublicKeys(), true );

        QByteArray oldGNUPGHOME = qgetenv( "GNUPGHOME" );
        // We test a small keyring - I downloaded a publically available one from
        // the Amsterdam Internet Exchange.
        if ( 0 == setenv( "GNUPGHOME",  "./keys1", 1 ) )
        {
            QList<QCA::KeyStoreEntry> keylist = pgpStore.entryList();
            QCOMPARE( keylist.count(), 6 );
            QStringList nameList;
            foreach( const QCA::KeyStoreEntry key,  keylist ) {
                QCOMPARE( key.isNull(), false );
                QCOMPARE( key.type(),  QCA::KeyStoreEntry::TypePGPPublicKey );
                QCOMPARE( key.id().length(),  16 ); // 16 hex digits
                QVERIFY( key.keyBundle().isNull() );
                QVERIFY( key.certificate().isNull() );
                QVERIFY( key.crl().isNull() );
                QVERIFY( key.pgpSecretKey().isNull() );
                QCOMPARE( key.pgpPublicKey().isNull(), false );

                // We accumulate the names, and check them next
                nameList << key.name();
            }
            QVERIFY( nameList.contains( "Steven Bakker <steven.bakker@ams-ix.net>" ) );
            QVERIFY( nameList.contains( "Romeo Zwart <rz@ams-ix.net>" ) );
            QVERIFY( nameList.contains( "Arien Vijn <arien.vijn@ams-ix.net>" ) );
            QVERIFY( nameList.contains( "Niels Bakker <niels.bakker@ams-ix.net>" ) );
            QVERIFY( nameList.contains( "Henk Steenman <Henk.Steenman@ams-ix.net>" ) );
            QVERIFY( nameList.contains( "Geert Nijpels <geert.nijpels@ams-ix.net>" ) );

            // TODO: We should test removeEntry() and writeEntry() here.
        } else {
            QFAIL( "Expected to be able to set the GNUPGHOME environment variable, but couldn't" );
        }

        // We now test an empty keyring
        if ( 0 == setenv( "GNUPGHOME",  "./keys2", 1 ) )
        {
            QList<QCA::KeyStoreEntry> keylist = pgpStore.entryList();
            QCOMPARE( keylist.count(), 0 );
            // TODO: We should test removeEntry() and writeEntry() here.
        } else {
            QFAIL( "Expected to be able to set the GNUPGHOME environment variable, but couldn't" );
        }

        if ( false == oldGNUPGHOME.isNull() )
        {
            setenv( "GNUPGHOME",  oldGNUPGHOME.data(), 1 );
        }
    }

}

class TesterThread : public QThread
{
    Q_OBJECT
protected:
    virtual void run()
    {
        testClearSign();
    }
private:
  void testClearSign();
};


void PgpUnitTest::testClearsign()
{
    // handler and asker cannot occur in the same thread
    TesterThread testerThread;
    testerThread.start();  
}

void TesterThread::testClearSign()
{
    PGPPassphraseProvider handler;

    // activate the KeyStoreManager
    QCA::KeyStoreManager::start();

    QCA::KeyStoreManager keyManager(this);
    keyManager.waitForBusyFinished();
    QStringList storeIds = keyManager.keyStores();
    QVERIFY( storeIds.contains( "qca-gnupg" ) );
    
    QCA::KeyStore pgpStore( QString("qca-gnupg"), &keyManager );
    QVERIFY( pgpStore.isValid() );

    if ( QCA::isSupported( QStringList( QString( "openpgp" ) ), QString( "qca-gnupg" ) ) ||
	 QCA::isSupported( QStringList( QString( "keystorelist" ) ), QString( "qca-gnupg" ) ) ) {

        QByteArray oldGNUPGHOME = qgetenv( "GNUPGHOME" );

	// This keyring has a private / public key pair
	if ( 0 != setenv( "GNUPGHOME",  "./keys3", 1 ) ) {
	        QFAIL( "Expected to be able to set the GNUPGHOME environment variable, but couldn't" );
	}
	
	QList<QCA::KeyStoreEntry> keylist = pgpStore.entryList();
	QCOMPARE( keylist.count(), 1 );

	QCA::KeyStoreEntry myPGPKey = keylist.at(0);	
	QCOMPARE( myPGPKey.isNull(), false );
	QCOMPARE( myPGPKey.name(), QString("Qca Test Key (This key is only for QCA unit tests) <qca@example.com>") );
	QCOMPARE( myPGPKey.type(),  QCA::KeyStoreEntry::TypePGPSecretKey );
	QCOMPARE( myPGPKey.id(), QString("9E946237DAFCCFF4") );
	QVERIFY( myPGPKey.keyBundle().isNull() );
	QVERIFY( myPGPKey.certificate().isNull() );
	QVERIFY( myPGPKey.crl().isNull() );
	QCOMPARE( myPGPKey.pgpSecretKey().isNull(), false );
	QCOMPARE( myPGPKey.pgpPublicKey().isNull(), false );
	  
	// first make the SecureMessageKey
	QCA::SecureMessageKey key;
	key.setPGPSecretKey( myPGPKey.pgpSecretKey() );
	QVERIFY( key.havePrivate() );

	// our data to sign
	QByteArray plain = "Hello, world";

	// let's do it
	QCA::OpenPGP pgp;
	QCA::SecureMessage msg(&pgp);
	msg.setSigner(key);
	msg.setFormat(QCA::SecureMessage::Ascii);
	msg.startSign(QCA::SecureMessage::Clearsign);
	msg.update(plain);
	msg.end();
	msg.waitForFinished(2000);

        QString str = QCA::KeyStoreManager::diagnosticText();
        QCA::KeyStoreManager::clearDiagnosticText();
        QStringList lines = str.split('\n', QString::SkipEmptyParts);
        for(int n = 0; n < lines.count(); ++n)
                fprintf(stderr, "keystore: %s\n", qPrintable(lines[n]));

        QString out = msg.diagnosticText();
        QStringList msglines = out.split('\n', QString::SkipEmptyParts);
        for(int n = 0; n < msglines.count(); ++n)
                fprintf(stderr, "message: %s\n", qPrintable(msglines[n]));

	if(msg.success()) {
	    QByteArray result = msg.read();
	    // result now contains the clearsign text data
	} else {
	    qDebug() << "Failure:" <<  msg.errorCode();
	    QFAIL("Failed to clearsign");
	}


	if ( false == oldGNUPGHOME.isNull() ) {
	    setenv( "GNUPGHOME",  oldGNUPGHOME.data(), 1 );
	}
    }
}


QTEST_MAIN(PgpUnitTest)

#include "pgpunittest.moc"
