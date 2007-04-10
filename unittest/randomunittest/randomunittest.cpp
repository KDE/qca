/**
 * Copyright (C)  2004, 2006  Brad Hards <bradh@frogmouth.net>
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

class RandomUnitTest : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void cleanupTestCase();
    void testSetGlobal();
    void testGetData();

private:
    QCA::Initializer* m_init;

};

void RandomUnitTest::initTestCase()
{
    m_init = new QCA::Initializer;
#include "../fixpaths.include"
}

void RandomUnitTest::cleanupTestCase()
{
    delete m_init;
}

void RandomUnitTest::testSetGlobal()
{
    QCA::setGlobalRandomProvider( "default" );
    QString pname = QCA::globalRandomProvider( );
    QCOMPARE( pname, QString( "default" ) );

    // Only check this if we have the Botan provider
    if ( QCA::findProvider( "qca-botan" ) ) {
        QCA::setGlobalRandomProvider( "qca-botan" );
        QString rng1name = QCA::globalRandomProvider( );
        QCOMPARE( rng1name, QString( "qca-botan" ) );
    }
}

void RandomUnitTest::testGetData()
{
    QStringList providersToTest;
    providersToTest.append("default");
    providersToTest.append("qca-botan");

    foreach(QString provider, providersToTest) {
	QCA::Random randObject (provider);
	QCOMPARE( randObject.nextByte() == randObject.nextByte(), false );
	QCOMPARE( QCA::Random().nextByte() == QCA::Random().nextByte(), false );
	QCOMPARE( randObject.nextBytes(4) == randObject.nextBytes(4), false );
	QCOMPARE( randObject.nextBytes(100) == randObject.nextBytes(100), false );
	QCOMPARE( randObject.randomChar() == randObject.randomChar(), false );
	QCOMPARE( QCA::Random().randomChar() == QCA::Random().randomChar(), false );
	QCOMPARE( QCA::Random::randomChar() == QCA::Random::randomChar(), false );
	QCOMPARE( QCA::Random().randomInt() == QCA::Random().randomInt(), false );
	QCOMPARE( QCA::Random::randomInt() == QCA::Random::randomInt(), false );
	QCOMPARE( QCA::Random().randomArray(3) == QCA::Random().randomArray(3), false );
	QCOMPARE( QCA::Random::randomArray(3) == QCA::Random::randomArray(3), false );

	for (int len = 1; len <= 1024; len*=2 ) {
	    QCOMPARE( QCA::Random::randomArray(len).size(), len );
	}
    }
}

QTEST_MAIN(RandomUnitTest)

#include "randomunittest.moc"
