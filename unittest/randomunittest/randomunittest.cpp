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
#include "randomunittest.h"

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
    QCA::Random rng = QCA::globalRNG( );
    QCOMPARE( rng.provider()->name(), QString( "qca-botan" ) );

    QCA::setGlobalRNG( "default" );
    rng = QCA::globalRNG( );
    QCOMPARE( rng.provider()->name(), QString( "default" ) );

    QCA::setGlobalRNG( "qca-botan" );
    QCA::Random rng1 = QCA::globalRNG();
    QCOMPARE( rng1.provider()->name(), QString( "qca-botan" ) );
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

	QCOMPARE( randObject.nextByte(QCA::Random::Nonce) == randObject.nextByte(QCA::Random::SessionKey), false );
	QCOMPARE( QCA::Random().nextByte(QCA::Random::PublicValue) == QCA::Random().nextByte(), false );
	QCOMPARE( randObject.nextBytes(4) == randObject.nextBytes(4, QCA::Random::Nonce), false );
	QCOMPARE( randObject.randomChar(QCA::Random::LongTermKey) == randObject.randomChar(), false );
	QCOMPARE( QCA::Random().randomChar() == QCA::Random().randomChar(QCA::Random::PublicValue), false );
	QCOMPARE( QCA::Random::randomChar(QCA::Random::PublicValue) == QCA::Random::randomChar(QCA::Random::Nonce), false );
	QCOMPARE( QCA::Random().randomInt(QCA::Random::Nonce) == QCA::Random().randomInt(), false );
	QCOMPARE( QCA::Random::randomInt(QCA::Random::Nonce) == QCA::Random::randomInt(QCA::Random::Nonce), false );
	QCOMPARE( QCA::Random().randomArray(3, QCA::Random::Nonce) == QCA::Random().randomArray(3), false );
	QCOMPARE( QCA::Random::randomArray(3, QCA::Random::SessionKey) == QCA::Random::randomArray(3, QCA::Random::PublicValue), false );

	for (int len = 1; len <= 1024; len*=2 ) {
	    QCOMPARE( QCA::globalRNG().nextBytes(len, QCA::Random::SessionKey).size(), len );
	}
    }
}

QTEST_MAIN(RandomUnitTest)

