/**
 * randomunittest.cpp
 *
 * Copyright (C)  2004  Brad Hards <bradh@frogmouth.net>
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
#include <QtCrypto>

RandomUnitTest::RandomUnitTest()
    : Tester()
{

}

void RandomUnitTest::allTests()
{
    QCA::Initializer init;

    QCA::Random rng = QCA::globalRNG( );
    CHECK( rng.provider()->name(), QString( "qca-botan" ) );

    QCA::setGlobalRNG( "default" );
    rng = QCA::globalRNG( );
    CHECK( rng.provider()->name(), QString( "default" ) );

    {
	QCA::Random randObject ("default");
	CHECK( randObject.nextByte() == randObject.nextByte(), false );
	CHECK( QCA::Random().nextByte() == QCA::Random().nextByte(), false );
	CHECK( randObject.nextBytes(4) == randObject.nextBytes(4), false );
	CHECK( randObject.nextBytes(100) == randObject.nextBytes(100), false );
	CHECK( randObject.randomChar() == randObject.randomChar(), false );
	CHECK( QCA::Random().randomChar() == QCA::Random().randomChar(), false );
	CHECK( QCA::Random::randomChar() == QCA::Random::randomChar(), false );
	CHECK( QCA::Random().randomInt() == QCA::Random().randomInt(), false );
	CHECK( QCA::Random::randomInt() == QCA::Random::randomInt(), false );
	CHECK( QCA::Random().randomArray(3) == QCA::Random().randomArray(3), false );
	CHECK( QCA::Random::randomArray(3) == QCA::Random::randomArray(3), false );

	CHECK( randObject.nextByte(QCA::Random::Nonce) == randObject.nextByte(QCA::Random::SessionKey), false );
	CHECK( QCA::Random().nextByte(QCA::Random::PublicValue) == QCA::Random().nextByte(), false );
	CHECK( randObject.nextBytes(4) == randObject.nextBytes(4, QCA::Random::Nonce), false );
	CHECK( randObject.randomChar(QCA::Random::LongTermKey) == randObject.randomChar(), false );
	CHECK( QCA::Random().randomChar() == QCA::Random().randomChar(QCA::Random::PublicValue), false );
	CHECK( QCA::Random::randomChar(QCA::Random::PublicValue) == QCA::Random::randomChar(QCA::Random::Nonce), false );
	CHECK( QCA::Random().randomInt(QCA::Random::Nonce) == QCA::Random().randomInt(), false );
	CHECK( QCA::Random::randomInt(QCA::Random::Nonce) == QCA::Random::randomInt(QCA::Random::Nonce), false );
	CHECK( QCA::Random().randomArray(3, QCA::Random::Nonce) == QCA::Random().randomArray(3), false );
	CHECK( QCA::Random::randomArray(3, QCA::Random::SessionKey) == QCA::Random::randomArray(3, QCA::Random::PublicValue), false );

	for (unsigned int len = 1; len <= 1024; len*=2 ) {
	    CHECK( QCA::globalRNG().nextBytes(len, QCA::Random::SessionKey).size(), len );
	}
    }

    QCA::setGlobalRNG( "qca-botan" );
    QCA::Random rng1 = QCA::globalRNG();
    CHECK( rng1.provider()->name(), QString( "qca-botan" ) );

    {
	QCA::Random randObject ( "qca-botan" );
	CHECK( randObject.nextByte() == randObject.nextByte(), false );
	CHECK( QCA::Random().nextByte() == QCA::Random().nextByte(), false );
	CHECK( randObject.nextBytes(4) == randObject.nextBytes(4), false );
	CHECK( randObject.nextBytes(100) == randObject.nextBytes(100), false );
	CHECK( randObject.randomChar() == randObject.randomChar(), false );
	CHECK( QCA::Random().randomChar() == QCA::Random().randomChar(), false );
	CHECK( QCA::Random::randomChar() == QCA::Random::randomChar(), false );
	CHECK( QCA::Random().randomInt() == QCA::Random().randomInt(), false );
	CHECK( QCA::Random::randomInt() == QCA::Random::randomInt(), false );
	CHECK( QCA::Random().randomArray(3) == QCA::Random().randomArray(3), false );
	CHECK( QCA::Random::randomArray(3) == QCA::Random::randomArray(3), false );

	CHECK( randObject.nextByte(QCA::Random::Nonce) == randObject.nextByte(QCA::Random::SessionKey), false );
	CHECK( QCA::Random().nextByte(QCA::Random::PublicValue) == QCA::Random().nextByte(), false );
	CHECK( randObject.nextBytes(4) == randObject.nextBytes(4, QCA::Random::Nonce), false );
	CHECK( randObject.randomChar(QCA::Random::LongTermKey) == randObject.randomChar(), false );
	CHECK( QCA::Random().randomChar() == QCA::Random().randomChar(QCA::Random::PublicValue), false );
	CHECK( QCA::Random::randomChar(QCA::Random::PublicValue) == QCA::Random::randomChar(QCA::Random::Nonce), false );
	CHECK( QCA::Random().randomInt(QCA::Random::Nonce) == QCA::Random().randomInt(), false );
	CHECK( QCA::Random::randomInt(QCA::Random::Nonce) == QCA::Random::randomInt(QCA::Random::Nonce), false );
	CHECK( QCA::Random().randomArray(3, QCA::Random::Nonce) == QCA::Random().randomArray(3), false );
	CHECK( QCA::Random::randomArray(3, QCA::Random::SessionKey) == QCA::Random::randomArray(3, QCA::Random::PublicValue), false );

	for (unsigned int len = 1; len <= 1024; len*=2 ) {
	    CHECK( QCA::globalRNG().nextBytes(len, QCA::Random::SessionKey).size(), len );
	}

	QCA::SymmetricKey testkey;
	testkey = QCA::globalRNG().nextBytes(10, QCA::Random::SessionKey);
    }

#if 0
    QCA::setGlobalRNG( "qca-egads" );
    QCA::Random rng2 = QCA::globalRNG();
    CHECK( rng2.provider()->name(), QString( "qca-egads" ) );

    {
	QCA::Random randObject ( "qca-egads" );
	CHECK( randObject.nextByte() == randObject.nextByte(), false );
	CHECK( QCA::Random("qca-egads").nextByte() == QCA::Random("qca-egads").nextByte(), false );
	CHECK( randObject.nextBytes(4) == randObject.nextBytes(4), false );
	CHECK( randObject.nextBytes(100) == randObject.nextBytes(100), false );
	CHECK( randObject.randomChar() == randObject.randomChar(), false );
	CHECK( QCA::Random("qca-egads").randomChar() == QCA::Random("qca-egads").randomChar(), false );
	CHECK( QCA::Random::randomChar() == QCA::Random::randomChar(), false );
	CHECK( QCA::Random("qca-egads").randomInt() == QCA::Random().randomInt(), false );
	CHECK( QCA::Random::randomInt() == QCA::Random::randomInt(), false );
	CHECK( QCA::Random().randomArray(3) == QCA::Random().randomArray(3), false );
	CHECK( QCA::Random::randomArray(3) == QCA::Random::randomArray(3), false );

	CHECK( randObject.nextByte(QCA::Random::Nonce) == randObject.nextByte(QCA::Random::SessionKey), false );
	CHECK( QCA::Random().nextByte(QCA::Random::PublicValue) == QCA::Random().nextByte(), false );
	CHECK( randObject.nextBytes(4) == randObject.nextBytes(4, QCA::Random::Nonce), false );
	CHECK( randObject.randomChar(QCA::Random::LongTermKey) == randObject.randomChar(), false );
	CHECK( QCA::Random().randomChar() == QCA::Random().randomChar(QCA::Random::PublicValue), false );
	CHECK( QCA::Random::randomChar(QCA::Random::PublicValue) == QCA::Random::randomChar(QCA::Random::Nonce), false );
	CHECK( QCA::Random().randomInt(QCA::Random::Nonce) == QCA::Random().randomInt(), false );
	CHECK( QCA::Random::randomInt(QCA::Random::Nonce) == QCA::Random::randomInt(QCA::Random::Nonce), false );
	CHECK( QCA::Random().randomArray(3, QCA::Random::Nonce) == QCA::Random().randomArray(3), false );
	CHECK( QCA::Random::randomArray(3, QCA::Random::SessionKey) == QCA::Random::randomArray(3, QCA::Random::PublicValue), false );

	for (unsigned int len = 1; len <= 1024; len*=2 ) {
	    CHECK( QCA::globalRNG().nextBytes(len, QCA::Random::SessionKey).size(), len );
	}

	QCA::SymmetricKey testkey;
	testkey = QCA::globalRNG().nextBytes(10, QCA::Random::SessionKey);
    }
#endif

}

