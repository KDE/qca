/**
 * kdfunittest.cpp
 *
 * Copyright (C)  2004-2005  Brad Hards <bradh@frogmouth.net>
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
#include "kdfunittest.h"
#include <QtCrypto>

struct kdfTestValues {
    QString secret; // usually a password or passphrase
    QString output; // the key you get back
    QString salt;   // a salt or initialisation vector
    unsigned int outputLength; // if the algo supports variable length keys, len
    unsigned int iterationCount; // number of iterations
};


// These are from Botan's test suite
static struct kdfTestValues pbkdf1TestValues[] = {
    { "66746C6B6662786474626A62766C6C7662776977",
      "768B277DC970F912DBDD3EDAD48AD2F065D25",
      "40AC5837560251C275AF5E30A6A3074E57CED38E", 19, 6 },

    { "786E736F736D6B766867677A7370636E63706F63",
      "4D90E846A4B6AAA02AC548014A00E97E506B2AFB",
      "7008A9DC1B9A81470A2360275C19DAB77F716824", 20, 6 },

    { "6F74696C71776C756B717473",
      "71ED1A995E693EFCD33155935E800037DA74EA28",
      "CCFC44C09339040E55D3F7F76CA6EF838FDE928717241DEB9AC1A4EF45A27711", 20, 2001 },

    { "6B7A6E657166666C6274767374686E6663746166",
      "F345FB8FBD880206B650266661F6",
      "8108883FC04A01FEB10661651516425DAD1C93E0", 14, 10000 },

    { "716B78686C7170656D7868796B6D7975636A626F",
      "2D54DFED0C7EF7D20B0945BA414A",
      "BC8BC53D4604977C3ADB1D19C15E87B77A84C2F6", 14, 10000 },

    { 0, 0, 0, 0, 0 }
};

KDFUnitTest::KDFUnitTest()
    : Tester()
{
    QCA::init();
}

void KDFUnitTest::allTests()
{
    pbkdf1Tests();
    pbkdf2Tests();
}

void KDFUnitTest::pbkdf1Tests()
{

    if(!QCA::isSupported("pbkdf1(sha1)"))
	SKIP("PBKDF version 1 with SHA1 not supported");
    else {
      for (int n = 0; (0 != pbkdf1TestValues[n].secret); n++) {
	    QSecureArray password = QCA::hexToArray( pbkdf1TestValues[n].secret );
	    QCA::InitializationVector salt( QCA::hexToArray( pbkdf1TestValues[n].salt) );
	    QCA::SymmetricKey key = QCA::PBKDF1().makeKey( password,
							   salt,
							   pbkdf1TestValues[n].outputLength,
							   pbkdf1TestValues[n].iterationCount);
	    CHECK( QCA::arrayToHex( key ), QString( pbkdf1TestValues[n].output ) );
	}
    }
}

void KDFUnitTest::pbkdf2Tests()
{

    if(!QCA::isSupported("pbkdf2(sha1)"))
	SKIP("PBKDF version 2 with SHA1 not supported");
    else {
	QCA::InitializationVector salt(QSecureArray("what do ya want for nothing?"));
	QSecureArray password("Jefe");
	int iterations = 1000;

	QCA::SymmetricKey passwordOut = QCA::PBKDF2().makeKey (password, salt, 16, iterations);
	CHECK( QCA::arrayToHex(passwordOut), QString( "6349e09cb6b8c1485cfa9780ee3264df" ) );
    }

}

