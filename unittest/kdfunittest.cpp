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
}

void KDFUnitTest::allTests()
{
    QCA::Initializer init;

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
	{
	    QCA::InitializationVector salt(QSecureArray("what do ya want for nothing?"));
	    QSecureArray password("Jefe");
	    int iterations = 1000;
	    QCA::SymmetricKey passwordOut = QCA::PBKDF2().makeKey (password, salt, 16, iterations);
	    CHECK( QCA::arrayToHex(passwordOut), QString( "6349e09cb6b8c1485cfa9780ee3264df" ) );
	}

	// RFC3962, Appendix B
	{
	    QCA::InitializationVector salt(QSecureArray("ATHENA.MIT.EDUraeburn"));
	    QSecureArray password("password");
	    int iterations = 1;
	    QCA::SymmetricKey passwordOut = QCA::PBKDF2().makeKey (password, salt, 16, iterations);
	    CHECK( QCA::arrayToHex(passwordOut), QString( "cdedb5281bb2f801565a1122b2563515" ) );
	    passwordOut = QCA::PBKDF2().makeKey (password, salt, 32, iterations);
	    CHECK( QCA::arrayToHex(passwordOut),
		   QString( "cdedb5281bb2f801565a1122b25635150ad1f7a04bb9f3a333ecc0e2e1f70837" ) );
	}

	// RFC3962, Appendix B
	{
	    QCA::InitializationVector salt(QSecureArray("ATHENA.MIT.EDUraeburn"));
	    QSecureArray password("password");
	    int iterations = 2;
	    QCA::SymmetricKey passwordOut = QCA::PBKDF2().makeKey (password, salt, 16, iterations);
	    CHECK( QCA::arrayToHex(passwordOut), QString( "01dbee7f4a9e243e988b62c73cda935d" ) );
	    passwordOut = QCA::PBKDF2().makeKey (password, salt, 32, iterations);
	    CHECK( QCA::arrayToHex(passwordOut),
		   QString( "01dbee7f4a9e243e988b62c73cda935da05378b93244ec8f48a99e61ad799d86" ) );
	}

	// RFC3962, Appendix B
	{
	    QCA::InitializationVector salt(QSecureArray("ATHENA.MIT.EDUraeburn"));
	    QSecureArray password("password");
	    int iterations = 1200;
	    QCA::SymmetricKey passwordOut = QCA::PBKDF2().makeKey (password, salt, 16, iterations);
	    CHECK( QCA::arrayToHex(passwordOut), QString( "5c08eb61fdf71e4e4ec3cf6ba1f5512b" ) );
	    passwordOut = QCA::PBKDF2().makeKey (password, salt, 32, iterations);
	    CHECK( QCA::arrayToHex(passwordOut),
		   QString( "5c08eb61fdf71e4e4ec3cf6ba1f5512ba7e52ddbc5e5142f708a31e2e62b1e13" ) );
	}

	// RFC3211 and RFC3962, Appendix B 
	{
	    QCA::InitializationVector salt(QCA::hexToArray("1234567878563412"));
	    QSecureArray password("password");
	    int iterations = 5;
	    QCA::SymmetricKey passwordOut = QCA::PBKDF2().makeKey (password, salt, 16, iterations);
	    CHECK( QCA::arrayToHex(passwordOut), QString( "d1daa78615f287e6a1c8b120d7062a49" ) );
	    passwordOut = QCA::PBKDF2().makeKey (password, salt, 32, iterations);
	    CHECK( QCA::arrayToHex(passwordOut),
		   QString( "d1daa78615f287e6a1c8b120d7062a493f98d203e6be49a6adf4fa574b6e64ee" ) );
	    passwordOut = QCA::PBKDF2().makeKey (password, salt, 8, iterations);
	    CHECK( QCA::arrayToHex(passwordOut),
		   QString( "d1daa78615f287e6" ) );
	}

	// RFC3962, Appendix B
	{
	    QCA::InitializationVector salt(QSecureArray("pass phrase equals block size"));
	    QSecureArray password("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
	    int iterations = 1200;
	    QCA::SymmetricKey passwordOut = QCA::PBKDF2().makeKey (password, salt, 16, iterations);
	    CHECK( QCA::arrayToHex(passwordOut), QString( "139c30c0966bc32ba55fdbf212530ac9" ) );
	    passwordOut = QCA::PBKDF2().makeKey (password, salt, 32, iterations);
	    CHECK( QCA::arrayToHex(passwordOut),
		   QString( "139c30c0966bc32ba55fdbf212530ac9c5ec59f1a452f5cc9ad940fea0598ed1" ) );
	}

	// RFC3962, Appendix B
	{
	    QCA::InitializationVector salt(QSecureArray("pass phrase exceeds block size"));
	    QSecureArray password("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
	    int iterations = 1200;
	    QCA::SymmetricKey passwordOut = QCA::PBKDF2().makeKey (password, salt, 16, iterations);
	    CHECK( QCA::arrayToHex(passwordOut), QString( "9ccad6d468770cd51b10e6a68721be61" ) );
	    passwordOut = QCA::PBKDF2().makeKey (password, salt, 32, iterations);
	    CHECK( QCA::arrayToHex(passwordOut),
		   QString( "9ccad6d468770cd51b10e6a68721be611a8b4d282601db3b36be9246915ec82a" ) );
	}

	// RFC3962, Appendix B
	{
	    QCA::InitializationVector salt(QSecureArray("EXAMPLE.COMpianist"));
	    QSecureArray password(QCA::hexToArray("f09d849e"));
	    int iterations = 50;
	    QCA::SymmetricKey passwordOut = QCA::PBKDF2().makeKey (password, salt, 16, iterations);
	    CHECK( QCA::arrayToHex(passwordOut), QString( "6b9cf26d45455a43a5b8bb276a403b39" ) );
	    passwordOut = QCA::PBKDF2().makeKey (password, salt, 32, iterations);
	    CHECK( QCA::arrayToHex(passwordOut),
		   QString( "6b9cf26d45455a43a5b8bb276a403b39e7fe37a0c41e02c281ff3069e1e94f52" ) );
	}

    }

}

