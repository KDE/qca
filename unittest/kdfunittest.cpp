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
    { "66746c6b6662786474626a62766c6c7662776977",
      "768b277dc970f912dbdd3edad48ad2f065d25d",
      "40ac5837560251c275af5e30a6a3074e57ced38e", 19, 6 },

    { "786e736f736d6b766867677a7370636e63706f63",
      "4d90e846a4b6aaa02ac548014a00e97e506b2afb",
      "7008a9dc1b9a81470a2360275c19dab77f716824", 20, 6 },

    { "6f74696c71776c756b717473",
      "71ed1a995e693efcd33155935e800037da74ea28",
      "ccfc44c09339040e55d3f7f76ca6ef838fde928717241deb9ac1a4ef45a27711", 20, 2001 },

    { "6b7a6e657166666c6274767374686e6663746166",
      "f345fb8fbd880206b650266661f6",
      "8108883fc04a01feb10661651516425dad1c93e0", 14, 10000 },

    { "716b78686c7170656d7868796b6d7975636a626f",
      "2d54dfed0c7ef7d20b0945ba414a",
      "bc8bc53d4604977c3adb1d19c15e87b77a84c2f6", 14, 10000 },

    { 0, 0, 0, 0, 0 }
};

// These are from Botan's test suite
static struct kdfTestValues pbkdf2TestValues[] = {
    { "6a79756571677872736367676c707864796b6366", "df6d9d72872404bf73e708cf3b7d", "9b56e55328a4c97a250738f8dba1b992e8a1b508", 14, 10000 },
    { "61717271737a6e7a76767a67746b73616d6d676f", "fa13f40af1ade2a30f2fffd66fc8a659ef95e6388c1682fc0fe4d15a70109517a32942e39c371440", "57487813cdd2220dfc485d932a2979ee8769ea8b", 40, 101 },
    { "6c7465786d666579796c6d6c62727379696b6177", "027afadd48f4be8dcc4f", "ed1f39a0a7f3889aaf7e60743b3bc1cc2c738e60", 10, 1000 },
    { "6378676e7972636772766c6c796c6f6c736a706f", "7c0d009fc91b48cb6d19bafbfccff3e2ccabfe725eaa234e56bde1d551c132f2", "94ac88200743fb0f6ac51be62166cbef08d94c15", 32, 1 },
    { "7871796668727865686965646c6865776e76626a", "4661301d3517ca4443a6a607b32b2a63f69996299df75db75f1e0b98dd0eb7d8", "24a1a50b17d63ee8394b69fc70887f4f94883d68", 32, 5 },
    { "616e6461716b706a7761627663666e706e6a6b6c", "82fb44a521448d5aac94b5158ead1e4dcd7363081a747b9f7626752bda2d", "9316c80801623cc2734af74bec42cf4dbaa3f6d5", 30, 100 },
    { "687361767679766f636c6f79757a746c736e6975", "f8ec2b0ac817896ac8189d787c6424ed24a6d881436687a4629802c0ecce", "612cc61df3cf2bdb36e10c4d8c9d73192bddee05", 30, 100 },
    { "6561696d72627a70636f706275736171746b6d77", "c9a0b2622f13916036e29e7462e206e8ba5b50ce9212752eb8ea2a4aa7b40a4cc1bf", "45248f9d0cebcb86a18243e76c972a1f3b36772a", 34, 100 },
    { "67777278707178756d7364736d626d6866686d666463766c63766e677a6b6967", "4c9db7ba24955225d5b845f65ef24ef1b0c6e86f2e39c8ddaa4b8abd26082d1f350381fadeaeb560dc447afc68a6b47e6ea1e7412f6cf7b2d82342fccd11d3b4", "a39b76c6eec8374a11493ad08c246a3e40dfae5064f4ee3489c273646178", 64, 1000 },
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

	for (int n = 0; (0 != pbkdf2TestValues[n].secret); n++) {
	    QSecureArray password = QCA::hexToArray( pbkdf2TestValues[n].secret );
	    QCA::InitializationVector salt( QCA::hexToArray( pbkdf2TestValues[n].salt) );
	    QCA::SymmetricKey key = QCA::PBKDF2().makeKey( password,
							   salt,
							   pbkdf2TestValues[n].outputLength,
							   pbkdf2TestValues[n].iterationCount);
	    CHECK( QCA::arrayToHex( key ), QString( pbkdf2TestValues[n].output ) );
	}
    }

}

