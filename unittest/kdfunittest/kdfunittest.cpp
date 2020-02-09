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

#ifdef QT_STATICPLUGIN
#include "import_plugins.h"
#endif

class KDFUnitTest : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void initTestCase();
    void cleanupTestCase();
    void pbkdf1md2Tests_data();
    void pbkdf1md2Tests();
    void pbkdf1sha1Tests_data();
    void pbkdf1sha1Tests();
	void pbkdf1sha1TimeTest();
    void pbkdf2Tests_data();
    void pbkdf2Tests();
	void pbkdf2TimeTest();
    void pbkdf2extraTests();
    void hkdfTests_data();
    void hkdfTests();
private:
    QCA::Initializer* m_init;
    QStringList providersToTest;
};


void KDFUnitTest::initTestCase()
{
    m_init = new QCA::Initializer;

    const auto providers = QCA::providers();
    for(QCA::Provider *provider : providers)
        providersToTest << provider->name();
}

void KDFUnitTest::cleanupTestCase()
{
    delete m_init;
}


void KDFUnitTest::pbkdf1md2Tests_data()
{
    QTest::addColumn<QString>("secret");  // usually a password or passphrase
    QTest::addColumn<QString>("output");  // the key you get back
    QTest::addColumn<QString>("salt");    // a salt or initialisation vector
    QTest::addColumn<unsigned int>("outputLength");   // if the algo supports variable length keys, len
    QTest::addColumn<unsigned int>("iterationCount"); // number of iterations

    // These are from Botan's test suite
    QTest::newRow("1") << QStringLiteral("71616c7a73656774")
		    << QStringLiteral("7c1991f3f38a09d70cf3b1acadb70bc6")
		    << QStringLiteral("40cf117c3865e0cf")
		    << static_cast<unsigned int>(16)
		    << static_cast<unsigned int>(1000);

    QTest::newRow("2") << QStringLiteral("766e68617a6a66736978626f6d787175")
		    << QStringLiteral("677500eda9f0c5e96e0a11f90fb9")
		    << QStringLiteral("3a2484ce5d3e1b4d")
		    << static_cast<unsigned int>(14)
		    << static_cast<unsigned int>(1);

    QTest::newRow("3") << QStringLiteral("66686565746e657162646d7171716e797977696f716a666c6f6976636371756a")
		    << QStringLiteral("91a5b689156b441bf27dd2bdd276")
		    << QStringLiteral("5d838b0f4fa22bfa2157f9083d87f8752e0495bb2113012761ef11b66e87c3cb")
		    << static_cast<unsigned int>(14)
		    << static_cast<unsigned int>(15);

    QTest::newRow("4") << QStringLiteral("736e6279696e6a7075696b7176787867726c6b66")
		    << QStringLiteral("49516935cc9f438bafa30ff038fb")
		    << QStringLiteral("f22d341361b47e3390107bd973fdc0d3e0bc02a3")
		    << static_cast<unsigned int>(14)
		    << static_cast<unsigned int>(2);
}

void KDFUnitTest::pbkdf1md2Tests()
{
    QFETCH(QString, secret);
    QFETCH(QString, output);
    QFETCH(QString, salt);
    QFETCH(unsigned int, outputLength);
    QFETCH(unsigned int, iterationCount);

    bool anyProviderTested = false;
    foreach(QString provider, providersToTest) {
	if(QCA::isSupported("pbkdf1(md2)", provider)) {
	    anyProviderTested = true;
	    QCA::SecureArray password = QCA::hexToArray( secret );
	    QCA::InitializationVector iv( QCA::hexToArray( salt) );
	    QCA::SymmetricKey key = QCA::PBKDF1(QStringLiteral("md2"), provider).makeKey( password,
									  iv,
									  outputLength,
									  iterationCount);
	    QCOMPARE( QCA::arrayToHex( key.toByteArray() ), output );
	}
    }
    if (!anyProviderTested) qWarning() << "NONE of the providers supports PBKDF version 1 with MD2:" << providersToTest;
}

void KDFUnitTest::pbkdf1sha1Tests_data()
{
    QTest::addColumn<QString>("secret");  // usually a password or passphrase
    QTest::addColumn<QString>("output");  // the key you get back
    QTest::addColumn<QString>("salt");    // a salt or initialisation vector
    QTest::addColumn<unsigned int>("outputLength");   // if the algo supports variable length keys, len
    QTest::addColumn<unsigned int>("iterationCount"); // number of iterations

    // These are from Botan's test suite
    QTest::newRow("1") << QStringLiteral("66746c6b6662786474626a62766c6c7662776977")
		       << QStringLiteral("768b277dc970f912dbdd3edad48ad2f065d25d")
		       << QStringLiteral("40ac5837560251c275af5e30a6a3074e57ced38e")
		       << static_cast<unsigned int>(19)
		       << static_cast<unsigned int>(6);

    QTest::newRow("2") << QStringLiteral("786e736f736d6b766867677a7370636e63706f63")
		       << QStringLiteral("4d90e846a4b6aaa02ac548014a00e97e506b2afb")
		       << QStringLiteral("7008a9dc1b9a81470a2360275c19dab77f716824")
		       << static_cast<unsigned int>(20)
		       << static_cast<unsigned int>(6);

    QTest::newRow("3") << QStringLiteral("6f74696c71776c756b717473")
		       << QStringLiteral("71ed1a995e693efcd33155935e800037da74ea28")
		       << QStringLiteral("ccfc44c09339040e55d3f7f76ca6ef838fde928717241deb9ac1a4ef45a27711")
		       << static_cast<unsigned int>(20)
		       << static_cast<unsigned int>(2001);

    QTest::newRow("4") << QStringLiteral("6b7a6e657166666c6274767374686e6663746166")
		       << QStringLiteral("f345fb8fbd880206b650266661f6")
		       << QStringLiteral("8108883fc04a01feb10661651516425dad1c93e0")
		       << static_cast<unsigned int>(14)
		       << static_cast<unsigned int>(10000);

    QTest::newRow("5") << QStringLiteral("716b78686c7170656d7868796b6d7975636a626f")
		       << QStringLiteral("2d54dfed0c7ef7d20b0945ba414a")
		       << QStringLiteral("bc8bc53d4604977c3adb1d19c15e87b77a84c2f6")
		       << static_cast<unsigned int>(14)
		       << static_cast<unsigned int>(10000);
}

void KDFUnitTest::pbkdf1sha1Tests()
{
    QFETCH(QString, secret);
    QFETCH(QString, output);
    QFETCH(QString, salt);
    QFETCH(unsigned int, outputLength);
    QFETCH(unsigned int, iterationCount);

    bool anyProviderTested = false;
    foreach(QString provider, providersToTest) {
	if(QCA::isSupported("pbkdf1(sha1)", provider)) {
	    anyProviderTested = true;
	    QCA::SecureArray password = QCA::hexToArray( secret );
	    QCA::InitializationVector iv( QCA::hexToArray( salt) );
	    QCA::PBKDF1 pbkdf = QCA::PBKDF1(QStringLiteral("sha1"), provider);
	    QCA::PBKDF1 copy = pbkdf;
	    copy.context(); // detach
	    QCA::SymmetricKey key = pbkdf.makeKey( password, iv, outputLength, iterationCount);
	    QCOMPARE( QCA::arrayToHex( key.toByteArray() ), output );
	}
    }
    if (!anyProviderTested) qWarning() << "NONE of the providers supports PBKDF version 1 with SHA1:" << providersToTest;
}

void KDFUnitTest::pbkdf1sha1TimeTest()
{
	QCA::SecureArray password("secret");
	QCA::InitializationVector iv(QByteArray("salt"));
	unsigned int outputLength = 20;
	int timeInterval = 200;
	unsigned int iterationCount;

	foreach(QString provider, providersToTest) {
		if(QCA::isSupported("pbkdf1(sha1)", provider)) {
			QCA::SymmetricKey key1(QCA::PBKDF1(QStringLiteral("sha1"), provider).makeKey(password,
																		 iv,
																		 outputLength,
																		 timeInterval,
																		 &iterationCount));

			QCA::SymmetricKey key2(QCA::PBKDF1(QStringLiteral("sha1"), provider).makeKey(password,
																		 iv,
																		 outputLength,
																		 iterationCount));

			QCOMPARE( key1, key2 );
		}
	}
}

void KDFUnitTest::pbkdf2Tests_data()
{
    QTest::addColumn<QString>("secret");  // usually a password or passphrase
    QTest::addColumn<QString>("output");  // the key you get back
    QTest::addColumn<QString>("salt");    // a salt or initialisation vector
    QTest::addColumn<unsigned int>("outputLength");   // if the algo supports variable length keys, len
    QTest::addColumn<unsigned int>("iterationCount"); // number of iterations

    // These are from Botan's test suite
    QTest::newRow("1") << QStringLiteral("6a79756571677872736367676c707864796b6366")
		       << QStringLiteral("df6d9d72872404bf73e708cf3b7d")
		       << QStringLiteral("9b56e55328a4c97a250738f8dba1b992e8a1b508")
		       << static_cast<unsigned int>(14)
		       << static_cast<unsigned int>(10000);

    QTest::newRow("2") << QStringLiteral("61717271737a6e7a76767a67746b73616d6d676f")
		       << QStringLiteral("fa13f40af1ade2a30f2fffd66fc8a659ef95e6388c1682fc0fe4d15a70109517a32942e39c371440")
		       << QStringLiteral("57487813cdd2220dfc485d932a2979ee8769ea8b")
		       << static_cast<unsigned int>(40)
		       << static_cast<unsigned int>(101);

    QTest::newRow("3") << QStringLiteral("6c7465786d666579796c6d6c62727379696b6177")
		       << QStringLiteral("027afadd48f4be8dcc4f")
		       << QStringLiteral("ed1f39a0a7f3889aaf7e60743b3bc1cc2c738e60")
		       << static_cast<unsigned int>(10)
		       << static_cast<unsigned int>(1000);

    QTest::newRow("4") << QStringLiteral("6378676e7972636772766c6c796c6f6c736a706f")
		       << QStringLiteral("7c0d009fc91b48cb6d19bafbfccff3e2ccabfe725eaa234e56bde1d551c132f2")
		       << QStringLiteral("94ac88200743fb0f6ac51be62166cbef08d94c15")
		       << static_cast<unsigned int>(32)
		       << static_cast<unsigned int>(1);

    QTest::newRow("5") << QStringLiteral("7871796668727865686965646c6865776e76626a")
		       << QStringLiteral("4661301d3517ca4443a6a607b32b2a63f69996299df75db75f1e0b98dd0eb7d8")
		       << QStringLiteral("24a1a50b17d63ee8394b69fc70887f4f94883d68")
		       << static_cast<unsigned int>(32)
		       << static_cast<unsigned int>(5);

    QTest::newRow("6") << QStringLiteral("616e6461716b706a7761627663666e706e6a6b6c")
		       << QStringLiteral("82fb44a521448d5aac94b5158ead1e4dcd7363081a747b9f7626752bda2d")
		       << QStringLiteral("9316c80801623cc2734af74bec42cf4dbaa3f6d5")
		       << static_cast<unsigned int>(30)
		       << static_cast<unsigned int>(100);

    QTest::newRow("7") << QStringLiteral("687361767679766f636c6f79757a746c736e6975")
		       << QStringLiteral("f8ec2b0ac817896ac8189d787c6424ed24a6d881436687a4629802c0ecce")
		       << QStringLiteral("612cc61df3cf2bdb36e10c4d8c9d73192bddee05")
		       << static_cast<unsigned int>(30)
		       << static_cast<unsigned int>(100);

    QTest::newRow("8") << QStringLiteral("6561696d72627a70636f706275736171746b6d77")
		       << QStringLiteral("c9a0b2622f13916036e29e7462e206e8ba5b50ce9212752eb8ea2a4aa7b40a4cc1bf")
		       << QStringLiteral("45248f9d0cebcb86a18243e76c972a1f3b36772a")
		       << static_cast<unsigned int>(34)
		       << static_cast<unsigned int>(100);

    QTest::newRow("9") << QStringLiteral("67777278707178756d7364736d626d6866686d666463766c63766e677a6b6967")
		       << QStringLiteral("4c9db7ba24955225d5b845f65ef24ef1b0c6e86f2e39c8ddaa4b8abd26082d1f350381fadeaeb560dc447afc68a6b47e6ea1e7412f6cf7b2d82342fccd11d3b4")
		       << QStringLiteral("a39b76c6eec8374a11493ad08c246a3e40dfae5064f4ee3489c273646178")
		       << static_cast<unsigned int>(64)
		       << static_cast<unsigned int>(1000);

}

void KDFUnitTest::pbkdf2Tests()
{
    QFETCH(QString, secret);
    QFETCH(QString, output);
    QFETCH(QString, salt);
    QFETCH(unsigned int, outputLength);
    QFETCH(unsigned int, iterationCount);


    bool anyProviderTested = false;
    foreach(QString provider, providersToTest) {
	if(QCA::isSupported("pbkdf2(sha1)", provider)) {
	    anyProviderTested = true;
	    QCA::SecureArray password = QCA::hexToArray( secret );
	    QCA::InitializationVector iv( QCA::hexToArray( salt) );
	    QCA::PBKDF2 pbkdf = QCA::PBKDF2(QStringLiteral("sha1"), provider);
	    QCA::PBKDF2 copy = pbkdf;
	    copy.context(); // detach
	    QCA::SymmetricKey key = pbkdf.makeKey( password, iv, outputLength, iterationCount);
	    QCOMPARE( QCA::arrayToHex( key.toByteArray() ), output );

	}
    }

    if (!anyProviderTested) qWarning() << "NONE of the providers supports PBKDF version 2 with SHA1:" << providersToTest;
}

void KDFUnitTest::pbkdf2TimeTest()
{
	QCA::SecureArray password("secret");
	QCA::InitializationVector iv(QByteArray("salt"));
	unsigned int outputLength = 20;
	int timeInterval = 200;
	unsigned int iterationCount;

	foreach(QString provider, providersToTest) {
		if(QCA::isSupported("pbkdf2(sha1)", provider)) {
			QCA::SymmetricKey key1(QCA::PBKDF2(QStringLiteral("sha1"), provider).makeKey(password,
																		 iv,
																		 outputLength,
																		 timeInterval,
																		 &iterationCount));

			QCA::SymmetricKey key2(QCA::PBKDF2(QStringLiteral("sha1"), provider).makeKey(password,
																		 iv,
																		 outputLength,
																		 iterationCount));

			QCOMPARE( key1, key2 );
		}
	}
}

void KDFUnitTest::pbkdf2extraTests()
{
    foreach(QString provider, providersToTest) {
	if(QCA::isSupported("pbkdf2(sha1)", provider)) {
	    // Not sure where this one came from...
	    {
		QCA::InitializationVector salt(QCA::SecureArray("what do ya want for nothing?"));
		QCA::SecureArray password("Jefe");
		int iterations = 1000;
		QCA::SymmetricKey passwordOut = QCA::PBKDF2(QStringLiteral("sha1"), provider).makeKey (password, salt, 16, iterations);
		QCOMPARE( QCA::arrayToHex(passwordOut.toByteArray()), QStringLiteral( "6349e09cb6b8c1485cfa9780ee3264df" ) );
	    }

	    // RFC3962, Appendix B
	    {
		QCA::InitializationVector salt(QCA::SecureArray("ATHENA.MIT.EDUraeburn"));
		QCA::SecureArray password("password");
		int iterations = 1;
		QCA::SymmetricKey passwordOut = QCA::PBKDF2(QStringLiteral("sha1"), provider).makeKey (password, salt, 16, iterations);
		QCOMPARE( QCA::arrayToHex(passwordOut.toByteArray()), QStringLiteral( "cdedb5281bb2f801565a1122b2563515" ) );
		passwordOut = QCA::PBKDF2(QStringLiteral("sha1"), provider).makeKey (password, salt, 32, iterations);
		QCOMPARE( QCA::arrayToHex(passwordOut.toByteArray()),
			  QStringLiteral( "cdedb5281bb2f801565a1122b25635150ad1f7a04bb9f3a333ecc0e2e1f70837" ) );
	    }

	    // RFC3962, Appendix B
	    {
		QCA::InitializationVector salt(QCA::SecureArray("ATHENA.MIT.EDUraeburn"));
		QCA::SecureArray password("password");
		int iterations = 2;
		QCA::SymmetricKey passwordOut = QCA::PBKDF2(QStringLiteral("sha1"), provider).makeKey (password, salt, 16, iterations);
		QCOMPARE( QCA::arrayToHex(passwordOut.toByteArray()), QStringLiteral( "01dbee7f4a9e243e988b62c73cda935d" ) );
		passwordOut = QCA::PBKDF2(QStringLiteral("sha1"), provider).makeKey (password, salt, 32, iterations);
		QCOMPARE( QCA::arrayToHex(passwordOut.toByteArray()),
			  QStringLiteral( "01dbee7f4a9e243e988b62c73cda935da05378b93244ec8f48a99e61ad799d86" ) );
	    }

	    // RFC3962, Appendix B
	    {
		QCA::InitializationVector salt(QCA::SecureArray("ATHENA.MIT.EDUraeburn"));
		QCA::SecureArray password("password");
		int iterations = 1200;
		QCA::SymmetricKey passwordOut = QCA::PBKDF2(QStringLiteral("sha1"), provider).makeKey (password, salt, 16, iterations);
		QCOMPARE( QCA::arrayToHex(passwordOut.toByteArray()), QStringLiteral( "5c08eb61fdf71e4e4ec3cf6ba1f5512b" ) );
		passwordOut = QCA::PBKDF2(QStringLiteral("sha1"), provider).makeKey (password, salt, 32, iterations);
		QCOMPARE( QCA::arrayToHex(passwordOut.toByteArray()),
			  QStringLiteral( "5c08eb61fdf71e4e4ec3cf6ba1f5512ba7e52ddbc5e5142f708a31e2e62b1e13" ) );
	    }

	    // RFC3211 and RFC3962, Appendix B
	    {
		QCA::InitializationVector salt(QCA::hexToArray(QStringLiteral("1234567878563412")));
		QCA::SecureArray password("password");
		int iterations = 5;
		QCA::SymmetricKey passwordOut = QCA::PBKDF2(QStringLiteral("sha1"), provider).makeKey (password, salt, 16, iterations);
		QCOMPARE( QCA::arrayToHex(passwordOut.toByteArray()), QStringLiteral( "d1daa78615f287e6a1c8b120d7062a49" ) );
		passwordOut = QCA::PBKDF2(QStringLiteral("sha1"), provider).makeKey (password, salt, 32, iterations);
		QCOMPARE( QCA::arrayToHex(passwordOut.toByteArray()),
			  QStringLiteral( "d1daa78615f287e6a1c8b120d7062a493f98d203e6be49a6adf4fa574b6e64ee" ) );
		passwordOut = QCA::PBKDF2().makeKey (password, salt, 8, iterations);
		QCOMPARE( QCA::arrayToHex(passwordOut.toByteArray()),
			  QStringLiteral( "d1daa78615f287e6" ) );
	    }

	    // RFC3962, Appendix B
	    {
		QCA::InitializationVector salt(QCA::SecureArray("pass phrase equals block size"));
		QCA::SecureArray password("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
		int iterations = 1200;
		QCA::SymmetricKey passwordOut = QCA::PBKDF2(QStringLiteral("sha1"), provider).makeKey (password, salt, 16, iterations);
		QCOMPARE( QCA::arrayToHex(passwordOut.toByteArray()), QStringLiteral( "139c30c0966bc32ba55fdbf212530ac9" ) );
		passwordOut = QCA::PBKDF2(QStringLiteral("sha1"), provider).makeKey (password, salt, 32, iterations);
		QCOMPARE( QCA::arrayToHex(passwordOut.toByteArray()),
			  QStringLiteral( "139c30c0966bc32ba55fdbf212530ac9c5ec59f1a452f5cc9ad940fea0598ed1" ) );
	    }

	    // RFC3962, Appendix B
	    {
		try {
		    QCA::InitializationVector salt(QCA::SecureArray("pass phrase exceeds block size"));
		    QCA::SecureArray password("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");
		    int iterations = 1200;
		    QCA::SymmetricKey passwordOut = QCA::PBKDF2(QStringLiteral("sha1"), provider).makeKey (password, salt, 16, iterations);
		    QCOMPARE( QCA::arrayToHex(passwordOut.toByteArray()), QStringLiteral( "9ccad6d468770cd51b10e6a68721be61" ) );
		    passwordOut = QCA::PBKDF2(QStringLiteral("sha1"), provider).makeKey (password, salt, 32, iterations);
		    QCOMPARE( QCA::arrayToHex(passwordOut.toByteArray()),
			      QStringLiteral( "9ccad6d468770cd51b10e6a68721be611a8b4d282601db3b36be9246915ec82a" ) );
		} catch(std::exception &) {
		    if (provider == QLatin1String("qca-botan"))
			qDebug() << "You should use a later version of Botan";
		    else
			QFAIL("exception");
		}
	    }

	    // RFC3962, Appendix B
	    {
		QCA::InitializationVector salt(QCA::SecureArray("EXAMPLE.COMpianist"));
		QCA::SecureArray password(QCA::hexToArray(QStringLiteral("f09d849e")));
		int iterations = 50;
		QCA::SymmetricKey passwordOut = QCA::PBKDF2(QStringLiteral("sha1"), provider).makeKey (password, salt, 16, iterations);
		QCOMPARE( QCA::arrayToHex(passwordOut.toByteArray()), QStringLiteral( "6b9cf26d45455a43a5b8bb276a403b39" ) );
		passwordOut = QCA::PBKDF2(QStringLiteral("sha1"), provider).makeKey (password, salt, 32, iterations);
		QCOMPARE( QCA::arrayToHex(passwordOut.toByteArray()),
			  QStringLiteral( "6b9cf26d45455a43a5b8bb276a403b39e7fe37a0c41e02c281ff3069e1e94f52" ) );
	    }
	}
    }
}

void KDFUnitTest::hkdfTests_data()
{
    QTest::addColumn<QString>("secret");  // usually a password or passphrase
    QTest::addColumn<QString>("salt");    // a salt or initialisation vector
    QTest::addColumn<QString>("info");    // an additional info
    QTest::addColumn<QString>("output");  // the key you get back

    // RFC 5869, Appendix A
    QTest::newRow("1") << QStringLiteral("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
		       << QStringLiteral("000102030405060708090a0b0c")
		       << QStringLiteral("f0f1f2f3f4f5f6f7f8f9")
		       << QStringLiteral("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");

    QTest::newRow("2") << QStringLiteral("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f")
		       << QStringLiteral("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
		       << QStringLiteral("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
		       << QStringLiteral("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87");

    QTest::newRow("3") << QStringLiteral("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
		       << QString()
		       << QString()
		       << QStringLiteral("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");
}

void KDFUnitTest::hkdfTests()
{
    QFETCH(QString, secret);
    QFETCH(QString, salt);
    QFETCH(QString, info);
    QFETCH(QString, output);

    bool anyProviderTested = false;
    foreach(QString provider, providersToTest) {
	if(QCA::isSupported("hkdf(sha256)", provider)) {
	    anyProviderTested = true;
	    QCA::SecureArray password = QCA::hexToArray( secret );
	    QCA::InitializationVector saltv( QCA::hexToArray( salt ) );
	    QCA::InitializationVector infov( QCA::hexToArray( info ) );
	    QCA::HKDF hkdf = QCA::HKDF(QStringLiteral("sha256"), provider);
	    QCA::HKDF copy = hkdf;
	    copy.context(); // detach

	    QCA::SymmetricKey key = hkdf.makeKey( password,
								   saltv,
								   infov,
								   output.size() / 2 );
	    QCOMPARE( QCA::arrayToHex( key.toByteArray() ), output );

	}
    }
    if (!anyProviderTested) qWarning() << "NONE of the providers supports HKDF version 1 with SHA256:" << providersToTest;
}

QTEST_MAIN(KDFUnitTest)

#include "kdfunittest.moc"

