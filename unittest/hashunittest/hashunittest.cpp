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
#include <QFile>

#ifdef QT_STATICPLUGIN
#include "import_plugins.h"
#endif

class HashUnitTest : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void initTestCase();
    void cleanupTestCase();
    void md2test_data();
    void md2test();
    void md4test_data();
    void md4test();
    void md5test_data();
    void md5test();
    void md5filetest();
    void sha0test_data();
    void sha0test();
    void sha0longtest();
    void sha1test_data();
    void sha1test();
    void sha1longtest();
    void sha224test_data();
    void sha224test();
    void sha224longtest();
    void sha256test_data();
    void sha256test();
    void sha256longtest();
    void sha384test_data();
    void sha384test();
    void sha384longtest();
    void sha512test_data();
    void sha512test();
    void sha512longtest();
    void rmd160test_data();
    void rmd160test();
    void rmd160longtest();
    void whirlpooltest_data();
    void whirlpooltest();
    void whirlpoollongtest();
private:
    QCA::Initializer* m_init;
    QStringList providersToTest;
};

void HashUnitTest::initTestCase()
{
    m_init = new QCA::Initializer;
    const auto providers = QCA::providers();
    for(QCA::Provider *provider : providers)
        providersToTest << provider->name();
}

void HashUnitTest::cleanupTestCase()
{
    QCA::unloadAllPlugins();
    delete m_init;
}

void HashUnitTest::md2test_data()
{
    // These are as specified in RFC 1319
    QTest::addColumn<QByteArray>("input");
    QTest::addColumn<QString>("expectedHash");

    QTest::newRow("md2()") << QByteArray("") << QStringLiteral("8350e5a3e24c153df2275c9f80692773");
    QTest::newRow("md2(a)") << QByteArray("a") << QStringLiteral("32ec01ec4a6dac72c0ab96fb34c0b5d1");
    QTest::newRow("md2(abc)") << QByteArray("abc")
			   << QStringLiteral("da853b0d3f88d99b30283a69e6ded6bb");
    QTest::newRow("md2(messageDigest)") << QByteArray("message digest")
				     << QStringLiteral("ab4f496bfb2a530b219ff33031fe06b0");
    QTest::newRow("md2([a-z])") << QByteArray("abcdefghijklmnopqrstuvwxyz")
			     << QStringLiteral("4e8ddff3650292ab5a4108c3aa47940b");
    QTest::newRow("md2([A-z,0-9])") << QByteArray("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
				 << QStringLiteral("da33def2a42df13975352846c30338cd");
    QTest::newRow("md2(nums)") << QByteArray("12345678901234567890123456789012345678901234567890123456789012345678901234567890")
			     << QStringLiteral("d5976f79d83d3a0dc9806c3c66f3efd8");
}

void HashUnitTest::md2test()
{
    QFETCH(QByteArray, input);
    QFETCH(QString, expectedHash);

    bool anyProviderTested = false;
    foreach(QString provider, providersToTest) {
	if(QCA::isSupported("md2", provider)) {
	    anyProviderTested = true;

	    QCA::Hash hash = QCA::Hash(QStringLiteral("md2"), provider);
	    QCA::Hash copy = hash;
	    copy.context(); // detach

	    QCOMPARE( hash.hashToString(input), expectedHash );
	    QCOMPARE( copy.hashToString(input), expectedHash );
	}
    }
    if (!anyProviderTested) qWarning() << "NONE of the providers supports MD2:" << providersToTest;

}

void HashUnitTest::md4test_data()
{
    // These are as specified in RFC 1320
    QTest::addColumn<QByteArray>("input");
    QTest::addColumn<QString>("expectedHash");

    QTest::newRow("md4()") << QByteArray("") << QStringLiteral("31d6cfe0d16ae931b73c59d7e0c089c0");
    QTest::newRow("md4(a)") << QByteArray("a") << QStringLiteral("bde52cb31de33e46245e05fbdbd6fb24");
    QTest::newRow("md4(abc)") << QByteArray("abc")
			   << QStringLiteral("a448017aaf21d8525fc10ae87aa6729d");
    QTest::newRow("md4(messageDigest)") << QByteArray("message digest")
				     << QStringLiteral("d9130a8164549fe818874806e1c7014b");
    QTest::newRow("md4([a-z])") << QByteArray("abcdefghijklmnopqrstuvwxyz")
			     << QStringLiteral("d79e1c308aa5bbcdeea8ed63df412da9");
    QTest::newRow("md4([A-z,0-9])") << QByteArray("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
				 << QStringLiteral("043f8582f241db351ce627e153e7f0e4");
    QTest::newRow("md4(nums)") << QByteArray("12345678901234567890123456789012345678901234567890123456789012345678901234567890")
			    << QStringLiteral("e33b4ddc9c38f2199c3e7b164fcc0536");
}


void HashUnitTest::md4test()
{
    bool anyProviderTested = false;
    QFETCH(QByteArray, input);
    QFETCH(QString, expectedHash);

    foreach(QString provider, providersToTest) {
	if(QCA::isSupported("md4", provider)) {
	    anyProviderTested = true;

	    QCA::Hash hash = QCA::Hash(QStringLiteral("md4"), provider);
	    QCA::Hash copy = hash;
	    hash.context(); // detach

	    QCOMPARE( hash.hashToString(input), expectedHash );
	    QCOMPARE( copy.hashToString(input), expectedHash );
	}
    }
    if (!anyProviderTested) qWarning() << "NONE of the providers supports MD4:" << providersToTest;
}

void HashUnitTest::md5test_data()
{
    // These are as specified in RFC 1321
    // They also match Australian Standard (AS) 2805.1.3.2-2000 Appendix A
    QTest::addColumn<QByteArray>("input");
    QTest::addColumn<QString>("expectedHash");

    QTest::newRow("md5()") << QByteArray("") << QStringLiteral("d41d8cd98f00b204e9800998ecf8427e");
    QTest::newRow("md5(a)") << QByteArray("a") << QStringLiteral("0cc175b9c0f1b6a831c399e269772661");
    QTest::newRow("md5(abc)") << QByteArray("abc")
			   << QStringLiteral("900150983cd24fb0d6963f7d28e17f72");
    QTest::newRow("md5(messageDigest)") << QByteArray("message digest")
				     << QStringLiteral("f96b697d7cb7938d525a2f31aaf161d0");
    QTest::newRow("md5([a-z])") << QByteArray("abcdefghijklmnopqrstuvwxyz")
			     << QStringLiteral("c3fcd3d76192e4007dfb496cca67e13b");
    QTest::newRow("md5([A-z,0-9])") << QByteArray("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
				 << QStringLiteral("d174ab98d277d9f5a5611c2c9f419d9f");
    QTest::newRow("md5(nums)") << QByteArray("12345678901234567890123456789012345678901234567890123456789012345678901234567890")
					<< QStringLiteral("57edf4a22be3c955ac49da2e2107b67a");
}

void HashUnitTest::md5test()
{
    bool anyProviderTested = false;
    QFETCH(QByteArray, input);
    QFETCH(QString, expectedHash);

    foreach(QString provider, providersToTest) {
	if(QCA::isSupported("md5", provider)) {
	    anyProviderTested = true;

	    QCA::Hash hash = QCA::Hash(QStringLiteral("md5"), provider);
	    QCA::Hash copy = hash;
	    hash.context(); // detach

	    QCOMPARE( hash.hashToString(input), expectedHash );
	    QCOMPARE( copy.hashToString(input), expectedHash );
	}
    }
    if (!anyProviderTested) qWarning() << "NONE of the providers supports MD2:" << providersToTest;
}


void HashUnitTest::md5filetest()
{
    foreach(QString provider, providersToTest) {
	if(!QCA::isSupported("md5", provider)) {
	    QFile f1( QStringLiteral(TEST_DATA_DIR "/data/empty") );
	    QVERIFY( f1.open( QIODevice::ReadOnly ) );
	    {
		QCA::Hash hashObj(QStringLiteral("md5"), provider);
		hashObj.update( &f1 );
		QCOMPARE( QString( QCA::arrayToHex( hashObj.final().toByteArray() ) ),
			    QStringLiteral( "d41d8cd98f00b204e9800998ecf8427e" ) );
	    }

	    QFile f2( QStringLiteral(TEST_DATA_DIR "/data/twobytes") );
	    QVERIFY( f2.open( QIODevice::ReadOnly ) );
	    {
		QCA::Hash hashObj(QStringLiteral("md5"), provider);
		hashObj.update( &f2 );
		QCOMPARE( QString( QCA::arrayToHex( hashObj.final().toByteArray() ) ),
			    QStringLiteral( "5fc9808ed18e442ab4164c59f151e757" ) );
	    }


	    QFile f3( QStringLiteral(TEST_DATA_DIR "/data/twohundredbytes") );
	    QVERIFY( f3.open( QIODevice::ReadOnly ) );
	    {
		QCA::Hash hashObj(QStringLiteral("md5"), provider);
		hashObj.update( &f3 );
		QCOMPARE( QString( QCA::arrayToHex( hashObj.final().toByteArray() ) ),
			    QStringLiteral( "b91c1f114d942520ecdf7e84e580cda3" ) );
	    }
	}
    }
}

void HashUnitTest::sha0test_data()
{
    // These are extracted from OpenOffice.org 1.1.2, in sal/workben/t_digest.c
    // Check FIPS 180-1?
    QTest::addColumn<QByteArray>("input");
    QTest::addColumn<QString>("expectedHash");

    QTest::newRow("sha0(abc)") << QByteArray("abc") << QStringLiteral("0164b8a914cd2a5e74c4f7ff082c4d97f1edf880");
    QTest::newRow("sha0(abc)") << QByteArray("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
			    << QStringLiteral("d2516ee1acfa5baf33dfc1c471e438449ef134c8");
}

void HashUnitTest::sha0test()
{
    bool anyProviderTested = false;
    QFETCH(QByteArray, input);
    QFETCH(QString, expectedHash);

    foreach(QString provider, providersToTest) {
	if(QCA::isSupported("sha0", provider)) {
	    anyProviderTested = true;

	    QCA::Hash hash = QCA::Hash(QStringLiteral("sha0"), provider);
	    QCA::Hash copy = hash;
	    hash.context(); // detach

	    QCOMPARE( hash.hashToString(input), expectedHash );
	    QCOMPARE( copy.hashToString(input), expectedHash );
	}
    }
    if (!anyProviderTested) qWarning() << "NONE of the providers supports SHA0:" << providersToTest;
}

void HashUnitTest::sha0longtest()
{
    QByteArray fillerString;
    fillerString.fill('a', 1000);

    // This test extracted from OpenOffice.org 1.1.2, in sal/workben/t_digest.c

    foreach(QString provider, providersToTest) {
	if(QCA::isSupported("sha0", provider)) {
	    QCA::Hash shaHash(QStringLiteral("sha0"), provider);
	    for (int i=0; i<1000; i++)
		shaHash.update(fillerString);
	    QCOMPARE( QString(QCA::arrayToHex(shaHash.final().toByteArray())),
		     QStringLiteral("3232affa48628a26653b5aaa44541fd90d690603" ) );

	    shaHash.clear();
	    for (int i=0; i<1000; i++)
		shaHash.update(fillerString);
	    QCOMPARE( QString(QCA::arrayToHex(shaHash.final().toByteArray())),
		     QStringLiteral("3232affa48628a26653b5aaa44541fd90d690603" ) );
	}
    }
}

void HashUnitTest::sha1test_data()
{
    // These are as specified in FIPS 180-2. Matches RFC3174
    // Some additions from Australian Standard (AS) 2805.13.3-2000
    QTest::addColumn<QByteArray>("input");
    QTest::addColumn<QString>("expectedHash");

    // FIPS 180-2, Appendix A.1
    QTest::newRow("sha1(abc)") << QByteArray("abc") << QStringLiteral("a9993e364706816aba3e25717850c26c9cd0d89d");

    // FIPS 180-2, Appendix A.2
    QTest::newRow("sha1(a-q)") << QByteArray("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
			    << QStringLiteral("84983e441c3bd26ebaae4aa1f95129e5e54670f1");

    // AS 2805.13.3-200 Appendix A
    // also has some duplicates from FIPS 180-2
    QTest::newRow("sha1()") << QByteArray("") << QStringLiteral("da39a3ee5e6b4b0d3255bfef95601890afd80709");
    QTest::newRow("sha1(a)") << QByteArray("a") << QStringLiteral("86f7e437faa5a7fce15d1ddcb9eaeaea377667b8");
    QTest::newRow("sha1(a-z)") << QByteArray("abcdefghijklmnopqrstuvwxyz")
			    << QStringLiteral("32d10c7b8cf96570ca04ce37f2a19d84240d3a89");
}

void HashUnitTest::sha1test()
{
    bool anyProviderTested = false;
    QFETCH(QByteArray, input);
    QFETCH(QString, expectedHash);

    foreach(QString provider, providersToTest) {
	if(QCA::isSupported("sha1", provider)) {
	    anyProviderTested = true;

	    QCA::Hash hash = QCA::Hash(QStringLiteral("sha1"), provider);
	    QCA::Hash copy = hash;
	    hash.context(); // detach

	    QCOMPARE( hash.hashToString(input), expectedHash );
	    QCOMPARE( copy.hashToString(input), expectedHash );
	}
    }
    if (!anyProviderTested) qWarning() << "NONE of the providers supports SHA1:" << providersToTest;
}

void HashUnitTest::sha1longtest()
{
    foreach(QString provider, providersToTest) {
	if(QCA::isSupported("sha1", provider)) {
	    // QTime t;
	    // t.start();
	    QByteArray fillerString;
	    fillerString.fill('a', 1000);

	    // This test extracted from OpenOffice.org 1.1.2, in sal/workben/t_digest.c
	    // It basically reflects FIPS 180-2, Appendix A.3
	    // Also as per AS 2805.13.3-2000 Appendix A
	    QCA::Hash shaHash(QStringLiteral("sha1"), provider);
	    for (int i=0; i<1000; i++)
		shaHash.update(fillerString);
	    QCOMPARE( QString(QCA::arrayToHex(shaHash.final().toByteArray())),
		     QStringLiteral("34aa973cd4c4daa4f61eeb2bdbad27316534016f") );

	    QFile f1( QStringLiteral(TEST_DATA_DIR "/data/empty") );
	    QVERIFY( f1.open( QIODevice::ReadOnly ) );
	    {
		QCA::Hash hashObj(QStringLiteral("sha1"), provider);
		hashObj.update( &f1 );
		QCOMPARE( QString( QCA::arrayToHex( hashObj.final().toByteArray() ) ),
			    QStringLiteral( "da39a3ee5e6b4b0d3255bfef95601890afd80709" ) );
	    }

	    QFile f2( QStringLiteral(TEST_DATA_DIR "/data/twobytes") );
	    QVERIFY( f2.open( QIODevice::ReadOnly ) );
	    {
		QCA::Hash hashObj(QStringLiteral("sha1"), provider);
		hashObj.update( &f2 );
		QCOMPARE( QString( QCA::arrayToHex( hashObj.final().toByteArray() ) ),
			    QStringLiteral( "efbd6de3c51ca16094391e837bf52f7452593e5c" ) );
	    }

	    QFile f3( QStringLiteral(TEST_DATA_DIR "/data/twohundredbytes") );
	    QVERIFY( f3.open( QIODevice::ReadOnly ) );
	    {
		QCA::Hash hashObj(QStringLiteral("sha1"), provider);
		hashObj.update( &f3 );
		QCOMPARE( QString( QCA::arrayToHex( hashObj.final().toByteArray() ) ),
			    QStringLiteral( "d636519dfb18d913acbe69fc3ee5a4c7ac870297" ) );
	    }
	}
    }
}

void HashUnitTest::sha224test_data()
{
    QTest::addColumn<QByteArray>("input");
    QTest::addColumn<QString>("expectedHash");

    // These are as specified in FIPS 180-2, change notice 1

    // FIPS 180-2, Appendix B.1
    QTest::newRow("sha224(abc)") << QByteArray("abc") << QStringLiteral("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");

    // FIPS 180-2, Appendix B.2
    QTest::newRow("sha224(aq)") << QByteArray("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
			      << QStringLiteral("75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525");
}

void HashUnitTest::sha224test()
{
    bool anyProviderTested = false;
    QFETCH(QByteArray, input);
    QFETCH(QString, expectedHash);

    foreach(QString provider, providersToTest) {
	if(QCA::isSupported("sha224", provider)) {
	    anyProviderTested = true;

	    QCA::Hash hash = QCA::Hash(QStringLiteral("sha224"), provider);
	    QCA::Hash copy = hash;
	    hash.context(); // detach

	    QCOMPARE( hash.hashToString(input), expectedHash );
	    QCOMPARE( copy.hashToString(input), expectedHash );
	}
    }
    if (!anyProviderTested) qWarning() << "NONE of the providers supports SHA224:" << providersToTest;
}


void HashUnitTest::sha224longtest()
{
    QByteArray fillerString;
    fillerString.fill('a', 1000);

    foreach(QString provider, providersToTest) {
	if(QCA::isSupported("sha224", provider)) {
	    QCA::Hash shaHash(QStringLiteral("sha224"), provider);

	    // This basically reflects FIPS 180-2, change notice 1, section 3
	    for (int i=0; i<1000; i++)
		shaHash.update(fillerString);
	    QCOMPARE( QString(QCA::arrayToHex(shaHash.final().toByteArray())),
		     QStringLiteral("20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67") );

	    shaHash.clear();
	    for (int i=0; i<1000; i++)
		shaHash.update(fillerString);
	    QCOMPARE( QString(QCA::arrayToHex(shaHash.final().toByteArray())),
		     QStringLiteral("20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67") );
	}
    }
}

void HashUnitTest::sha256test_data()
{
    QTest::addColumn<QByteArray>("input");
    QTest::addColumn<QString>("expectedHash");

    // These are as specified in FIPS 180-2

    // FIPS 180-2, Appendix B.1
    QTest::newRow("sha256(abc)") << QByteArray("abc") << QStringLiteral("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    // FIPS 180-2, Appendix B.2
    QTest::newRow("sha256(abc)") << QByteArray("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
			      << QStringLiteral("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

void HashUnitTest::sha256test()
{
    bool anyProviderTested = false;
    QFETCH(QByteArray, input);
    QFETCH(QString, expectedHash);

    foreach(QString provider, providersToTest) {
	if(QCA::isSupported("sha256", provider)) {
	    anyProviderTested = true;

	    QCA::Hash hash = QCA::Hash(QStringLiteral("sha256"), provider);
	    QCA::Hash copy = hash;
	    hash.context(); // detach

	    QCOMPARE( hash.hashToString(input), expectedHash );
	    QCOMPARE( copy.hashToString(input), expectedHash );
	}
    }
    if (!anyProviderTested) qWarning() << "NONE of the providers supports SHA256:" << providersToTest;
}

void HashUnitTest::sha256longtest()
{
    QByteArray fillerString;
    fillerString.fill('a', 1000);

    foreach(QString provider, providersToTest) {
	if(QCA::isSupported("sha256", provider)) {
	    QCA::Hash shaHash(QStringLiteral("sha256"), provider);

	    // This basically reflects FIPS 180-2, change notice 1, section 3
	    for (int i=0; i<1000; i++)
		shaHash.update(fillerString);
	    QCOMPARE( QString(QCA::arrayToHex(shaHash.final().toByteArray())),
		     QStringLiteral("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0") );


	    shaHash.clear();
	    for (int i=0; i<1000; i++)
		shaHash.update(fillerString);
	    QCOMPARE( QString(QCA::arrayToHex(shaHash.final().toByteArray())),
		     QStringLiteral("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0") );
	}
    }
}


void HashUnitTest::sha384test_data()
{
    QTest::addColumn<QByteArray>("input");
    QTest::addColumn<QString>("expectedHash");

    // These are as specified in FIPS 180-2, and from Aaron Gifford's SHA2 tests

    // FIPS 180-2, Appendix B.1
    QTest::newRow("sha384(abc)") << QByteArray("abc")
			      << QStringLiteral("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");

    // FIPS 180-2, Appendix B.2
    QTest::newRow("sha384(a-u)") << QByteArray("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")
			      << QStringLiteral("09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039");

    // Aaron Gifford, vector002.info
    QTest::newRow("sha384(a-q)") << QByteArray("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
			      << QStringLiteral("3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b");


}

void HashUnitTest::sha384test()
{
    bool anyProviderTested = false;
    QFETCH(QByteArray, input);
    QFETCH(QString, expectedHash);

    foreach(QString provider, providersToTest) {
	if(QCA::isSupported("sha384", provider)) {
	    anyProviderTested = true;

	    QCA::Hash hash = QCA::Hash(QStringLiteral("sha384"), provider);
	    QCA::Hash copy = hash;
	    hash.context(); // detach

	    QCOMPARE( hash.hashToString(input), expectedHash );
	    QCOMPARE( copy.hashToString(input), expectedHash );

	}
    }
    if (!anyProviderTested) qWarning() << "NONE of the providers supports SHA384:" << providersToTest;
}

void HashUnitTest::sha384longtest()
{
    QByteArray fillerString;
    fillerString.fill('a', 1000);

    foreach(QString provider, providersToTest) {
	if(!QCA::isSupported("sha384", provider)) {
	    // QTime t;
	    // t.start();
	    QCA::Hash shaHash(QStringLiteral("sha384"), provider);

	    // This basically reflects FIPS 180-2, change notice 1, section 3
	    for (int i=0; i<1000; i++)
		shaHash.update(fillerString);
	    QCOMPARE( QString(QCA::arrayToHex(shaHash.final().toByteArray())),
		     QStringLiteral("9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985") );


	    shaHash.clear();
	    for (int i=0; i<1000; i++)
		shaHash.update(fillerString);
	    QCOMPARE( QString(QCA::arrayToHex(shaHash.final().toByteArray())),
		     QStringLiteral("9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985") );
	    // qDebug() << "SHA384: " << provider << " elapsed " << t.elapsed();
	}
    }
}


// These are as specified in FIPS 180-2, and from Aaron Gifford's SHA2 tests
void HashUnitTest::sha512test_data()
{
    QTest::addColumn<QByteArray>("input");
    QTest::addColumn<QString>("expectedHash");

    // FIPS 180-2, Appendix C.1
    QTest::newRow("sha512(abc)") << QByteArray("abc")
			      << QStringLiteral("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    // FIPS 180-2, Appendix C.2
    QTest::newRow("sha512(a-u)") << QByteArray("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")
			      << QStringLiteral("8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");

    // Aaron Gifford, vector002.info
    QTest::newRow("sha512(a-q)") << QByteArray("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
			      << QStringLiteral("204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445");
}

void HashUnitTest::sha512test()
{
    bool anyProviderTested = false;
    QFETCH(QByteArray, input);
    QFETCH(QString, expectedHash);

    foreach(QString provider, providersToTest) {
	if(QCA::isSupported("sha512", provider)) {
	    anyProviderTested = true;

	    QCA::Hash hash = QCA::Hash(QStringLiteral("sha512"), provider);
	    QCA::Hash copy = hash;
	    hash.context(); // detach

	    QCOMPARE( hash.hashToString(input), expectedHash );
	    QCOMPARE( copy.hashToString(input), expectedHash );
	}
    }
    if (!anyProviderTested) qWarning() << "NONE of the providers supports SHA512:" << providersToTest;
}

void HashUnitTest::sha512longtest()
{
    QByteArray fillerString;
    fillerString.fill('a', 1000);

    foreach(QString provider, providersToTest) {
	if(QCA::isSupported("sha512", provider)) {
	    QCA::Hash shaHash(QStringLiteral("sha512"), provider);

	    // This basically reflects FIPS 180-2, change notice 1, section 3
	    for (int i=0; i<1000; i++)
		shaHash.update(fillerString);
	    QCOMPARE( QString(QCA::arrayToHex(shaHash.final().toByteArray())),
		     QStringLiteral("e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b") );

	    shaHash.clear();
	    for (int i=0; i<1000; i++)
		shaHash.update(fillerString);
	    QCOMPARE( QString(QCA::arrayToHex(shaHash.final().toByteArray())),
		     QStringLiteral("e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b") );
	}
    }
}

// These are as specified in http://www.esat.kuleuven.ac.be/~bosselae/ripemd160.html
// ISO/IEC 10118-3 costs a bit of money.
void HashUnitTest::rmd160test_data()
{
    QTest::addColumn<QByteArray>("input");
    QTest::addColumn<QString>("expectedHash");

    QTest::newRow("rmd160()") << QByteArray("") << QStringLiteral("9c1185a5c5e9fc54612808977ee8f548b2258d31");
    QTest::newRow("rmd160(a)") << QByteArray("a") << QStringLiteral("0bdc9d2d256b3ee9daae347be6f4dc835a467ffe");
    QTest::newRow("rmd160(abc)") << QByteArray("abc") << QStringLiteral("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
    QTest::newRow("rmd160(md)") << QByteArray("message digest") << QStringLiteral("5d0689ef49d2fae572b881b123a85ffa21595f36");
    QTest::newRow("rmd160(a-z)") << QByteArray("abcdefghijklmnopqrstuvwxyz") << QStringLiteral("f71c27109c692c1b56bbdceb5b9d2865b3708dbc");
    QTest::newRow("rmd160(a-q)") << QByteArray("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
			      << QStringLiteral("12a053384a9c0c88e405a06c27dcf49ada62eb2b");
    QTest::newRow("rmd160(A-9)") << QByteArray("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
			      << QStringLiteral("b0e20b6e3116640286ed3a87a5713079b21f5189");
    QTest::newRow("rmd160(1-0)") << QByteArray("12345678901234567890123456789012345678901234567890123456789012345678901234567890")
			      << QStringLiteral("9b752e45573d4b39f4dbd3323cab82bf63326bfb");
}


void HashUnitTest::rmd160test()
{
    bool anyProviderTested = false;
    QFETCH(QByteArray, input);
    QFETCH(QString, expectedHash);

    foreach(QString provider, providersToTest) {
	if(QCA::isSupported("ripemd160", provider)) {
	    anyProviderTested = true;

	    QCA::Hash hash = QCA::Hash(QStringLiteral("ripemd160"), provider);
	    QCA::Hash copy = hash;
	    hash.context(); // detach

	    QCOMPARE( hash.hashToString(input), expectedHash );
	    QCOMPARE( copy.hashToString(input), expectedHash );
	}
    }
    if (!anyProviderTested) qWarning() << "NONE of the providers supports RIPEMD160:" << providersToTest;
}

void HashUnitTest::rmd160longtest()
{
    QByteArray fillerString;
    fillerString.fill('a', 1000);

    foreach(QString provider, providersToTest) {
	if(QCA::isSupported("ripemd160", provider)) {
	    QCA::Hash rmdHash(QStringLiteral("ripemd160"), provider);

	    // This is the "million times 'a' test"
	    for (int i=0; i<1000; i++)
	        rmdHash.update(fillerString);
	    QCOMPARE( QString(QCA::arrayToHex(rmdHash.final().toByteArray())),
		     QStringLiteral("52783243c1697bdbe16d37f97f68f08325dc1528") );

	    rmdHash.clear();
	    for (int i=0; i<1000; i++)
		rmdHash.update(fillerString);
	    QCOMPARE( QString(QCA::arrayToHex(rmdHash.final().toByteArray())),
		     QStringLiteral("52783243c1697bdbe16d37f97f68f08325dc1528") );

	    // This is the "8 rounds of 1234567890" test.
	    // It also ensure that we can re-use hash objects correctly.
	    static char bindata[] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30 };
	    QByteArray fillerArray( bindata, sizeof(bindata) ); // "1234567890"
	    rmdHash.clear();
	    for (int i=0; i<8; i++)
		rmdHash.update(fillerArray);
	    QCOMPARE( QString(QCA::arrayToHex(rmdHash.final().toByteArray())),
		     QStringLiteral("9b752e45573d4b39f4dbd3323cab82bf63326bfb") );

	}
    }
}


// These are from the documentation pack at http://paginas.terra.com.br/informatica/paulobarreto/WhirlpoolPage.html
void HashUnitTest::whirlpooltest_data()
{
    QTest::addColumn<QByteArray>("input");
    QTest::addColumn<QString>("expectedHash");

    QTest::newRow("whirlpool()") << QByteArray("") << QStringLiteral("19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3");
    QTest::newRow("whirlpool(a)") << QByteArray("a") << QStringLiteral("8aca2602792aec6f11a67206531fb7d7f0dff59413145e6973c45001d0087b42d11bc645413aeff63a42391a39145a591a92200d560195e53b478584fdae231a");
    QTest::newRow("whirlpool(abc)") << QByteArray("abc") << QStringLiteral("4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5");
    QTest::newRow("whirlpool(md)") << QByteArray("message digest") << QStringLiteral("378c84a4126e2dc6e56dcc7458377aac838d00032230f53ce1f5700c0ffb4d3b8421557659ef55c106b4b52ac5a4aaa692ed920052838f3362e86dbd37a8903e");
    QTest::newRow("whirlpool(a-k)") << QByteArray("abcdbcdecdefdefgefghfghighijhijk")
			      << QStringLiteral("2a987ea40f917061f5d6f0a0e4644f488a7a5a52deee656207c562f988e95c6916bdc8031bc5be1b7b947639fe050b56939baaa0adff9ae6745b7b181c3be3fd");
    QTest::newRow("whirlpool(a-z)") << QByteArray("abcdefghijklmnopqrstuvwxyz") << QStringLiteral("f1d754662636ffe92c82ebb9212a484a8d38631ead4238f5442ee13b8054e41b08bf2a9251c30b6a0b8aae86177ab4a6f68f673e7207865d5d9819a3dba4eb3b");
    QTest::newRow("whirlpool(A-9)") << QByteArray("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
			      << QStringLiteral("dc37e008cf9ee69bf11f00ed9aba26901dd7c28cdec066cc6af42e40f82f3a1e08eba26629129d8fb7cb57211b9281a65517cc879d7b962142c65f5a7af01467");
    QTest::newRow("whirlpool(1-0)") << QByteArray("12345678901234567890123456789012345678901234567890123456789012345678901234567890")
				    << QStringLiteral("466ef18babb0154d25b9d38a6414f5c08784372bccb204d6549c4afadb6014294d5bd8df2a6c44e538cd047b2681a51a2c60481e88c5a20b2c2a80cf3a9a083b");

}


void HashUnitTest::whirlpooltest()
{
    bool anyProviderTested = false;
    QFETCH(QByteArray, input);
    QFETCH(QString, expectedHash);

    foreach(QString provider, providersToTest) {
	if(QCA::isSupported("whirlpool", provider)) {
	    anyProviderTested = true;

	    QCA::Hash hash = QCA::Hash(QStringLiteral("whirlpool"), provider);
	    QCA::Hash copy = hash;
	    hash.context(); // detach

	    QCOMPARE( hash.hashToString(input), expectedHash );
	    QCOMPARE( copy.hashToString(input), expectedHash );
	}
    }
    if (!anyProviderTested) qWarning() << "NONE of the providers supports Whirlpool:" << providersToTest;
}

void HashUnitTest::whirlpoollongtest()
{
    QByteArray fillerString;
    fillerString.fill('a', 1000);

    foreach(QString provider, providersToTest) {
	if(QCA::isSupported("whirlpool", provider)) {
	    QCA::Hash rmdHash(QStringLiteral("whirlpool"), provider);

	    // This is the "million times 'a' test"
	    for (int i=0; i<1000; i++)
	        rmdHash.update(fillerString);
	    QCOMPARE( QString(QCA::arrayToHex(rmdHash.final().toByteArray())),
		     QStringLiteral("0c99005beb57eff50a7cf005560ddf5d29057fd86b20bfd62deca0f1ccea4af51fc15490eddc47af32bb2b66c34ff9ad8c6008ad677f77126953b226e4ed8b01") );

	    rmdHash.clear();
	    for (int i=0; i<1000; i++)
		rmdHash.update(fillerString);
	    QCOMPARE( QString(QCA::arrayToHex(rmdHash.final().toByteArray())),
		     QStringLiteral("0c99005beb57eff50a7cf005560ddf5d29057fd86b20bfd62deca0f1ccea4af51fc15490eddc47af32bb2b66c34ff9ad8c6008ad677f77126953b226e4ed8b01") );

	    // This is the "8 rounds of 1234567890" test.
	    // It also ensure that we can re-use hash objects correctly.
	    static char bindata[] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30 };
	    QByteArray fillerArray( bindata, sizeof(bindata) ); // "1234567890"
	    rmdHash.clear();
	    for (int i=0; i<8; i++)
		rmdHash.update(fillerArray);
	    QCOMPARE( QString(QCA::arrayToHex(rmdHash.final().toByteArray())),
		     QStringLiteral("466ef18babb0154d25b9d38a6414f5c08784372bccb204d6549c4afadb6014294d5bd8df2a6c44e538cd047b2681a51a2c60481e88c5a20b2c2a80cf3a9a083b") );

	}
    }
}


QTEST_MAIN(HashUnitTest)

#include "hashunittest.moc"

