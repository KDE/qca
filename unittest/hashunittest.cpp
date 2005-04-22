/**
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
#include "hashunittest.h"
#include <QtCrypto>
#include <qfile.h>

HashUnitTest::HashUnitTest()
    : Tester()
{

}

struct hashTestValues {
    QByteArray inputString;
    QString expectedHash;
};


// These are as specified in RFC 1319
static struct hashTestValues md2TestValues[] = {
    { "", "8350e5a3e24c153df2275c9f80692773" },
    { "a", "32ec01ec4a6dac72c0ab96fb34c0b5d1" },
    { "abc", "da853b0d3f88d99b30283a69e6ded6bb" },
    { "message digest", "ab4f496bfb2a530b219ff33031fe06b0" },
    { "abcdefghijklmnopqrstuvwxyz", "4e8ddff3650292ab5a4108c3aa47940b" },
    { "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
      "da33def2a42df13975352846c30338cd" },
    { "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
      "d5976f79d83d3a0dc9806c3c66f3efd8" },
    { 0, 0 }
};

// These are as specified in RFC 1320
static struct hashTestValues md4TestValues[] = {
	{ "", "31d6cfe0d16ae931b73c59d7e0c089c0" },
	{ "a", "bde52cb31de33e46245e05fbdbd6fb24" },
	{ "abc", "a448017aaf21d8525fc10ae87aa6729d" },
	{ "message digest", "d9130a8164549fe818874806e1c7014b" },
	{ "abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9" },
	{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
	  "043f8582f241db351ce627e153e7f0e4" },
	{ "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
	  "e33b4ddc9c38f2199c3e7b164fcc0536" },
	{ 0, 0 }
};

// These are as specified in RFC 1321
// They also match Australian Standard (AS) 2805.1.3.2-2000 Appendix A
static struct hashTestValues md5TestValues[] = {
	{ "", "d41d8cd98f00b204e9800998ecf8427e" },
	{ "a", "0cc175b9c0f1b6a831c399e269772661" },
	{ "abc", "900150983cd24fb0d6963f7d28e17f72" },
	{ "message digest", "f96b697d7cb7938d525a2f31aaf161d0" },
	{ "abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b" },
	{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
	  "d174ab98d277d9f5a5611c2c9f419d9f" },
	{ "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
	  "57edf4a22be3c955ac49da2e2107b67a" },
	{ 0, 0 }
};

// These are extracted from OpenOffice.org 1.1.2, in sal/workben/t_digest.c
// Check FIPS 180-1?
static struct hashTestValues sha0TestValues[] = {
	{ "abc", "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880" },
	{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	  "d2516ee1acfa5baf33dfc1c471e438449ef134c8" },
	{ 0, 0 }
};

// These are as specfied in FIPS 180-2. Matches RFC3174
// Some additions from Australian Standard (AS) 2805.13.3-2000
static struct hashTestValues sha1TestValues[] = {

	// FIPS 180-2, Appendix A.1
	{ "abc", "a9993e364706816aba3e25717850c26c9cd0d89d" },

	// FIPS 180-2, Appendix A.2
	{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	  "84983e441c3bd26ebaae4aa1f95129e5e54670f1" },

	// AS 2805.13.3-200 Appendix A
	// has some duplicates from FIPS 180-2
	{ "", "da39a3ee5e6b4b0d3255bfef95601890afd80709" },
	{ "a", "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8" },
	{ "abc",  "a9993e364706816aba3e25717850c26c9cd0d89d" },
	{ "abcdefghijklmnopqrstuvwxyz", "32d10c7b8cf96570ca04ce37f2a19d84240d3a89" },
	{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	  "84983e441c3bd26ebaae4aa1f95129e5e54670f1" },
	{ 0, 0 }
};

// These are as specfied in FIPS 180-2
static struct hashTestValues sha256TestValues[] = {

	// FIPS 180-2, Appendix B.1
	{ "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },

	// FIPS 180-2, Appendix B.2
	{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	  "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" },

	{ 0, 0 }
};

// These are as specfied in FIPS 180-2, change notice 1
static struct hashTestValues sha224TestValues[] = {

	// FIPS 180-2, Appendix B.1
	{ "abc", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7" },

	// FIPS 180-2, Appendix B.2
	{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	  "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525" },

	{ 0, 0 }
};

// These are as specfied in FIPS 180-2, and from Aaron Gifford's SHA2 tests
static struct hashTestValues sha384TestValues[] = {

	// FIPS 180-2, Appendix D.1
	{ "abc", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7" },

	// FIPS 180-2, Appendix D.2
	{ "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
	  "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039" },

	// Aaron Gifford, vector002.info
	{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	  "3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b" },

	{ 0, 0 }
};

// These are as specfied in FIPS 180-2, and from Aaron Gifford's SHA2 tests
static struct hashTestValues sha512TestValues[] = {

	// FIPS 180-2, Appendix C.1
	{ "abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" },
	// FIPS 180-2, Appendix C.2
	{ "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
	  "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909" },
	// Aaron Gifford, vector002.info
	{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	  "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445" },
	{ 0, 0 }
};

// These are as specified in http://www.esat.kuleuven.ac.be/~bosselae/ripemd160.html
// ISO/IEC 10118-3 costs a bit of money.
static struct hashTestValues ripemd160TestValues[] = {
	{ "", "9c1185a5c5e9fc54612808977ee8f548b2258d31" },
	{ "a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe" },
	{ "abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc" },
	{ "message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36" },
	{ "abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc" },
	{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	  "12a053384a9c0c88e405a06c27dcf49ada62eb2b" },
	{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
	  "b0e20b6e3116640286ed3a87a5713079b21f5189" },
	{ "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
	  "9b752e45573d4b39f4dbd3323cab82bf63326bfb" },
	{ 0, 0 }
};


void HashUnitTest::allTests()
{
    QCA::Initializer init;

    QString hashResult; // used as the actual result

    QStringList providersToTest;
    providersToTest.append("qca-openssl");
    providersToTest.append("qca-gcrypt");
    providersToTest.append("default");
    
    for ( QStringList::Iterator it = providersToTest.begin(); it != providersToTest.end(); ++it ) {
	if(!QCA::isSupported("md2"))
	    SKIP("MD2 not supported" );
	else {
	    for (int n = 0;  (0 != md2TestValues[n].expectedHash); n++) {
		hashResult = QCA::MD2(*it).hashToString(md2TestValues[n].inputString);
		CHECK( hashResult, md2TestValues[n].expectedHash );
	    }
	}

	if(!QCA::isSupported("md4"))
	    SKIP("MD4 not supported");
	else {
	    for (int n = 0; (0 != md4TestValues[n].expectedHash); n++) {
	    hashResult = QCA::MD4(*it).hashToString(md4TestValues[n].inputString);
	    CHECK( hashResult, md4TestValues[n].expectedHash );
	    }
	}
    

	if(!QCA::isSupported("md5"))
	    SKIP("MD5 not supported");
	else {
	    for (int n = 0; (0 != md5TestValues[n].expectedHash); n++) {
		hashResult = QCA::MD5(*it).hashToString(md5TestValues[n].inputString);
		CHECK( hashResult, md5TestValues[n].expectedHash );
	    }
	    
	    QFile f1( "./data/empty" );
	    if ( f1.open( QIODevice::ReadOnly ) ) {
		QCA::MD5 hashObj(*it);
		hashObj.update( f1 );
		CHECK( QString( QCA::arrayToHex( hashObj.final() ) ),
		       QString( "d41d8cd98f00b204e9800998ecf8427e" ) );
	    } else {
		SKIP( "./data/empty could not be opened - do you need to create it?");
	    }

	    QFile f2( "./data/Botan-1.4.1.tar.bz2" );
	    if ( f2.open( QIODevice::ReadOnly ) ) {
		QCA::MD5 hashObj(*it);
		hashObj.update( f2 );
		CHECK( QString( QCA::arrayToHex( hashObj.final() ) ),
		       QString( "7c4b3d8a360c6c3cb647160fa9adfe71" ) );
	    } else {
		SKIP( "./data/Botan-1.4.1.tar.bz2 could not be opened - do you need to download it?");
	    }
	    

	    QFile f3( "./data/linux-2.6.7.tar.bz2" );
	    if ( f3.open( QIODevice::ReadOnly ) ) {
		QCA::MD5 hashObj(*it);
		hashObj.update( f3 );
		CHECK( QString( QCA::arrayToHex( hashObj.final() ) ),
		       QString( "a74671ea68b0e3c609e8785ed8497c14" ) );
	    } else {
		SKIP( "./data/linux-2.6.7.tar.bz2 could not be opened - do you need to download it?");
	    }
	    
	    QFile f4( "./data/scribus-1.2.tar.bz2" );
	    if ( f4.open( QIODevice::ReadOnly ) ) {
		QCA::MD5 hashObj(*it);
		hashObj.update( f4 );
		CHECK( QString( QCA::arrayToHex( hashObj.final() ) ),
		       QString( "7d2c2b228f9a6ff82c9401fd54bdbe16" ) );
	    } else {
		SKIP( "./data/scribus-1.2.tar.bz2 could not be opened - do you need to download it?");
	    }
	    
	}
	
	if(!QCA::isSupported("sha0"))
	    SKIP("SHA0 not supported");
	else {
	    for (int n = 0; (0 != sha0TestValues[n].expectedHash); n++) {
		hashResult = QCA::SHA0(*it).hashToString(sha0TestValues[n].inputString);
		CHECK( hashResult, sha0TestValues[n].expectedHash );
	    }
	    
	    QByteArray fillerString;
	    fillerString.fill('a', 1000);


	    // This test extracted from OpenOffice.org 1.1.2, in sal/workben/t_digest.c
	    QCA::SHA0 shaHash(*it);
	    for (int i=0; i<1000; i++)
		shaHash.update(fillerString);
	    CHECK( QString(QCA::arrayToHex(shaHash.final())),
		   QString("3232affa48628a26653b5aaa44541fd90d690603" ) );
	    
	    shaHash.clear();
	    for (int i=0; i<1000; i++)
		shaHash.update(fillerString);
	    CHECK( QString(QCA::arrayToHex(shaHash.final())),
		   QString("3232affa48628a26653b5aaa44541fd90d690603" ) );
	}
	
	
	if(!QCA::isSupported("sha1"))
	    SKIP("SHA1 not supported");
	else {
	    for (int n = 0; (0 != sha1TestValues[n].expectedHash); n++) {
		hashResult = QCA::SHA1(*it).hashToString(sha1TestValues[n].inputString);
		CHECK( hashResult, sha1TestValues[n].expectedHash );
	    }
	    
	    QByteArray fillerString;
	    fillerString.fill('a', 1000);
	    
	    // This test extracted from OpenOffice.org 1.1.2, in sal/workben/t_digest.c
	    // It basically reflects FIPS 180-2, Appendix A.3
	    // Also as per AS 2805.13.3-2000 Appendix A
	    QCA::SHA1 shaHash(*it);
	    for (int i=0; i<1000; i++)
		shaHash.update(fillerString);
	    CHECK( QString(QCA::arrayToHex(shaHash.final())),
		   QString("34aa973cd4c4daa4f61eeb2bdbad27316534016f") );

	    QFile f1( "./data/empty" );
	    if ( f1.open( QIODevice::ReadOnly ) ) {
		QCA::SHA1 hashObj(*it);
		hashObj.update( f1 );
		CHECK( QString( QCA::arrayToHex( hashObj.final() ) ),
		       QString( "da39a3ee5e6b4b0d3255bfef95601890afd80709" ) );
	    } else {
		SKIP( "./data/empty could not be opened - do you need to create it?");
	    }
	    
	    QFile f2( "./data/Botan-1.4.1.tar.bz2" );
	    if ( f2.open( QIODevice::ReadOnly ) ) {
		QCA::SHA1 hashObj(*it);
		hashObj.update( f2 );
		CHECK( QString( QCA::arrayToHex( hashObj.final() ) ),
		       QString( "cda343591428a68e22bd2e349b890cbafb642cf7" ) );
	    } else {
		SKIP( "./data/Botan-1.4.1.tar.bz2 could not be opened - do you need to download it?");
	    }

	    QFile f3( "./data/linux-2.6.7.tar.bz2" );
	    if ( f3.open( QIODevice::ReadOnly ) ) {
		QCA::SHA1 hashObj(*it);
		hashObj.update( f3 );
		CHECK( QString( QCA::arrayToHex( hashObj.final() ) ),
		       QString( "a030a9c6dcd10c5d90a86f915ad4710084cbca71" ) );
	    } else {
		SKIP( "./data/linux-2.6.7.tar.bz2 could not be opened - do you need to download it?");
	    }
	    
	    QFile f4( "./data/scribus-1.2.tar.bz2" );
	    if ( f4.open( QIODevice::ReadOnly ) ) {
		QCA::SHA1 hashObj(*it);
		hashObj.update( f4 );
		CHECK( QString( QCA::arrayToHex( hashObj.final() ) ),
		       QString( "a1fb6ed6acfd92381055b310d926d6e83e76ff1e" ) );
	    } else {
		SKIP( "./data/scribus-1.2.tar.bz2 could not be opened - do you need to download it?");
	    }
	    
	}

	if(!QCA::isSupported("sha224"))
	    SKIP("SHA224 not supported");
	else {
	    for (int n = 0; (0 != sha224TestValues[n].expectedHash); n++) {
		hashResult = QCA::SHA224(*it).hashToString(sha224TestValues[n].inputString);
		CHECK( hashResult, sha224TestValues[n].expectedHash );
	    }
	    
	    QByteArray fillerString;
	    fillerString.fill('a', 1000);

	    // This basically reflects FIPS 180-2, change notice 1, section 3
	    QCA::SHA224 shaHash(*it);
	    for (int i=0; i<1000; i++)
		shaHash.update(fillerString);
	    CHECK( QString(QCA::arrayToHex(shaHash.final())),
		   QString("20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67") );
	}

	if(!QCA::isSupported("sha256"))
	    SKIP("SHA256 not supported");
	else {
	    for (int n = 0; (0 != sha256TestValues[n].expectedHash); n++) {
		hashResult = QCA::SHA256(*it).hashToString(sha256TestValues[n].inputString);
		CHECK( hashResult, sha256TestValues[n].expectedHash );
	    }
	    
	    QByteArray fillerString;
	    fillerString.fill('a', 1000);

	    // This basically reflects FIPS 180-2, Appendix B.3
	    QCA::SHA256 shaHash(*it);
	    for (int i=0; i<1000; i++)
		shaHash.update(fillerString);
	    CHECK( QString(QCA::arrayToHex(shaHash.final())),
		   QString("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0") );
	}
	
	if(!QCA::isSupported("sha384"))
	    SKIP("SHA384 not supported");
	else {
	    for (int n = 0; (0 != sha384TestValues[n].expectedHash); n++) {
		hashResult = QCA::SHA384(*it).hashToString(sha384TestValues[n].inputString);
		CHECK( hashResult, sha384TestValues[n].expectedHash );
	    }
	    
	    QByteArray fillerString;
	    fillerString.fill('a', 1000);

	    // This basically reflects FIPS 180-2, Appendix D.3
	    QCA::SHA384 shaHash(*it);
	    for (int i=0; i<1000; i++)
		shaHash.update(fillerString);
	    CHECK( QString(QCA::arrayToHex(shaHash.final())),
		   QString("9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985") );

	}


	if(!QCA::isSupported("sha512"))
	    SKIP("SHA512 not supported");
	else {
	    for (int n = 0; (0 != sha512TestValues[n].expectedHash); n++) {
		hashResult = QCA::SHA512(*it).hashToString(sha512TestValues[n].inputString);
		CHECK( hashResult, sha512TestValues[n].expectedHash );
	    }
	    
	    QByteArray fillerString;
	    fillerString.fill('a', 1000);
	    
	    // This basically reflects FIPS 180-2, Appendix C.3
	    QCA::SHA512 shaHash;
	    for (int i=0; i<1000; i++)
		shaHash.update(fillerString);
	    CHECK( QString(QCA::arrayToHex(shaHash.final())),
		   QString("e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b") );
	}
	
	
	if(!QCA::isSupported("ripemd160"))
	    SKIP("RIPEMD160 not supported");
	else {
	    for (int n = 0; (0 != ripemd160TestValues[n].expectedHash); n++) {
		hashResult = QCA::RIPEMD160(*it).hashToString(ripemd160TestValues[n].inputString);
		CHECK( hashResult, ripemd160TestValues[n].expectedHash );
	    }
	    
	    // This is the "million times 'a' test"
	    QByteArray fillerString;
	    fillerString.fill('a', 1000);
	    
	    QCA::RIPEMD160 shaHash(*it);
	    for (int i=0; i<1000; i++)
		shaHash.update(fillerString);
	    CHECK( QString(QCA::arrayToHex(shaHash.final())),
		   QString("52783243c1697bdbe16d37f97f68f08325dc1528") );
	    
	    // This is the "8 rounds of 1234567890" test.
	    // It also ensure that we can re-use hash objects correctly.
	    static char bindata[] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30 };
	    QByteArray fillerArray( bindata, sizeof(bindata) ); // "1234567890"
	    shaHash.clear();
	    for (int i=0; i<8; i++)
		shaHash.update(fillerArray);
	    CHECK( QString(QCA::arrayToHex(shaHash.final())),
		   QString("9b752e45573d4b39f4dbd3323cab82bf63326bfb") );
	}
    }
}


