/**
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
#include "hashunittest.h"
#include "qca.h"

HashUnitTest::HashUnitTest()
    : Tester()
{

}

struct hashTestValues {
    QCString inputString;
    QCString expectedHash;
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

    QCString hashResult; // used as the actual result

    if(!QCA::isSupported("md2"))
	SKIP("MD2 not supported!\n");
    else {
	for (int n = 0; md2TestValues[n].inputString; n++) {
	    hashResult = QCA::MD2().hashToString(md2TestValues[n].inputString);
	    CHECK( hashResult, md2TestValues[n].expectedHash );
        }
    }

    if(!QCA::isSupported("md4"))
	SKIP("MD4 not supported!\n");
    else {
	for (int n = 0; md4TestValues[n].inputString; n++) {
	    hashResult = QCA::MD4().hashToString(md4TestValues[n].inputString);
	    CHECK( hashResult, md4TestValues[n].expectedHash );
        }
    }
    
    if(!QCA::isSupported("md5"))
	SKIP("MD5 not supported!\n");
    else {
	for (int n = 0; md5TestValues[n].inputString; n++) {
	    hashResult = QCA::MD5().hashToString(md5TestValues[n].inputString);
	    CHECK( hashResult, md5TestValues[n].expectedHash );
        }
    }

    if(!QCA::isSupported("sha0"))
	SKIP("SHA0 not supported!\n");
    else {
	for (int n = 0; sha0TestValues[n].inputString; n++) {
	    hashResult = QCA::SHA0().hashToString(sha0TestValues[n].inputString);
	    CHECK( hashResult, sha0TestValues[n].expectedHash );
	}
                
	QByteArray fillerString;
	fillerString.fill('a', 1000);


	// This test extracted from OpenOffice.org 1.1.2, in sal/workben/t_digest.c
	QCA::SHA0 shaHash;
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
	SKIP("SHA1 not supported!\n");
    else {
	for (int n = 0; sha1TestValues[n].inputString; n++) {
	    hashResult = QCA::SHA1().hashToString(sha1TestValues[n].inputString);
	    CHECK( hashResult, sha1TestValues[n].expectedHash );
	}
                
	QByteArray fillerString;
	fillerString.fill('a', 1000);

	// This test extracted from OpenOffice.org 1.1.2, in sal/workben/t_digest.c
	// It basically reflects FIPS 180-2, Appendix A.3
	// Also as per AS 2805.13.3-2000 Appendix A
	QCA::SHA1 shaHash;
	for (int i=0; i<1000; i++)
	    shaHash.update(fillerString);
	CHECK( QString(QCA::arrayToHex(shaHash.final())),
	       QString("34aa973cd4c4daa4f61eeb2bdbad27316534016f") );
    }

    if(!QCA::isSupported("sha256"))
	SKIP("SHA256 not supported!\n");
    else {
	for (int n = 0; sha256TestValues[n].inputString; n++) {
	    hashResult = QCA::SHA256().hashToString(sha256TestValues[n].inputString);
	    CHECK( hashResult, sha256TestValues[n].expectedHash );
	}
                
	QByteArray fillerString;
	fillerString.fill('a', 1000);

	// This basically reflects FIPS 180-2, Appendix B.3
	QCA::SHA256 shaHash;
	for (int i=0; i<1000; i++)
	    shaHash.update(fillerString);
	CHECK( QString(QCA::arrayToHex(shaHash.final())),
	       QString("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39cc046d39ccc7122cd0") );
    }

    if(!QCA::isSupported("ripemd160"))
	SKIP("RIPEMD160 not supported!\n");
    else {
	for (int n = 0; ripemd160TestValues[n].inputString; n++) {
	    hashResult = QCA::RIPEMD160().hashToString(ripemd160TestValues[n].inputString);
	    CHECK( hashResult, ripemd160TestValues[n].expectedHash );
	}
                
	// This is the "million times 'a' test"
	QByteArray fillerString;
	fillerString.fill('a', 1000);

	QCA::RIPEMD160 shaHash;
	for (int i=0; i<1000; i++)
	    shaHash.update(fillerString);
	CHECK( QString(QCA::arrayToHex(shaHash.final())),
	       QString("52783243c1697bdbe16d37f97f68f08325dc1528") );

	// This is the "8 rounds of 1234567890" test.
	// It also ensure that we can re-use hash objects correctly.
	static char bindata[] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30 };
	fillerString.resize(10);
	fillerString.setRawData( bindata, sizeof(bindata) ); // "1234567890"
	shaHash.clear();
	for (int i=0; i<8; i++)
	    shaHash.update(fillerString);
	fillerString.resetRawData( bindata, sizeof(bindata) );
	CHECK( QString(QCA::arrayToHex(shaHash.final())),
	       QString("9b752e45573d4b39f4dbd3323cab82bf63326bfb") );
    }
}


