/*
 * hashunittest.cpp - Qt Cryptographic Architecture
 * Copyright (C) 2004 Brad Hards <bradh@frogmouth.net>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include"qca.h"
#include<stdio.h>

struct hashTestValues {
	QCString inputString;
	QCString expectedHash;
};


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

// These are as specified in RFC 1319
void doMD2tests(void)
{
        if(!QCA::isSupported(QCA::CAP_MD2))
                printf("MD2 not supported!\n");
        else {
                QCString actualResult;
		
                for (int n = 0; md2TestValues[n].inputString; n++) {
			actualResult = QCA::MD2::hashToString(md2TestValues[n].inputString);
			if (md2TestValues[n].expectedHash == actualResult ) {
				printf("md2(%s) is OK\n", md2TestValues[n].inputString.data() );
			} else {
				printf("md2(%s) failed\n", md2TestValues[n].inputString.data() );
				printf("  expected: %s\n", md2TestValues[n].expectedHash.data() );
				printf("       got: %s\n", actualResult.data() );
			}
                }
        }
}


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

void doMD4tests(void)
{
        if(!QCA::isSupported(QCA::CAP_MD4))
                printf("MD4 not supported!\n");
        else {
                QCString actualResult;
		
                for (int n = 0; md4TestValues[n].inputString; n++) {
			actualResult = QCA::MD4::hashToString(md2TestValues[n].inputString);
			if (md4TestValues[n].expectedHash == actualResult ) {
				printf("md4(%s) is OK\n", md4TestValues[n].inputString.data() );
			} else {
				printf("md4(%s) failed\n", md4TestValues[n].inputString.data() );
				printf("  expected: %s\n", md4TestValues[n].expectedHash.data() );
				printf("       got: %s\n", actualResult.data() );
			}
                }
        }
}


// These are as specified in RFC 1321
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

void doMD5tests(void)
{
        if(!QCA::isSupported(QCA::CAP_MD5))
                printf("MD5 not supported!\n");
        else {
                QCString actualResult;
		
                for (int n = 0; md5TestValues[n].inputString; n++) {
			actualResult = QCA::MD5::hashToString(md5TestValues[n].inputString);
			if (md5TestValues[n].expectedHash == actualResult ) {
				printf("md5(%s) is OK\n", md5TestValues[n].inputString.data() );
			} else {
				printf("md5(%s) failed\n", md5TestValues[n].inputString.data() );
				printf("  expected: %s\n", md5TestValues[n].expectedHash.data() );
				printf("       got: %s\n", actualResult.data() );
			}
                }
        }
}

// These are extracted from OpenOffice.org 1.1.2, in sal/workben/t_digest.c
// Check FIPS 180-1?
static struct hashTestValues sha0TestValues[] = {
	{ "abc", "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880" },
	{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	  "d2516ee1acfa5baf33dfc1c471e438449ef134c8" },
	{ 0, 0 }
};

void doSHA0tests(void)
{
	if(!QCA::isSupported(QCA::CAP_SHA0))
		printf("SHA0 not supported!\n");
	else {
                QCString actualResult;
		
                for (int n = 0; sha0TestValues[n].inputString; n++) {
			actualResult = QCA::SHA0::hashToString(sha0TestValues[n].inputString);
			if (sha0TestValues[n].expectedHash == actualResult ) {
				printf("sha0(%s) is OK\n", sha0TestValues[n].inputString.data() );
			} else {
				printf("sha0(%s) failed\n", sha0TestValues[n].inputString.data() );
				printf("  expected: %s\n", sha0TestValues[n].expectedHash.data() );
				printf("       got: %s\n", actualResult.data() );
			}
                }
                
		QByteArray fillerString;
                fillerString.fill('a', 1000);


                // This test extracted from OpenOffice.org 1.1.2, in sal/workben/t_digest.c
                QCA::SHA0 shaHash;
                for (int i=0; i<1000; i++)
                        shaHash.update(fillerString);
                QByteArray hashResult = shaHash.final();
                if ( "3232affa48628a26653b5aaa44541fd90d690603" == QCA::arrayToHex(hashResult) ) {
                        printf("big SHA0 is OK\n");
                } else {
                        printf("big SHA0 failed\n");
                        printf("  expected: 3232affa48628a26653b5aaa44541fd90d690603\n");
                        printf("       got: %s\n", QCA::arrayToHex(hashResult).latin1() );
                }
		
		shaHash.clear();
                for (int i=0; i<1000; i++)
                        shaHash.update(fillerString);
                hashResult = shaHash.final();
                if ( "3232affa48628a26653b5aaa44541fd90d690603" == QCA::arrayToHex(hashResult) ) {
                        printf("big SHA0, second pass is OK\n");
                } else {
                        printf("big SHA0, second pass failed\n");
                        printf("  expected: 3232affa48628a26653b5aaa44541fd90d690603\n");
                        printf("       got: %s\n", QCA::arrayToHex(hashResult).latin1() );
                }
	}
}

// These are as specfied in FIPS 180-2. Matches RFC3174
static struct hashTestValues sha1TestValues[] = {

	// FIPS 180-2, Appendix A.1
	{ "abc", "a9993e364706816aba3e25717850c26c9cd0d89d" },

	// FIPS 180-2, Appendix A.2
	{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	  "84983e441c3bd26ebaae4aa1f95129e5e54670f1" },
	
	{ 0, 0 }
};

void doSHA1tests(void)
{
	if(!QCA::isSupported(QCA::CAP_SHA1))
		printf("SHA1 not supported!\n");
	else {
                QCString actualResult;
		
                for (int n = 0; sha1TestValues[n].inputString; n++) {
			actualResult = QCA::SHA1::hashToString(sha1TestValues[n].inputString);
			if (sha1TestValues[n].expectedHash == actualResult ) {
				printf("sha1(%s) is OK\n", sha1TestValues[n].inputString.data() );
			} else {
				printf("sha1(%s) failed\n", sha1TestValues[n].inputString.data() );
				printf("  expected: %s\n", sha1TestValues[n].expectedHash.data() );
				printf("       got: %s\n", actualResult.data() );
			}
                }
                
		QByteArray fillerString;
                fillerString.fill('a', 1000);

                // This test extracted from OpenOffice.org 1.1.2, in sal/workben/t_digest.c
		// It basically reflects FIPS 180-2, Appendix A.3
                QCA::SHA1 shaHash;
                for (int i=0; i<1000; i++)
                        shaHash.update(fillerString);
                QByteArray hashResult = shaHash.final();
                if ( "34aa973cd4c4daa4f61eeb2bdbad27316534016f" == QCA::arrayToHex(hashResult) ) {
                        printf("big SHA1 is OK\n");
                } else {
                        printf("big SHA1 failed\n");
                        printf("  expected: 34aa973cd4c4daa4f61eeb2bdbad27316534016f\n");
                        printf("       got: %s\n", QCA::arrayToHex(hashResult).latin1() );
                }
	}
}

// These are as specfied in FIPS 180-2
static struct hashTestValues sha256TestValues[] = {

	// FIPS 180-2, Appendix B.1
	{ "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },

	// FIPS 180-2, Appendix B.2
	{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
	  "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" },

	{ 0, 0 }
};

void doSHA256tests(void)
{
	if(!QCA::isSupported(QCA::CAP_SHA256))
		printf("SHA256 not supported!\n");
	else {
                QCString actualResult;
		
                for (int n = 0; sha256TestValues[n].inputString; n++) {
			actualResult = QCA::SHA256::hashToString(sha256TestValues[n].inputString);
			if (sha256TestValues[n].expectedHash == actualResult ) {
				printf("sha256(%s) is OK\n", sha256TestValues[n].inputString.data() );
			} else {
				printf("sha256(%s) failed\n", sha256TestValues[n].inputString.data() );
				printf("  expected: %s\n", sha256TestValues[n].expectedHash.data() );
				printf("       got: %s\n", actualResult.data() );
			}
                }
                
		QByteArray fillerString;
                fillerString.fill('a', 1000);

		// This basically reflects FIPS 180-2, Appendix B.3
                QCA::SHA256 shaHash;
                for (int i=0; i<1000; i++)
                        shaHash.update(fillerString);
                QByteArray hashResult = shaHash.final();
                if ( "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39cc046d39ccc7122cd0" == QCA::arrayToHex(hashResult) ) {
                        printf("big SHA256 is OK\n");
                } else {
                        printf("big SHA256 failed\n");
                        printf("  expected: cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39cc046d39ccc7122cd0\n");
                        printf("       got: %s\n", QCA::arrayToHex(hashResult).latin1() );
                }
	}
}

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

void doRIPEMD160tests(void)
{
	if(!QCA::isSupported(QCA::CAP_RIPEMD160))
		printf("RIPEMD160 not supported!\n");
	else {
                QCString actualResult;
		
                for (int n = 0; ripemd160TestValues[n].inputString; n++) {
			actualResult = QCA::RIPEMD160::hashToString(ripemd160TestValues[n].inputString);
			if (ripemd160TestValues[n].expectedHash == actualResult ) {
				printf("ripemd160(%s) is OK\n", ripemd160TestValues[n].inputString.data() );
			} else {
				printf("ripemd160(%s) failed\n", ripemd160TestValues[n].inputString.data() );
				printf("  expected: %s\n", ripemd160TestValues[n].expectedHash.data() );
				printf("       got: %s\n", actualResult.data() );
			}
                }
                
		// This is the "million times 'a' test"
		QByteArray fillerString;
                fillerString.fill('a', 1000);

                QCA::RIPEMD160 shaHash;
                for (int i=0; i<1000; i++)
                        shaHash.update(fillerString);
                QByteArray hashResult = shaHash.final();
                if ( "52783243c1697bdbe16d37f97f68f08325dc1528" == QCA::arrayToHex(hashResult) ) {
                        printf("big RIPEMD160 is OK\n");
                } else {
                        printf("big RIPEMD160 failed\n");
                        printf("  expected: 52783243c1697bdbe16d37f97f68f08325dc1528\n");
                        printf("       got: %s\n", QCA::arrayToHex(hashResult).latin1() );
                }

		// This is the "8 rounds of 1234567890" test.
		// It also ensure that we can re-use hash objects correctly.
		static char bindata[] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30 };
		fillerString.resize(10);
		fillerString.setRawData( bindata, sizeof(bindata) ); // "1234567890"
                shaHash.clear();
                for (int i=0; i<8; i++)
                        shaHash.update(fillerString);
		fillerString.resetRawData( bindata, sizeof(bindata) );
                hashResult = shaHash.final();
                if ( "9b752e45573d4b39f4dbd3323cab82bf63326bfb" == QCA::arrayToHex(hashResult) ) {
                        printf("8-round RIPEMD160 is OK\n");
                } else {
                        printf("8-round RIPEMD160 failed\n");
                        printf("  expected: 9b752e45573d4b39f4dbd3323cab82bf63326bfb\n");
                        printf("       got: %s\n", QCA::arrayToHex(hashResult).latin1() );
                }
	}
}

int main(int argc, char **argv)
{
	QCA::init();

	doSHA0tests();
        printf("\n");
	doSHA1tests();
        printf("\n");
	doSHA256tests();

        printf("\n");

	doMD2tests();
        printf("\n");
	doMD4tests();
        printf("\n");
	doMD5tests();

	printf("\n");
	doRIPEMD160tests();

	return 0;
}

