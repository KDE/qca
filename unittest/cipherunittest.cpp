/**
 * cipherunittest.cpp
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
#include "cipherunittest.h"
#include "qca.h"

CipherUnitTest::CipherUnitTest()
    : Tester()
{

}

void CipherUnitTest::allTests()
{
    QCA::Initializer init;

    if (!QCA::isSupported("aes128") )
	SKIP("AES128 not supported!\n");
    else {
	QCA::SymmetricKey key1(QCA::hexToArray( "00010203050607080A0B0C0D0F101112" ) );
	QCA::AES128 cipherObj1(QCA::Cipher::ECB, QCA::Encode, key1, QCA::InitializationVector(), false );
	QSecureArray inter = cipherObj1.update( QCA::hexToArray( "506812A45F08C889B97F5980038B8359" ) );
	CHECK( QCA::arrayToHex( inter ), QString( "d8f532538289ef7d06b506a4fd5be9c9") );
	CHECK( QCA::arrayToHex( cipherObj1.final() ), QString( "d8f532538289ef7d06b506a4fd5be9c9") );


	// From the NIST rijndael-vals.zip set, see ecb_iv.txt
	QCA::SymmetricKey key2(QCA::hexToArray( "000102030405060708090A0B0C0D0E0F" ) );
	QCA::AES128 cipherObj2(QCA::Cipher::ECB, QCA::Encode, key2, QCA::InitializationVector(), false );
	QSecureArray ct2r1 = cipherObj2.update( QCA::hexToArray( "000102030405060708090A0B0C0D0E0F" ) );
	CHECK( QCA::arrayToHex( ct2r1 ), QString("0a940bb5416ef045f1c39458c653ea5a" ) );
	CHECK( QCA::arrayToHex( cipherObj2.final() ), QString("0a940bb5416ef045f1c39458c653ea5a" ) );

	// From the NIST rijndael-vals.zip set, see ecb_iv.txt
	QCA::AES128 cipherObj3(QCA::Cipher::ECB, QCA::Decode, key2, QCA::InitializationVector(), false );
	cipherObj3.update( QCA::hexToArray( "0A940BB5416EF045F1C39458C653EA5A" ) );
	CHECK( QCA::arrayToHex( cipherObj3.final() ), QString("000102030405060708090a0b0c0d0e0f" ) );

	// From FIPS-197 Annex C.1
	QCA::AES128 cipherObj4(QCA::Cipher::ECB, QCA::Encode, key2, QCA::InitializationVector(), false );
	cipherObj4.update( QCA::hexToArray( "00112233445566778899aabbccddeeff" ) );
	CHECK( QCA::arrayToHex( cipherObj4.final() ), QString("69c4e0d86a7b0430d8cdb78070b4c55a" ) );

	// From FIPS-197 Annex C.1
	QCA::AES128 cipherObj5(QCA::Cipher::ECB, QCA::Decode, key2, QCA::InitializationVector(), false );
	cipherObj5.update( QCA::hexToArray( "69c4e0d86a7b0430d8cdb78070b4c55a" ) );
	CHECK( QCA::arrayToHex( cipherObj5.final() ), QString( "00112233445566778899aabbccddeeff" ) );
    }

    if (!QCA::isSupported("aes192") )
	SKIP("AES192 not supported!\n");
    else {
    }


    if (!QCA::isSupported("aes256") )
	SKIP("AES256 not supported!\n");
    else {
    }

    if (!QCA::isSupported("tripledes") )
	SKIP("Triple DES not supported!\n");
    else {
    }

    if (!QCA::isSupported("blowfish") )
	SKIP("Blowfish not supported!\n");
    else {
    }
}

