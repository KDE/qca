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

struct cipherTestValues {
    QCString plaintext;
    QCString ciphertext;
    QCString key;
};
// These are from the Botan test suite
static struct cipherTestValues aes128TestValues[] = {


    { "506812a45f08c889b97f5980038b8359",
      "d8f532538289ef7d06b506a4fd5be9c9",
      "00010203050607080a0b0c0d0f101112" },

    { "5c6d71ca30de8b8b00549984d2ec7d4b",
      "59ab30f4d4ee6e4ff9907ef65b1fb68c",
      "14151617191a1b1c1e1f202123242526" },

    { "53f3f4c64f8616e4e7c56199f48f21f6",
      "bf1ed2fcb2af3fd41443b56d85025cb1",
      "28292a2b2d2e2f30323334353738393a" },

    { "a1eb65a3487165fb0f1c27ff9959f703",
      "7316632d5c32233edcb0780560eae8b2",
      "3c3d3e3f41424344464748494b4c4d4e" },

    { "3553ecf0b1739558b08e350a98a39bfa",
      "408c073e3e2538072b72625e68b8364b",
      "50515253555657585a5b5c5d5f606162" },

    { "67429969490b9711ae2b01dc497afde8",
      "e1f94dfa776597beaca262f2f6366fea",
      "64656667696a6b6c6e6f707173747576" },

    { "93385c1f2aec8bed192f5a8e161dd508",
      "f29e986c6a1c27d7b29ffd7ee92b75f1",
      "78797a7b7d7e7f80828384858788898a" },

    { "3e23b3bc065bcc152407e23896d77783",
      "1959338344e945670678a5d432c90b93",
      "54555657595a5b5c5e5f606163646566" },

    { "79f0fba002be1744670e7e99290d8f52",
      "e49bddd2369b83ee66e6c75a1161b394",
      "68696a6b6d6e6f70727374757778797a" },

    { "da23fe9d5bd63e1d72e3dafbe21a6c2a",
      "d3388f19057ff704b70784164a74867d",
      "7c7d7e7f81828384868788898b8c8d8e" },

    { "e3f5698ba90b6a022efd7db2c7e6c823",
      "23aa03e2d5e4cd24f3217e596480d1e1",
      "a4a5a6a7a9aaabacaeafb0b1b3b4b5b6" },

    { "bdc2691d4f1b73d2700679c3bcbf9c6e",
      "c84113d68b666ab2a50a8bdb222e91b9",
      "e0e1e2e3e5e6e7e8eaebecedeff0f1f2" },

    { "ba74e02093217ee1ba1b42bd5624349a",
      "ac02403981cd4340b507963db65cb7b6",
      "08090a0b0d0e0f10121314151718191a" },

    { "b5c593b5851c57fbf8b3f57715e8f680",
      "8d1299236223359474011f6bf5088414",
      "6c6d6e6f71727374767778797b7c7d7e" },

    { 0, 0, 0 }
};

// These are from the Botan test suite
static struct cipherTestValues aes192TestValues[] = {

    { "fec1c04f529bbd17d8cecfcc4718b17f",
      "62564c738f3efe186e1a127a0c4d3c61",
      "4a4b4c4d4f50515254555657595a5b5c5e5f606163646566" },
    { "32df99b431ed5dc5acf8caf6dc6ce475", 
      "07805aa043986eb23693e23bef8f3438",
      "68696a6b6d6e6f70727374757778797a7c7d7e7f81828384" },
    { "7fdc2b746f3f665296943b83710d1f82",
      "df0b4931038bade848dee3b4b85aa44b", 
      "868788898b8c8d8e90919293959697989a9b9c9d9fa0a1a2" },
    { "8fba1510a3c5b87e2eaa3f7a91455ca2", 
      "592d5fded76582e4143c65099309477c", 
      "a4a5a6a7a9aaabacaeafb0b1b3b4b5b6b8b9babbbdbebfc0" },
    { "2c9b468b1c2eed92578d41b0716b223b", 
      "c9b8d6545580d3dfbcdd09b954ed4e92", 
      "c2c3c4c5c7c8c9cacccdcecfd1d2d3d4d6d7d8d9dbdcddde" },
    { "0a2bbf0efc6bc0034f8a03433fca1b1a", 
      "5dccd5d6eb7c1b42acb008201df707a0", 
      "e0e1e2e3e5e6e7e8eaebecedeff0f1f2f4f5f6f7f9fafbfc" },
    { "25260e1f31f4104d387222e70632504b", 
      "a2a91682ffeb6ed1d34340946829e6f9", 
      "fefe01010304050608090a0b0d0e0f10121314151718191a" },
    { "c527d25a49f08a5228d338642ae65137", 
      "e45d185b797000348d9267960a68435d", 
      "1c1d1e1f21222324262728292b2c2d2e3031323335363738" },
    { "3b49fc081432f5890d0e3d87e884a69e", 
      "45e060dae5901cda8089e10d4f4c246b", 
      "3a3b3c3d3f40414244454647494a4b4c4e4f505153545556" },
    { "d173f9ed1e57597e166931df2754a083", 
      "f6951afacc0079a369c71fdcff45df50", 
      "58595a5b5d5e5f60626364656768696a6c6d6e6f71727374" },
    { "8c2b7cafa5afe7f13562daeae1adede0", 
      "9e95e00f351d5b3ac3d0e22e626ddad6", 
      "767778797b7c7d7e80818283858687888a8b8c8d8f909192" },
    { "aaf4ec8c1a815aeb826cab741339532c", 
      "9cb566ff26d92dad083b51fdc18c173c", 
      "94959697999a9b9c9e9fa0a1a3a4a5a6a8a9aaabadaeafb0" },
    { "40be8c5d9108e663f38f1a2395279ecf", 
      "c9c82766176a9b228eb9a974a010b4fb", 
      "d0d1d2d3d5d6d7d8dadbdcdddfe0e1e2e4e5e6e7e9eaebec" },
    { "0c8ad9bc32d43e04716753aa4cfbe351", 
      "d8e26aa02945881d5137f1c1e1386e88", 
      "2a2b2c2d2f30313234353637393a3b3c3e3f404143444546" },
    { "1407b1d5f87d63357c8dc7ebbaebbfee",
      "c0e024ccd68ff5ffa4d139c355a77c55",
      "48494a4b4d4e4f50525354555758595a5c5d5e5f61626364" },
    { 0, 0, 0 }
};

// These are from the Botan test suite
static struct cipherTestValues aes256TestValues[] = {
    { "e51aa0b135dba566939c3b6359a980c5",
      "8cd9423dfc459e547155c5d1d522e540",
      "e0e1e2e3e5e6e7e8eaebecedeff0f1f2f4f5f6f7f9fafbfcfefe010103040506" },

    { "069a007fc76a459f98baf917fedf9521",
      "080e9517eb1677719acf728086040ae3",
      "08090a0b0d0e0f10121314151718191a1c1d1e1f21222324262728292b2c2d2e" },

    { "726165c1723fbcf6c026d7d00b091027",
      "7c1700211a3991fc0ecded0ab3e576b0",
      "30313233353637383a3b3c3d3f40414244454647494a4b4c4e4f505153545556" },
    
    { "d7c544de91d55cfcde1f84ca382200ce",
      "dabcbcc855839251db51e224fbe87435",
      "58595a5b5d5e5f60626364656768696a6c6d6e6f71727374767778797b7c7d7e" },
    
    { "fed3c9a161b9b5b2bd611b41dc9da357",
      "68d56fad0406947a4dd27a7448c10f1d",
      "80818283858687888a8b8c8d8f90919294959697999a9b9c9e9fa0a1a3a4a5a6" },
    
    { "4f634cdc6551043409f30b635832cf82",
      "da9a11479844d1ffee24bbf3719a9925",
      "a8a9aaabadaeafb0b2b3b4b5b7b8b9babcbdbebfc1c2c3c4c6c7c8c9cbcccdce" },
    
    { "109ce98db0dfb36734d9f3394711b4e6",
      "5e4ba572f8d23e738da9b05ba24b8d81",
      "d0d1d2d3d5d6d7d8dadbdcdddfe0e1e2e4e5e6e7e9eaebeceeeff0f1f3f4f5f6" },
    
    { "4ea6dfaba2d8a02ffdffa89835987242",
      "a115a2065d667e3f0b883837a6e903f8",
      "70717273757677787a7b7c7d7f80818284858687898a8b8c8e8f909193949596" },

    { "5ae094f54af58e6e3cdbf976dac6d9ef",
      "3e9e90dc33eac2437d86ad30b137e66e",
      "98999a9b9d9e9fa0a2a3a4a5a7a8a9aaacadaeafb1b2b3b4b6b7b8b9bbbcbdbe" },
    
    { "764d8e8e0f29926dbe5122e66354fdbe",
      "01ce82d8fbcdae824cb3c48e495c3692",
      "c0c1c2c3c5c6c7c8cacbcccdcfd0d1d2d4d5d6d7d9dadbdcdedfe0e1e3e4e5e6" },
    
    { "3f0418f888cdf29a982bf6b75410d6a9",
      "0c9cff163ce936faaf083cfd3dea3117",
      "e8e9eaebedeeeff0f2f3f4f5f7f8f9fafcfdfeff01020304060708090b0c0d0e" },
    
    { "e4a3e7cb12cdd56aa4a75197a9530220",
      "5131ba9bd48f2bba85560680df504b52",
      "10111213151617181a1b1c1d1f20212224252627292a2b2c2e2f303133343536" },
    
    { "211677684aac1ec1a160f44c4ebf3f26",
      "9dc503bbf09823aec8a977a5ad26ccb2",
      "38393a3b3d3e3f40424344454748494a4c4d4e4f51525354565758595b5c5d5e" },
    
    { "d21e439ff749ac8f18d6d4b105e03895",
      "9a6db0c0862e506a9e397225884041d7",
      "60616263656667686a6b6c6d6f70717274757677797a7b7c7e7f808183848586" },
    
    { "d9f6ff44646c4725bd4c0103ff5552a7",
      "430bf9570804185e1ab6365fc6a6860c",
      "88898a8b8d8e8f90929394959798999a9c9d9e9fa1a2a3a4a6a7a8a9abacadae" },
    
    { "0b1256c2a00b976250cfc5b0c37ed382",
      "3525ebc02f4886e6a5a3762813e8ce8a",
      "b0b1b2b3b5b6b7b8babbbcbdbfc0c1c2c4c5c6c7c9cacbcccecfd0d1d3d4d5d6" },
    
    { "b056447ffc6dc4523a36cc2e972a3a79",
      "07fa265c763779cce224c7bad671027b",
      "d8d9dadbdddedfe0e2e3e4e5e7e8e9eaecedeeeff1f2f3f4f6f7f8f9fbfcfdfe" },
    
    { "5e25ca78f0de55802524d38da3fe4456",
      "e8b72b4e8be243438c9fff1f0e205872",
      "00010203050607080a0b0c0d0f10111214151617191a1b1c1e1f202123242526" },
    
    { "a5bcf4728fa5eaad8567c0dc24675f83",
      "109d4f999a0e11ace1f05e6b22cbcb50",
      "28292a2b2d2e2f30323334353738393a3c3d3e3f41424344464748494b4c4d4e" },
    
    { "814e59f97ed84646b78b2ca022e9ca43",
      "45a5e8d4c3ed58403ff08d68a0cc4029",
      "50515253555657585a5b5c5d5f60616264656667696a6b6c6e6f707173747576" },
    
    { "15478beec58f4775c7a7f5d4395514d7",
      "196865964db3d417b6bd4d586bcb7634",
      "78797a7b7d7e7f80828384858788898a8c8d8e8f91929394969798999b9c9d9e" },
    
    { 0, 0, 0 }
};

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

	for (int n = 0; aes128TestValues[n].plaintext; n++) {
	    QCA::SymmetricKey key( QCA::hexToArray( aes128TestValues[n].key ) );
	    QCA::AES128 forwardCipher( QCA::Cipher::ECB, QCA::Encode, key );
	    forwardCipher.update( QCA::hexToArray( aes128TestValues[n].plaintext ) );
	    CHECK( QCA::arrayToHex( forwardCipher.final() ), QString( aes128TestValues[n].ciphertext ) );

	    QCA::AES128 reverseCipher( QCA::Cipher::ECB, QCA::Decode, key );
	    reverseCipher.update( QCA::hexToArray( aes128TestValues[n].ciphertext ) );
	    CHECK( QCA::arrayToHex( reverseCipher.final() ), QString( aes128TestValues[n].plaintext ) );
        }
    }

    if (!QCA::isSupported("aes192") )
	SKIP("AES192 not supported!\n");
    else {
	// FIPS 197, Appendix C.2
	QCA::SymmetricKey key1(QCA::hexToArray( "000102030405060708090A0B0C0D0E0F1011121314151617" ) );
	QCA::AES192 cipherObj1(QCA::Cipher::ECB, QCA::Encode, key1, QCA::InitializationVector(), false );
	QSecureArray data1 = QCA::hexToArray( "00112233445566778899AABBCCDDEEFF" );
	cipherObj1.update( data1 );
	CHECK( QCA::arrayToHex( cipherObj1.final() ), QString( "dda97ca4864cdfe06eaf70a0ec0d7191") );

	QCA::AES192 cipherObj2(QCA::Cipher::ECB, QCA::Decode, key1, QCA::InitializationVector(), false );
	cipherObj2.update( QCA::hexToArray( "dda97ca4864cdfe06eaf70a0ec0d7191") );
	CHECK( QCA::arrayToHex( cipherObj2.final() ), QString( "00112233445566778899aabbccddeeff" ) );

	for (int n = 0; aes192TestValues[n].plaintext; n++) {
	    QCA::SymmetricKey key( QCA::hexToArray( aes192TestValues[n].key ) );
	    QCA::AES192 forwardCipher( QCA::Cipher::ECB, QCA::Encode, key );
	    forwardCipher.update( QCA::hexToArray( aes192TestValues[n].plaintext ) );
	    CHECK( QCA::arrayToHex( forwardCipher.final() ), QString( aes192TestValues[n].ciphertext ) );

	    QCA::AES192 reverseCipher( QCA::Cipher::ECB, QCA::Decode, key );
	    reverseCipher.update( QCA::hexToArray( aes192TestValues[n].ciphertext ) );
	    CHECK( QCA::arrayToHex( reverseCipher.final() ), QString( aes192TestValues[n].plaintext ) );
        }
    }


    if (!QCA::isSupported("aes256") )
	SKIP("AES256 not supported!\n");
    else {
	// FIPS 197, Appendix C.3
	QCA::SymmetricKey key1(QCA::hexToArray( "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F" ) );
	QCA::AES256 cipherObj1(QCA::Cipher::ECB, QCA::Encode, key1, QCA::InitializationVector(), false );
	QSecureArray data1 = QCA::hexToArray( "00112233445566778899AABBCCDDEEFF" );
	cipherObj1.update( data1 );
	CHECK( QCA::arrayToHex( cipherObj1.final() ), QString( "8ea2b7ca516745bfeafc49904b496089") );

	QCA::AES256 cipherObj2(QCA::Cipher::ECB, QCA::Decode, key1, QCA::InitializationVector(), false );
	cipherObj2.update( QCA::hexToArray( "8EA2B7CA516745BFEAFC49904B496089") );
	CHECK( QCA::arrayToHex( cipherObj2.final() ), QString( "00112233445566778899aabbccddeeff" ) );

	for (int n = 0; aes256TestValues[n].plaintext; n++) {
	    QCA::SymmetricKey key( QCA::hexToArray( aes256TestValues[n].key ) );
	    QCA::AES256 forwardCipher( QCA::Cipher::ECB, QCA::Encode, key );
	    forwardCipher.update( QCA::hexToArray( aes256TestValues[n].plaintext ) );
	    CHECK( QCA::arrayToHex( forwardCipher.final() ), QString( aes256TestValues[n].ciphertext ) );

	    QCA::AES256 reverseCipher( QCA::Cipher::ECB, QCA::Decode, key );
	    reverseCipher.update( QCA::hexToArray( aes256TestValues[n].ciphertext ) );
	    CHECK( QCA::arrayToHex( reverseCipher.final() ), QString( aes256TestValues[n].plaintext ) );
        }
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

