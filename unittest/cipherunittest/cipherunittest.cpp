/**
 * Copyright (C)  2004-2007  Brad Hards <bradh@frogmouth.net>
 * Copyright (C)  2013-2016  Ivan Romanov <drizt@land.ru>
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

#include <QtCrypto>
#include <QtTest/QtTest>

#ifdef QT_STATICPLUGIN
#include "import_plugins.h"
#endif

void CipherUnitTest::initTestCase()
{
	m_init = new QCA::Initializer;
}

void CipherUnitTest::cleanupTestCase()
{
	delete m_init;
}

void CipherUnitTest::aes128_data()
{
	QTest::addColumn<QString>("plainText");
	QTest::addColumn<QString>("cipherText");
	QTest::addColumn<QString>("keyText");

	// Not sure where this came from...
	QTest::newRow("mystery") << QString("506812a45f08c889b97f5980038b8359")
							 << QString("d8f532538289ef7d06b506a4fd5be9c9")
							 << QString("00010203050607080a0b0c0d0f101112");

	// From FIPS 197 Appendix C.1
	QTest::newRow("FIPS197 App C.1") << QString("00112233445566778899aabbccddeeff")
									 << QString("69c4e0d86a7b0430d8cdb78070b4c55a")
									 << QString("000102030405060708090a0b0c0d0e0f");

	// These are from the Botan test suite
	QTest::newRow("1") << QString("506812a45f08c889b97f5980038b8359")
					   << QString("d8f532538289ef7d06b506a4fd5be9c9")
					   << QString("00010203050607080a0b0c0d0f101112");
	QTest::newRow("2") << QString("5c6d71ca30de8b8b00549984d2ec7d4b")
					   << QString("59ab30f4d4ee6e4ff9907ef65b1fb68c")
					   << QString("14151617191a1b1c1e1f202123242526");
	QTest::newRow("3") << QString("53f3f4c64f8616e4e7c56199f48f21f6")
					   << QString("bf1ed2fcb2af3fd41443b56d85025cb1")
					   << QString("28292a2b2d2e2f30323334353738393a");
	QTest::newRow("4") << QString("a1eb65a3487165fb0f1c27ff9959f703")
					   << QString("7316632d5c32233edcb0780560eae8b2")
					   << QString("3c3d3e3f41424344464748494b4c4d4e");
	QTest::newRow("5") << QString("3553ecf0b1739558b08e350a98a39bfa")
					   << QString("408c073e3e2538072b72625e68b8364b")
					   << QString("50515253555657585a5b5c5d5f606162");
	QTest::newRow("6") << QString("67429969490b9711ae2b01dc497afde8")
					   << QString("e1f94dfa776597beaca262f2f6366fea")
					   << QString("64656667696a6b6c6e6f707173747576");
	QTest::newRow("7") << QString("93385c1f2aec8bed192f5a8e161dd508")
					   << QString("f29e986c6a1c27d7b29ffd7ee92b75f1")
					   << QString("78797a7b7d7e7f80828384858788898a");
	QTest::newRow("8") << QString("3e23b3bc065bcc152407e23896d77783")
					   << QString("1959338344e945670678a5d432c90b93")
					   << QString("54555657595a5b5c5e5f606163646566");
	QTest::newRow("9") << QString("79f0fba002be1744670e7e99290d8f52")
					   << QString("e49bddd2369b83ee66e6c75a1161b394")
					   << QString("68696a6b6d6e6f70727374757778797a");
	QTest::newRow("10") << QString("da23fe9d5bd63e1d72e3dafbe21a6c2a")
						<< QString("d3388f19057ff704b70784164a74867d")
						<< QString("7c7d7e7f81828384868788898b8c8d8e");
	QTest::newRow("11") << QString("e3f5698ba90b6a022efd7db2c7e6c823")
						<< QString("23aa03e2d5e4cd24f3217e596480d1e1")
						<< QString("a4a5a6a7a9aaabacaeafb0b1b3b4b5b6");
	QTest::newRow("12") << QString("bdc2691d4f1b73d2700679c3bcbf9c6e")
						<< QString("c84113d68b666ab2a50a8bdb222e91b9")
						<< QString("e0e1e2e3e5e6e7e8eaebecedeff0f1f2");
	QTest::newRow("13") << QString("ba74e02093217ee1ba1b42bd5624349a")
						<< QString("ac02403981cd4340b507963db65cb7b6")
						<< QString("08090a0b0d0e0f10121314151718191a");
	QTest::newRow("14") << QString("b5c593b5851c57fbf8b3f57715e8f680")
						<< QString("8d1299236223359474011f6bf5088414")
						<< QString("6c6d6e6f71727374767778797b7c7d7e");

}


void CipherUnitTest::aes128()
{
	QStringList providersToTest;
	providersToTest.append("qca-ossl");
	// providersToTest.append("qca-gcrypt");
	providersToTest.append("qca-botan");
	providersToTest.append("qca-nss");

	foreach(const QString provider, providersToTest) {
		if( !QCA::isSupported( "aes128-ecb", provider ) )
			QWARN( QString( "AES128 ECB not supported for "+provider).toLocal8Bit() );
		else {
			QFETCH( QString, plainText );
			QFETCH( QString, cipherText );
			QFETCH( QString, keyText );

			QCA::SymmetricKey key( QCA::hexToArray( keyText ) );
			QCA::Cipher forwardCipher( QString( "aes128" ),
									   QCA::Cipher::ECB,
									   QCA::Cipher::NoPadding,
									   QCA::Encode,
									   key,
									   QCA::InitializationVector(),
									   provider );

			QCOMPARE( forwardCipher.blockSize(), 16 );
			QCOMPARE( forwardCipher.keyLength().minimum(), 16 );
			QCOMPARE( forwardCipher.keyLength().maximum(), 16 );

			QString afterEncodeText = QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( plainText ) ).toByteArray() );
			QVERIFY( forwardCipher.ok() );

			afterEncodeText += QCA::arrayToHex( forwardCipher.final().toByteArray() );
			QVERIFY( forwardCipher.ok() );

			QCOMPARE( afterEncodeText, cipherText );

			QCA::Cipher reverseCipher( QString( "aes128" ),
									   QCA::Cipher::ECB,
									   QCA::Cipher::NoPadding,
									   QCA::Decode,
									   key,
									   QCA::InitializationVector(),
									   provider );

			QCOMPARE( reverseCipher.blockSize(), 16 );
			QCOMPARE( reverseCipher.keyLength().minimum(), 16 );
			QCOMPARE( reverseCipher.keyLength().maximum(), 16 );

			QString afterDecodeText = QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( cipherText ) ).toByteArray() );
			QVERIFY( reverseCipher.ok() );

			afterDecodeText += QCA::arrayToHex( reverseCipher.final().toByteArray() );
			QVERIFY( reverseCipher.ok() );

			QCOMPARE( afterDecodeText, plainText );
		}
	}
}


// This is from the Botan test suite
void CipherUnitTest::aes128_cbc_data()
{
	QTest::addColumn<QString>("plainText");
	QTest::addColumn<QString>("cipherText");
	QTest::addColumn<QString>("keyText");
	QTest::addColumn<QString>("ivText");

	QTest::newRow("1") << QString("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
					   << QString("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7")
					   << QString("2b7e151628aed2a6abf7158809cf4f3c")
					   << QString("000102030405060708090a0b0c0d0e0f");
}

void CipherUnitTest::aes128_cbc()
{
	QStringList providersToTest;
	providersToTest.append("qca-ossl");
	providersToTest.append("qca-gcrypt");
	providersToTest.append("qca-botan");
	providersToTest.append("qca-nss");

	foreach(const QString provider, providersToTest) {
		if( !QCA::isSupported( "aes128-cbc", provider ) )
			QWARN( QString( "AES128 CBC not supported for "+provider).toLocal8Bit() );
		else {
			QFETCH( QString, plainText );
			QFETCH( QString, cipherText );
			QFETCH( QString, keyText );
			QFETCH( QString, ivText );

			QCA::SymmetricKey key( QCA::hexToArray( keyText ) );
			QCA::InitializationVector iv( QCA::hexToArray( ivText ) );
			QCA::Cipher forwardCipher( QString( "aes128" ),
									   QCA::Cipher::CBC,
									   QCA::Cipher::NoPadding,
									   QCA::Encode,
									   key,
									   iv,
									   provider);
			QString update = QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( plainText ) ).toByteArray() );
			QVERIFY( forwardCipher.ok() );
			QCOMPARE( update + QCA::arrayToHex( forwardCipher.final().toByteArray() ), cipherText );
			QVERIFY( forwardCipher.ok() );

			QCA::Cipher reverseCipher( QString( "aes128" ),
									   QCA::Cipher::CBC,
									   QCA::Cipher::NoPadding,
									   QCA::Decode,
									   key,
									   iv,
									   provider);
			update = QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( cipherText ) ).toByteArray() );
			QVERIFY( reverseCipher.ok() );
			QCOMPARE( update, plainText.left(update.size() ) );
			QCOMPARE( update + QCA::arrayToHex( reverseCipher.final().toByteArray() ), plainText );
			QVERIFY( reverseCipher.ok() );
		}
	}
}

// These were generated using OpenSSL's enc command
void CipherUnitTest::aes128_cbc_pkcs7_data()
{
	QTest::addColumn<QString>("plainText");
	QTest::addColumn<QString>("cipherText");
	QTest::addColumn<QString>("keyText");
	QTest::addColumn<QString>("ivText");

	QTest::newRow("1") << QString("")
					   << QString("18fe62efa4dc4b21a4127b225855b475")
					   << QString("0123456789ABCDEF0123456789ABCDEF")
					   << QString("00001111222233334444555566667777");

	QTest::newRow("2") << QString("610a")
					   << QString("92823eab12924cd168f54d3f4baa9a4d")
					   << QString("0123456789ABCDEF0123456789ABCDEF")
					   << QString("00001111222233334444555566667777");

	QTest::newRow("3") << QString("6162636465666768696a0a")
					   << QString("9d41b355abd61e3dfa482f3c1aeaae49")
					   << QString("0123456789ABCDEF0123456789ABCDEF")
					   << QString("00001111222233334444555566667777");

	QTest::newRow("block size - 1") << QString("6162636465666768696a6b6c6d6e0a")
									<< QString("c86b53850815cae7ae4a6e7529a87587")
									<< QString("0123456789ABCDEF0123456789ABCDEF")
									<< QString("00001111222233334444555566667777");

	QTest::newRow("block size") << QString("6162636465666768696a6b6c6d6e310a")
								<< QString("26fb0474b70d118f2b1d5b74e58c97bf3bb81bece1250509c5c68771ae23ceac")
								<< QString("0123456789ABCDEF0123456789ABCDEF")
								<< QString("00001111222233334444555566667777");

	QTest::newRow("block size+1") << QString("6162636465666768696a6b6c6d6e6f310a")
								  << QString("656f5c5693741967e059149e9239452fa286ac7c86ef653182d226d543d53013")
								  << QString("0123456789ABCDEF0123456789ABCDEF")
								  << QString("00001111222233334444555566667777");

}

void CipherUnitTest::aes128_cbc_pkcs7()
{
	QStringList providersToTest;
	providersToTest.append("qca-ossl");
	providersToTest.append("qca-gcrypt");
	providersToTest.append("qca-botan");
	providersToTest.append("qca-nss");

	foreach(const QString provider, providersToTest) {
		if( !QCA::isSupported( "aes128-cbc-pkcs7", provider ) )
			QWARN( QString( "AES128 CBC with PKCS7 padding not supported for "+provider).toLocal8Bit() );
		else {
			QFETCH( QString, plainText );
			QFETCH( QString, cipherText );
			QFETCH( QString, keyText );
			QFETCH( QString, ivText );

			QCA::SymmetricKey key( QCA::hexToArray( keyText ) );
			QCA::InitializationVector iv( QCA::hexToArray( ivText ) );
			QCA::Cipher forwardCipher( QString( "aes128" ),
									   QCA::Cipher::CBC,
									   QCA::Cipher::DefaultPadding,
									   QCA::Encode,
									   key,
									   iv,
									   provider);
			QString update = QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( plainText ) ).toByteArray() );
			QVERIFY( forwardCipher.ok() );
			QCOMPARE( update + QCA::arrayToHex( forwardCipher.final().toByteArray() ), cipherText );
			QVERIFY( forwardCipher.ok() );

			QCA::Cipher reverseCipher( QString( "aes128" ),
									   QCA::Cipher::CBC,
									   QCA::Cipher::DefaultPadding,
									   QCA::Decode,
									   key,
									   iv,
									   provider);
			update = QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( cipherText ) ).toByteArray() );
			QVERIFY( reverseCipher.ok() );
			QCOMPARE( update, plainText.left(update.size() ) );
			QCOMPARE( update + QCA::arrayToHex( reverseCipher.final().toByteArray() ), plainText );
			QVERIFY( reverseCipher.ok() );
		}
	}
}

// This is from the Botan test suite
void CipherUnitTest::aes128_cfb_data()
{
	QTest::addColumn<QString>("plainText");
	QTest::addColumn<QString>("cipherText");
	QTest::addColumn<QString>("keyText");
	QTest::addColumn<QString>("ivText");

	QTest::newRow("1") << QString("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
					   << QString("3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6")
					   << QString("2b7e151628aed2a6abf7158809cf4f3c")
					   << QString("000102030405060708090a0b0c0d0e0f");
}

void CipherUnitTest::aes128_cfb()
{
	QStringList providersToTest;
	providersToTest.append("qca-ossl");
	providersToTest.append("qca-gcrypt");
	providersToTest.append("qca-botan");
	providersToTest.append("qca-nss");

	foreach(const QString provider, providersToTest) {
		if( !QCA::isSupported( "aes128-cfb", provider ) )
			QWARN( QString( "AES128 CFB not supported for "+provider).toLocal8Bit() );
		else {
			QFETCH( QString, plainText );
			QFETCH( QString, cipherText );
			QFETCH( QString, keyText );
			QFETCH( QString, ivText );

			QCA::SymmetricKey key( QCA::hexToArray( keyText ) );
			QCA::InitializationVector iv( QCA::hexToArray( ivText ) );
			QCA::Cipher forwardCipher( QString( "aes128" ),
									   QCA::Cipher::CFB,
									   QCA::Cipher::NoPadding,
									   QCA::Encode,
									   key,
									   iv,
									   provider);
			QString update = QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( plainText ) ).toByteArray() );
			QVERIFY( forwardCipher.ok() );
			QCOMPARE( update + QCA::arrayToHex( forwardCipher.final().toByteArray() ), cipherText );
			QVERIFY( forwardCipher.ok() );

			QCA::Cipher reverseCipher( QString( "aes128" ),
									   QCA::Cipher::CFB,
									   QCA::Cipher::NoPadding,
									   QCA::Decode,
									   key,
									   iv,
									   provider);
			update = QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( cipherText ) ).toByteArray() );
			QVERIFY( reverseCipher.ok() );
			QCOMPARE( update, plainText.left(update.size() ) );
			QCOMPARE( update + QCA::arrayToHex( reverseCipher.final().toByteArray() ), plainText );
			QVERIFY( reverseCipher.ok() );
		}
	}
}

// This is from the Botan test suite
void CipherUnitTest::aes128_ofb_data()
{
	QTest::addColumn<QString>("plainText");
	QTest::addColumn<QString>("cipherText");
	QTest::addColumn<QString>("keyText");
	QTest::addColumn<QString>("ivText");

	QTest::newRow("1") << QString("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
					   << QString("3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed8259740051e9c5fecf64344f7a82260edcc304c6528f659c77866a510d9c1d6ae5e")
					   << QString("2b7e151628aed2a6abf7158809cf4f3c")
					   << QString("000102030405060708090a0b0c0d0e0f");
}

void CipherUnitTest::aes128_ofb()
{
	QStringList providersToTest;
	providersToTest.append("qca-ossl");
	providersToTest.append("qca-gcrypt");
	providersToTest.append("qca-botan");
	providersToTest.append("qca-nss");

	foreach(const QString provider, providersToTest) {
		if( !QCA::isSupported( "aes128-ofb", provider ) )
			QWARN( QString( "AES128 OFB not supported for "+provider).toLocal8Bit() );
		else {
			QFETCH( QString, plainText );
			QFETCH( QString, cipherText );
			QFETCH( QString, keyText );
			QFETCH( QString, ivText );

			QCA::SymmetricKey key( QCA::hexToArray( keyText ) );
			QCA::InitializationVector iv( QCA::hexToArray( ivText ) );
			QCA::Cipher forwardCipher( QString( "aes128" ),
									   QCA::Cipher::OFB,
									   QCA::Cipher::NoPadding,
									   QCA::Encode,
									   key,
									   iv,
									   provider);
			QString update = QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( plainText ) ).toByteArray() );
			QVERIFY( forwardCipher.ok() );
			QCOMPARE( update + QCA::arrayToHex( forwardCipher.final().toByteArray() ), cipherText );
			QVERIFY( forwardCipher.ok() );

			QCA::Cipher reverseCipher( QString( "aes128" ),
									   QCA::Cipher::OFB,
									   QCA::Cipher::NoPadding,
									   QCA::Decode,
									   key,
									   iv,
									   provider);
			update = QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( cipherText ) ).toByteArray() );
			QVERIFY( reverseCipher.ok() );
			QCOMPARE( update, plainText.left(update.size() ) );
			QCOMPARE( update + QCA::arrayToHex( reverseCipher.final().toByteArray() ), plainText );
			QVERIFY( reverseCipher.ok() );
		}
	}
}

void CipherUnitTest::aes128_ctr_data()
{
	QTest::addColumn<QString>("plainText");
	QTest::addColumn<QString>("cipherText");
	QTest::addColumn<QString>("keyText");
	QTest::addColumn<QString>("ivText");

	QTest::newRow("1") << QString("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
					   << QString("3b3fd92eb72dad20333449f8e83cfb4a010c041999e03f36448624483e582d0ea62293cfa6df74535c354181168774df2d55a54706273c50d7b4f8a8cddc6ed7")
					   << QString("2b7e151628aed2a6abf7158809cf4f3c")
					   << QString("000102030405060708090a0b0c0d0e0f");
}

void CipherUnitTest::aes128_ctr()
{
	QStringList providersToTest;
	providersToTest.append("qca-ossl");
	providersToTest.append("qca-gcrypt");
	providersToTest.append("qca-botan");
	providersToTest.append("qca-nss");

	foreach(const QString provider, providersToTest) {
		if( !QCA::isSupported( "aes128-ctr", provider ) )
			QWARN( QString( "AES128 CTR not supported for "+provider).toLocal8Bit() );
		else {
			QFETCH( QString, plainText );
			QFETCH( QString, cipherText );
			QFETCH( QString, keyText );
			QFETCH( QString, ivText );

			QCA::SymmetricKey key( QCA::hexToArray( keyText ) );
			QCA::InitializationVector iv( QCA::hexToArray( ivText ) );
			QCA::Cipher forwardCipher( QString( "aes128" ),
									   QCA::Cipher::CTR,
									   QCA::Cipher::NoPadding,
									   QCA::Encode,
									   key,
									   iv,
									   provider);
			QString update = QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( plainText ) ).toByteArray() );
			QVERIFY( forwardCipher.ok() );
			QCOMPARE( update + QCA::arrayToHex( forwardCipher.final().toByteArray() ), cipherText );
			QVERIFY( forwardCipher.ok() );

			QCA::Cipher reverseCipher( QString( "aes128" ),
									   QCA::Cipher::CTR,
									   QCA::Cipher::NoPadding,
									   QCA::Decode,
									   key,
									   iv,
									   provider);
			update = QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( cipherText ) ).toByteArray() );
			QVERIFY( reverseCipher.ok() );
			QCOMPARE( update, plainText.left(update.size() ) );
			QCOMPARE( update + QCA::arrayToHex( reverseCipher.final().toByteArray() ), plainText );
			QVERIFY( reverseCipher.ok() );
		}
	}
}

void CipherUnitTest::aes128_gcm_data()
{
	QTest::addColumn<QString>("plainText");
	QTest::addColumn<QString>("payload");
	QTest::addColumn<QString>("tag");
	QTest::addColumn<QString>("keyText");
	QTest::addColumn<QString>("ivText");

	QTest::newRow("short") << QString("6f6820526f6d656d6f21")
						   << QString("a9f2558b9a74e6fc551f")
						   << QString("f8ebf75f108c6f74e6fe49035d268d43")
						   << QString("1f491f8ddf4856ae4bff9039d418175a")
						   << QString("f85f8aad39164daf64a12ad9b3fc8a3a");

	QTest::newRow("long") << QString("54484520515549434b2042524f574e20464f58204a554d504544204f56455220544845204c415a5920444f472753204241434b2031323334353637383930")
						  << QString("04e321a8870b6b9cd6846239c27a63fb41d0a7b8994f1514c066f0427fa9ed6707ea6e3b4f161fdff0eb5fc087ed3827b569cd72456c697b5a3a62c9e767")
						  << QString("b0ad4aa545ea25fc3117cbed955ff155")
						  << QString("56341f2b431d3b0dbad787db003f2215")
						  << QString("bfcd3a7252f7f199bf788df8cf61032a");


	QTest::newRow("wrongtag") << QString("6f6820526f6d656d6f21")
							  << QString("a9f2558b9a74e6fc551f")
							  << QString("f8ebf75f108c6f74e6fe49035d268d44")
							  << QString("1f491f8ddf4856ae4bff9039d418175a")
							  << QString("f85f8aad39164daf64a12ad9b3fc8a3a");
}

void CipherUnitTest::aes128_gcm()
{
	QStringList providersToTest;
	providersToTest.append("qca-ossl");
	providersToTest.append("qca-gcrypt");
	providersToTest.append("qca-botan");
	providersToTest.append("qca-nss");

	foreach (const QString &provider, providersToTest) {
		if (!QCA::isSupported( "aes128-gcm", provider))
			QWARN(QString("AES128 GCM not supported for " + provider).toLocal8Bit());
		else {
			QFETCH(QString, plainText);
			QFETCH(QString, payload);
			QFETCH(QString, tag);
			QFETCH(QString, keyText);
			QFETCH(QString, ivText);

			QCA::SymmetricKey key(QCA::hexToArray(keyText));
			QCA::InitializationVector iv(QCA::hexToArray(ivText));
			QCA::AuthTag authTag(16);
			QCA::Cipher forwardCipher(QString("aes128"),
									  QCA::Cipher::GCM,
									  QCA::Cipher::NoPadding,
									  QCA::Encode,
									  key,
									  iv,
									  authTag,
									  provider);
			QString update = QCA::arrayToHex(forwardCipher.update(QCA::hexToArray(plainText)).toByteArray());
			QVERIFY(forwardCipher.ok());
			update += QCA::arrayToHex(forwardCipher.final().toByteArray());
			authTag = forwardCipher.tag();
			QEXPECT_FAIL("wrongtag", "It's OK", Continue);
			QCOMPARE(QCA::arrayToHex(authTag.toByteArray()), tag);
			QCOMPARE(update, payload);
			QVERIFY(forwardCipher.ok());

			QCA::Cipher reverseCipher(QString( "aes128"),
									  QCA::Cipher::GCM,
									  QCA::Cipher::NoPadding,
									  QCA::Decode,
									  key,
									  iv,
									  QCA::AuthTag(QCA::hexToArray(tag)),
									  provider);

			update = QCA::arrayToHex(reverseCipher.update(QCA::hexToArray(payload)).toByteArray());
			QVERIFY(reverseCipher.ok());
			QCOMPARE(update, plainText.left(update.size()));
			update += QCA::arrayToHex(reverseCipher.final().toByteArray());
			QEXPECT_FAIL("wrongtag", "It's OK", Continue);
			QCOMPARE(update, plainText);
			QEXPECT_FAIL("wrongtag", "It's OK", Continue);
			QVERIFY(reverseCipher.ok());
		}
	}
}

void CipherUnitTest::aes128_ccm_data()
{

}

void CipherUnitTest::aes128_ccm()
{
	// For future implementation
}

void CipherUnitTest::aes192_data()
{
	QTest::addColumn<QString>("plainText");
	QTest::addColumn<QString>("cipherText");
	QTest::addColumn<QString>("keyText");


	// From FIPS 197 Appendix C.2
	QTest::newRow("FIPS197 App C.2") << QString("00112233445566778899aabbccddeeff")
									 << QString("dda97ca4864cdfe06eaf70a0ec0d7191")
									 << QString("000102030405060708090A0B0C0D0E0F1011121314151617");

	// These are from the Botan test suite
	QTest::newRow("1") << QString("fec1c04f529bbd17d8cecfcc4718b17f")
					   << QString("62564c738f3efe186e1a127a0c4d3c61")
					   << QString("4a4b4c4d4f50515254555657595a5b5c5e5f606163646566");
	QTest::newRow("2") << QString("32df99b431ed5dc5acf8caf6dc6ce475")
					   << QString("07805aa043986eb23693e23bef8f3438")
					   << QString("68696a6b6d6e6f70727374757778797a7c7d7e7f81828384");
	QTest::newRow("3") << QString("7fdc2b746f3f665296943b83710d1f82")
					   << QString("df0b4931038bade848dee3b4b85aa44b")
					   << QString("868788898b8c8d8e90919293959697989a9b9c9d9fa0a1a2");
	QTest::newRow("4") << QString("8fba1510a3c5b87e2eaa3f7a91455ca2")
					   << QString("592d5fded76582e4143c65099309477c")
					   << QString("a4a5a6a7a9aaabacaeafb0b1b3b4b5b6b8b9babbbdbebfc0");
	QTest::newRow("5") << QString("2c9b468b1c2eed92578d41b0716b223b")
					   << QString("c9b8d6545580d3dfbcdd09b954ed4e92")
					   << QString("c2c3c4c5c7c8c9cacccdcecfd1d2d3d4d6d7d8d9dbdcddde");
	QTest::newRow("6") << QString("0a2bbf0efc6bc0034f8a03433fca1b1a")
					   << QString("5dccd5d6eb7c1b42acb008201df707a0")
					   << QString("e0e1e2e3e5e6e7e8eaebecedeff0f1f2f4f5f6f7f9fafbfc");
	QTest::newRow("7") << QString("25260e1f31f4104d387222e70632504b")
					   << QString("a2a91682ffeb6ed1d34340946829e6f9")
					   << QString("fefe01010304050608090a0b0d0e0f10121314151718191a");
	QTest::newRow("8") << QString("c527d25a49f08a5228d338642ae65137")
					   << QString("e45d185b797000348d9267960a68435d")
					   << QString("1c1d1e1f21222324262728292b2c2d2e3031323335363738");
	QTest::newRow("9") << QString("3b49fc081432f5890d0e3d87e884a69e")
					   << QString("45e060dae5901cda8089e10d4f4c246b")
					   << QString("3a3b3c3d3f40414244454647494a4b4c4e4f505153545556");
	QTest::newRow("10") << QString("d173f9ed1e57597e166931df2754a083")
						<< QString("f6951afacc0079a369c71fdcff45df50")
						<< QString("58595a5b5d5e5f60626364656768696a6c6d6e6f71727374");
	QTest::newRow("11") << QString("8c2b7cafa5afe7f13562daeae1adede0")
						<< QString("9e95e00f351d5b3ac3d0e22e626ddad6")
						<< QString("767778797b7c7d7e80818283858687888a8b8c8d8f909192");
	QTest::newRow("12") << QString("aaf4ec8c1a815aeb826cab741339532c")
						<< QString("9cb566ff26d92dad083b51fdc18c173c")
						<< QString("94959697999a9b9c9e9fa0a1a3a4a5a6a8a9aaabadaeafb0");
	QTest::newRow("13") << QString("40be8c5d9108e663f38f1a2395279ecf")
						<< QString("c9c82766176a9b228eb9a974a010b4fb")
						<< QString("d0d1d2d3d5d6d7d8dadbdcdddfe0e1e2e4e5e6e7e9eaebec");
	QTest::newRow("14") << QString("0c8ad9bc32d43e04716753aa4cfbe351")
						<< QString("d8e26aa02945881d5137f1c1e1386e88")
						<< QString("2a2b2c2d2f30313234353637393a3b3c3e3f404143444546");
	QTest::newRow("15") << QString("1407b1d5f87d63357c8dc7ebbaebbfee")
						<< QString("c0e024ccd68ff5ffa4d139c355a77c55")
						<< QString("48494a4b4d4e4f50525354555758595a5c5d5e5f61626364");
}


void CipherUnitTest::aes192()
{
	QStringList providersToTest;
	providersToTest.append("qca-ossl");
	// providersToTest.append("qca-gcrypt");
	providersToTest.append("qca-botan");
	providersToTest.append("qca-nss");

	foreach(const QString provider, providersToTest) {
		if( !QCA::isSupported( "aes192-ecb", provider ) )
			QWARN( QString( "AES192 ECB not supported for "+provider).toLocal8Bit() );
		else {
			QFETCH( QString, plainText );
			QFETCH( QString, cipherText );
			QFETCH( QString, keyText );

			QCA::SymmetricKey key( QCA::hexToArray( keyText ) );
			QCA::Cipher forwardCipher( QString( "aes192" ),
									   QCA::Cipher::ECB,
									   QCA::Cipher::NoPadding,
									   QCA::Encode,
									   key,
									   QCA::InitializationVector(),
									   provider );

			QCOMPARE( forwardCipher.blockSize(), 16 );
			QCOMPARE( forwardCipher.keyLength().minimum(), 24 );
			QCOMPARE( forwardCipher.keyLength().maximum(), 24 );

			QString afterEncodeText = QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( plainText ) ).toByteArray() );
			QVERIFY( forwardCipher.ok() );

			afterEncodeText += QCA::arrayToHex( forwardCipher.final().toByteArray() );
			QVERIFY( forwardCipher.ok() );

			QCOMPARE( afterEncodeText, cipherText );

			QCA::Cipher reverseCipher( QString( "aes192" ),
									   QCA::Cipher::ECB,
									   QCA::Cipher::NoPadding,
									   QCA::Decode,
									   key,
									   QCA::InitializationVector(),
									   provider );

			QCOMPARE( reverseCipher.blockSize(), 16 );
			QCOMPARE( reverseCipher.keyLength().minimum(), 24 );
			QCOMPARE( reverseCipher.keyLength().maximum(), 24 );

			QString afterDecodeText = QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( cipherText ) ).toByteArray() );
			QVERIFY( reverseCipher.ok() );

			afterDecodeText += QCA::arrayToHex( reverseCipher.final().toByteArray() );
			QVERIFY( reverseCipher.ok() );

			QCOMPARE( afterDecodeText, plainText );
		}
	}
}


// This is from the Botan test suite
void CipherUnitTest::aes192_cbc_data()
{
	QTest::addColumn<QString>("plainText");
	QTest::addColumn<QString>("cipherText");
	QTest::addColumn<QString>("keyText");
	QTest::addColumn<QString>("ivText");

	QTest::newRow("1") << QString("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
					   << QString("4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd")
					   << QString("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")
					   << QString("000102030405060708090a0b0c0d0e0f");
}


void CipherUnitTest::aes192_cbc()
{
	QStringList providersToTest;
	providersToTest.append("qca-ossl");
	providersToTest.append("qca-gcrypt");
	providersToTest.append("qca-botan");
	providersToTest.append("qca-nss");

	foreach(const QString provider, providersToTest) {
		if( !QCA::isSupported( "aes192-cbc", provider ) )
			QWARN( QString( "AES192 CBC not supported for "+provider).toLocal8Bit() );
		else {
			QFETCH( QString, plainText );
			QFETCH( QString, cipherText );
			QFETCH( QString, keyText );
			QFETCH( QString, ivText );

			QCA::SymmetricKey key( QCA::hexToArray( keyText ) );
			QCA::InitializationVector iv( QCA::hexToArray( ivText ) );
			QCA::Cipher forwardCipher( QString( "aes192" ),
									   QCA::Cipher::CBC,
									   QCA::Cipher::NoPadding,
									   QCA::Encode,
									   key,
									   iv,
									   provider);
			QString update = QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( plainText ) ).toByteArray() );
			QVERIFY( forwardCipher.ok() );
			QCOMPARE( update + QCA::arrayToHex( forwardCipher.final().toByteArray() ), cipherText );
			QVERIFY( forwardCipher.ok() );

			QCA::Cipher reverseCipher( QString( "aes192" ),
									   QCA::Cipher::CBC,
									   QCA::Cipher::NoPadding,
									   QCA::Decode,
									   key,
									   iv,
									   provider);
			update = QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( cipherText ) ).toByteArray() );
			QVERIFY( reverseCipher.ok() );
			QCOMPARE( update, plainText.left(update.size() ) );
			QCOMPARE( update + QCA::arrayToHex( reverseCipher.final().toByteArray() ), plainText );
			QVERIFY( reverseCipher.ok() );
		}
	}
}

// These were generated using OpenSSL's enc command
void CipherUnitTest::aes192_cbc_pkcs7_data()
{
	QTest::addColumn<QString>("plainText");
	QTest::addColumn<QString>("cipherText");
	QTest::addColumn<QString>("keyText");
	QTest::addColumn<QString>("ivText");

	QTest::newRow("1") << QString("")
					   << QString("49c1da70f461d1bb5147ded60f0f01ef")
					   << QString("0123456789ABCDEF0123456789ABCDEF0011223344556677")
					   << QString("00001111222233334444555566667777");

	QTest::newRow("2") << QString("610a")
					   << QString("42e5a030df8b6bf896899853744e480c")
					   << QString("0123456789ABCDEF0123456789ABCDEF0011223344556677")
					   << QString("00001111222233334444555566667777");

	QTest::newRow("3") << QString("6162636465666768696a0a")
					   << QString("160a3b6ff48d6850906ffa6b8291f511")
					   << QString("0123456789ABCDEF0123456789ABCDEF0011223344556677")
					   << QString("00001111222233334444555566667777");

	QTest::newRow("block size - 1") << QString("6162636465666768696a6b6c6d6e0a")
									<< QString("b113c5aec849e49dc8487f66ce29bab0")
									<< QString("0123456789ABCDEF0123456789ABCDEF0011223344556677")
									<< QString("00001111222233334444555566667777");

	QTest::newRow("block size") << QString("6162636465666768696a6b6c6d6e310a")
								<< QString("80c4a001f93c468b7dd3525cc46020b470e3ac39a13be57ab18c7903d121a266")
								<< QString("0123456789ABCDEF0123456789ABCDEF0011223344556677")
								<< QString("00001111222233334444555566667777");

	QTest::newRow("block size+1") << QString("6162636465666768696a6b6c6d6e6f310a")
								  << QString("f0f9982e4118287cda37062f5acfd7b2f27741ddac7bd3882c7b4e4872b81047")
								  << QString("0123456789ABCDEF0123456789ABCDEF0011223344556677")
								  << QString("00001111222233334444555566667777");

}

void CipherUnitTest::aes192_cbc_pkcs7()
{
	QStringList providersToTest;
	providersToTest.append("qca-ossl");
	providersToTest.append("qca-gcrypt");
	providersToTest.append("qca-botan");
	providersToTest.append("qca-nss");

	foreach(const QString provider, providersToTest) {
		if( !QCA::isSupported( "aes192-cbc-pkcs7", provider ) )
			QWARN( QString( "AES192 CBC with PKCS7 padding not supported for "+provider).toLocal8Bit() );
		else {
			QFETCH( QString, plainText );
			QFETCH( QString, cipherText );
			QFETCH( QString, keyText );
			QFETCH( QString, ivText );

			QCA::SymmetricKey key( QCA::hexToArray( keyText ) );
			QCA::InitializationVector iv( QCA::hexToArray( ivText ) );
			QCA::Cipher forwardCipher( QString( "aes192" ),
									   QCA::Cipher::CBC,
									   QCA::Cipher::DefaultPadding,
									   QCA::Encode,
									   key,
									   iv,
									   provider);
			QString update = QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( plainText ) ).toByteArray() );
			QVERIFY( forwardCipher.ok() );
			QCOMPARE( update + QCA::arrayToHex( forwardCipher.final().toByteArray() ), cipherText );
			QVERIFY( forwardCipher.ok() );

			QCA::Cipher reverseCipher( QString( "aes192" ),
									   QCA::Cipher::CBC,
									   QCA::Cipher::DefaultPadding,
									   QCA::Decode,
									   key,
									   iv,
									   provider);
			update = QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( cipherText ) ).toByteArray() );
			QVERIFY( reverseCipher.ok() );
			QCOMPARE( update, plainText.left(update.size() ) );
			QCOMPARE( update + QCA::arrayToHex( reverseCipher.final().toByteArray() ), plainText );
			QVERIFY( reverseCipher.ok() );
		}
	}
}


// This is from the Botan test suite
void CipherUnitTest::aes192_cfb_data()
{
	QTest::addColumn<QString>("plainText");
	QTest::addColumn<QString>("cipherText");
	QTest::addColumn<QString>("keyText");
	QTest::addColumn<QString>("ivText");

	QTest::newRow("1") << QString("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
					   << QString("cdc80d6fddf18cab34c25909c99a417467ce7f7f81173621961a2b70171d3d7a2e1e8a1dd59b88b1c8e60fed1efac4c9c05f9f9ca9834fa042ae8fba584b09ff")
					   << QString("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")
					   << QString("000102030405060708090a0b0c0d0e0f");
}

void CipherUnitTest::aes192_cfb()
{
	QStringList providersToTest;
	providersToTest.append("qca-ossl");
	providersToTest.append("qca-gcrypt");
	providersToTest.append("qca-botan");
	providersToTest.append("qca-nss");

	foreach(const QString provider, providersToTest) {
		if( !QCA::isSupported( "aes192-cfb", provider ) )
			QWARN( QString( "AES192 CFB not supported for "+provider).toLocal8Bit() );
		else {
			QFETCH( QString, plainText );
			QFETCH( QString, cipherText );
			QFETCH( QString, keyText );
			QFETCH( QString, ivText );

			QCA::SymmetricKey key( QCA::hexToArray( keyText ) );
			QCA::InitializationVector iv( QCA::hexToArray( ivText ) );
			QCA::Cipher forwardCipher( QString( "aes192" ),
									   QCA::Cipher::CFB,
									   QCA::Cipher::NoPadding,
									   QCA::Encode,
									   key,
									   iv,
									   provider);
			QString update = QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( plainText ) ).toByteArray() );
			QVERIFY( forwardCipher.ok() );
			QCOMPARE( update + QCA::arrayToHex( forwardCipher.final().toByteArray() ), cipherText );
			QVERIFY( forwardCipher.ok() );

			QCA::Cipher reverseCipher( QString( "aes192" ),
									   QCA::Cipher::CFB,
									   QCA::Cipher::NoPadding,
									   QCA::Decode,
									   key,
									   iv,
									   provider);
			update = QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( cipherText ) ).toByteArray() );
			QVERIFY( reverseCipher.ok() );
			QCOMPARE( update, plainText.left(update.size() ) );
			QCOMPARE( update + QCA::arrayToHex( reverseCipher.final().toByteArray() ), plainText );
			QVERIFY( reverseCipher.ok() );
		}
	}
}

// This is from the Botan test suite
void CipherUnitTest::aes192_ofb_data()
{
	QTest::addColumn<QString>("plainText");
	QTest::addColumn<QString>("cipherText");
	QTest::addColumn<QString>("keyText");
	QTest::addColumn<QString>("ivText");

	QTest::newRow("1") << QString("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
					   << QString("cdc80d6fddf18cab34c25909c99a4174fcc28b8d4c63837c09e81700c11004018d9a9aeac0f6596f559c6d4daf59a5f26d9f200857ca6c3e9cac524bd9acc92a")
					   << QString("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")
					   << QString("000102030405060708090a0b0c0d0e0f");
}

void CipherUnitTest::aes192_ofb()
{
	QStringList providersToTest;
	providersToTest.append("qca-ossl");
	providersToTest.append("qca-gcrypt");
	providersToTest.append("qca-botan");
	providersToTest.append("qca-nss");

	foreach(const QString provider, providersToTest) {
		if( !QCA::isSupported( "aes192-ofb", provider ) )
			QWARN( QString( "AES192 OFB not supported for "+provider).toLocal8Bit() );
		else {
			QFETCH( QString, plainText );
			QFETCH( QString, cipherText );
			QFETCH( QString, keyText );
			QFETCH( QString, ivText );

			QCA::SymmetricKey key( QCA::hexToArray( keyText ) );
			QCA::InitializationVector iv( QCA::hexToArray( ivText ) );
			QCA::Cipher forwardCipher( QString( "aes192" ),
									   QCA::Cipher::OFB,
									   QCA::Cipher::NoPadding,
									   QCA::Encode,
									   key,
									   iv,
									   provider);
			QString update = QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( plainText ) ).toByteArray() );
			QVERIFY( forwardCipher.ok() );
			QCOMPARE( update + QCA::arrayToHex( forwardCipher.final().toByteArray() ), cipherText );
			QVERIFY( forwardCipher.ok() );

			QCA::Cipher reverseCipher( QString( "aes192" ),
									   QCA::Cipher::OFB,
									   QCA::Cipher::NoPadding,
									   QCA::Decode,
									   key,
									   iv,
									   provider);
			update = QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( cipherText ) ).toByteArray() );
			QVERIFY( reverseCipher.ok() );
			QCOMPARE( update, plainText.left(update.size() ) );
			QCOMPARE( update + QCA::arrayToHex( reverseCipher.final().toByteArray() ), plainText );
			QVERIFY( reverseCipher.ok() );
		}
	}
}

void CipherUnitTest::aes192_ctr_data()
{
	QTest::addColumn<QString>("plainText");
	QTest::addColumn<QString>("cipherText");
	QTest::addColumn<QString>("keyText");
	QTest::addColumn<QString>("ivText");

	QTest::newRow("1") << QString("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
					   << QString("cdc80d6fddf18cab34c25909c99a417437d8a639171fdcca63ebd17ce2d7321a79a0c96b53c7eeecd9ed7157c444fc7a845c37b2f511697b0e89d5ed60c4d49e")
					   << QString("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")
					   << QString("000102030405060708090a0b0c0d0e0f");
}

void CipherUnitTest::aes192_ctr()
{
	QStringList providersToTest;
	providersToTest.append("qca-ossl");
	providersToTest.append("qca-gcrypt");
	providersToTest.append("qca-botan");
	providersToTest.append("qca-nss");

	foreach(const QString provider, providersToTest) {
		if( !QCA::isSupported( "aes192-ctr", provider ) )
			QWARN( QString( "AES192 CTR not supported for "+provider).toLocal8Bit() );
		else {
			QFETCH( QString, plainText );
			QFETCH( QString, cipherText );
			QFETCH( QString, keyText );
			QFETCH( QString, ivText );

			QCA::SymmetricKey key( QCA::hexToArray( keyText ) );
			QCA::InitializationVector iv( QCA::hexToArray( ivText ) );
			QCA::Cipher forwardCipher( QString( "aes192" ),
									   QCA::Cipher::CTR,
									   QCA::Cipher::NoPadding,
									   QCA::Encode,
									   key,
									   iv,
									   provider);
			QString update = QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( plainText ) ).toByteArray() );
			QVERIFY( forwardCipher.ok() );
			QCOMPARE( update + QCA::arrayToHex( forwardCipher.final().toByteArray() ), cipherText );
			QVERIFY( forwardCipher.ok() );

			QCA::Cipher reverseCipher( QString( "aes192" ),
									   QCA::Cipher::CTR,
									   QCA::Cipher::NoPadding,
									   QCA::Decode,
									   key,
									   iv,
									   provider);
			update = QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( cipherText ) ).toByteArray() );
			QVERIFY( reverseCipher.ok() );
			QCOMPARE( update, plainText.left(update.size() ) );
			QCOMPARE( update + QCA::arrayToHex( reverseCipher.final().toByteArray() ), plainText );
			QVERIFY( reverseCipher.ok() );
		}
	}
}

void CipherUnitTest::aes192_gcm_data()
{
	QTest::addColumn<QString>("plainText");
	QTest::addColumn<QString>("payload");
	QTest::addColumn<QString>("tag");
	QTest::addColumn<QString>("keyText");
	QTest::addColumn<QString>("ivText");

	QTest::newRow("short") << QString("6f6820526f6d656d6f21")
						   << QString("01ca25ff74121917f397")
						   << QString("b90e97706d8eacbabc0be5e0a671b4e4")
						   << QString("7ecb21a647fae54a0996ad281ab0c1a00cb905d9e2eb3b82")
						   << QString("f85f8aad39164daf64a12ad9b3fc8a3a");

	QTest::newRow("long") << QString("54484520515549434b2042524f574e20464f58204a554d504544204f56455220544845204c415a5920444f472753204241434b2031323334353637383930")
						  << QString("4c1c5874877f0bee6efd450ec341b1c591e1e100da40bd4744e1035ed0ed0fb458f8efdb7c4b0b2101e29c950c56dc2489c2febec2d7062da28b9a033173")
						  << QString("af3ea1b7f275ea1e4d4e1fdce63f83fe")
						  << QString("7ecb21a647fae54a0996ad281ab0c1a00cb905d9e2eb3b82")
						  << QString("bfcd3a7252f7f199bf788df8cf61032a");


	QTest::newRow("wrongtag") << QString("6f6820526f6d656d6f21")
							  << QString("773c3d06b94727c04afc")
							  << QString("c558aca7f19050db49d94d99119277af")
							  << QString("7ecb21a647fae54a0996ad281ab0c1a00cb905d9e2eb3b82")
							  << QString("bfcd3a7252f7f199bf788df8cf61032a");
}

void CipherUnitTest::aes192_gcm()
{
	QStringList providersToTest;
	providersToTest.append("qca-ossl");
	providersToTest.append("qca-gcrypt");
	providersToTest.append("qca-botan");
	providersToTest.append("qca-nss");

	foreach (const QString &provider, providersToTest) {
		if (!QCA::isSupported( "aes192-gcm", provider))
			QWARN(QString("AES128 GCM not supported for " + provider).toLocal8Bit());
		else {
			QFETCH(QString, plainText);
			QFETCH(QString, payload);
			QFETCH(QString, tag);
			QFETCH(QString, keyText);
			QFETCH(QString, ivText);

			QCA::SymmetricKey key(QCA::hexToArray(keyText));
			QCA::InitializationVector iv(QCA::hexToArray(ivText));
			QCA::AuthTag authTag(16);
			QCA::Cipher forwardCipher(QString("aes192"),
									  QCA::Cipher::GCM,
									  QCA::Cipher::NoPadding,
									  QCA::Encode,
									  key,
									  iv,
									  authTag,
									  provider);
			QString update = QCA::arrayToHex(forwardCipher.update(QCA::hexToArray(plainText)).toByteArray());
			QVERIFY(forwardCipher.ok());
			update += QCA::arrayToHex(forwardCipher.final().toByteArray());
			authTag = forwardCipher.tag();
			QEXPECT_FAIL("wrongtag", "It's OK", Continue);
			QCOMPARE(QCA::arrayToHex(authTag.toByteArray()), tag);
			QCOMPARE(update, payload);
			QVERIFY(forwardCipher.ok());

			QCA::Cipher reverseCipher(QString( "aes192"),
									  QCA::Cipher::GCM,
									  QCA::Cipher::NoPadding,
									  QCA::Decode,
									  key,
									  iv,
									  QCA::AuthTag(QCA::hexToArray(tag)),
									  provider);

			update = QCA::arrayToHex(reverseCipher.update(QCA::hexToArray(payload)).toByteArray());
			QVERIFY(reverseCipher.ok());
			QCOMPARE(update, plainText.left(update.size()));
			update += QCA::arrayToHex(reverseCipher.final().toByteArray());
			QEXPECT_FAIL("wrongtag", "It's OK", Continue);
			QCOMPARE(update, plainText);
			QEXPECT_FAIL("wrongtag", "It's OK", Continue);
			QVERIFY(reverseCipher.ok());
		}
	}
}


void CipherUnitTest::aes192_ccm_data()
{

}

void CipherUnitTest::aes192_ccm()
{
	// For future implementation
}

void CipherUnitTest::aes256_data()
{
	QTest::addColumn<QString>("plainText");
	QTest::addColumn<QString>("cipherText");
	QTest::addColumn<QString>("keyText");


	// From FIPS 197 Appendix C.3
	QTest::newRow("FIPS197 App C.3") << QString("00112233445566778899aabbccddeeff")
									 << QString("8ea2b7ca516745bfeafc49904b496089")
									 << QString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

	// These are from the Botan test suite
	QTest::newRow("1") << QString("e51aa0b135dba566939c3b6359a980c5")
					   << QString("8cd9423dfc459e547155c5d1d522e540")
					   << QString("e0e1e2e3e5e6e7e8eaebecedeff0f1f2f4f5f6f7f9fafbfcfefe010103040506");

	QTest::newRow("2") << QString("069a007fc76a459f98baf917fedf9521")
					   << QString("080e9517eb1677719acf728086040ae3")
					   << QString("08090a0b0d0e0f10121314151718191a1c1d1e1f21222324262728292b2c2d2e");

	QTest::newRow("3") << QString("726165c1723fbcf6c026d7d00b091027")
					   << QString("7c1700211a3991fc0ecded0ab3e576b0")
					   << QString("30313233353637383a3b3c3d3f40414244454647494a4b4c4e4f505153545556");

	QTest::newRow("4") << QString("d7c544de91d55cfcde1f84ca382200ce")
					   << QString("dabcbcc855839251db51e224fbe87435")
					   << QString("58595a5b5d5e5f60626364656768696a6c6d6e6f71727374767778797b7c7d7e");

	QTest::newRow("5") << QString("fed3c9a161b9b5b2bd611b41dc9da357")
					   << QString("68d56fad0406947a4dd27a7448c10f1d")
					   << QString("80818283858687888a8b8c8d8f90919294959697999a9b9c9e9fa0a1a3a4a5a6");

	QTest::newRow("6") << QString("4f634cdc6551043409f30b635832cf82")
					   << QString("da9a11479844d1ffee24bbf3719a9925")
					   << QString("a8a9aaabadaeafb0b2b3b4b5b7b8b9babcbdbebfc1c2c3c4c6c7c8c9cbcccdce");

	QTest::newRow("7") << QString("109ce98db0dfb36734d9f3394711b4e6")
					   << QString("5e4ba572f8d23e738da9b05ba24b8d81")
					   << QString("d0d1d2d3d5d6d7d8dadbdcdddfe0e1e2e4e5e6e7e9eaebeceeeff0f1f3f4f5f6");

	QTest::newRow("8") << QString("4ea6dfaba2d8a02ffdffa89835987242")
					   << QString("a115a2065d667e3f0b883837a6e903f8")
					   << QString("70717273757677787a7b7c7d7f80818284858687898a8b8c8e8f909193949596");

	QTest::newRow("9") << QString("5ae094f54af58e6e3cdbf976dac6d9ef")
					   << QString("3e9e90dc33eac2437d86ad30b137e66e")
					   << QString("98999a9b9d9e9fa0a2a3a4a5a7a8a9aaacadaeafb1b2b3b4b6b7b8b9bbbcbdbe");

	QTest::newRow("10") << QString("764d8e8e0f29926dbe5122e66354fdbe")
						<< QString("01ce82d8fbcdae824cb3c48e495c3692")
						<< QString("c0c1c2c3c5c6c7c8cacbcccdcfd0d1d2d4d5d6d7d9dadbdcdedfe0e1e3e4e5e6");

	QTest::newRow("11") << QString("3f0418f888cdf29a982bf6b75410d6a9")
						<< QString("0c9cff163ce936faaf083cfd3dea3117")
						<< QString("e8e9eaebedeeeff0f2f3f4f5f7f8f9fafcfdfeff01020304060708090b0c0d0e");

	QTest::newRow("12") << QString("e4a3e7cb12cdd56aa4a75197a9530220")
						<< QString("5131ba9bd48f2bba85560680df504b52")
						<< QString("10111213151617181a1b1c1d1f20212224252627292a2b2c2e2f303133343536");

	QTest::newRow("13") << QString("211677684aac1ec1a160f44c4ebf3f26")
						<< QString("9dc503bbf09823aec8a977a5ad26ccb2")
						<< QString("38393a3b3d3e3f40424344454748494a4c4d4e4f51525354565758595b5c5d5e");

	QTest::newRow("14") << QString("d21e439ff749ac8f18d6d4b105e03895")
						<< QString("9a6db0c0862e506a9e397225884041d7")
						<< QString("60616263656667686a6b6c6d6f70717274757677797a7b7c7e7f808183848586");

	QTest::newRow("15") << QString("d9f6ff44646c4725bd4c0103ff5552a7")
						<< QString("430bf9570804185e1ab6365fc6a6860c")
						<< QString("88898a8b8d8e8f90929394959798999a9c9d9e9fa1a2a3a4a6a7a8a9abacadae");

	QTest::newRow("16") << QString("0b1256c2a00b976250cfc5b0c37ed382")
						<< QString("3525ebc02f4886e6a5a3762813e8ce8a")
						<< QString("b0b1b2b3b5b6b7b8babbbcbdbfc0c1c2c4c5c6c7c9cacbcccecfd0d1d3d4d5d6");

	QTest::newRow("17") << QString("b056447ffc6dc4523a36cc2e972a3a79")
						<< QString("07fa265c763779cce224c7bad671027b")
						<< QString("d8d9dadbdddedfe0e2e3e4e5e7e8e9eaecedeeeff1f2f3f4f6f7f8f9fbfcfdfe");

	QTest::newRow("18") << QString("5e25ca78f0de55802524d38da3fe4456")
						<< QString("e8b72b4e8be243438c9fff1f0e205872")
						<< QString("00010203050607080a0b0c0d0f10111214151617191a1b1c1e1f202123242526");

	QTest::newRow("19") << QString("a5bcf4728fa5eaad8567c0dc24675f83")
						<< QString("109d4f999a0e11ace1f05e6b22cbcb50")
						<< QString("28292a2b2d2e2f30323334353738393a3c3d3e3f41424344464748494b4c4d4e");

	QTest::newRow("20") << QString("814e59f97ed84646b78b2ca022e9ca43")
						<< QString("45a5e8d4c3ed58403ff08d68a0cc4029")
						<< QString("50515253555657585a5b5c5d5f60616264656667696a6b6c6e6f707173747576");

	QTest::newRow("21") << QString("15478beec58f4775c7a7f5d4395514d7")
						<< QString("196865964db3d417b6bd4d586bcb7634")
						<< QString("78797a7b7d7e7f80828384858788898a8c8d8e8f91929394969798999b9c9d9e");
}



void CipherUnitTest::aes256()
{
	QStringList providersToTest;
	providersToTest.append("qca-ossl");
	// providersToTest.append("qca-gcrypt");
	providersToTest.append("qca-botan");
	providersToTest.append("qca-nss");

	foreach(const QString provider, providersToTest) {
		if( !QCA::isSupported( "aes256-ecb", provider ) )
			QWARN( QString( "AES256 ECB not supported for "+provider).toLocal8Bit() );
		else {
			QFETCH( QString, plainText );
			QFETCH( QString, cipherText );
			QFETCH( QString, keyText );

			QCA::SymmetricKey key( QCA::hexToArray( keyText ) );
			QCA::Cipher forwardCipher( QString( "aes256" ),
									   QCA::Cipher::ECB,
									   QCA::Cipher::NoPadding,
									   QCA::Encode,
									   key,
									   QCA::InitializationVector(),
									   provider );

			QCOMPARE( forwardCipher.blockSize(), 16 );
			QCOMPARE( forwardCipher.keyLength().minimum(), 32 );
			QCOMPARE( forwardCipher.keyLength().maximum(), 32 );

			QString afterEncodeText = QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( plainText ) ).toByteArray() );
			QVERIFY( forwardCipher.ok() );

			afterEncodeText += QCA::arrayToHex( forwardCipher.final().toByteArray() );
			QVERIFY( forwardCipher.ok() );

			QCOMPARE( afterEncodeText, cipherText );

			QCA::Cipher reverseCipher( QString( "aes256" ),
									   QCA::Cipher::ECB,
									   QCA::Cipher::NoPadding,
									   QCA::Decode,
									   key,
									   QCA::InitializationVector(),
									   provider );

			QCOMPARE( reverseCipher.blockSize(), 16 );
			QCOMPARE( reverseCipher.keyLength().minimum(), 32 );
			QCOMPARE( reverseCipher.keyLength().maximum(), 32 );

			QString afterDecodeText = QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( cipherText ) ).toByteArray() );
			QVERIFY( reverseCipher.ok() );

			afterDecodeText += QCA::arrayToHex( reverseCipher.final().toByteArray() );
			QVERIFY( reverseCipher.ok() );

			QCOMPARE( afterDecodeText, plainText );
		}
	}
}


// These are from the Botan test suite
void CipherUnitTest::aes256_cbc_data()
{
	QTest::addColumn<QString>("plainText");
	QTest::addColumn<QString>("cipherText");
	QTest::addColumn<QString>("keyText");
	QTest::addColumn<QString>("ivText");

	QTest::newRow("1") << QString("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
					   << QString("f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b")
					   << QString("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
					   << QString("000102030405060708090a0b0c0d0e0f");
}

void CipherUnitTest::aes256_cbc()
{
	QStringList providersToTest;
	providersToTest.append("qca-ossl");
	providersToTest.append("qca-gcrypt");
	providersToTest.append("qca-botan");
	providersToTest.append("qca-nss");

	foreach(const QString provider, providersToTest) {
		if( !QCA::isSupported( "aes256-cbc", provider ) )
			QWARN( QString( "AES256 CBC not supported for "+provider).toLocal8Bit() );
		else {
			QFETCH( QString, plainText );
			QFETCH( QString, cipherText );
			QFETCH( QString, keyText );
			QFETCH( QString, ivText );

			QCA::SymmetricKey key( QCA::hexToArray( keyText ) );
			QCA::InitializationVector iv( QCA::hexToArray( ivText ) );
			QCA::Cipher forwardCipher( QString( "aes256" ),
									   QCA::Cipher::CBC,
									   QCA::Cipher::NoPadding,
									   QCA::Encode,
									   key,
									   iv,
									   provider);
			QString update = QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( plainText ) ).toByteArray() );
			QVERIFY( forwardCipher.ok() );
			QCOMPARE( update + QCA::arrayToHex( forwardCipher.final().toByteArray() ), cipherText );
			QVERIFY( forwardCipher.ok() );

			QCA::Cipher reverseCipher( QString( "aes256" ),
									   QCA::Cipher::CBC,
									   QCA::Cipher::NoPadding,
									   QCA::Decode,
									   key,
									   iv,
									   provider);

			update = QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( cipherText ) ).toByteArray() );
			QVERIFY( reverseCipher.ok() );
			QCOMPARE( update, plainText.left(update.size() ) );
			QCOMPARE( update + QCA::arrayToHex( reverseCipher.final().toByteArray() ), plainText );
			QVERIFY( reverseCipher.ok() );
		}
	}
}

// These were generated using OpenSSL's enc command
void CipherUnitTest::aes256_cbc_pkcs7_data()
{
	QTest::addColumn<QString>("plainText");
	QTest::addColumn<QString>("cipherText");
	QTest::addColumn<QString>("keyText");
	QTest::addColumn<QString>("ivText");

	QTest::newRow("1") << QString("")
					   << QString("99fac653629ddb546d65ac699d7323ba")
					   << QString("0123456789ABCDEF0123456789ABCDEF00112233445566778899AABBCCDDEEFF")
					   << QString("00001111222233334444555566667777");

	QTest::newRow("2") << QString("610a")
					   << QString("1dd0366efe719f6bf0e2c30e8cc168fd")
					   << QString("0123456789ABCDEF0123456789ABCDEF00112233445566778899AABBCCDDEEFF")
					   << QString("00001111222233334444555566667777");

	QTest::newRow("3") << QString("6162636465666768696a0a")
					   << QString("a433fb0dc673093f726d748c8f76cf0d")
					   << QString("0123456789ABCDEF0123456789ABCDEF00112233445566778899AABBCCDDEEFF")
					   << QString("00001111222233334444555566667777");

	QTest::newRow("block size - 1") << QString("6162636465666768696a6b6c6d6e0a")
									<< QString("b5cfa68d21ad91649eafc35dee06f007")
									<< QString("0123456789ABCDEF0123456789ABCDEF00112233445566778899AABBCCDDEEFF")
									<< QString("00001111222233334444555566667777");

	QTest::newRow("block size") << QString("6162636465666768696a6b6c6d6e310a")
								<< QString("45c4b50e4d4433b011187983da5034fe14cf12c04cfc3bceb57a88c455491f46")
								<< QString("0123456789ABCDEF0123456789ABCDEF00112233445566778899AABBCCDDEEFF")
								<< QString("00001111222233334444555566667777");

	QTest::newRow("block size+1") << QString("6162636465666768696a6b6c6d6e6f310a")
								  << QString("4ef5702f0c16bbfda9b57e6e98186763325c81c99b6cdd8e4bc34dcaa82d00e9")
								  << QString("0123456789ABCDEF0123456789ABCDEF00112233445566778899AABBCCDDEEFF")
								  << QString("00001111222233334444555566667777");

}

void CipherUnitTest::aes256_cbc_pkcs7()
{
	QStringList providersToTest;
	providersToTest.append("qca-ossl");
	providersToTest.append("qca-gcrypt");
	providersToTest.append("qca-botan");
	providersToTest.append("qca-nss");

	foreach(const QString provider, providersToTest) {
		if( !QCA::isSupported( "aes256-cbc-pkcs7", provider ) )
			QWARN( QString( "AES256 CBC with PKCS7 padding not supported for "+provider).toLocal8Bit() );
		else {
			QFETCH( QString, plainText );
			QFETCH( QString, cipherText );
			QFETCH( QString, keyText );
			QFETCH( QString, ivText );

			QCA::SymmetricKey key( QCA::hexToArray( keyText ) );
			QCA::InitializationVector iv( QCA::hexToArray( ivText ) );
			QCA::Cipher forwardCipher( QString( "aes256" ),
									   QCA::Cipher::CBC,
									   QCA::Cipher::DefaultPadding,
									   QCA::Encode,
									   key,
									   iv,
									   provider);
			QString update = QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( plainText ) ).toByteArray() );
			QVERIFY( forwardCipher.ok() );
			QCOMPARE( update + QCA::arrayToHex( forwardCipher.final().toByteArray() ), cipherText );
			QVERIFY( forwardCipher.ok() );

			QCA::Cipher reverseCipher( QString( "aes256" ),
									   QCA::Cipher::CBC,
									   QCA::Cipher::DefaultPadding,
									   QCA::Decode,
									   key,
									   iv,
									   provider);
			update = QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( cipherText ) ).toByteArray() );
			QVERIFY( reverseCipher.ok() );
			QCOMPARE( update, plainText.left(update.size() ) );
			QCOMPARE( update + QCA::arrayToHex( reverseCipher.final().toByteArray() ), plainText );
			QVERIFY( reverseCipher.ok() );
		}
	}
}


// These are from the Botan test suite
void CipherUnitTest::aes256_cfb_data()
{
	QTest::addColumn<QString>("plainText");
	QTest::addColumn<QString>("cipherText");
	QTest::addColumn<QString>("keyText");
	QTest::addColumn<QString>("ivText");

	QTest::newRow("1") << QString("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
					   << QString("dc7e84bfda79164b7ecd8486985d386039ffed143b28b1c832113c6331e5407bdf10132415e54b92a13ed0a8267ae2f975a385741ab9cef82031623d55b1e471")
					   << QString("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
					   << QString("000102030405060708090a0b0c0d0e0f");
}

void CipherUnitTest::aes256_cfb()
{
	QStringList providersToTest;
	providersToTest.append("qca-ossl");
	providersToTest.append("qca-gcrypt");
	providersToTest.append("qca-botan");
	providersToTest.append("qca-nss");

	foreach(const QString provider, providersToTest) {
		if( !QCA::isSupported( "aes256-cfb", provider ) )
			QWARN( QString( "AES256 CFB not supported for "+provider).toLocal8Bit() );
		else {
			QFETCH( QString, plainText );
			QFETCH( QString, cipherText );
			QFETCH( QString, keyText );
			QFETCH( QString, ivText );

			QCA::SymmetricKey key( QCA::hexToArray( keyText ) );
			QCA::InitializationVector iv( QCA::hexToArray( ivText ) );
			QCA::Cipher forwardCipher( QString( "aes256" ),
									   QCA::Cipher::CFB,
									   QCA::Cipher::NoPadding,
									   QCA::Encode,
									   key,
									   iv,
									   provider);
			QString update = QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( plainText ) ).toByteArray() );
			QVERIFY( forwardCipher.ok() );
			QCOMPARE( update + QCA::arrayToHex( forwardCipher.final().toByteArray() ), cipherText );
			QVERIFY( forwardCipher.ok() );

			QCA::Cipher reverseCipher( QString( "aes256" ),
									   QCA::Cipher::CFB,
									   QCA::Cipher::NoPadding,
									   QCA::Decode,
									   key,
									   iv,
									   provider);

			QCOMPARE( QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( cipherText ) ).toByteArray() ), plainText  );
			QVERIFY( reverseCipher.ok() );
			QCOMPARE( QCA::arrayToHex( reverseCipher.final().toByteArray() ), QString( "" ) );
			QVERIFY( reverseCipher.ok() );
		}
	}
}

void CipherUnitTest::aes256_ofb_data()
{
	QTest::addColumn<QString>("plainText");
	QTest::addColumn<QString>("cipherText");
	QTest::addColumn<QString>("keyText");
	QTest::addColumn<QString>("ivText");

	QTest::newRow("1") << QString("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
					   << QString("dc7e84bfda79164b7ecd8486985d38604febdc6740d20b3ac88f6ad82a4fb08d71ab47a086e86eedf39d1c5bba97c4080126141d67f37be8538f5a8be740e484")
					   << QString("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
					   << QString("000102030405060708090a0b0c0d0e0f");
}

void CipherUnitTest::aes256_ofb()
{
	QStringList providersToTest;
	providersToTest.append("qca-ossl");
	providersToTest.append("qca-gcrypt");
	providersToTest.append("qca-botan");
	providersToTest.append("qca-nss");

	foreach(const QString provider, providersToTest) {
		if( !QCA::isSupported( "aes256-ofb", provider ) )
			QWARN( QString( "AES256 OFB not supported for "+provider).toLocal8Bit() );
		else {
			QFETCH( QString, plainText );
			QFETCH( QString, cipherText );
			QFETCH( QString, keyText );
			QFETCH( QString, ivText );

			QCA::SymmetricKey key( QCA::hexToArray( keyText ) );
			QCA::InitializationVector iv( QCA::hexToArray( ivText ) );
			QCA::Cipher forwardCipher( QString( "aes256" ),
									   QCA::Cipher::OFB,
									   QCA::Cipher::NoPadding,
									   QCA::Encode,
									   key,
									   iv,
									   provider);
			QString update = QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( plainText ) ).toByteArray() );
			QVERIFY( forwardCipher.ok() );
			QCOMPARE( update + QCA::arrayToHex( forwardCipher.final().toByteArray() ), cipherText );
			QVERIFY( forwardCipher.ok() );

			QCA::Cipher reverseCipher( QString( "aes256" ),
									   QCA::Cipher::OFB,
									   QCA::Cipher::NoPadding,
									   QCA::Decode,
									   key,
									   iv,
									   provider);

			QCOMPARE( QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( cipherText ) ).toByteArray() ), plainText  );
			QVERIFY( reverseCipher.ok() );
			QCOMPARE( QCA::arrayToHex( reverseCipher.final().toByteArray() ), QString( "" ) );
			QVERIFY( reverseCipher.ok() );
		}
	}
}

void CipherUnitTest::aes256_ctr_data()
{
	QTest::addColumn<QString>("plainText");
	QTest::addColumn<QString>("cipherText");
	QTest::addColumn<QString>("keyText");
	QTest::addColumn<QString>("ivText");

	QTest::newRow("1") << QString("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
					   << QString("dc7e84bfda79164b7ecd8486985d3860d577788b8d8a85745513a5d50f821f30ffe96d5cf54b238dcc8d6783a87f3beae9af546344cb9ca4d1e553ffc06bc73e")
					   << QString("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
					   << QString("000102030405060708090a0b0c0d0e0f");
}

void CipherUnitTest::aes256_ctr()
{
	QStringList providersToTest;
	providersToTest.append("qca-ossl");
	providersToTest.append("qca-gcrypt");
	providersToTest.append("qca-botan");
	providersToTest.append("qca-nss");

	foreach(const QString provider, providersToTest) {
		if( !QCA::isSupported( "aes256-ctr", provider ) )
			QWARN( QString( "AES256 CTR not supported for "+provider).toLocal8Bit() );
		else {
			QFETCH( QString, plainText );
			QFETCH( QString, cipherText );
			QFETCH( QString, keyText );
			QFETCH( QString, ivText );

			QCA::SymmetricKey key( QCA::hexToArray( keyText ) );
			QCA::InitializationVector iv( QCA::hexToArray( ivText ) );
			QCA::Cipher forwardCipher( QString( "aes256" ),
									   QCA::Cipher::CTR,
									   QCA::Cipher::NoPadding,
									   QCA::Encode,
									   key,
									   iv,
									   provider);
			QString update = QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( plainText ) ).toByteArray() );
			QVERIFY( forwardCipher.ok() );
			QCOMPARE( update + QCA::arrayToHex( forwardCipher.final().toByteArray() ), cipherText );
			QVERIFY( forwardCipher.ok() );

			QCA::Cipher reverseCipher( QString( "aes256" ),
									   QCA::Cipher::CTR,
									   QCA::Cipher::NoPadding,
									   QCA::Decode,
									   key,
									   iv,
									   provider);

			QCOMPARE( QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( cipherText ) ).toByteArray() ), plainText  );
			QVERIFY( reverseCipher.ok() );
			QCOMPARE( QCA::arrayToHex( reverseCipher.final().toByteArray() ), QString( "" ) );
			QVERIFY( reverseCipher.ok() );
		}
	}
}

void CipherUnitTest::aes256_gcm_data()
{
	QTest::addColumn<QString>("plainText");
	QTest::addColumn<QString>("payload");
	QTest::addColumn<QString>("tag");
	QTest::addColumn<QString>("keyText");
	QTest::addColumn<QString>("ivText");

	QTest::newRow("short") << QString("6f6820526f6d656d6f21")
						   << QString("4ce2f4df041252820847")
						   << QString("1c570805832dfe7babc1b386c26bcd04")
						   << QString("3fa609690bf07a81a75839b0a4c0add774f54eb804d4f02df488691910298b04")
						   << QString("f85f8aad39164daf64a12ad9b3fc8a3a");

	QTest::newRow("long") << QString("54484520515549434b2042524f574e20464f58204a554d504544204f56455220544845204c415a5920444f472753204241434b2031323334353637383930")
						  << QString("e516c267146d6cfd3af3300e24aba7ac23ab3c5cb4765937a6c0156e454cae357e14f4c0dfb0def9624f4f70de90ad2bc9cd555171c4551c26b6346922ed")
						  << QString("f59aac31ab9dace3fcc693e114dd6610")
						  << QString("3fa609690bf07a81a75839b0a4c0add774f54eb804d4f02df488691910298b04")
						  << QString("bfcd3a7252f7f199bf788df8cf61032a");


	QTest::newRow("wrongtag") << QString("6f6820526f6d656d6f21")
							  << QString("4ce2f4df041252820847")
							  << QString("1c570805833dfe7babc1b386c26bcd04")
							  << QString("3fa609690bf07a81a75839b0a4c0add774f54eb804d4f02df488691910298b04")
							  << QString("f85f8aad39164daf64a12ad9b3fc8a3a");
}

void CipherUnitTest::aes256_gcm()
{
	QStringList providersToTest;
	providersToTest.append("qca-ossl");
	providersToTest.append("qca-gcrypt");
	providersToTest.append("qca-botan");
	providersToTest.append("qca-nss");

	foreach (const QString &provider, providersToTest) {
		if (!QCA::isSupported( "aes256-gcm", provider))
			QWARN(QString("AES256 GCM not supported for " + provider).toLocal8Bit());
		else {
			QFETCH(QString, plainText);
			QFETCH(QString, payload);
			QFETCH(QString, tag);
			QFETCH(QString, keyText);
			QFETCH(QString, ivText);

			QCA::SymmetricKey key(QCA::hexToArray(keyText));
			QCA::InitializationVector iv(QCA::hexToArray(ivText));
			QCA::AuthTag authTag(16);
			QCA::Cipher forwardCipher(QString("aes256"),
									  QCA::Cipher::GCM,
									  QCA::Cipher::NoPadding,
									  QCA::Encode,
									  key,
									  iv,
									  authTag,
									  provider);
			QString update = QCA::arrayToHex(forwardCipher.update(QCA::hexToArray(plainText)).toByteArray());
			QVERIFY(forwardCipher.ok());
			update += QCA::arrayToHex(forwardCipher.final().toByteArray());
			authTag = forwardCipher.tag();
			QEXPECT_FAIL("wrongtag", "It's OK", Continue);
			QCOMPARE(QCA::arrayToHex(authTag.toByteArray()), tag);
			QCOMPARE(update, payload);
			QVERIFY(forwardCipher.ok());

			QCA::Cipher reverseCipher(QString( "aes256"),
									  QCA::Cipher::GCM,
									  QCA::Cipher::NoPadding,
									  QCA::Decode,
									  key,
									  iv,
									  QCA::AuthTag(QCA::hexToArray(tag)),
									  provider);

			update = QCA::arrayToHex(reverseCipher.update(QCA::hexToArray(payload)).toByteArray());
			QVERIFY(reverseCipher.ok());
			QCOMPARE(update, plainText.left(update.size()));
			update += QCA::arrayToHex(reverseCipher.final().toByteArray());
			QEXPECT_FAIL("wrongtag", "It's OK", Continue);
			QCOMPARE(update, plainText);
			QEXPECT_FAIL("wrongtag", "It's OK", Continue);
			QVERIFY(reverseCipher.ok());
		}
	}
}

void CipherUnitTest::aes256_ccm_data()
{

}

void CipherUnitTest::aes256_ccm()
{
	// For future implementation
}

void CipherUnitTest::tripleDES_data()
{
	QTest::addColumn<QString>("plainText");
	QTest::addColumn<QString>("cipherText");
	QTest::addColumn<QString>("keyText");

	QTest::newRow("1") << QString("42fd443059577fa2")
					   << QString("af37fb421f8c4095")
					   << QString("04b915ba43feb5b604b915ba43feb5b604b915ba43feb5b6");

	QTest::newRow("2") << QString("736f6d6564617461")
					   << QString("18d748e563620572")
					   << QString("0123456789abcdef5555555555555555fedcba9876543210");
	QTest::newRow("3") << QString("7371756967676c65")
					   << QString("c07d2a0fa566fa30")
					   << QString("0352020767208217860287665908219864056abdfea93457");
	QTest::newRow("4") << QString("0123456789abcde7")
					   << QString("de0b7c06ae5e0ed5")
					   << QString("0123456789abcdeffedcba987654321089abcdef01234567");
	QTest::newRow("5") << QString("0123456789abcde7")
					   << QString("7f1d0a77826b8aff")
					   << QString("0123456789abcdeffedcba98765432100123456789abcdef");
	QTest::newRow("6") << QString("4115e551299a5c4b")
					   << QString("f7a0822fc310686c")
					   << QString("1ef743a68d629f68a5e3136c36ad7953a835cf849bb4ec3c");
	QTest::newRow("7") << QString("d5ab44e0fe46e1b5")
					   << QString("02aed9bf72eca222")
					   << QString("b7d560be49c3936728ef0bf57b602d2eb7e5c631dd7f753e");
	QTest::newRow("8") << QString("b4077dfdb721d88c")
					   << QString("f76aba838b1c4372")
					   << QString("d2d98706e9ab867647d244bdcdbcd5ef8b4dbc9cf4f35493");
	QTest::newRow("9") << QString("890e98ab385fa1a1")
					   << QString("187087c77790c3b2")
					   << QString("153b963004101d12683e8f87116001b8c5526475510b5036");
	QTest::newRow("10") << QString("02d5da6d5f247cd2")
						<< QString("89fc7df1e7913163")
						<< QString("45e4275dccc5d8b5a27993c16d9960ca939c023e2763216a");
	QTest::newRow("11") << QString("5af9e5a3525e3f7d")
						<< QString("8fcc7a8bc337e484")
						<< QString("f6c2474b33934ea76e6c841d9b1e86e37189095a895a3e5a");
	QTest::newRow("12") << QString("12864dde8e694bd1")
						<< QString("5b4dde8f000a5a9b")
						<< QString("5b4f6d3185efbae97d58ed9cc75e2bae655d2cefb2dd09cd");
	QTest::newRow("13") << QString("0123456789abcde7")
						<< QString("c95744256a5ed31d")
						<< QString("0123456789abcdef0123456789abcdef0123456789abcdef");
	QTest::newRow("14") << QString("68652074696d6520")
						<< QString("6a271787ab8883f9")
						<< QString("0123456789abcdef0123456789abcdef0123456789abcdef");

	QTest::newRow("15") << QString("4e6f772069732074")
						<< QString("3fa40e8a984d4815")
						<< QString("0123456789abcdef0123456789abcdef0123456789abcdef");

	// These are from the Botan test suite
	QTest::newRow("16") << QString("0123456789abcde7")
						<< QString("7f1d0a77826b8aff")
						<< QString("0123456789abcdeffedcba9876543210");
	QTest::newRow("17") << QString("4e6f772069732074")
						<< QString("3fa40e8a984d4815")
						<< QString("0123456789abcdef0123456789abcdef");
	QTest::newRow("18") << QString("42fd443059577fa2")
						<< QString("af37fb421f8c4095")
						<< QString("04b915ba43feb5b604b915ba43feb5b6");
	QTest::newRow("19") << QString("afa4284fcceaa61a")
						<< QString("32527d5701d92b90")
						<< QString("4bc59e2c68aca60767a9a4b623bbbccc");
	QTest::newRow("20") << QString("50b503a331d5b5cc")
						<< QString("e46a59e18b0c41e3")
						<< QString("b955bb7861fde77e7dc6418475457fe1");
	QTest::newRow("21") << QString("3404435d5df2cb47")
						<< QString("644dd68ea73053ae")
						<< QString("c0557629eaa72abd4c102c5dc9ce8b47");
	QTest::newRow("22") << QString("c7d80e955d1b6627")
						<< QString("9fe1c5a12cce6dd9")
						<< QString("9eaa94da916f30092e79dacdcdcc45c0");
	QTest::newRow("23") << QString("bdcbe8929cd0e12f")
						<< QString("f2b6430450ab348b")
						<< QString("a55279671807d9b71fe62a77341249f8");
	QTest::newRow("24") << QString("4b7a96b7051c64fc")
						<< QString("1555f08b2de690a0")
						<< QString("672e20826ad49c3df7579fab3752479e");
	QTest::newRow("25") << QString("902f4edd44eaf3c1")
						<< QString("3ce357eba0fb3e26")
						<< QString("0ce61ede2659b413ab9f717ae4afad3e");
	QTest::newRow("26") << QString("39c0f8e4c85cd70d")
						<< QString("882de9b6d0209a58")
						<< QString("e878020815ae517cd2808b6571eac2b4");
	QTest::newRow("27") << QString("f77a1947a921b209")
						<< QString("e10dbee5615f312e")
						<< QString("d891ca20919f06a054ba3943c7daba16");
	QTest::newRow("28") << QString("06d0416e0f0db7ce")
						<< QString("0cec5d1e59d7e347")
						<< QString("4909aed1f94eb77b6cacbcae2b25689a");
	QTest::newRow("29") << QString("f7bb3a396d73d8a8")
						<< QString("f893b6b2a15d3fce")
						<< QString("8b9a5c13b0b118a1ee35eb912866ffa6");
	QTest::newRow("30") << QString("bd35e3134b90ccbc")
						<< QString("12a7af172fd0ca7f")
						<< QString("fa7911d664326074b42e2f38e599b288");
	QTest::newRow("31") << QString("e046b7f5707da4fc")
						<< QString("32b6a3fc72c7c480")
						<< QString("406903b340b8637928fde8058bdd6710");
	QTest::newRow("32") << QString("58eb1dc16c482213")
						<< QString("a6c6234a8bbaa116")
						<< QString("37a2b53e2af8f6c9a73b39f919d969de");
	QTest::newRow("33") << QString("4bd0f4854297fbde")
						<< QString("f4ab771861457dc6")
						<< QString("711f2cecdb92b2e201dfefa79fa7ba2f");
}

// TODO: ECB-PKCS7
void CipherUnitTest::tripleDES()
{
	QStringList providersToTest;
	providersToTest.append("qca-ossl");
	// providersToTest.append("qca-gcrypt");
	providersToTest.append("qca-botan");
	providersToTest.append("qca-nss");

	foreach(const QString provider, providersToTest) {
		if( !QCA::isSupported( "tripledes-ecb", provider ) )
			QWARN( QString( "Triple DES, ECB not supported for "+provider).toLocal8Bit() );
		else {
			QCA::Cipher cipherObj1( QString( "tripledes" ),
									QCA::Cipher::ECB,
									QCA::Cipher::NoPadding,
									QCA::Encode,
									QCA::SymmetricKey( 24 ),
									QCA::InitializationVector(),
									provider );
			// checking minimum is a bit hairy, because it depends on whether you are
			// doing 2 key or 3 key triple DES.
			QCOMPARE( cipherObj1.keyLength().minimum(), 16 );
			QCOMPARE( cipherObj1.keyLength().maximum(), 24 );
			QCOMPARE( cipherObj1.blockSize(), 8 );

			QFETCH( QString, plainText );
			QFETCH( QString, cipherText );
			QFETCH( QString, keyText );

			QCA::SymmetricKey key( QCA::hexToArray( keyText ) );
			QCA::Cipher forwardCipher( QString( "tripledes" ),
									   QCA::Cipher::ECB,
									   QCA::Cipher::NoPadding,
									   QCA::Encode,
									   key,
									   QCA::InitializationVector(),
									   provider );

			QString afterEncodeText = QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( plainText ) ).toByteArray() );
			QVERIFY( forwardCipher.ok() );

			afterEncodeText += QCA::arrayToHex( forwardCipher.final().toByteArray() );
			QVERIFY( forwardCipher.ok() );

			QCOMPARE( afterEncodeText, cipherText );

			QCA::Cipher reverseCipher( QString( "tripledes" ),
									   QCA::Cipher::ECB,
									   QCA::Cipher::NoPadding,
									   QCA::Decode,
									   key,
									   QCA::InitializationVector(),
									   provider );

			QString afterDecodeText = QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( cipherText ) ).toByteArray() );
			QVERIFY( reverseCipher.ok() );

			afterDecodeText += QCA::arrayToHex( reverseCipher.final().toByteArray() );
			QVERIFY( reverseCipher.ok() );

			QCOMPARE( afterDecodeText, plainText );
		}
	}
}

// These are from the Botan test suite - its ECB mode, no padding
void CipherUnitTest::des_data()
{
	QTest::addColumn<QString>("plainText");
	QTest::addColumn<QString>("cipherText");
	QTest::addColumn<QString>("keyText");

	QTest::newRow("") << QString("059b5e0851cf143a") << QString("86a560f10ec6d85b") << QString("0113b970fd34f2ce");
	QTest::newRow("") << QString("4e6f772069732074") << QString("3fa40e8a984d4815") << QString("0123456789abcdef");
	QTest::newRow("") << QString("666f7220616c6c20") << QString("893d51ec4b563b53") << QString("0123456789abcdef");
	QTest::newRow("") << QString("68652074696d6520") << QString("6a271787ab8883f9") << QString("0123456789abcdef");
	QTest::newRow("") << QString("5cd54ca83def57da") << QString("7a389d10354bd271") << QString("0131d9619dc1376e");
	QTest::newRow("") << QString("0756d8e0774761d2") << QString("0cd3da020021dc09") << QString("0170f175468fb5e6");
	QTest::newRow("") << QString("1d9d5c5018f728c2") << QString("5f4c038ed12b2e41") << QString("018310dc409b26d6");
	QTest::newRow("") << QString("480d39006ee762f2") << QString("a1f9915541020b56") << QString("025816164629b007");
	QTest::newRow("") << QString("26955f6835af609a") << QString("5c513c9c4886c088") << QString("04689104c2fd3b2f");
	QTest::newRow("") << QString("42fd443059577fa2") << QString("af37fb421f8c4095") << QString("04b915ba43feb5b6");
	QTest::newRow("") << QString("0248d43806f67172") << QString("868ebb51cab4599a") << QString("07a1133e4a0b2686");
	QTest::newRow("") << QString("3bdd119049372802") << QString("dfd64a815caf1a0f") << QString("07a7137045da2a16");
	QTest::newRow("") << QString("16393bcdd6560506") << QString("9966adcfc53bf968") << QString("0a3fddc8350aff39");
	QTest::newRow("") << QString("dc7fc6cf0358ecc0") << QString("a47a7485661f7085") << QString("10dd6dcd5c89e151");
	QTest::newRow("") << QString("305532286d6f295a") << QString("63fac0d034d9f793") << QString("1c587f1c13924fef");
	QTest::newRow("") << QString("f786d02413c574fc") << QString("54c160d369f62ae3") << QString("1eb00767bdee584e");
	QTest::newRow("") << QString("6b056e18759f5cca") << QString("ef1bf03e5dfa575a") << QString("1f08260d1ac2465e");
	QTest::newRow("") << QString("905ea29aeea26e07") << QString("2292e9aebee6a4b6") << QString("28ee445d8a21c534");
	QTest::newRow("") << QString("164d5e404f275232") << QString("0a2aeeae3ff4ab77") << QString("37d06bb516cb7546");
	QTest::newRow("") << QString("51454b582ddf440a") << QString("7178876e01f19b2a") << QString("3849674c2602319e");
	QTest::newRow("") << QString("68ff9d6068c71513") << QString("84595f5b9d046132") << QString("3cde816ef9ef8edb");
	QTest::newRow("") << QString("762514b829bf486a") << QString("ea676b2cb7db2b7a") << QString("43297fad38e373fe");
	QTest::newRow("") << QString("437540c8698f3cfa") << QString("6fbf1cafcffd0556") << QString("49793ebc79b3258f");
	QTest::newRow("") << QString("02fe55778117f12a") << QString("5a6b612cc26cce4a") << QString("49e95d6d4ca229bf");
	QTest::newRow("") << QString("1f508a50adb3d6e2") << QString("470204969876604a") << QString("4bb53ecfefb38dde");
	QTest::newRow("") << QString("072d43a077075292") << QString("2f22e49bab7ca1ac") << QString("4fb05e1515ab73a7");
	QTest::newRow("") << QString("004bd6ef09176062") << QString("88bf0db6d70dee56") << QString("584023641aba6176");
	QTest::newRow("") << QString("5aa1d62806ae0ead") << QString("6db0f280fef2b564") << QString("5f2b51f59e781d9c");
	QTest::newRow("") << QString("7e1b1c6776833772") << QString("eb11cd3c72f7e90e") << QString("699c920d7ce1e0b1");
	QTest::newRow("") << QString("5dbfb47c5f471136") << QString("9c8b904d4d772be7") << QString("7ac2fdeee4c79746");
	QTest::newRow("") << QString("01a1d6d039776742") << QString("690f5b0d9a26939b") << QString("7ca110454a1a6e57");
	QTest::newRow("") << QString("4de2f0926cf598d7") << QString("ba107655991df529") << QString("7fc92c3098ecf14a");
	QTest::newRow("") << QString("f45e6819e3108559") << QString("f0c76ba556283b2f") << QString("9ab645e268430854");
	QTest::newRow("") << QString("51d4eaaac6d76553") << QString("bf3c6e8fd15ba861") << QString("a6b0ae88f980011a");
	QTest::newRow("") << QString("6a89626ea8038511") << QString("1067b36913cbcc47") << QString("bafebafafeaeeaff");
	QTest::newRow("") << QString("7b0313c0d3a866f9") << QString("e49e15e4f46f10e9") << QString("bb2420b5fee5a6a1");
	QTest::newRow("") << QString("9d4a44aefce79965") << QString("77b2ecc9278e9714") << QString("bebafbeabaffeaaf");
	QTest::newRow("") << QString("59bcdfc253424cb5") << QString("0a50abbbcd07061a") << QString("c38c6f20230d9ed5");
	QTest::newRow("") << QString("d6c059a85ee2b13e") << QString("25977533635beb5b") << QString("c6f974504d954c7e");
	QTest::newRow("") << QString("f9e4821dfcaa5466") << QString("48ec3a79399e9a00") << QString("cb959b7ffd94f734");
	QTest::newRow("") << QString("35e8554bad60fb29") << QString("993a3af0bc0d77a4") << QString("cfb23034323cd19a");
	QTest::newRow("") << QString("9f97210d75b7e6df") << QString("4729e3396e57ae4e") << QString("d4d861035745f2c8");
	QTest::newRow("") << QString("ffffffffffffffff") << QString("b5ce4f28fdeb21e8") << QString("e36972fc4bec7587");
	QTest::newRow("") << QString("323837024123c918") << QString("7f28bf28adfa1cf0") << QString("e91a71a7ed5eb0ef");
	QTest::newRow("") << QString("37dfe527086af0a0") << QString("5f53c6c87760256e") << QString("ebbbbaebfbbefaba");
	QTest::newRow("") << QString("20678f45b5b8ac00") << QString("7cc8ecf2638cc808") << QString("ebbeeeaebbbbffff");
	QTest::newRow("") << QString("78481ed0c5a7c93e") << QString("4ca3a08300ea6afc") << QString("fbeaffeeffeeabab");
	QTest::newRow("") << QString("e2ccd415ac25412a") << QString("bd85b3b659ab7276") << QString("fd8a675c0ed08301");
	// weak key
	QTest::newRow("") << QString("cccc5bdfd9029507") << QString("da57553d7d55775f") << QString("ffffffffffffffff");
	QTest::newRow("") << QString("0000000000000000") << QString("23083a3ca70dd027") << QString("d5d44ff720683d0d");
	QTest::newRow("") << QString("0100000000000000") << QString("6f353e3388abe2ef") << QString("d5d44ff720683d0d");
	//weak keys till next comment.
	QTest::newRow("") << QString("95f8a5e5dd31d900") << QString("8000000000000000") << QString("0101010101010101");
	QTest::newRow("") << QString("95f8a5e5dd31d900") << QString("8000000000000000") << QString("0000000000000000");
	QTest::newRow("") << QString("dd7f121ca5015619") << QString("4000000000000000") << QString("0101010101010101");
	QTest::newRow("") << QString("2e8653104f3834ea") << QString("2000000000000000") << QString("0101010101010101");
	QTest::newRow("") << QString("4bd388ff6cd81d4f") << QString("1000000000000000") << QString("0101010101010101");
	QTest::newRow("") << QString("20b9e767b2fb1456") << QString("0800000000000000") << QString("0101010101010101");
	QTest::newRow("") << QString("20b9e767b2fb1456") << QString("0800000000000000") << QString("0001010101010100");
	QTest::newRow("") << QString("55579380d77138ef") << QString("0400000000000000") << QString("0101010101010101");
	QTest::newRow("") << QString("6cc5defaaf04512f") << QString("0200000000000000") << QString("0101010101010101");
	QTest::newRow("") << QString("0d9f279ba5d87260") << QString("0100000000000000") << QString("0101010101010101");
	QTest::newRow("") << QString("d9031b0271bd5a0a") << QString("0080000000000000") << QString("0101010101010101");
	QTest::newRow("") << QString("424250b37c3dd951") << QString("0040000000000000") << QString("0101010101010101");
	QTest::newRow("") << QString("b8061b7ecd9a21e5") << QString("0020000000000000") << QString("0101010101010101");
	QTest::newRow("") << QString("f15d0f286b65bd28") << QString("0010000000000000") << QString("0101010101010101");
	QTest::newRow("") << QString("add0cc8d6e5deba1") << QString("0008000000000000") << QString("0101010101010101");
	QTest::newRow("") << QString("e6d5f82752ad63d1") << QString("0004000000000000") << QString("0101010101010101");
	QTest::newRow("") << QString("ecbfe3bd3f591a5e") << QString("0002000000000000") << QString("0101010101010101");
	QTest::newRow("") << QString("f356834379d165cd") << QString("0001000000000000") << QString("0101010101010101");
	QTest::newRow("") << QString("2b9f982f20037fa9") << QString("0000800000000000") << QString("0101010101010101");
	QTest::newRow("") << QString("889de068a16f0be6") << QString("0000400000000000") << QString("0101010101010101");
	QTest::newRow("") << QString("e19e275d846a1298") << QString("0000200000000000") << QString("0101010101010101");
	QTest::newRow("") << QString("329a8ed523d71aec") << QString("0000100000000000") << QString("0101010101010101");
	QTest::newRow("") << QString("e7fce22557d23c97") << QString("0000080000000000") << QString("0101010101010101");
	QTest::newRow("") << QString("12a9f5817ff2d65d") << QString("0000040000000000") << QString("0101010101010101");
	QTest::newRow("") << QString("a484c3ad38dc9c19") << QString("0000020000000000") << QString("0101010101010101");
	QTest::newRow("") << QString("fbe00a8a1ef8ad72") << QString("0000010000000000") << QString("0101010101010101");
	QTest::newRow("") << QString("750d079407521363") << QString("0000008000000000") << QString("0101010101010101");
	QTest::newRow("") << QString("64feed9c724c2faf") << QString("0000004000000000") << QString("0101010101010101");
	QTest::newRow("") << QString("f02b263b328e2b60") << QString("0000002000000000") << QString("0101010101010101");
	QTest::newRow("") << QString("9d64555a9a10b852") << QString("0000001000000000") << QString("0101010101010101");
	QTest::newRow("") << QString("d106ff0bed5255d7") << QString("0000000800000000") << QString("0101010101010101");
	QTest::newRow("") << QString("e1652c6b138c64a5") << QString("0000000400000000") << QString("0101010101010101");
	QTest::newRow("") << QString("e428581186ec8f46") << QString("0000000200000000") << QString("0101010101010101");
	QTest::newRow("") << QString("aeb5f5ede22d1a36") << QString("0000000100000000") << QString("0101010101010101");
	QTest::newRow("") << QString("e943d7568aec0c5c") << QString("0000000080000000") << QString("0101010101010101");
	QTest::newRow("") << QString("df98c8276f54b04b") << QString("0000000040000000") << QString("0101010101010101");
	QTest::newRow("") << QString("b160e4680f6c696f") << QString("0000000020000000") << QString("0101010101010101");
	QTest::newRow("") << QString("fa0752b07d9c4ab8") << QString("0000000010000000") << QString("0101010101010101");
	QTest::newRow("") << QString("ca3a2b036dbc8502") << QString("0000000008000000") << QString("0101010101010101");
	QTest::newRow("") << QString("5e0905517bb59bcf") << QString("0000000004000000") << QString("0101010101010101");
	QTest::newRow("") << QString("814eeb3b91d90726") << QString("0000000002000000") << QString("0101010101010101");
	QTest::newRow("") << QString("4d49db1532919c9f") << QString("0000000001000000") << QString("0101010101010101");
	QTest::newRow("") << QString("25eb5fc3f8cf0621") << QString("0000000000800000") << QString("0101010101010101");
	QTest::newRow("") << QString("ab6a20c0620d1c6f") << QString("0000000000400000") << QString("0101010101010101");
	QTest::newRow("") << QString("79e90dbc98f92cca") << QString("0000000000200000") << QString("0101010101010101");
	QTest::newRow("") << QString("866ecedd8072bb0e") << QString("0000000000100000") << QString("0101010101010101");
	QTest::newRow("") << QString("8b54536f2f3e64a8") << QString("0000000000080000") << QString("0101010101010101");
	QTest::newRow("") << QString("ea51d3975595b86b") << QString("0000000000040000") << QString("0101010101010101");
	QTest::newRow("") << QString("caffc6ac4542de31") << QString("0000000000020000") << QString("0101010101010101");
	QTest::newRow("") << QString("8dd45a2ddf90796c") << QString("0000000000010000") << QString("0101010101010101");
	QTest::newRow("") << QString("1029d55e880ec2d0") << QString("0000000000008000") << QString("0101010101010101");
	QTest::newRow("") << QString("5d86cb23639dbea9") << QString("0000000000004000") << QString("0101010101010101");
	QTest::newRow("") << QString("1d1ca853ae7c0c5f") << QString("0000000000002000") << QString("0101010101010101");
	QTest::newRow("") << QString("ce332329248f3228") << QString("0000000000001000") << QString("0101010101010101");
	QTest::newRow("") << QString("8405d1abe24fb942") << QString("0000000000000800") << QString("0101010101010101");
	QTest::newRow("") << QString("e643d78090ca4207") << QString("0000000000000400") << QString("0101010101010101");
	QTest::newRow("") << QString("48221b9937748a23") << QString("0000000000000200") << QString("0101010101010101");
	QTest::newRow("") << QString("dd7c0bbd61fafd54") << QString("0000000000000100") << QString("0101010101010101");
	QTest::newRow("") << QString("2fbc291a570db5c4") << QString("0000000000000080") << QString("0101010101010101");
	QTest::newRow("") << QString("e07c30d7e4e26e12") << QString("0000000000000040") << QString("0101010101010101");
	QTest::newRow("") << QString("0953e2258e8e90a1") << QString("0000000000000020") << QString("0101010101010101");
	QTest::newRow("") << QString("5b711bc4ceebf2ee") << QString("0000000000000010") << QString("0101010101010101");
	QTest::newRow("") << QString("cc083f1e6d9e85f6") << QString("0000000000000008") << QString("0101010101010101");
	QTest::newRow("") << QString("d2fd8867d50d2dfe") << QString("0000000000000004") << QString("0101010101010101");
	QTest::newRow("") << QString("06e7ea22ce92708f") << QString("0000000000000002") << QString("0101010101010101");
	QTest::newRow("") << QString("166b40b44aba4bd6") << QString("0000000000000001") << QString("0101010101010101");
	QTest::newRow("") << QString("0000000000000000") << QString("95a8d72813daa94d") << QString("8001010101010101");
	QTest::newRow("") << QString("0000000000000000") << QString("0eec1487dd8c26d5") << QString("4001010101010101");
	QTest::newRow("") << QString("0000000000000000") << QString("7ad16ffb79c45926") << QString("2001010101010101");
	QTest::newRow("") << QString("0000000000000000") << QString("d3746294ca6a6cf3") << QString("1001010101010101");
	QTest::newRow("") << QString("0000000000000000") << QString("809f5f873c1fd761") << QString("0801010101010101");
	QTest::newRow("") << QString("0000000000000000") << QString("c02faffec989d1fc") << QString("0401010101010101");
	QTest::newRow("") << QString("0000000000000000") << QString("4615aa1d33e72f10") << QString("0201010101010101");
	QTest::newRow("") << QString("0000000000000000") << QString("2055123350c00858") << QString("0180010101010101");
	QTest::newRow("") << QString("0000000000000000") << QString("df3b99d6577397c8") << QString("0140010101010101");
	QTest::newRow("") << QString("0000000000000000") << QString("31fe17369b5288c9") << QString("0120010101010101");
	QTest::newRow("") << QString("0000000000000000") << QString("dfdd3cc64dae1642") << QString("0110010101010101");
	QTest::newRow("") << QString("0000000000000000") << QString("178c83ce2b399d94") << QString("0108010101010101");
	QTest::newRow("") << QString("0000000000000000") << QString("50f636324a9b7f80") << QString("0104010101010101");
	QTest::newRow("") << QString("0000000000000000") << QString("a8468ee3bc18f06d") << QString("0102010101010101");
	QTest::newRow("") << QString("0000000000000000") << QString("a2dc9e92fd3cde92") << QString("0101800101010101");
	QTest::newRow("") << QString("0000000000000000") << QString("cac09f797d031287") << QString("0101400101010101");
	QTest::newRow("") << QString("0000000000000000") << QString("90ba680b22aeb525") << QString("0101200101010101");
	QTest::newRow("") << QString("0000000000000000") << QString("ce7a24f350e280b6") << QString("0101100101010101");
	QTest::newRow("") << QString("0000000000000000") << QString("882bff0aa01a0b87") << QString("0101080101010101");
	QTest::newRow("") << QString("0000000000000000") << QString("25610288924511c2") << QString("0101040101010101");
	QTest::newRow("") << QString("0000000000000000") << QString("c71516c29c75d170") << QString("0101020101010101");
	QTest::newRow("") << QString("0000000000000000") << QString("5199c29a52c9f059") << QString("0101018001010101");
	QTest::newRow("") << QString("0000000000000000") << QString("c22f0a294a71f29f") << QString("0101014001010101");
	QTest::newRow("") << QString("0000000000000000") << QString("ee371483714c02ea") << QString("0101012001010101");
	QTest::newRow("") << QString("0000000000000000") << QString("a81fbd448f9e522f") << QString("0101011001010101");
	QTest::newRow("") << QString("0000000000000000") << QString("4f644c92e192dfed") << QString("0101010801010101");
	QTest::newRow("") << QString("0000000000000000") << QString("1afa9a66a6df92ae") << QString("0101010401010101");
	QTest::newRow("") << QString("0000000000000000") << QString("b3c1cc715cb879d8") << QString("0101010201010101");
	QTest::newRow("") << QString("0000000000000000") << QString("19d032e64ab0bd8b") << QString("0101010180010101");
	QTest::newRow("") << QString("0000000000000000") << QString("3cfaa7a7dc8720dc") << QString("0101010140010101");
	QTest::newRow("") << QString("0000000000000000") << QString("b7265f7f447ac6f3") << QString("0101010120010101");
	QTest::newRow("") << QString("0000000000000000") << QString("9db73b3c0d163f54") << QString("0101010110010101");
	QTest::newRow("") << QString("0000000000000000") << QString("8181b65babf4a975") << QString("0101010108010101");
	QTest::newRow("") << QString("0000000000000000") << QString("93c9b64042eaa240") << QString("0101010104010101");
	QTest::newRow("") << QString("0000000000000000") << QString("5570530829705592") << QString("0101010102010101");
	QTest::newRow("") << QString("0000000000000000") << QString("8638809e878787a0") << QString("0101010101800101");
	QTest::newRow("") << QString("0000000000000000") << QString("41b9a79af79ac208") << QString("0101010101400101");
	QTest::newRow("") << QString("0000000000000000") << QString("7a9be42f2009a892") << QString("0101010101200101");
	QTest::newRow("") << QString("0000000000000000") << QString("29038d56ba6d2745") << QString("0101010101100101");
	QTest::newRow("") << QString("0000000000000000") << QString("5495c6abf1e5df51") << QString("0101010101080101");
	QTest::newRow("") << QString("0000000000000000") << QString("ae13dbd561488933") << QString("0101010101040101");
	QTest::newRow("") << QString("0000000000000000") << QString("024d1ffa8904e389") << QString("0101010101020101");
	QTest::newRow("") << QString("0000000000000000") << QString("d1399712f99bf02e") << QString("0101010101018001");
	QTest::newRow("") << QString("0000000000000000") << QString("14c1d7c1cffec79e") << QString("0101010101014001");
	QTest::newRow("") << QString("0000000000000000") << QString("1de5279dae3bed6f") << QString("0101010101012001");
	QTest::newRow("") << QString("0000000000000000") << QString("e941a33f85501303") << QString("0101010101011001");
	QTest::newRow("") << QString("0000000000000000") << QString("da99dbbc9a03f379") << QString("0101010101010801");
	QTest::newRow("") << QString("0000000000000000") << QString("b7fc92f91d8e92e9") << QString("0101010101010401");
	QTest::newRow("") << QString("0000000000000000") << QString("ae8e5caa3ca04e85") << QString("0101010101010201");
	QTest::newRow("") << QString("0000000000000000") << QString("9cc62df43b6eed74") << QString("0101010101010180");
	QTest::newRow("") << QString("0000000000000000") << QString("d863dbb5c59a91a0") << QString("0101010101010140");
	QTest::newRow("") << QString("0000000000000000") << QString("a1ab2190545b91d7") << QString("0101010101010120");
	QTest::newRow("") << QString("0000000000000000") << QString("0875041e64c570f7") << QString("0101010101010110");
	QTest::newRow("") << QString("0000000000000000") << QString("5a594528bebef1cc") << QString("0101010101010108");
	QTest::newRow("") << QString("0000000000000000") << QString("fcdb3291de21f0c0") << QString("0101010101010104");
	QTest::newRow("") << QString("0000000000000000") << QString("869efd7f9f265a09") << QString("0101010101010102");
	//end of weak keys
	QTest::newRow("") << QString("0000000000000000") << QString("88d55e54f54c97b4") << QString("1046913489980131");
	QTest::newRow("") << QString("0000000000000000") << QString("0c0cc00c83ea48fd") << QString("1007103489988020");
	QTest::newRow("") << QString("0000000000000000") << QString("83bc8ef3a6570183") << QString("10071034c8980120");
	QTest::newRow("") << QString("0000000000000000") << QString("df725dcad94ea2e9") << QString("1046103489988020");
	QTest::newRow("") << QString("0000000000000000") << QString("e652b53b550be8b0") << QString("1086911519190101");
	QTest::newRow("") << QString("0000000000000000") << QString("af527120c485cbb0") << QString("1086911519580101");
	QTest::newRow("") << QString("0000000000000000") << QString("0f04ce393db926d5") << QString("5107b01519580101");
	QTest::newRow("") << QString("0000000000000000") << QString("c9f00ffc74079067") << QString("1007b01519190101");
	QTest::newRow("") << QString("0000000000000000") << QString("7cfd82a593252b4e") << QString("3107915498080101");
	QTest::newRow("") << QString("0000000000000000") << QString("cb49a2f9e91363e3") << QString("3107919498080101");
	QTest::newRow("") << QString("0000000000000000") << QString("00b588be70d23f56") << QString("10079115b9080140");
	QTest::newRow("") << QString("0000000000000000") << QString("406a9a6ab43399ae") << QString("3107911598090140");
	QTest::newRow("") << QString("0000000000000000") << QString("6cb773611dca9ada") << QString("1007d01589980101");
	QTest::newRow("") << QString("0000000000000000") << QString("67fd21c17dbb5d70") << QString("9107911589980101");
	QTest::newRow("") << QString("0000000000000000") << QString("9592cb4110430787") << QString("9107d01589190101");
	QTest::newRow("") << QString("0000000000000000") << QString("a6b7ff68a318ddd3") << QString("1007d01598980120");
	QTest::newRow("") << QString("0000000000000000") << QString("4d102196c914ca16") << QString("1007940498190101");
	QTest::newRow("") << QString("0000000000000000") << QString("2dfa9f4573594965") << QString("0107910491190401");
	QTest::newRow("") << QString("0000000000000000") << QString("b46604816c0e0774") << QString("0107910491190101");
	QTest::newRow("") << QString("0000000000000000") << QString("6e7e6221a4f34e87") << QString("0107940491190401");
	QTest::newRow("") << QString("0000000000000000") << QString("aa85e74643233199") << QString("19079210981a0101");
	QTest::newRow("") << QString("0000000000000000") << QString("2e5a19db4d1962d6") << QString("1007911998190801");
	QTest::newRow("") << QString("0000000000000000") << QString("23a866a809d30894") << QString("10079119981a0801");
	QTest::newRow("") << QString("0000000000000000") << QString("d812d961f017d320") << QString("1007921098190101");
	QTest::newRow("") << QString("0000000000000000") << QString("055605816e58608f") << QString("100791159819010b");
	QTest::newRow("") << QString("0000000000000000") << QString("abd88e8b1b7716f1") << QString("1004801598190101");
	QTest::newRow("") << QString("0000000000000000") << QString("537ac95be69da1e1") << QString("1004801598190102");
	QTest::newRow("") << QString("0000000000000000") << QString("aed0f6ae3c25cdd8") << QString("1004801598190108");
	QTest::newRow("") << QString("0000000000000000") << QString("b3e35a5ee53e7b8d") << QString("1002911598100104");
	QTest::newRow("") << QString("0000000000000000") << QString("61c79c71921a2ef8") << QString("1002911598190104");
	QTest::newRow("") << QString("0000000000000000") << QString("e2f5728f0995013c") << QString("1002911598100201");
	QTest::newRow("") << QString("0000000000000000") << QString("1aeac39a61f0a464") << QString("1002911698100101");
	QTest::newRow("") << QString("059b5e0851cf143a") << QString("86a560f10ec6d85b") << QString("0113b970fd34f2ce");
	QTest::newRow("") << QString("4e6f772069732074") << QString("3fa40e8a984d4815") << QString("0123456789abcdef");
}


void CipherUnitTest::des()
{
	QStringList providersToTest;
	providersToTest.append("qca-ossl");
	// providersToTest.append("qca-gcrypt");
	providersToTest.append("qca-botan");
	providersToTest.append("qca-nss");

	foreach(const QString provider, providersToTest) {
		if( !QCA::isSupported( "des-ecb", provider ) )
			QWARN( QString( "DES ECB not supported for "+provider).toLocal8Bit() );
		else {
			QFETCH( QString, plainText );
			QFETCH( QString, cipherText );
			QFETCH( QString, keyText );

			QCA::SymmetricKey key( QCA::hexToArray( keyText ) );
			QCA::Cipher forwardCipher( QString( "des" ),
									   QCA::Cipher::ECB,
									   QCA::Cipher::NoPadding,
									   QCA::Encode,
									   key,
									   QCA::InitializationVector(),
									   provider );

			QCOMPARE( forwardCipher.blockSize(), 8 );
			QCOMPARE( forwardCipher.keyLength().minimum(), 8 );
			QCOMPARE( forwardCipher.keyLength().maximum(), 8 );

			QString afterEncodeText = QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( plainText ) ).toByteArray() );
			QVERIFY( forwardCipher.ok() );

			afterEncodeText += QCA::arrayToHex( forwardCipher.final().toByteArray() );
			QVERIFY( forwardCipher.ok() );

			QCOMPARE( afterEncodeText, cipherText );

			QCA::Cipher reverseCipher( QString( "des" ),
									   QCA::Cipher::ECB,
									   QCA::Cipher::NoPadding,
									   QCA::Decode,
									   key,
									   QCA::InitializationVector(),
									   provider );

			QCOMPARE( reverseCipher.blockSize(), 8 );
			QCOMPARE( reverseCipher.keyLength().minimum(), 8 );
			QCOMPARE( reverseCipher.keyLength().maximum(), 8 );

			QString afterDecodeText = QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( cipherText ) ).toByteArray() );
			QVERIFY( reverseCipher.ok() );

			afterDecodeText += QCA::arrayToHex( reverseCipher.final().toByteArray() );
			QVERIFY( reverseCipher.ok() );

			QCOMPARE( afterDecodeText, plainText );
		}
	}
}

// This is from the Botan test suite
void CipherUnitTest::des_cbc_data()
{
	QTest::addColumn<QString>("plainText");
	QTest::addColumn<QString>("cipherText");
	QTest::addColumn<QString>("keyText");
	QTest::addColumn<QString>("ivText");

	QTest::newRow("1") << QString("4e6f77206973207468652074696d6520666f7220616c6c20")
					   << QString("e5c7cdde872bf27c43e934008c389c0f683788499a7c05f6")
					   << QString("0123456789abcdef")
					   << QString("1234567890abcdef");
}


void CipherUnitTest::des_cbc()
{
	QStringList providersToTest;
	providersToTest.append("qca-ossl");
	providersToTest.append("qca-gcrypt");
	providersToTest.append("qca-botan");
	providersToTest.append("qca-nss");

	foreach(const QString provider, providersToTest) {
		if( !QCA::isSupported( "des-cbc", provider ) )
			QWARN( QString( "DES CBC not supported for "+provider).toLocal8Bit() );
		else {
			QFETCH( QString, plainText );
			QFETCH( QString, cipherText );
			QFETCH( QString, keyText );
			QFETCH( QString, ivText );

			QCA::SymmetricKey key( QCA::hexToArray( keyText ) );
			QCA::InitializationVector iv( QCA::hexToArray( ivText ) );
			QCA::Cipher forwardCipher( QString( "des" ),
									   QCA::Cipher::CBC,
									   QCA::Cipher::NoPadding,
									   QCA::Encode,
									   key,
									   iv,
									   provider);
			QString update = QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( plainText ) ).toByteArray() );
			QVERIFY( forwardCipher.ok() );
			QCOMPARE( update + QCA::arrayToHex( forwardCipher.final().toByteArray() ), cipherText );
			QVERIFY( forwardCipher.ok() );

			QCA::Cipher reverseCipher( QString( "des" ),
									   QCA::Cipher::CBC,
									   QCA::Cipher::NoPadding,
									   QCA::Decode,
									   key,
									   iv,
									   provider);
			update = QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( cipherText ) ).toByteArray() );
			QVERIFY( reverseCipher.ok() );
			QCOMPARE( update, plainText.left(update.size() ) );
			QCOMPARE( update + QCA::arrayToHex( reverseCipher.final().toByteArray() ), plainText );
			QVERIFY( reverseCipher.ok() );
		}
	}
}


// This is from the Botan test suite
void CipherUnitTest::des_cfb_data()
{
	QTest::addColumn<QString>("plainText");
	QTest::addColumn<QString>("cipherText");
	QTest::addColumn<QString>("keyText");
	QTest::addColumn<QString>("ivText");

	QTest::newRow("") << QString("5eef8199471c2a7ef97509623cae32c35a90245b70a21ce36e")
					  << QString("658b25e25df23948847afa4c9ffdd5b3ddf35d801cbe945168")
					  << QString("add9ce7bcf48c44b") << QString("0f90e78835ba3183");
	QTest::newRow("") << QString("4e6f77206973207468652074696d6520666f7220616c6c20")
					  << QString("f3096249c7f46e51a69e839b1a92f78403467133898ea622")
					  << QString("0123456789abcdef") << QString("1234567890abcdef");
	QTest::newRow("") << QString("d14fd67a9b4d7b0f65b7ca3da91741603da446")
					  << QString("0cb8929a854e61ab3beb72ce0f13ba328ba73a")
					  << QString("7132d895529a7aff") << QString("fa1fe8f921706c75");
	QTest::newRow("") << QString("16") << QString("e1")
					  << QString("f51cf13fd55f33b8") << QString("10e61c7f8276132e");
	QTest::newRow("") << QString("b8f7") << QString("9f09")
					  << QString("6a2306397e6399af") << QString("6791874e16642dd8");
	QTest::newRow("") << QString("914aa4") << QString("1cddad")
					  << QString("08d3b08cb02e2547") << QString("b35072a53fa36190");
	QTest::newRow("") << QString("252f0616") << QString("e22a706a")
					  << QString("454a9aca108ad24c") << QString("64dadb33ccf1debd");
	QTest::newRow("") << QString("f06f376c6e") << QString("c2f054e435")
					  << QString("087fc9f0b8be08f3") << QString("5e511251c063b3c7");
	QTest::newRow("") << QString("9a181afec04c") << QString("c49218c8a25b")
					  << QString("fe1ea0f0ac5f2c02") << QString("a247e69ced4a2bf1");
	QTest::newRow("") << QString("ac465cbd745341") << QString("768b6f5bfa9c24")
					  << QString("1e7c7274307edb90") << QString("afb634941c366c1d");
	QTest::newRow("") << QString("52bdfd51e3434e94") << QString("c5d84483756ac360")
					  << QString("53e241e43aad03e7") << QString("be0a4ae59056d8fe");
	QTest::newRow("") << QString("a62c02059afe67cd7f") << QString("032a99be4df6b63f97")
					  << QString("487c9fbd140ef278") << QString("43f88de155e98523");
	QTest::newRow("") << QString("32d3c8a283257f6276c3") << QString("bcfa26efe2d93a4b1364")
					  << QString("8b068595d5b79177") << QString("7129287761d94d9f");
	QTest::newRow("") << QString("17cb11a60f880c16d6cc3a") << QString("3dc099d927b8aa66b2a5c8")
					  << QString("750c87995afd65ee") << QString("a61398fff559faad");
	QTest::newRow("") << QString("eaa91cede4efc60f02b1e0ee") << QString("75614ea2fd5474fdfe3a5612")
					  << QString("08a5f56200ac9300") << QString("9f9ed0928b8cd2dd");
	QTest::newRow("") << QString("68db8992e91d759256ab373748") << QString("9d0e14f0b2be2d3b47103da75f")
					  << QString("b11dfa915ad86ff9") << QString("3885ecf48a611dc5");
	QTest::newRow("") << QString("d75acdd3e4040dfda924ce09e627")
					  << QString("a878ce766412a9c387ad61642fb7")
					  << QString("fbf9e6d9344b0f2c") << QString("6917f8fe1ac12101");
	QTest::newRow("") << QString("38b667a6e4458c8732aae6f4d0ac36")
					  << QString("5bcfd93d6b4b45d9d0d03162fa8fb9")
					  << QString("8616d2ea6e6106b3") << QString("cfe4dfa7044f56ab");
	QTest::newRow("") << QString("0b439a72a4430b3d15e234034ba2c066")
					  << QString("1adae0a4a0d582b70b60ed1c859a07b3")
					  << QString("e255e4a4c3606081") << QString("3f160dff918c3f78");
	QTest::newRow("") << QString("82e27182fc22cd8918dddbdb850034a4f2")
					  << QString("9767881b1909db5e146caaf5fc6a118814")
					  << QString("b9cdd5442e1c7fd7") << QString("5d1b1eceb7335274");
}


void CipherUnitTest::des_cfb()
{
	QStringList providersToTest;
	providersToTest.append("qca-ossl");
	providersToTest.append("qca-gcrypt");
	providersToTest.append("qca-botan");

	foreach(const QString provider, providersToTest) {
		if( !QCA::isSupported( "des-cfb", provider ) )
			QWARN( QString( "DES CFB not supported for "+provider).toLocal8Bit() );
		else {
			QFETCH( QString, plainText );
			QFETCH( QString, cipherText );
			QFETCH( QString, keyText );
			QFETCH( QString, ivText );

			QCA::SymmetricKey key( QCA::hexToArray( keyText ) );
			QCA::InitializationVector iv( QCA::hexToArray( ivText ) );
			QCA::Cipher forwardCipher( QString( "des" ),
									   QCA::Cipher::CFB,
									   QCA::Cipher::NoPadding,
									   QCA::Encode,
									   key,
									   iv,
									   provider);
			QString update = QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( plainText ) ).toByteArray() );
			QVERIFY( forwardCipher.ok() );
			QCOMPARE( update + QCA::arrayToHex( forwardCipher.final().toByteArray() ), cipherText );
			QVERIFY( forwardCipher.ok() );

			QCA::Cipher reverseCipher( QString( "des" ),
									   QCA::Cipher::CFB,
									   QCA::Cipher::NoPadding,
									   QCA::Decode,
									   key,
									   iv,
									   provider);
			update = QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( cipherText ) ).toByteArray() );
			QVERIFY( reverseCipher.ok() );
			QCOMPARE( update, plainText.left(update.size() ) );
			QCOMPARE( update + QCA::arrayToHex( reverseCipher.final().toByteArray() ), plainText );
			QVERIFY( reverseCipher.ok() );
		}
	}
}

// This is from the Botan test suite
void CipherUnitTest::des_ofb_data()
{
	QTest::addColumn<QString>("plainText");
	QTest::addColumn<QString>("cipherText");
	QTest::addColumn<QString>("keyText");
	QTest::addColumn<QString>("ivText");

	QTest::newRow("1") << QString("4e6f77206973207468652074696d6520666f7220616c6c20")
					   << QString("f3096249c7f46e5135f24a242eeb3d3f3d6d5be3255af8c3")
					   << QString("0123456789abcdef") << QString("1234567890abcdef");
	QTest::newRow("2") << QString("b25330d1cab11fddff278192aa2c935a9c7745733e6da8")
					   << QString("39b9bf284d6da6e639b8040b8da01e469dba4c6e50b1ab")
					   << QString("f871822c7fd1d6a3") << QString("b311792c8bc02ee8");
	QTest::newRow("3") << QString("73ad356623a1d6e0717e838b9344b4fff21bda")
					   << QString("0c06e63e9e81d9976e16d2009255f917797d51")
					   << QString("5860f4a413de6c68") << QString("527a1e050a9d71f0");
	QTest::newRow("4") << QString("08a6091fa2987fdc682a8199a6d6bd1f")
					   << QString("640b5033dcf26873fa8a34db644f2bf2")
					   << QString("3307042dc775035e") << QString("99de32ff0351509b");
}


void CipherUnitTest::des_ofb()
{
	QStringList providersToTest;
	providersToTest.append("qca-ossl");
	providersToTest.append("qca-gcrypt");
	providersToTest.append("qca-botan");

	foreach(const QString provider, providersToTest) {
		if( !QCA::isSupported( "des-ofb", provider ) )
			QWARN( QString( "DES OFB not supported for "+provider).toLocal8Bit() );
		else {
			QFETCH( QString, plainText );
			QFETCH( QString, cipherText );
			QFETCH( QString, keyText );
			QFETCH( QString, ivText );

			QCA::SymmetricKey key( QCA::hexToArray( keyText ) );
			QCA::InitializationVector iv( QCA::hexToArray( ivText ) );
			QCA::Cipher forwardCipher( QString( "des" ),
									   QCA::Cipher::OFB,
									   QCA::Cipher::NoPadding,
									   QCA::Encode,
									   key,
									   iv,
									   provider);
			QString update = QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( plainText ) ).toByteArray() );
			QVERIFY( forwardCipher.ok() );
			QCOMPARE( update + QCA::arrayToHex( forwardCipher.final().toByteArray() ), cipherText );
			QVERIFY( forwardCipher.ok() );

			QCA::Cipher reverseCipher( QString( "des" ),
									   QCA::Cipher::OFB,
									   QCA::Cipher::NoPadding,
									   QCA::Decode,
									   key,
									   iv,
									   provider);
			update = QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( cipherText ) ).toByteArray() );
			QVERIFY( reverseCipher.ok() );
			QCOMPARE( update, plainText.left(update.size() ) );
			QCOMPARE( update + QCA::arrayToHex( reverseCipher.final().toByteArray() ), plainText );
			QVERIFY( reverseCipher.ok() );
		}
	}
}

// These are from the Botan test suite
void CipherUnitTest::des_pkcs7_data()
{
	QTest::addColumn<QString>("plainText");
	QTest::addColumn<QString>("cipherText");
	QTest::addColumn<QString>("keyText");

	QTest::newRow("") << QString("") << QString("705fdf4dc7abfbfc") << QString("02d863a4885d417a");
	QTest::newRow("") << QString("fa") << QString("2281ac7cfa703ba9") << QString("05add235b01bbda7");
	QTest::newRow("") << QString("b895") << QString("8c3bf9ab9d16c8cf") << QString("93f04843afc3a191");
	QTest::newRow("") << QString("8e97de") << QString("be38bd2afe108d2a") << QString("1f4e2c013314b55a");
	QTest::newRow("") << QString("c1dae88e") << QString("998341e8b0cce82e") << QString("0f59c05186431e13");
	QTest::newRow("") << QString("a6e0360e88") << QString("f5e88fcc387b8883") << QString("e68bf7b98d61fed0");
	QTest::newRow("") << QString("55e67a79f043") << QString("a868b107bd96f35c") << QString("ae3ab00a0ba38be0");
	QTest::newRow("") << QString("d77c93b63d6d5b") << QString("19da07a34fa683c4") << QString("9b661c7a536afc6d");
	QTest::newRow("") << QString("328d09508e747ae1")
					  << QString("9c75845c6bff94438eb7e7e4c77342f0") << QString("8e1c689280575f05");
	QTest::newRow("") << QString("421d4bdc3869e59f07")
					  << QString("8df60dc27a2e2ee23360be31343fcbdb") << QString("eb4a6b437572e1e7");
	QTest::newRow("") << QString("160e525583c3e4fbc4fe")
					  << QString("9b649660dfe5b875cd81180ad627943f") << QString("ffe58726b90c9f97");
	QTest::newRow("") << QString("e873b3c2b31130719e6469")
					  << QString("6e33ae2af48cc39697800a3aa357cc5e")
					  << QString("560ee1ed2cc2bffb");
	QTest::newRow("") << QString("405915adc0111eb8af225612")
					  << QString("569be1f2ae91785b0634f8dd4ec1dff2") << QString("012a7de9cbfbd230");
	QTest::newRow("") << QString("e923c535186730f309cdea6dea")
					  << QString("846d7314f76e00902054bd2b2ae1f580") << QString("3d5d56ca2e8e359c");
	QTest::newRow("") << QString("116053a5820f9d36650eef49a05b")
					  << QString("9bd56c43036485b648efe6d31e69f0c6") << QString("2ad63a5312bf4259");
	QTest::newRow("") << QString("b6dcd40077fe89138b5a2ed35e1b3d")
					  << QString("2fbe419bada6d4bf3f6c7bb2a1aac329") << QString("7ff12d4d8a9ef138");
	QTest::newRow("") << QString("08f0aa208f8a06c6292838a8cee9104e")
					  << QString("44bfca2722d274504af482e9261cdb7b16918be77a461b3b")
					  << QString("f71a3b1aabd660bd");
	QTest::newRow("") << QString("878412f6255ff4360a22772711289fd351")
					  << QString("9c92fdde178d3b6c895aad1b8dc886176910b021d5b3aa77")
					  << QString("1ed8b08898872631");
	QTest::newRow("") << QString("1399a0cd9f2778bcfba9c0f7e7c89ca069e3")
					  << QString("5972f89d8c161dd30a409bcdbf43b20bb104e8a293c48fdd")
					  << QString("0dcb3527035253a5");
	QTest::newRow("") << QString("ea1cc272d3725e4c5dc56079fa3c9f26a1373a")
					  << QString("d1b2fcc83cbf11e022c058fcb988cbbbc3843517f5e9d900")
					  << QString("bf4b260909243b2f");
	QTest::newRow("") << QString("098dd47ea5784d307c115824cfc3443983fdf58b")
					  << QString("77dfae7f46af6db0d0e5775859943e2875854a680b54b59b")
					  << QString("5d869f3486dfe1a1");

}


// This is DES ECB, PKCS7 padding
void CipherUnitTest::des_pkcs7()
{
	QStringList providersToTest;
	providersToTest.append("qca-ossl");
	providersToTest.append("qca-botan");
	providersToTest.append("qca-nss");

	foreach(const QString provider, providersToTest) {
		if( !QCA::isSupported( "des-ecb-pkcs7", provider ) )
			QWARN( QString( "DES ECB with PKCS7 padding not supported for "+provider).toLocal8Bit() );
		else {
			QFETCH( QString, plainText );
			QFETCH( QString, cipherText );
			QFETCH( QString, keyText );

			QCA::SymmetricKey key( QCA::hexToArray( keyText ) );
			// just a filler
			QCA::InitializationVector iv;
			QCA::Cipher forwardCipher( QString( "des" ),
									   QCA::Cipher::ECB,
									   QCA::Cipher::PKCS7,
									   QCA::Encode,
									   key,
									   iv,
									   provider);

			QCOMPARE( forwardCipher.keyLength().minimum(), 8 );
			QCOMPARE( forwardCipher.keyLength().maximum(), 8 );
			QCOMPARE( forwardCipher.blockSize(), 8 );

			QString update = QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( plainText ) ).toByteArray() );
			QVERIFY( forwardCipher.ok() );
			QCOMPARE( update, cipherText.left(update.size())  );
			QCOMPARE( update + QCA::arrayToHex( forwardCipher.final().toByteArray() ), cipherText );
			QVERIFY( forwardCipher.ok() );

			QCA::Cipher reverseCipher( QString( "des" ),
									   QCA::Cipher::ECB,
									   QCA::Cipher::PKCS7,
									   QCA::Decode,
									   key,
									   iv,
									   provider);

			QCOMPARE( reverseCipher.keyLength().minimum(), 8 );
			QCOMPARE( reverseCipher.keyLength().maximum(), 8 );
			QCOMPARE( reverseCipher.blockSize(), 8 );

			update = QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( cipherText ) ).toByteArray() );
			QVERIFY( reverseCipher.ok() );
			QCOMPARE( update, plainText.left(update.size())  );
			QCOMPARE( update + QCA::arrayToHex( reverseCipher.final().toByteArray() ), plainText );
			QVERIFY( reverseCipher.ok() );
		}
	}
}

// These are from the Botan test suite
void CipherUnitTest::des_cbc_pkcs7_data()
{
	QTest::addColumn<QString>("plainText");
	QTest::addColumn<QString>("cipherText");
	QTest::addColumn<QString>("keyText");
	QTest::addColumn<QString>("ivText");

	QTest::newRow("1") << QString("4e6f77206973207468652074696d6520666f7220616c6c20")
					   << QString("e5c7cdde872bf27c43e934008c389c0f683788499a7c05f662c16a27e4fcf277")
					   << QString("0123456789abcdef") << QString("1234567890abcdef");
	QTest::newRow("2") << QString("") << QString("ff4903e653af83c4")
					   << QString("46b534fbffdae457") << QString("297873b948a44b5f");
	QTest::newRow("3") << QString("69") << QString("60fa7b46523aa51f")
					   << QString("d581a1d0c70f94a1") << QString("c1ddd7447249ef80");
	QTest::newRow("4") << QString("02b7") << QString("63c1c1ef79555ed8")
					   << QString("a415b62e7e94caf2") << QString("57fa9b2f95f57401");
	QTest::newRow("5") << QString("568960") << QString("d0321483090f524d")
					   << QString("5dcbe42db374090e") << QString("b6215a095582763f");
	QTest::newRow("6") << QString("b6eaf23c") << QString("88e289e1de3e6451")
					   << QString("8fe92291c654ec9b") << QString("0c054bbd31a9f623");
	QTest::newRow("7") << QString("60a658cbbd") << QString("89bffa9e36ff1780")
					   << QString("dbcee35e86088501") << QString("11a8928bc6d0d117");
	QTest::newRow("8") << QString("7e10cbd9e95c") << QString("afc5cdf559abc6d3")
					   << QString("72338f946012ced5") << QString("eaaa48b0c2ee2f3f");
	QTest::newRow("9") << QString("d907ce88f077fa") << QString("3476402272856ea8")
					   << QString("837fbb3167f0ccaa") << QString("cd399dd3e402f8f2");
	QTest::newRow("10") << QString("9476e85b198c9aee") << QString("1af298a150514ca70d252f88271b3ca7")
						<< QString("308d1c02e7a4e09d") << QString("6baa74f7f1a72e1f");
	QTest::newRow("11") << QString("5c11285270e9606cdf") << QString("78665abfe3def34f8bd55796825ee915")
						<< QString("126aff39882542ea") << QString("51badb479de66a73");
	QTest::newRow("12") << QString("d1d3d8675e42a4242fba")
						<< QString("e77bb4a24b4ee8c9ebda4971c2e60d10")
						<< QString("0ae8510bb0fb3994") << QString("6c7293a8427bcb3b");
	QTest::newRow("13") << QString("65026a8a41edc1d880f6c9")
						<< QString("45a6ef4acd49f9f1d892a808fa7b6f28")
						<< QString("0be9277b3504d524") << QString("e47ec7a77db94755");
	QTest::newRow("14") << QString("d72e81f4130107e396d5fb27")
						<< QString("a88eff91876a1b6958d52f99fe9b18fb")
						<< QString("2f03c36de4f78e13") << QString("99fd2e8848f33fe7");
	QTest::newRow("15") << QString("c8a3971efda18af1b18bfad98f")
						<< QString("54ff90bd90f6213d761f4b3ff89a8ded")
						<< QString("69329672e546c969") << QString("294922cbe7e12341");
	QTest::newRow("16") << QString("bb9a90f11551531de512dd48270e")
						<< QString("9ba7908e56edb1bef992faee40f5b1ca")
						<< QString("3007d71e86d8eaf2") << QString("d7e300e168f60063");
	QTest::newRow("17") << QString("77d6c182e4ddd444d614bcff98fb13")
						<< QString("cb50dec4728fc2f1a1a5dfb84fa1bd25")
						<< QString("f73c8c3355092eb6") << QString("2e0db2552bb83ad3");
	QTest::newRow("18") << QString("40aed22f93dcfcb1d734b7e4657dd31a")
						<< QString("66d17a6e9d5be3281e857b4c7e497988ca684524fd994882")
						<< QString("dd006f15e727cb62") << QString("b256dc4fdb58451b");
	QTest::newRow("19") << QString("bb25564c7ea1e5bd22016915805c27b51b")
						<< QString("b7ceb5f5ed2945f131064bbb9213694b19a04fbd1f138866")
						<< QString("df70ff987582ccfe") << QString("88bb3b9bb2ea56d7");
	QTest::newRow("20") << QString("49dab8d85ea753cf4ae2ece7a80f0784e42b")
						<< QString("d7fce9e5bed161ad7d950e453677e5bee422b7542afc0bd3")
						<< QString("747e09fa9ba257dc") << QString("f1bbd406191de0d1");
	QTest::newRow("21") << QString("dc13a6abaa35ceb3e6650f825a67942114af2e")
						<< QString("bafdb50e16c9ff4449bf336d410441d56e1e5335b54c9f11")
						<< QString("cdad411d0fa80e9d") << QString("c83d55b1196958c4");
	QTest::newRow("22") << QString("a8896d88907ad77ae790828c0a3384c1614e07d9")
						<< QString("70a9eb1c11bfd1b1d68c20a6b72c869dac5372a8ed46aa07")
						<< QString("642d12c591f6a4f4") << QString("c17d0c69067af296");
	QTest::newRow("23") << QString("b3fec4cc29dc1abbcf7d86f01d2c02c2a723e7c2f8")
						<< QString("48ed5583a04d333ffac9d6462fd96bf79222eeec70a6ae70")
						<< QString("62c62f54c426c59f") << QString("cb6252ca271ff303");
	QTest::newRow("24") << QString("ac0b4d5752d2009bdcd42314d9723716294146424542")
						<< QString("8a284713f8c9873ad5f558b995c5a67a66557a52601975d1")
						<< QString("386dcad5eae86830") << QString("48153b966c8d686d");
	QTest::newRow("25") << QString("ea331f6e518a8aeab2ef0a4e92e0d198df5dd0cc74369e")
						<< QString("6d3d7de9938935f9fb9af839e416ef6f842f2ed827334bfb")
						<< QString("782545ea65d89b01") << QString("c2ce203020aabb0a");
	QTest::newRow("26") << QString("b292d3a3fdc5d709709c87ef91122761847871f9b4e33426")
						<< QString("21dae17d157192146b52c49d90f898b25d0d1dfe677e8cd5b568814e9c6bb6a8")
						<< QString("ecc650e1ed1ce8a0") << QString("aebc43ab811ab5f1");
	QTest::newRow("27") << QString("65026a8a41edc1d880f6c90be9277b3504d524e47ec7a77db9")
						<< QString("a3b6404c4d87f72d5e0995d7cc20ece742d9705d48524cfa2820317087faf578")
						<< QString("4755b8639fd7c8a1") << QString("4152e22f14baaf0a");
	QTest::newRow("28") << QString("d1d3d8675e42a4242fba0ae8510bb0fb39946c7293a8427bcb3b")
						<< QString("db621f2fac9a924c83ed0b9e8acec9f1e23bf3ff2ad6efa814903f2ce293107b")
						<< QString("92a18b78a25c4b7a") << QString("c3aabc68ceeb22d9");
	QTest::newRow("29") << QString("c8a3971efda18af1b18bfad98f69329672e546c969294922cbe7e1")
						<< QString("940c610a41f04e7d9be0a74d5d00fe97a2647d3d16e9b76ff0db5bbdc197c82a")
						<< QString("2341239c09c73427") << QString("c4d5b2b6863db060");
	QTest::newRow("30") << QString("d72e81f4130107e396d5fb272f03c36de4f78e1399fd2e8848f33fe7")
						<< QString("7d495cba50c4127347e3ad29e3b8c098a3312782e3d45abfa1621f64bf8b8a06")
						<< QString("166ea8ed9d29e1b0") << QString("2be993c1be8fe9ed");
	QTest::newRow("31") << QString("77d6c182e4ddd444d614bcff98fb13f73c8c3355092eb62e0db2552bb8")
						<< QString("9d926142271e814ba4603509187c9020daa0d50f15af6e698e384644e9468c11")
						<< QString("3ad3301094b2f471") << QString("8638489af44732f0");
	QTest::newRow("32") << QString("bb9a90f11551531de512dd48270e3007d71e86d8eaf2d7e300e168f60063")
						<< QString("44858416f946c7fbdffd720282881630803803ab91ceab1af4f68f50e9c16dce")
						<< QString("04bbfd95ac12e6ff") << QString("30cb120d13391c44");
	QTest::newRow("33") << QString("8eb8faf49126ad5b8a0aa6df8b52dbe50dd5aed271641ef983bd650da69816")
						<< QString("5b4622f1c4faa817ee3ac181b969a7afed7117e23f68bc6017519a7d1399cfe9")
						<< QString("35501029e137d63d") << QString("c1e0e3a06b357b51");
}

void CipherUnitTest::des_cbc_pkcs7()
{
	QStringList providersToTest;
	providersToTest.append("qca-ossl");
	// providersToTest.append("qca-gcrypt");
	providersToTest.append("qca-botan");
	providersToTest.append("qca-nss");

	foreach(const QString provider, providersToTest) {
		if( !QCA::isSupported( "des-cbc-pkcs7", provider ) )
			QWARN( QString( "DES CBC with PKCS7 padding not supported for "+provider).toLocal8Bit() );
		else {
			QFETCH( QString, plainText );
			QFETCH( QString, cipherText );
			QFETCH( QString, keyText );
			QFETCH( QString, ivText );

			QCA::SymmetricKey key( QCA::hexToArray( keyText ) );
			QCA::InitializationVector iv( QCA::hexToArray( ivText ) );
			QCA::Cipher forwardCipher( QString( "des" ),
									   QCA::Cipher::CBC,
									   QCA::Cipher::PKCS7,
									   QCA::Encode,
									   key,
									   iv,
									   provider);

			QCOMPARE( forwardCipher.keyLength().minimum(), 8 );
			QCOMPARE( forwardCipher.keyLength().maximum(), 8 );
			QCOMPARE( forwardCipher.blockSize(), 8 );

			QString update = QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( plainText ) ).toByteArray() );
			QVERIFY( forwardCipher.ok() );
			QCOMPARE( update, cipherText.left(update.size())  );
			QCOMPARE( update + QCA::arrayToHex( forwardCipher.final().toByteArray() ), cipherText );
			QVERIFY( forwardCipher.ok() );

			QCA::Cipher reverseCipher( QString( "des" ),
									   QCA::Cipher::CBC,
									   QCA::Cipher::PKCS7,
									   QCA::Decode,
									   key,
									   iv,
									   provider);

			QCOMPARE( reverseCipher.keyLength().minimum(), 8 );
			QCOMPARE( reverseCipher.keyLength().maximum(), 8 );
			QCOMPARE( reverseCipher.blockSize(), 8 );

			update = QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( cipherText ) ).toByteArray() );
			QVERIFY( reverseCipher.ok() );
			QCOMPARE( update, plainText.left(update.size())  );
			QCOMPARE( update + QCA::arrayToHex( reverseCipher.final().toByteArray() ), plainText );
			QVERIFY( reverseCipher.ok() );
		}
	}
}

#if 0
if (!QCA::isSupported("des-ecb-pkcs7") )
QWARN("DES, ECB mode with PKCS7 padding not supported!");
else {
QCA::Cipher cipherObj1( QString( "des" ),
						QCA::Cipher::ECB,
						QCA::Cipher::PKCS7,
						QCA::Encode,
						QCA::SymmetricKey( 8 ) );
QCOMPARE( cipherObj1.keyLength().minimum(), 8 );
QCOMPARE( cipherObj1.keyLength().maximum(), 8 );
QCOMPARE( cipherObj1.blockSize(), 8 );

for (int n = 0; (0 != desEcbPkcs7TestValues[n].plaintext); n++) {
	QCA::SymmetricKey key( QCA::hexToArray( desEcbPkcs7TestValues[n].key ) );
	QCA::DES forwardCipher( QCA::Cipher::ECB, QCA::Cipher::PKCS7, QCA::Encode, key);
	QCOMPARE( QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( desEcbPkcs7TestValues[n].plaintext ) ).toByteArray() ),
			  QString( desEcbPkcs7TestValues[n].ciphertext ) );
	QCOMPARE( forwardCipher.ok(), true );
	QCOMPARE( QCA::arrayToHex( forwardCipher.final().toByteArray() ), QString( "" ) );
	QCOMPARE( forwardCipher.ok(), true );

	QCA::DES reverseCipher( QCA::Cipher::ECB, QCA::Cipher::PKCS7, QCA::Decode, key);

	QCOMPARE( QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( desEcbPkcs7TestValues[n].ciphertext ) ).toByteArray() ),
			  QString( desEcbPkcs7TestValues[n].plaintext ) );
	QCOMPARE( reverseCipher.ok(), true );
	QCOMPARE( QCA::arrayToHex( reverseCipher.final().toByteArray() ), QString( "" ) );
	QCOMPARE( reverseCipher.ok(), true );
}
}
#endif

// These are from the Botan test suite. They match the test vectors from Bruce's site
void CipherUnitTest::blowfish_data()
{
	QTest::addColumn<QString>("plainText");
	QTest::addColumn<QString>("cipherText");
	QTest::addColumn<QString>("keyText");

	QTest::newRow("1") << QString("0000000000000000") << QString("245946885754369a") << QString("0123456789abcdef" );
	QTest::newRow("2") << QString("0000000000000000") << QString("4ef997456198dd78") << QString("0000000000000000" );
	QTest::newRow("3") << QString("0000000000000000") << QString("f21e9a77b71c49bc") << QString("ffffffffffffffff" );
	QTest::newRow("4") << QString("004bd6ef09176062") << QString("452031c1e4fada8e") << QString("584023641aba6176" );
	QTest::newRow("5") << QString("0123456789abcdef") << QString("0aceab0fc6a0a28d") << QString("fedcba9876543210" );
	QTest::newRow("6") << QString("0123456789abcdef") << QString("7d0cc630afda1ec7") << QString("1111111111111111" );
	QTest::newRow("7") << QString("0123456789abcdef") << QString("a790795108ea3cae") << QString("1f1f1f1f0e0e0e0e" );
	QTest::newRow("8") << QString("0123456789abcdef") << QString("c39e072d9fac631d") << QString("e0fee0fef1fef1fe" );
	QTest::newRow("9") << QString("0123456789abcdef") << QString("fa34ec4847b268b2") << QString("0101010101010101" );
	QTest::newRow("10") << QString("01a1d6d039776742") << QString("59c68245eb05282b") << QString("7ca110454a1a6e57" );
	QTest::newRow("11") << QString("0248d43806f67172") << QString("1730e5778bea1da4") << QString("07a1133e4a0b2686" );
	QTest::newRow("12") << QString("02fe55778117f12a") << QString("cf9c5d7a4986adb5") << QString("49e95d6d4ca229bf" );
	QTest::newRow("13") << QString("059b5e0851cf143a") << QString("48f4d0884c379918") << QString("0113b970fd34f2ce" );
	QTest::newRow("14") << QString("072d43a077075292") << QString("7a8e7bfa937e89a3") << QString("4fb05e1515ab73a7" );
	QTest::newRow("15") << QString("0756d8e0774761d2") << QString("432193b78951fc98") << QString("0170f175468fb5e6" );
	QTest::newRow("16") << QString("1000000000000001") << QString("7d856f9a613063f2") << QString("3000000000000000" );
	QTest::newRow("17") << QString("1111111111111111") << QString("2466dd878b963c9d") << QString("1111111111111111" );
	QTest::newRow("18") << QString("1111111111111111") << QString("61f9c3802281b096") << QString("0123456789abcdef" );
	QTest::newRow("19") << QString("164d5e404f275232") << QString("5f99d04f5b163969") << QString("37d06bb516cb7546" );
	QTest::newRow("20") << QString("1d9d5c5018f728c2") << QString("d1abb290658bc778") << QString("018310dc409b26d6" );
	QTest::newRow("21") << QString("26955f6835af609a") << QString("d887e0393c2da6e3") << QString("04689104c2fd3b2f" );
	QTest::newRow("22") << QString("305532286d6f295a") << QString("55cb3774d13ef201") << QString("1c587f1c13924fef" );
	QTest::newRow("23") << QString("3bdd119049372802") << QString("2eedda93ffd39c79") << QString("07a7137045da2a16" );
	QTest::newRow("24") << QString("42fd443059577fa2") << QString("353882b109ce8f1a") << QString("04b915ba43feb5b6" );
	QTest::newRow("25") << QString("437540c8698f3cfa") << QString("53c55f9cb49fc019") << QString("49793ebc79b3258f" );
	QTest::newRow("26") << QString("480d39006ee762f2") << QString("7555ae39f59b87bd") << QString("025816164629b007" );
	QTest::newRow("27") << QString("51454b582ddf440a") << QString("a25e7856cf2651eb") << QString("3849674c2602319e" );
	QTest::newRow("28") << QString("5cd54ca83def57da") << QString("b1b8cc0b250f09a0") << QString("0131d9619dc1376e" );
	QTest::newRow("29") << QString("6b056e18759f5cca") << QString("4a057a3b24d3977b") << QString("1f08260d1ac2465e" );
	QTest::newRow("30") << QString("762514b829bf486a") << QString("13f04154d69d1ae5") << QString("43297fad38e373fe" );
	QTest::newRow("31") << QString("ffffffffffffffff") << QString("014933e0cdaff6e4") << QString("0000000000000000" );
	QTest::newRow("32") << QString("ffffffffffffffff") << QString("51866fd5b85ecb8a") << QString("ffffffffffffffff" );
	QTest::newRow("33") << QString("ffffffffffffffff") << QString("6b5c5a9c5d9e0a5a") << QString("fedcba9876543210" );
	QTest::newRow("34") << QString("0123456789abcdef1111111111111111") << QString("7d0cc630afda1ec72466dd878b963c9d")
						<< QString("1111111111111111" );
	QTest::newRow("35") << QString("fedcba9876543210") << QString("cc91732b8022f684")
						<< QString("57686f206973204a6f686e2047616c743f" );
	QTest::newRow("36") << QString("424c4f5746495348") << QString("324ed0fef413a203")
						<< QString("6162636465666768696a6b6c6d6e6f707172737475767778797a" );
	QTest::newRow("37") << QString("fedcba9876543210") << QString("f9ad597c49db005e") << QString("f0" );
	QTest::newRow("38") << QString("fedcba9876543210") << QString("e91d21c1d961a6d6") << QString("f0e1" );
	QTest::newRow("39") << QString("fedcba9876543210") << QString("e9c2b70a1bc65cf3") << QString("f0e1d2" );
	QTest::newRow("40") << QString("fedcba9876543210") << QString("be1e639408640f05") << QString("f0e1d2c3" );
	QTest::newRow("41") << QString("fedcba9876543210") << QString("b39e44481bdb1e6e") << QString("f0e1d2c3b4" );
	QTest::newRow("42") << QString("fedcba9876543210") << QString("9457aa83b1928c0d") << QString("f0e1d2c3b4a5" );
	QTest::newRow("43") << QString("fedcba9876543210") << QString("8bb77032f960629d") << QString("f0e1d2c3b4a596" );
	QTest::newRow("44") << QString("fedcba9876543210") << QString("e87a244e2cc85e82") << QString("f0e1d2c3b4a59687" );
	QTest::newRow("45") << QString("fedcba9876543210") << QString("15750e7a4f4ec577") << QString("f0e1d2c3b4a5968778" );
	QTest::newRow("46") << QString("fedcba9876543210") << QString("122ba70b3ab64ae0") << QString("f0e1d2c3b4a596877869" );
	QTest::newRow("47") << QString("fedcba9876543210") << QString("3a833c9affc537f6")
						<< QString("f0e1d2c3b4a5968778695a" );
	QTest::newRow("48") << QString("fedcba9876543210") << QString("9409da87a90f6bf2")
						<< QString("f0e1d2c3b4a5968778695a4b" );
	QTest::newRow("49") << QString("fedcba9876543210") << QString("884f80625060b8b4")
						<< QString("f0e1d2c3b4a5968778695a4b3c" );
	QTest::newRow("50") << QString("fedcba9876543210") << QString("1f85031c19e11968")
						<< QString("f0e1d2c3b4a5968778695a4b3c2d" );
	QTest::newRow("51") << QString("fedcba9876543210") << QString("79d9373a714ca34f")
						<< QString("f0e1d2c3b4a5968778695a4b3c2d1e" );
	QTest::newRow("52") << QString("fedcba9876543210") << QString("93142887ee3be15c")
						<< QString("f0e1d2c3b4a5968778695a4b3c2d1e0f" );
	QTest::newRow("53") << QString("fedcba9876543210") << QString("03429e838ce2d14b")
						<< QString("f0e1d2c3b4a5968778695a4b3c2d1e0f00" );
	QTest::newRow("54") << QString("fedcba9876543210") << QString("a4299e27469ff67b")
						<< QString("f0e1d2c3b4a5968778695a4b3c2d1e0f0011" );
	QTest::newRow("55") << QString("fedcba9876543210") << QString("afd5aed1c1bc96a8")
						<< QString("f0e1d2c3b4a5968778695a4b3c2d1e0f001122" );
	QTest::newRow("56") << QString("fedcba9876543210") << QString("10851c0e3858da9f")
						<< QString("f0e1d2c3b4a5968778695a4b3c2d1e0f00112233" );
	QTest::newRow("57") << QString("fedcba9876543210") << QString("e6f51ed79b9db21f")
						<< QString("f0e1d2c3b4a5968778695a4b3c2d1e0f0011223344" );
	QTest::newRow("58") << QString("fedcba9876543210") << QString("64a6e14afd36b46f")
						<< QString("f0e1d2c3b4a5968778695a4b3c2d1e0f001122334455" );
	QTest::newRow("59") << QString("fedcba9876543210") << QString("80c7d7d45a5479ad")
						<< QString("f0e1d2c3b4a5968778695a4b3c2d1e0f00112233445566" );
	QTest::newRow("60") << QString("fedcba9876543210") << QString("05044b62fa52d080")
						<< QString("f0e1d2c3b4a5968778695a4b3c2d1e0f0011223344556677" );
}


void CipherUnitTest::blowfish()
{
	QStringList providersToTest;
	providersToTest.append("qca-ossl");
	// providersToTest.append("qca-gcrypt");
	providersToTest.append("qca-botan");
	providersToTest.append("qca-nss");

	foreach(const QString provider, providersToTest) {
		if( !QCA::isSupported( "blowfish-ecb", provider ) )
			QWARN( QString( "Blowfish ECB not supported for "+provider).toLocal8Bit() );
		else {
			QCA::Cipher cipherObj1( QString( "blowfish" ),
									QCA::Cipher::ECB,
									QCA::Cipher::NoPadding,
									QCA::Encode,
									QCA::SymmetricKey( 16 ),
									QCA::InitializationVector(), provider );

			// TODO: add some test for min and max keysizes
			QCOMPARE( cipherObj1.blockSize(), 8 );

			QFETCH( QString, plainText );
			QFETCH( QString, cipherText );
			QFETCH( QString, keyText );

			QCA::SymmetricKey key( QCA::hexToArray( keyText ) );
			QCA::Cipher forwardCipher( QString( "blowfish" ),
									   QCA::Cipher::ECB,
									   QCA::Cipher::NoPadding,
									   QCA::Encode,
									   key,
									   QCA::InitializationVector(),
									   provider );

			QString afterEncodeText = QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( plainText ) ).toByteArray() );
			QVERIFY( forwardCipher.ok() );

			afterEncodeText += QCA::arrayToHex( forwardCipher.final().toByteArray() );
			QVERIFY( forwardCipher.ok() );

			QCOMPARE( afterEncodeText, cipherText );

			QCA::Cipher reverseCipher( QString( "blowfish" ),
									   QCA::Cipher::ECB,
									   QCA::Cipher::NoPadding,
									   QCA::Decode,
									   key,
									   QCA::InitializationVector(),
									   provider );
			QString afterDecodeText = QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( cipherText ) ).toByteArray() );
			QVERIFY( reverseCipher.ok() );

			afterDecodeText += QCA::arrayToHex( reverseCipher.final().toByteArray() );
			QVERIFY( reverseCipher.ok() );

			QCOMPARE( afterDecodeText, plainText );
		}
	}
}

// From the Eric Young test vectors on Bruce's site. I modified
// them to remove the incomplete block.
void CipherUnitTest::blowfish_cbc_data()
{
	QTest::addColumn<QString>("plainText");
	QTest::addColumn<QString>("cipherText");
	QTest::addColumn<QString>("keyText");
	QTest::addColumn<QString>("ivText");

	QTest::newRow("1") << QString("37363534333231204e6f77206973207468652074696d6520")
					   << QString("6b77b4d63006dee605b156e27403979358deb9e7154616d9")
					   << QString("0123456789abcdeff0e1d2c3b4a59687")
					   << QString("fedcba9876543210");
	QTest::newRow("pkcs7") << QString("37363534333231204e6f77206973207468652074696d6520666f722000030303")
						   << QString("6b77b4d63006dee605b156e27403979358deb9e7154616d9749decbec05d264b")
						   << QString("0123456789abcdeff0e1d2c3b4a59687")
						   << QString("fedcba9876543210");
}


void CipherUnitTest::blowfish_cbc()
{
	QStringList providersToTest;
	providersToTest.append("qca-ossl");
	providersToTest.append("qca-gcrypt");
	providersToTest.append("qca-botan");
	providersToTest.append("qca-nss");

	foreach(const QString provider, providersToTest) {
		if( !QCA::isSupported( "blowfish-cbc", provider ) )
			QWARN( QString( "Blowfish CBC not supported for "+provider).toLocal8Bit() );
		else {
			QFETCH( QString, plainText );
			QFETCH( QString, cipherText );
			QFETCH( QString, keyText );
			QFETCH( QString, ivText );

			QCA::SymmetricKey key( QCA::hexToArray( keyText ) );
			QCA::InitializationVector iv( QCA::hexToArray( ivText ) );
			QCA::Cipher forwardCipher( QString( "blowfish" ),
									   QCA::Cipher::CBC,
									   QCA::Cipher::NoPadding,
									   QCA::Encode,
									   key,
									   iv,
									   provider);
			QString update = QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( plainText ) ).toByteArray() );
			QVERIFY( forwardCipher.ok() );
			QCOMPARE( update + QCA::arrayToHex( forwardCipher.final().toByteArray() ), cipherText );
			QVERIFY( forwardCipher.ok() );

			QCA::Cipher reverseCipher( QString( "blowfish" ),
									   QCA::Cipher::CBC,
									   QCA::Cipher::NoPadding,
									   QCA::Decode,
									   key,
									   iv,
									   provider);
			update = QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( cipherText ) ).toByteArray() );
			QVERIFY( reverseCipher.ok() );
			QCOMPARE( update, plainText.left(update.size() ) );
			QCOMPARE( update + QCA::arrayToHex( reverseCipher.final().toByteArray() ), plainText );
			QVERIFY( reverseCipher.ok() );
		}
	}
}

// I can't find any independent test vectors. I used the no padding case, with hand padding added,
// as a poor check.
void CipherUnitTest::blowfish_cbc_pkcs7_data()
{
	QTest::addColumn<QString>("plainText");
	QTest::addColumn<QString>("cipherText");
	QTest::addColumn<QString>("keyText");
	QTest::addColumn<QString>("ivText");


	QTest::newRow("1") << QString("37363534333231204e6f77206973207468652074696d6520666f722000")
					   << QString("6b77b4d63006dee605b156e27403979358deb9e7154616d9749decbec05d264b")
					   << QString("0123456789abcdeff0e1d2c3b4a59687")
					   << QString("fedcba9876543210");
}

void CipherUnitTest::blowfish_cbc_pkcs7()
{
	QStringList providersToTest;
	providersToTest.append("qca-ossl");
	providersToTest.append("qca-gcrypt");
	providersToTest.append("qca-botan");
	providersToTest.append("qca-nss");

	foreach(const QString provider, providersToTest) {
		if( !QCA::isSupported( "blowfish-cbc-pkcs7", provider ) )
			QWARN( QString( "Blowfish CBC with PKCS7 padding not supported for "+provider).toLocal8Bit() );
		else {
			QFETCH( QString, plainText );
			QFETCH( QString, cipherText );
			QFETCH( QString, keyText );
			QFETCH( QString, ivText );

			QCA::SymmetricKey key( QCA::hexToArray( keyText ) );
			QCA::InitializationVector iv( QCA::hexToArray( ivText ) );
			QCA::Cipher forwardCipher( QString( "blowfish" ),
									   QCA::Cipher::CBC,
									   QCA::Cipher::PKCS7,
									   QCA::Encode,
									   key,
									   iv,
									   provider);
			QString update = QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( plainText ) ).toByteArray() );
			QVERIFY( forwardCipher.ok() );
			QCOMPARE( update, cipherText.left(update.size())  );
			QCOMPARE( update + QCA::arrayToHex( forwardCipher.final().toByteArray() ), cipherText );
			QVERIFY( forwardCipher.ok() );

			QCA::Cipher reverseCipher( QString( "blowfish" ),
									   QCA::Cipher::CBC,
									   QCA::Cipher::PKCS7,
									   QCA::Decode,
									   key,
									   iv,
									   provider);
			update = QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( cipherText ) ).toByteArray() );
			QVERIFY( reverseCipher.ok() );
			QCOMPARE( update, plainText.left(update.size())  );
			QCOMPARE( update + QCA::arrayToHex( reverseCipher.final().toByteArray() ), plainText );
			QVERIFY( reverseCipher.ok() );
		}
	}
}


// From the Eric Young test vectors on Bruce's site:
void CipherUnitTest::blowfish_cfb_data()
{
	QTest::addColumn<QString>("plainText");
	QTest::addColumn<QString>("cipherText");
	QTest::addColumn<QString>("keyText");
	QTest::addColumn<QString>("ivText");

	QTest::newRow("1") << QString("37363534333231204e6f77206973207468652074696d6520666f722000")
					   << QString("e73214a2822139caf26ecf6d2eb9e76e3da3de04d1517200519d57a6c3")
					   << QString("0123456789abcdeff0e1d2c3b4a59687")
					   << QString("fedcba9876543210");
}

void CipherUnitTest::blowfish_cfb()
{
	QStringList providersToTest;
	providersToTest.append("qca-ossl");
	providersToTest.append("qca-gcrypt");
	providersToTest.append("qca-botan");

	foreach(const QString provider, providersToTest) {
		if( !QCA::isSupported( "blowfish-cfb", provider ) )
			QWARN( QString( "Blowfish CFB not supported for "+provider).toLocal8Bit() );
		else {
			QFETCH( QString, plainText );
			QFETCH( QString, cipherText );
			QFETCH( QString, keyText );
			QFETCH( QString, ivText );

			QCA::SymmetricKey key( QCA::hexToArray( keyText ) );
			QCA::InitializationVector iv( QCA::hexToArray( ivText ) );
			QCA::Cipher forwardCipher( QString( "blowfish" ),
									   QCA::Cipher::CFB,
									   QCA::Cipher::NoPadding,
									   QCA::Encode,
									   key,
									   iv,
									   provider);
			QString update = QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( plainText ) ).toByteArray() );
			QVERIFY( forwardCipher.ok() );
			QCOMPARE( update + QCA::arrayToHex( forwardCipher.final().toByteArray() ), cipherText );
			QVERIFY( forwardCipher.ok() );

			QCA::Cipher reverseCipher( QString( "blowfish" ),
									   QCA::Cipher::CFB,
									   QCA::Cipher::NoPadding,
									   QCA::Decode,
									   key,
									   iv,
									   provider);
			QCOMPARE( QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( cipherText ) ).toByteArray() ), plainText  );
			QVERIFY( reverseCipher.ok() );
			QCOMPARE( QCA::arrayToHex( reverseCipher.final().toByteArray() ), QString( "" ) );
			QVERIFY( reverseCipher.ok() );
		}
	}
}

// From the Eric Young test vectors on Bruce's site:
void CipherUnitTest::blowfish_ofb_data()
{
	QTest::addColumn<QString>("plainText");
	QTest::addColumn<QString>("cipherText");
	QTest::addColumn<QString>("keyText");
	QTest::addColumn<QString>("ivText");

	QTest::newRow("1") << QString("37363534333231204e6f77206973207468652074696d6520666f722000")
					   << QString("e73214a2822139ca62b343cc5b65587310dd908d0c241b2263c2cf80da")
					   << QString("0123456789abcdeff0e1d2c3b4a59687")
					   << QString("fedcba9876543210");
}

void CipherUnitTest::blowfish_ofb()
{
	QStringList providersToTest;
	providersToTest.append("qca-ossl");
	providersToTest.append("qca-gcrypt");
	providersToTest.append("qca-botan");

	foreach(const QString provider, providersToTest) {
		if( !QCA::isSupported( "blowfish-ofb", provider ) )
			QWARN( QString( "Blowfish OFB not supported for "+provider).toLocal8Bit() );
		else {
			QFETCH( QString, plainText );
			QFETCH( QString, cipherText );
			QFETCH( QString, keyText );
			QFETCH( QString, ivText );

			QCA::SymmetricKey key( QCA::hexToArray( keyText ) );
			QCA::InitializationVector iv( QCA::hexToArray( ivText ) );
			QCA::Cipher forwardCipher( QString( "blowfish" ),
									   QCA::Cipher::OFB,
									   QCA::Cipher::NoPadding,
									   QCA::Encode,
									   key,
									   iv,
									   provider);
			QString update = QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( plainText ) ).toByteArray() );
			QVERIFY( forwardCipher.ok() );
			QCOMPARE( update + QCA::arrayToHex( forwardCipher.final().toByteArray() ), cipherText );
			QVERIFY( forwardCipher.ok() );

			QCA::Cipher reverseCipher( QString( "blowfish" ),
									   QCA::Cipher::OFB,
									   QCA::Cipher::NoPadding,
									   QCA::Decode,
									   key,
									   iv,
									   provider);

			QCOMPARE( QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( cipherText ) ).toByteArray() ), plainText  );
			QVERIFY( reverseCipher.ok() );
			QCOMPARE( QCA::arrayToHex( reverseCipher.final().toByteArray() ), QString( "" ) );
			QVERIFY( reverseCipher.ok() );
		}
	}
}


// From RFC2144 Appendix B
void CipherUnitTest::cast5_data()
{
	QTest::addColumn<QString>("plainText");
	QTest::addColumn<QString>("cipherText");
	QTest::addColumn<QString>("keyText");

	QTest::newRow("128-bit") << QString("0123456789abcdef")
							 << QString("238b4fe5847e44b2")
							 << QString("0123456712345678234567893456789A");

	QTest::newRow("80-bit") << QString("0123456789abcdef")
							<< QString("eb6a711a2c02271b")
							<< QString("01234567123456782345");

	QTest::newRow("40-bit") << QString("0123456789abcdef")
							<< QString("7ac816d16e9b302e")
							<< QString("0123456712");
}

void CipherUnitTest::cast5()
{
	QStringList providersToTest;
	providersToTest.append("qca-ossl");

	foreach(const QString provider, providersToTest) {
		if( !QCA::isSupported( "cast5-ecb", provider ) )
			QWARN( QString( "CAST5 not supported for "+provider).toLocal8Bit() );
		else {
			QFETCH( QString, plainText );
			QFETCH( QString, cipherText );
			QFETCH( QString, keyText );

			QCA::SymmetricKey key( QCA::hexToArray( keyText ) );
			QCA::InitializationVector iv;
			QCA::Cipher forwardCipher( QString( "cast5" ),
									   QCA::Cipher::ECB,
									   QCA::Cipher::NoPadding,
									   QCA::Encode,
									   key,
									   iv,
									   provider);
			QString update = QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( plainText ) ).toByteArray() );
			QVERIFY( forwardCipher.ok() );
			QCOMPARE( update + QCA::arrayToHex( forwardCipher.final().toByteArray() ), cipherText );
			QVERIFY( forwardCipher.ok() );

			QCA::Cipher reverseCipher( QString( "cast5" ),
									   QCA::Cipher::ECB,
									   QCA::Cipher::NoPadding,
									   QCA::Decode,
									   key,
									   iv,
									   provider);

			QCOMPARE( QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( cipherText ) ).toByteArray() ), plainText  );
			QVERIFY( reverseCipher.ok() );
			QCOMPARE( QCA::arrayToHex( reverseCipher.final().toByteArray() ), QString( "" ) );
			QVERIFY( reverseCipher.ok() );
		}
	}
}



QTEST_MAIN(CipherUnitTest)
