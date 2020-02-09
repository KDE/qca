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

class MACUnitTest : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void initTestCase();
    void cleanupTestCase();
    void HMACMD5();
    void HMACSHA1();
    void HMACSHA256();
    void HMACSHA224();
    void HMACSHA384();
    void HMACSHA512();
    void HMACRMD160();
private:
    QCA::Initializer* m_init;
};


void MACUnitTest::initTestCase()
{
    m_init = new QCA::Initializer;
}

void MACUnitTest::cleanupTestCase()
{
    delete m_init;
}

void MACUnitTest::HMACMD5()
{
    QStringList providersToTest;
    providersToTest.append(QStringLiteral("qca-ossl"));
    providersToTest.append(QStringLiteral("qca-gcrypt"));
    providersToTest.append(QStringLiteral("qca-botan"));
    providersToTest.append(QStringLiteral("qca-nss"));

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "hmac(md5)", provider ) )
            QWARN( (QStringLiteral( "HMAC(MD5) not supported for ")+provider).toLocal8Bit().constData() );
        else {
	    QCA::MessageAuthenticationCode md5hmacLenTest( QStringLiteral("hmac(md5)"), QCA::SymmetricKey(), provider );
	    QCOMPARE( md5hmacLenTest.validKeyLength( 0 ), true );
	    QCOMPARE( md5hmacLenTest.validKeyLength( 1 ), true );
	    QCOMPARE( md5hmacLenTest.validKeyLength( 848888 ), true );
	    QCOMPARE( md5hmacLenTest.validKeyLength( -2 ), false );

	    QCA::MessageAuthenticationCode copy = md5hmacLenTest;
	    copy.context(); // detach

	    // These tests are from RFC2202, Section 2.
	    // The first three are also in the Appendix to RFC2104
	    QCA::MessageAuthenticationCode md5hmac1( QStringLiteral("hmac(md5)"), QCA::SymmetricKey(), provider );
	    QCA::SymmetricKey key1( QCA::SecureArray( "Jefe" ) );
	    md5hmac1.setup( key1 );
	    QCA::SecureArray data1( "what do ya want for nothing?" );
	    md5hmac1.update( data1 );
	    QCOMPARE( QCA::arrayToHex( md5hmac1.final().toByteArray() ), QStringLiteral( "750c783e6ab0b503eaa86e310a5db738" ) );

	    QCA::MessageAuthenticationCode md5hmac2( QStringLiteral("hmac(md5)"), QCA::SymmetricKey(), provider );
	    QCA::SymmetricKey key2( QCA::hexToArray( QStringLiteral("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b") ) );
	    md5hmac2.setup( key2 );
	    QCA::SecureArray data2 = QCA::SecureArray( "Hi There" );
	    md5hmac2.update( data2 );
	    QCOMPARE( QCA::arrayToHex( md5hmac2.final().toByteArray() ), QStringLiteral( "9294727a3638bb1c13f48ef8158bfc9d" ) );

	    // test reuse
	    md5hmac2.clear();
	    QCA::SymmetricKey key3( QCA::hexToArray( QStringLiteral("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") ) );
	    md5hmac2.setup ( key3 );
	    QCA::SecureArray data3( 50 );
	    for ( int i = 0; i < data3.size(); i++ )
		data3[ i ] = (char)0xDD;
	    md5hmac2.update( data3 );
	    QCOMPARE( QCA::arrayToHex( md5hmac2.final().toByteArray() ), QStringLiteral( "56be34521d144c88dbb8c733f0e8b3f6" ) );

	    QCA::SymmetricKey key4( QCA::hexToArray( QStringLiteral("0102030405060708090a0b0c0d0e0f10111213141516171819")) );
	    QCA::MessageAuthenticationCode md5hmac4( QStringLiteral("hmac(md5)"), key4, provider );
	    QCA::SecureArray data4( 50 );
	    for (int i = 0; i < data4.size(); i++ )
		data4[ i ] = (char)0xcd;
	    md5hmac4.update( data4 );
	    QCOMPARE( QCA::arrayToHex( md5hmac4.final().toByteArray() ), QStringLiteral( "697eaf0aca3a3aea3a75164746ffaa79" ) );

	    QCA::MessageAuthenticationCode md5hmac5( QStringLiteral("hmac(md5)"), QCA::SecureArray() );
	    QCA::SymmetricKey key5( QCA::hexToArray( QStringLiteral("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c") ) );
	    md5hmac5.setup( key5 );
	    QCA::SecureArray data5( "Test With Truncation" );
	    md5hmac5.update( data5 );
	    QCOMPARE( QCA::arrayToHex( md5hmac5.final().toByteArray() ), QStringLiteral( "56461ef2342edc00f9bab995690efd4c" ) );

	    QCA::MessageAuthenticationCode md5hmac6( QStringLiteral("hmac(md5)"), QCA::SymmetricKey(), provider );
	    QCA::SymmetricKey key6( 80 );
	    for (int i = 0; i < key6.size(); i++)
		key6[ i ] = (char)0xaa;
	    md5hmac6.setup( key6 );
	    QCA::SecureArray data6( "Test Using Larger Than Block-Size Key - Hash Key First" );
	    md5hmac6.update( data6 );
	    QCOMPARE( QCA::arrayToHex( md5hmac6.final().toByteArray() ), QStringLiteral( "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd" ) );

	    md5hmac6.clear(); // reuse the same key
	    QCA::SecureArray data7( "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data" );
	    md5hmac6.update( data7 );
	    QCOMPARE( QCA::arrayToHex( md5hmac6.final().toByteArray() ), QStringLiteral( "6f630fad67cda0ee1fb1f562db3aa53e" ) );
	}
    }
}


void MACUnitTest::HMACSHA256()
{
    QStringList providersToTest;
    providersToTest.append(QStringLiteral("qca-ossl"));
    providersToTest.append(QStringLiteral("qca-gcrypt"));
    providersToTest.append(QStringLiteral("qca-botan"));
    providersToTest.append(QStringLiteral("qca-nss"));

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "hmac(sha256)", provider ) )
            QWARN( (QStringLiteral( "HMAC(SHA256) not supported for ")+provider).toLocal8Bit().constData() );
        else {
	    QCA::MessageAuthenticationCode hmacLenTest( QStringLiteral("hmac(sha256)"), QCA::SymmetricKey(), provider );
	    QCOMPARE( hmacLenTest.validKeyLength( 0 ), true );
	    QCOMPARE( hmacLenTest.validKeyLength( 1 ), true );
	    QCOMPARE( hmacLenTest.validKeyLength( 848888 ), true );
	    QCOMPARE( hmacLenTest.validKeyLength( -2 ), false );

	    QCA::MessageAuthenticationCode copy = hmacLenTest;
	    copy.context(); // detach

	    QCA::MessageAuthenticationCode hmac1( QStringLiteral("hmac(sha256)"), QCA::SymmetricKey(), provider );
	    QCA::SymmetricKey key1( QCA::SecureArray( "Jefe" ) );
	    hmac1.setup( key1 );
	    QCA::SecureArray data1( "what do ya want for nothing?" );
	    hmac1.update( data1 );
	    QCOMPARE( QCA::arrayToHex( hmac1.final().toByteArray() ),
		      QStringLiteral( "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843" ) );

	    QCA::MessageAuthenticationCode hmac2( QStringLiteral("hmac(sha256)"), QCA::SymmetricKey(), provider );
	    QCA::SymmetricKey key2( QCA::hexToArray( QStringLiteral("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b") ) );
	    hmac2.setup( key2 );
	    QCA::SecureArray data2 = QCA::SecureArray( "Hi There" );
	    hmac2.update( data2 );
	    QCOMPARE( QCA::arrayToHex( hmac2.final().toByteArray() ),
		      QStringLiteral( "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7" ) );

	    // test reuse
	    hmac2.clear();
	    QCA::SymmetricKey key3( QCA::hexToArray( QStringLiteral("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") ) );
	    hmac2.setup ( key3 );
	    QCA::SecureArray data3( 50 );
	    for ( int i = 0; i < data3.size(); i++ )
		data3[ i ] = (char)0xDD;
	    hmac2.update( data3 );
	    QCOMPARE( QCA::arrayToHex( hmac2.final().toByteArray() ),
		      QStringLiteral( "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe" ) );

	    QCA::SymmetricKey key4( QCA::hexToArray( QStringLiteral("0102030405060708090a0b0c0d0e0f10111213141516171819")) );
	    QCA::MessageAuthenticationCode hmac4( QStringLiteral("hmac(sha256)"), key4, provider );
	    QCA::SecureArray data4( 50 );
	    for (int i = 0; i < data4.size(); i++ )
		data4[ i ] = (char)0xcd;
	    hmac4.update( data4 );
	    QCOMPARE( QCA::arrayToHex( hmac4.final().toByteArray() ),
		      QStringLiteral( "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b" ) );

	    QCA::MessageAuthenticationCode hmac5( QStringLiteral("hmac(sha256)"), QCA::SymmetricKey(), provider );
	    QCA::SymmetricKey key5( QCA::hexToArray( QStringLiteral("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c") ) );
	    hmac5.setup( key5 );
	    QCA::SecureArray data5( "Test With Truncation" );
	    hmac5.update( data5 );
	    QString resultWithTrunc = QCA::arrayToHex( hmac5.final().toByteArray() );
	    resultWithTrunc.resize(32);
	    QCOMPARE( resultWithTrunc, QStringLiteral( "a3b6167473100ee06e0c796c2955552b" ) );

	    QCA::MessageAuthenticationCode hmac6( QStringLiteral("hmac(sha256)"), QCA::SymmetricKey(), provider );
	    QCA::SymmetricKey key6( 131 );
	    for (int i = 0; i < key6.size(); i++)
		key6[ i ] = (char)0xaa;
	    hmac6.setup( key6 );
	    QCA::SecureArray data6( "Test Using Larger Than Block-Size Key - Hash Key First" );
	    hmac6.update( data6 );
	    QCOMPARE( QCA::arrayToHex( hmac6.final().toByteArray() ),
		      QStringLiteral( "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54" ) );

	    hmac6.clear(); // reuse the same key
	    QCA::SecureArray data7( "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm." );
	    hmac6.update( data7 );
	    QCOMPARE( QCA::arrayToHex( hmac6.final().toByteArray() ),
		      QStringLiteral( "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2" ) );
	}
    }
}

void MACUnitTest::HMACSHA224()
{
    QStringList providersToTest;
    providersToTest.append(QStringLiteral("qca-ossl"));
    providersToTest.append(QStringLiteral("qca-gcrypt"));
    providersToTest.append(QStringLiteral("qca-botan"));

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "hmac(sha224)", provider ) )
            QWARN( (QStringLiteral( "HMAC(SHA224) not supported for ")+provider).toLocal8Bit().constData() );
        else {
	    QCA::MessageAuthenticationCode hmacLenTest( QStringLiteral("hmac(sha224)"), QCA::SymmetricKey(), provider );
	    QCOMPARE( hmacLenTest.validKeyLength( 0 ), true );
	    QCOMPARE( hmacLenTest.validKeyLength( 1 ), true );
	    QCOMPARE( hmacLenTest.validKeyLength( 848888 ), true );
	    QCOMPARE( hmacLenTest.validKeyLength( -2 ), false );

	    QCA::MessageAuthenticationCode copy = hmacLenTest;
	    copy.context(); // detach

	    QCA::MessageAuthenticationCode hmac1( QStringLiteral("hmac(sha224)"), QCA::SymmetricKey(), provider );
	    QCA::SymmetricKey key1( QCA::SecureArray( "Jefe" ) );
	    hmac1.setup( key1 );
	    QCA::SecureArray data1( "what do ya want for nothing?" );
	    hmac1.update( data1 );
	    QCOMPARE( QCA::arrayToHex( hmac1.final().toByteArray() ),
		      QStringLiteral( "a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44" ) );

	    QCA::MessageAuthenticationCode hmac2( QStringLiteral("hmac(sha224)"), QCA::SymmetricKey(), provider );
	    QCA::SymmetricKey key2( QCA::hexToArray( QStringLiteral("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b") ) );
	    hmac2.setup( key2 );
	    QCA::SecureArray data2 = QCA::SecureArray( "Hi There" );
	    hmac2.update( data2 );
	    QCOMPARE( QCA::arrayToHex( hmac2.final().toByteArray() ),
		      QStringLiteral( "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22" ) );

	    // test reuse
	    hmac2.clear();
	    QCA::SymmetricKey key3( QCA::hexToArray( QStringLiteral("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") ) );
	    hmac2.setup ( key3 );
	    QCA::SecureArray data3( 50 );
	    for ( int i = 0; i < data3.size(); i++ )
		data3[ i ] = (char)0xDD;
	    hmac2.update( data3 );
	    QCOMPARE( QCA::arrayToHex( hmac2.final().toByteArray() ),
		      QStringLiteral( "7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea" ) );

	    QCA::SymmetricKey key4( QCA::hexToArray( QStringLiteral("0102030405060708090a0b0c0d0e0f10111213141516171819")) );
	    QCA::MessageAuthenticationCode hmac4( QStringLiteral("hmac(sha224)"), key4, provider );
	    QCA::SecureArray data4( 50 );
	    for (int i = 0; i < data4.size(); i++ )
		data4[ i ] = (char)0xcd;
	    hmac4.update( data4 );
	    QCOMPARE( QCA::arrayToHex( hmac4.final().toByteArray() ),
		      QStringLiteral( "6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a" ) );

	    QCA::MessageAuthenticationCode hmac5( QStringLiteral("hmac(sha224)"), QCA::SymmetricKey(), provider );
	    QCA::SymmetricKey key5( QCA::hexToArray( QStringLiteral("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c") ) );
	    hmac5.setup( key5 );
	    QCA::SecureArray data5( "Test With Truncation" );
	    hmac5.update( data5 );
	    QString resultWithTrunc = QCA::arrayToHex( hmac5.final().toByteArray() );
	    resultWithTrunc.resize(32);
	    QCOMPARE( resultWithTrunc, QStringLiteral( "0e2aea68a90c8d37c988bcdb9fca6fa8" ) );

	    QCA::MessageAuthenticationCode hmac6( QStringLiteral("hmac(sha224)"), QCA::SymmetricKey(), provider );
	    QCA::SymmetricKey key6( 131 );
	    for (int i = 0; i < key6.size(); i++)
		key6[ i ] = (char)0xaa;
	    hmac6.setup( key6 );
	    QCA::SecureArray data6( "Test Using Larger Than Block-Size Key - Hash Key First" );
	    hmac6.update( data6 );
	    QCOMPARE( QCA::arrayToHex( hmac6.final().toByteArray() ),
		      QStringLiteral( "95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e" ) );

	    hmac6.clear(); // reuse the same key
	    QCA::SecureArray data7( "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm." );
	    hmac6.update( data7 );
	    QCOMPARE( QCA::arrayToHex( hmac6.final().toByteArray() ),
		      QStringLiteral( "3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1" ) );
	}
    }
}

void MACUnitTest::HMACSHA384()
{
    QStringList providersToTest;
    providersToTest.append(QStringLiteral("qca-ossl"));
    providersToTest.append(QStringLiteral("qca-gcrypt"));
    providersToTest.append(QStringLiteral("qca-botan"));
    providersToTest.append(QStringLiteral("qca-nss"));

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "hmac(sha384)", provider ) )
            QWARN( (QStringLiteral( "HMAC(SHA384) not supported for ")+provider).toLocal8Bit().constData() );
        else {
	    QCA::MessageAuthenticationCode hmacLenTest( QStringLiteral("hmac(sha384)"), QCA::SymmetricKey(), provider );
	    QCOMPARE( hmacLenTest.validKeyLength( 0 ), true );
	    QCOMPARE( hmacLenTest.validKeyLength( 1 ), true );
	    QCOMPARE( hmacLenTest.validKeyLength( 848888 ), true );
	    QCOMPARE( hmacLenTest.validKeyLength( -2 ), false );

	    QCA::MessageAuthenticationCode copy = hmacLenTest;
	    copy.context(); // detach

	    QCA::MessageAuthenticationCode hmac1( QStringLiteral("hmac(sha384)"), QCA::SymmetricKey(), provider );
	    QCA::SymmetricKey key1( QCA::SecureArray( "Jefe" ) );
	    hmac1.setup( key1 );
	    QCA::SecureArray data1( "what do ya want for nothing?" );
	    hmac1.update( data1 );
	    QCOMPARE( QCA::arrayToHex( hmac1.final().toByteArray() ),
		      QStringLiteral( "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649" ) );

	    QCA::MessageAuthenticationCode hmac2( QStringLiteral("hmac(sha384)"), QCA::SymmetricKey(), provider );
	    QCA::SymmetricKey key2( QCA::hexToArray( QStringLiteral("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b") ) );
	    hmac2.setup( key2 );
	    QCA::SecureArray data2 = QCA::SecureArray( "Hi There" );
	    hmac2.update( data2 );
	    QCOMPARE( QCA::arrayToHex( hmac2.final().toByteArray() ),
		      QStringLiteral( "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6" ) );

	    // test reuse
	    hmac2.clear();
	    QCA::SymmetricKey key3( QCA::hexToArray( QStringLiteral("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") ) );
	    hmac2.setup ( key3 );
	    QCA::SecureArray data3( 50 );
	    for ( int i = 0; i < data3.size(); i++ )
		data3[ i ] = (char)0xDD;
	    hmac2.update( data3 );
	    QCOMPARE( QCA::arrayToHex( hmac2.final().toByteArray() ),
		      QStringLiteral( "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27" ) );

	    QCA::SymmetricKey key4( QCA::hexToArray( QStringLiteral("0102030405060708090a0b0c0d0e0f10111213141516171819")) );
	    QCA::MessageAuthenticationCode hmac4( QStringLiteral("hmac(sha384)"), key4, provider );
	    QCA::SecureArray data4( 50 );
	    for (int i = 0; i < data4.size(); i++ )
		data4[ i ] = (char)0xcd;
	    hmac4.update( data4 );
	    QCOMPARE( QCA::arrayToHex( hmac4.final().toByteArray() ),
		      QStringLiteral( "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb" ) );

	    QCA::MessageAuthenticationCode hmac5( QStringLiteral("hmac(sha384)"), QCA::SecureArray(), provider );
	    QCA::SymmetricKey key5( QCA::hexToArray( QStringLiteral("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c") ) );
	    hmac5.setup( key5 );
	    QCA::SecureArray data5( "Test With Truncation" );
	    hmac5.update( data5 );
	    QString resultWithTrunc = QCA::arrayToHex( hmac5.final().toByteArray() );
	    resultWithTrunc.resize(32);
	    QCOMPARE( resultWithTrunc, QStringLiteral( "3abf34c3503b2a23a46efc619baef897" ) );

	    QCA::MessageAuthenticationCode hmac6( QStringLiteral("hmac(sha384)"), QCA::SymmetricKey(), provider );
	    QCA::SymmetricKey key6( 131 );
	    for (int i = 0; i < key6.size(); i++)
		key6[ i ] = (char)0xaa;
	    hmac6.setup( key6 );
	    QCA::SecureArray data6( "Test Using Larger Than Block-Size Key - Hash Key First" );
	    hmac6.update( data6 );
	    QCOMPARE( QCA::arrayToHex( hmac6.final().toByteArray() ),
		      QStringLiteral( "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952" ) );

	    hmac6.clear(); // reuse the same key
	    QCA::SecureArray data7( "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm." );
	    hmac6.update( data7 );
	    QCOMPARE( QCA::arrayToHex( hmac6.final().toByteArray() ),
		      QStringLiteral( "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e" ) );
	}
    }
}

void MACUnitTest::HMACSHA512()
{
    QStringList providersToTest;
    providersToTest.append(QStringLiteral("qca-ossl"));
    providersToTest.append(QStringLiteral("qca-gcrypt"));
    providersToTest.append(QStringLiteral("qca-botan"));
    providersToTest.append(QStringLiteral("qca-nss"));

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "hmac(sha512)", provider ) )
            QWARN( (QStringLiteral( "HMAC(SHA512) not supported for ")+provider).toLocal8Bit().constData() );
        else {
	    QCA::MessageAuthenticationCode hmacLenTest( QStringLiteral("hmac(sha512)"), QCA::SymmetricKey(), provider );
	    QCOMPARE( hmacLenTest.validKeyLength( 0 ), true );
	    QCOMPARE( hmacLenTest.validKeyLength( 1 ), true );
	    QCOMPARE( hmacLenTest.validKeyLength( 848888 ), true );
	    QCOMPARE( hmacLenTest.validKeyLength( -2 ), false );

	    QCA::MessageAuthenticationCode copy = hmacLenTest;
	    copy.context(); // detach

	    QCA::MessageAuthenticationCode hmac1( QStringLiteral("hmac(sha512)"), QCA::SymmetricKey(), provider );
	    QCA::SymmetricKey key1( QCA::SecureArray( "Jefe" ) );
	    hmac1.setup( key1 );
	    QCA::SecureArray data1( "what do ya want for nothing?" );
	    hmac1.update( data1 );
	    QCOMPARE( QCA::arrayToHex( hmac1.final().toByteArray() ),
		      QStringLiteral( "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737" ) );

	    QCA::MessageAuthenticationCode hmac2( QStringLiteral("hmac(sha512)"), QCA::SymmetricKey(), provider );
	    QCA::SymmetricKey key2( QCA::hexToArray( QStringLiteral("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b") ) );
	    hmac2.setup( key2 );
	    QCA::SecureArray data2 = QCA::SecureArray( "Hi There" );
	    hmac2.update( data2 );
	    QCOMPARE( QCA::arrayToHex( hmac2.final().toByteArray() ),
		      QStringLiteral( "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854" ) );

	    // test reuse
	    hmac2.clear();
	    QCA::SymmetricKey key3( QCA::hexToArray( QStringLiteral("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") ) );
	    hmac2.setup ( key3 );
	    QCA::SecureArray data3( 50 );
	    for ( int i = 0; i < data3.size(); i++ )
		data3[ i ] = (char)0xDD;
	    hmac2.update( data3 );
	    QCOMPARE( QCA::arrayToHex( hmac2.final().toByteArray() ),
		      QStringLiteral( "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb" ) );

	    QCA::SymmetricKey key4( QCA::hexToArray( QStringLiteral("0102030405060708090a0b0c0d0e0f10111213141516171819")) );
	    QCA::MessageAuthenticationCode hmac4( QStringLiteral("hmac(sha512)"), key4, provider );
	    QCA::SecureArray data4( 50 );
	    for (int i = 0; i < data4.size(); i++ )
		data4[ i ] = (char)0xcd;
	    hmac4.update( data4 );
	    QCOMPARE( QCA::arrayToHex( hmac4.final().toByteArray() ),
		      QStringLiteral( "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd" ) );

	    QCA::MessageAuthenticationCode hmac5( QStringLiteral("hmac(sha512)"), QCA::SecureArray(), provider );
	    QCA::SymmetricKey key5( QCA::hexToArray( QStringLiteral("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c") ) );
	    hmac5.setup( key5 );
	    QCA::SecureArray data5( "Test With Truncation" );
	    hmac5.update( data5 );
	    QString resultWithTrunc = QCA::arrayToHex( hmac5.final().toByteArray() );
	    resultWithTrunc.resize(32);
	    QCOMPARE( resultWithTrunc, QStringLiteral( "415fad6271580a531d4179bc891d87a6" ) );

	    QCA::MessageAuthenticationCode hmac6( QStringLiteral("hmac(sha512)"), QCA::SymmetricKey(), provider );
	    QCA::SymmetricKey key6( 131 );
	    for (int i = 0; i < key6.size(); i++)
		key6[ i ] = (char)0xaa;
	    hmac6.setup( key6 );
	    QCA::SecureArray data6( "Test Using Larger Than Block-Size Key - Hash Key First" );
	    hmac6.update( data6 );
	    QCOMPARE( QCA::arrayToHex( hmac6.final().toByteArray() ),
		      QStringLiteral( "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598" ) );

	    hmac6.clear(); // reuse the same key
	    QCA::SecureArray data7( "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm." );
	    hmac6.update( data7 );
	    QCOMPARE( QCA::arrayToHex( hmac6.final().toByteArray() ),
		      QStringLiteral( "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58" ) );
	}
    }
}

void MACUnitTest::HMACSHA1()
{
    QStringList providersToTest;
    providersToTest.append(QStringLiteral("qca-ossl"));
    providersToTest.append(QStringLiteral("qca-gcrypt"));
    providersToTest.append(QStringLiteral("qca-botan"));
    providersToTest.append(QStringLiteral("qca-nss"));

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "hmac(sha1)", provider ) )
            QWARN( (QStringLiteral( "HMAC(SHA1) not supported for ")+provider).toLocal8Bit().constData() );
        else {
	    QCA::MessageAuthenticationCode sha1hmacLenTest( QStringLiteral("hmac(sha1)"), QCA::SymmetricKey(), provider );
	    QCOMPARE( sha1hmacLenTest.validKeyLength( 0 ), true );
	    QCOMPARE( sha1hmacLenTest.validKeyLength( 1 ), true );
	    QCOMPARE( sha1hmacLenTest.validKeyLength( 848888 ), true );
	    QCOMPARE( sha1hmacLenTest.validKeyLength( -2 ), false );

	    QCA::MessageAuthenticationCode copy = sha1hmacLenTest;
	    copy.context(); // detach

	    // These tests are from RFC2202, Section 3.
	    QCA::MessageAuthenticationCode test1( QStringLiteral("hmac(sha1)"), QCA::SecureArray() );
	    QCA::SymmetricKey key1( QCA::hexToArray( QStringLiteral("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b") ) );
	    test1.setup( key1 );
	    QCA::SecureArray data1( "Hi There" );
	    test1.update( data1 );
	    QCOMPARE( QCA::arrayToHex( test1.final().toByteArray() ), QStringLiteral( "b617318655057264e28bc0b6fb378c8ef146be00" ) );

	    QCA::MessageAuthenticationCode test2( QStringLiteral("hmac(sha1)"), QCA::SymmetricKey(), provider);
	    QCA::SymmetricKey key2( QCA::SecureArray( "Jefe" ) );
	    test2.setup( key2 );
	    QCA::SecureArray data2( "what do ya want for nothing?" );
	    test2.update( data2 );
	    QCOMPARE( QCA::arrayToHex( test2.final().toByteArray() ), QStringLiteral( "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79" ) );

	    QCA::MessageAuthenticationCode test3( QStringLiteral("hmac(sha1)"), QCA::SymmetricKey(), provider);
	    QCA::SymmetricKey key3( QCA::hexToArray( QStringLiteral("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") ) );
	    test3.setup( key3 );
	    QCA::SecureArray data3( 50 );
	    for ( int i = 0; i < data3.size(); i++ )
		data3[ i ] = (char)0xDD;
	    test3.update( data3 );
	    QCOMPARE( QCA::arrayToHex( test3.final().toByteArray() ), QStringLiteral( "125d7342b9ac11cd91a39af48aa17b4f63f175d3" ) );

	    QCA::MessageAuthenticationCode test4( QStringLiteral("hmac(sha1)"), QCA::SymmetricKey(), provider);
	    QCA::SymmetricKey key4( QCA::hexToArray( QStringLiteral("0102030405060708090a0b0c0d0e0f10111213141516171819") ) );
	    test4.setup( key4 );
	    QCA::SecureArray data4( 50 );
	    for ( int i = 0; i < data4.size(); i++ )
		data4[ i ] = (char)0xcd;
	    test4.update( data4 );
	    QCOMPARE( QCA::arrayToHex( test4.final().toByteArray() ), QStringLiteral( "4c9007f4026250c6bc8414f9bf50c86c2d7235da" ) );

	    QCA::MessageAuthenticationCode test5( QStringLiteral("hmac(sha1)"), QCA::SymmetricKey(), provider);
	    QCA::SymmetricKey key5 ( QCA::hexToArray( QStringLiteral("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c") ) );
	    test5.setup( key5 );
	    QCA::SecureArray data5( "Test With Truncation" );
	    test5.update( data5 );
	    QCOMPARE( QCA::arrayToHex( test5.final().toByteArray() ), QStringLiteral( "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04" ) );

	    QCA::MessageAuthenticationCode test6( QStringLiteral("hmac(sha1)"), QCA::SymmetricKey(), provider);
	    QCA::SymmetricKey key6( 80 );
	    for ( int i = 0; i < key6.size(); i++ )
		key6[i] = (char)0xAA;
	    test6.setup( key6 );
	    QCA::SecureArray data6( "Test Using Larger Than Block-Size Key - Hash Key First" );
	    test6.update( data6 );
	    QCOMPARE( QCA::arrayToHex( test6.final().toByteArray() ), QStringLiteral( "aa4ae5e15272d00e95705637ce8a3b55ed402112" ) );

	    test6.clear(); // this should reuse the same key
	    QCA::SecureArray data7( "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data" );
	    test6.update( data7 );
	    QCOMPARE( QCA::arrayToHex( test6.final().toByteArray() ), QStringLiteral( "e8e99d0f45237d786d6bbaa7965c7808bbff1a91" ) );
	}
    }
}

void MACUnitTest::HMACRMD160()
{
    QStringList providersToTest;
    providersToTest.append(QStringLiteral("qca-ossl"));
    providersToTest.append(QStringLiteral("qca-gcrypt"));
    providersToTest.append(QStringLiteral("qca-botan"));
    providersToTest.append(QStringLiteral("qca-nss"));

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "hmac(ripemd160)", provider ) )
            QWARN( (QStringLiteral( "HMAC(RIPEMD160) not supported for ")+provider).toLocal8Bit().constData() );
        else {
	    QCA::MessageAuthenticationCode ripemd160hmacLenTest( QStringLiteral("hmac(ripemd160)"), QCA::SymmetricKey(), provider );
	    QCOMPARE( ripemd160hmacLenTest.validKeyLength( 0 ), true );
	    QCOMPARE( ripemd160hmacLenTest.validKeyLength( 1 ), true );
	    QCOMPARE( ripemd160hmacLenTest.validKeyLength( 848888 ), true );
	    QCOMPARE( ripemd160hmacLenTest.validKeyLength( -2 ), false );

	    QCA::MessageAuthenticationCode copy = ripemd160hmacLenTest;
	    copy.context(); // detach

	    // These tests are from RFC2286, Section 2.
	    QCA::MessageAuthenticationCode test1( QStringLiteral("hmac(ripemd160)"), QCA::SymmetricKey(), provider );
	    QCA::SymmetricKey key1 ( QCA::hexToArray( QStringLiteral("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b") ) );
	    test1.setup( key1 );
	    QCA::SecureArray data1( "Hi There" );
	    test1.update( data1 );
	    QCOMPARE( QCA::arrayToHex( test1.final().toByteArray() ), QStringLiteral( "24cb4bd67d20fc1a5d2ed7732dcc39377f0a5668" ) );

	    QCA::MessageAuthenticationCode test2( QStringLiteral("hmac(ripemd160)"), QCA::SymmetricKey(), provider );
	    QCA::SymmetricKey key2( QCA::SecureArray( "Jefe" ) );
	    test2.setup( key2 );
	    QCA::SecureArray data2( "what do ya want for nothing?" );
	    test2.update( data2 );
	    QCOMPARE( QCA::arrayToHex( test2.final().toByteArray() ), QStringLiteral( "dda6c0213a485a9e24f4742064a7f033b43c4069" ) );

	    QCA::MessageAuthenticationCode test3( QStringLiteral("hmac(ripemd160)"), QCA::SymmetricKey(), provider );
	    QCA::SymmetricKey key3( QCA::hexToArray( QStringLiteral("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") ) );
	    test3.setup( key3 );
	    QCA::SecureArray data3( 50 );
	    for ( int i = 0; i < data3.size(); i++ )
		data3[ i ] = (char)0xDD;
	    test3.update( data3 );
	    QCOMPARE( QCA::arrayToHex( test3.final().toByteArray() ), QStringLiteral( "b0b105360de759960ab4f35298e116e295d8e7c1" ) );

	    QCA::SymmetricKey key4( QCA::hexToArray( QStringLiteral("0102030405060708090a0b0c0d0e0f10111213141516171819") ) );
	    QCA::MessageAuthenticationCode test4( QStringLiteral("hmac(ripemd160)"), key4, provider );
	    QCA::SecureArray data4( 50 );
	    for ( int i = 0; i < data4.size(); i++ )
		data4[ i ] = (char)0xcd;
	    test4.update( data4 );
	    QCOMPARE( QCA::arrayToHex( test4.final().toByteArray() ), QStringLiteral( "d5ca862f4d21d5e610e18b4cf1beb97a4365ecf4" ) );

	    QCA::MessageAuthenticationCode test5( QStringLiteral("hmac(ripemd160)"), QCA::SymmetricKey(), provider );
	    QCA::SymmetricKey key5 ( QCA::hexToArray( QStringLiteral("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c") ) );
	    test5.setup( key5 );
	    QCA::SecureArray data5( "Test With Truncation" );
	    test5.update( data5 );
	    QCOMPARE( QCA::arrayToHex( test5.final().toByteArray() ), QStringLiteral( "7619693978f91d90539ae786500ff3d8e0518e39" ) );

	    QCA::MessageAuthenticationCode test6( QStringLiteral("hmac(ripemd160)"), QCA::SymmetricKey(), provider );
	    QCA::SymmetricKey key6( 80 );
	    for ( int i = 0; i < key6.size(); i++ )
		key6[i] = (char)0xAA;
	    test6.setup( key6 );
	    QCA::SecureArray data6( "Test Using Larger Than Block-Size Key - Hash Key First" );
	    test6.update( data6 );
	    QCOMPARE( QCA::arrayToHex( test6.final().toByteArray() ), QStringLiteral( "6466ca07ac5eac29e1bd523e5ada7605b791fd8b" ) );

	    test6.clear(); // reuse the key
	    QCA::SecureArray data7( "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data" );
	    test6.update( data7 );
	    QCOMPARE( QCA::arrayToHex( test6.final().toByteArray() ), QStringLiteral( "69ea60798d71616cce5fd0871e23754cd75d5a0a" ) );
	}
    }
}

QTEST_MAIN(MACUnitTest)

#include "macunittest.moc"



