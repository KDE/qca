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
#include "macunittest.h"
#include <QtCrypto>
#include <iostream>

MACUnitTest::MACUnitTest()
    : Tester()
{

}

void MACUnitTest::allTests()
{
    QCA::Initializer init;

    QCString macResult; // used as the actual result

    if(!QCA::isSupported("hmac(md5)"))
	SKIP("HMAC(MD5) not supported!");
    else {
	QCA::HMAC md5hmacLenTest( "md5" );
	CHECK( md5hmacLenTest.validKeyLength( 0 ), true );
	CHECK( md5hmacLenTest.validKeyLength( 1 ), true );
	CHECK( md5hmacLenTest.validKeyLength( 848888 ), true );
	CHECK( md5hmacLenTest.validKeyLength( -2 ), false );

	// These tests are from RFC2202, Section 2.
	// The first three are also in the Appendix to RFC2104
	QCA::HMAC md5hmac1( "md5" );
	QCA::SymmetricKey key1( QCString( "Jefe" ) );
	md5hmac1.setup( key1 );
	QSecureArray data1 = QCString( "what do ya want for nothing?" );
	md5hmac1.update( data1 );
	CHECK( QCA::arrayToHex( md5hmac1.final() ), QString( "750c783e6ab0b503eaa86e310a5db738" ) );

	QCA::HMAC md5hmac2( "md5" );
	QCA::SymmetricKey key2( QCA::hexToArray( "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" ) );
	md5hmac2.setup( key2 );
	QSecureArray data2 = QCString( "Hi There" );
	md5hmac2.update( data2 );
	CHECK( QCA::arrayToHex( md5hmac2.final() ), QString( "9294727a3638bb1c13f48ef8158bfc9d" ) );

	// test reuse
	md5hmac2.clear();
	QCA::SymmetricKey key3( QCA::hexToArray( "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ) );
	md5hmac2.setup ( key3 );
	QSecureArray data3( 50 );
	for (unsigned int i = 0; i < data3.size(); i++ )
	    data3[ i ] = 0xDD;
	md5hmac2.update( data3 );
	CHECK( QCA::arrayToHex( md5hmac2.final() ), QString( "56be34521d144c88dbb8c733f0e8b3f6" ) );

	QCA::SymmetricKey key4 ( QCA::hexToArray( "0102030405060708090a0b0c0d0e0f10111213141516171819") );
	QCA::HMAC md5hmac4( "md5", key4 );
	QSecureArray data4( 50 );
	for (unsigned int i = 0; i < data4.size(); i++ )
	    data4[ i ] = 0xcd;
	md5hmac4.update( data4 );
	CHECK( QCA::arrayToHex( md5hmac4.final() ), QString( "697eaf0aca3a3aea3a75164746ffaa79" ) );

	QCA::HMAC md5hmac5( "md5" );
	QCA::SymmetricKey key5 ( QCA::hexToArray( "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c" ) );
	md5hmac5.setup( key5 );
	QSecureArray data5 = QCString( "Test With Truncation" );
    	md5hmac5.update( data5 );
	CHECK( QCA::arrayToHex( md5hmac5.final() ), QString( "56461ef2342edc00f9bab995690efd4c" ) );

	QCA::HMAC md5hmac6( "md5" );
	QCA::SymmetricKey key6( 80 );
	for (unsigned int i = 0; i < key6.size(); i++)
	    key6[ i ] = 0xaa;
	md5hmac6.setup( key6 );
	QSecureArray data6 = QCString( "Test Using Larger Than Block-Size Key - Hash Key First" );
    	md5hmac6.update( data6 );
	CHECK( QCA::arrayToHex( md5hmac6.final() ), QString( "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd" ) );

	md5hmac6.clear(); // reuse the same key
	QSecureArray data7 = QCString( "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data" );
    	md5hmac6.update( data7 );
	CHECK( QCA::arrayToHex( md5hmac6.final() ), QString( "6f630fad67cda0ee1fb1f562db3aa53e" ) );
    }

    if(!QCA::isSupported("hmac(sha1)"))
	SKIP("HMAC(SHA1) not supported!");
    else {
	QCA::HMAC sha1hmacLenTest( "sha1" );
	CHECK( sha1hmacLenTest.validKeyLength( 0 ), true );
	CHECK( sha1hmacLenTest.validKeyLength( 1 ), true );
	CHECK( sha1hmacLenTest.validKeyLength( 848888 ), true );
	CHECK( sha1hmacLenTest.validKeyLength( -2 ), false );

	// These tests are from RFC2202, Section 3.
	QCA::HMAC test1; // should be default
	QCA::SymmetricKey key1 ( QCA::hexToArray( "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" ) );
	test1.setup( key1 );
	QSecureArray data1 = QCString( "Hi There" );
    	test1.update( data1 );
	CHECK( QCA::arrayToHex( test1.final() ), QString( "b617318655057264e28bc0b6fb378c8ef146be00" ) );

	QCA::HMAC test2( "sha1");
	QCA::SymmetricKey key2( QCString( "Jefe" ) );
	test2.setup( key2 );
	QSecureArray data2 = QCString( "what do ya want for nothing?" );
    	test2.update( data2 );
	CHECK( QCA::arrayToHex( test2.final() ), QString( "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79" ) );

	QCA::HMAC test3;
	QCA::SymmetricKey key3( QCA::hexToArray( "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ) );
	test3.setup( key3 );
	QSecureArray data3( 50 );
	for ( unsigned int i = 0; i < data3.size(); i++ )
	    data3[ i ] = 0xDD;
	test3.update( data3 );
	CHECK( QCA::arrayToHex( test3.final() ), QString( "125d7342b9ac11cd91a39af48aa17b4f63f175d3" ) );

	QCA::HMAC test4;
	QCA::SymmetricKey key4( QCA::hexToArray( "0102030405060708090a0b0c0d0e0f10111213141516171819" ) );
	test4.setup( key4 );
	QSecureArray data4( 50 );
	for ( unsigned int i = 0; i < data4.size(); i++ )
	    data4[ i ] = 0xcd;
	test4.update( data4 );
	CHECK( QCA::arrayToHex( test4.final() ), QString( "4c9007f4026250c6bc8414f9bf50c86c2d7235da" ) );

	QCA::HMAC test5; // should be default
	QCA::SymmetricKey key5 ( QCA::hexToArray( "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c" ) );
	test5.setup( key5 );
	QSecureArray data5 = QCString( "Test With Truncation" );
    	test5.update( data5 );
	CHECK( QCA::arrayToHex( test5.final() ), QString( "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04" ) );

	QCA::HMAC test6; // should be default
	QCA::SymmetricKey key6( 80 );
	for ( unsigned int i = 0; i < key6.size(); i++ )
	    key6[i] = 0xAA;
	test6.setup( key6 );
	QSecureArray data6 = QCString( "Test Using Larger Than Block-Size Key - Hash Key First" );
    	test6.update( data6 );
	CHECK( QCA::arrayToHex( test6.final() ), QString( "aa4ae5e15272d00e95705637ce8a3b55ed402112" ) );

	test6.clear(); // this should reuse the same key
	QSecureArray data7 = QCString( "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data" );
    	test6.update( data7 );
	CHECK( QCA::arrayToHex( test6.final() ), QString( "e8e99d0f45237d786d6bbaa7965c7808bbff1a91" ) );

    }

    if(!QCA::isSupported("hmac(ripemd160)"))
	SKIP("HMAC(RIPEMD160) not supported!");
    else {
	QCA::HMAC ripemd160hmacLenTest( "ripemd160" );
	CHECK( ripemd160hmacLenTest.validKeyLength( 0 ), true );
	CHECK( ripemd160hmacLenTest.validKeyLength( 1 ), true );
	CHECK( ripemd160hmacLenTest.validKeyLength( 848888 ), true );
	CHECK( ripemd160hmacLenTest.validKeyLength( -2 ), false );

	// These tests are from RFC2286, Section 2.
	QCA::HMAC test1( "ripemd160" ); 
	QCA::SymmetricKey key1 ( QCA::hexToArray( "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" ) );
	test1.setup( key1 );
	QSecureArray data1 = QCString( "Hi There" );
    	test1.update( data1 );
	CHECK( QCA::arrayToHex( test1.final() ), QString( "24cb4bd67d20fc1a5d2ed7732dcc39377f0a5668" ) );

	QCA::HMAC test2( "ripemd160" ); 
	QCA::SymmetricKey key2( QCString( "Jefe" ) );
	test2.setup( key2 );
	QSecureArray data2 = QCString( "what do ya want for nothing?" );
    	test2.update( data2 );
	CHECK( QCA::arrayToHex( test2.final() ), QString( "dda6c0213a485a9e24f4742064a7f033b43c4069" ) );

	QCA::HMAC test3( "ripemd160" );
	QCA::SymmetricKey key3( QCA::hexToArray( "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ) );
	test3.setup( key3 );
	QSecureArray data3( 50 );
	for ( unsigned int i = 0; i < data3.size(); i++ )
	    data3[ i ] = 0xDD;
	test3.update( data3 );
	CHECK( QCA::arrayToHex( test3.final() ), QString( "b0b105360de759960ab4f35298e116e295d8e7c1" ) );

	QCA::SymmetricKey key4( QCA::hexToArray( "0102030405060708090a0b0c0d0e0f10111213141516171819" ) );
	QCA::HMAC test4( "ripemd160", key4 );
	QSecureArray data4( 50 );
	for ( unsigned int i = 0; i < data4.size(); i++ )
	    data4[ i ] = 0xcd;
	test4.update( data4 );
	CHECK( QCA::arrayToHex( test4.final() ), QString( "d5ca862f4d21d5e610e18b4cf1beb97a4365ecf4" ) );

	QCA::HMAC test5( "ripemd160" );
	QCA::SymmetricKey key5 ( QCA::hexToArray( "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c" ) );
	test5.setup( key5 );
	QSecureArray data5 = QCString( "Test With Truncation" );
    	test5.update( data5 );
	CHECK( QCA::arrayToHex( test5.final() ), QString( "7619693978f91d90539ae786500ff3d8e0518e39" ) );

	QCA::HMAC test6( "ripemd160" );
	QCA::SymmetricKey key6( 80 );
	for ( unsigned int i = 0; i < key6.size(); i++ )
	    key6[i] = 0xAA;
	test6.setup( key6 );
	QSecureArray data6 = QCString( "Test Using Larger Than Block-Size Key - Hash Key First" );
    	test6.update( data6 );
	CHECK( QCA::arrayToHex( test6.final() ), QString( "6466ca07ac5eac29e1bd523e5ada7605b791fd8b" ) );

	test6.clear(); // reuse the key
	QSecureArray data7 = QCString( "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data" );
    	test6.update( data7 );
	CHECK( QCA::arrayToHex( test6.final() ), QString( "69ea60798d71616cce5fd0871e23754cd75d5a0a" ) );

    }

}


