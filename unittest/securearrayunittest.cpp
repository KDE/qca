/**
 * securearrayunittest.cpp
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
#include "securearrayunittest.h"
#include <QtCrypto>


SecureArrayUnitTest::SecureArrayUnitTest()
    : Tester()
{

}

void SecureArrayUnitTest::allTests()
{
    QCA::Initializer init;

    QSecureArray emptyArray;
    CHECK( emptyArray.size(), (unsigned int)0 );
    CHECK( emptyArray.isEmpty(), true );

    QSecureArray testArray(10);
    CHECK( testArray.size(), (unsigned int) 10 );
    CHECK( testArray.isEmpty(), false );

    QSecureArray testArray64(64);
    CHECK( testArray64.size(), (unsigned int) 64 );
    CHECK( testArray64.isEmpty(), false );

    //testArray.fill( 'a' );
    for (unsigned int i = 0; i < testArray.size(); i++) {
	testArray[ i ] = 0x61;
    }
    CHECK( QCA::arrayToHex( testArray ), QString( "61616161616161616161" ) );

    testArray.fill( 'b' );
    testArray[7] = 0x00;
    CHECK( QCA::arrayToHex( testArray ), QString( "62626262626262006262" ) );

    QByteArray byteArray(10);
    byteArray.fill( 'c' );
    QSecureArray secureArray( byteArray );
    CHECK( secureArray.size(), (unsigned int) 10 );
    CHECK( QCA::arrayToHex ( secureArray ), QString( "63636363636363636363" ) );
    byteArray.fill( 'd' );
    // it should be a copy, so no effect
    CHECK( QCA::arrayToHex ( secureArray ), QString( "63636363636363636363" ) );

    QSecureArray copyArray( secureArray );
    CHECK( QCA::arrayToHex ( copyArray ), QString( "63636363636363636363" ) );
    copyArray.fill(0x64);
    CHECK( QCA::arrayToHex ( copyArray ), QString( "64646464646464646464" ) );
    CHECK( QCA::arrayToHex ( secureArray ), QString( "63636363636363636363" ) );

    // test for detaching
    QSecureArray detachArray1 = secureArray; // currently the same
    CHECK( QCA::arrayToHex ( detachArray1 ), QString( "63636363636363636363" ) );
    for (unsigned int i = 0; i < detachArray1.size(); i++) {
	detachArray1[i] = 0x66; // implicit detach
    }
    CHECK( QCA::arrayToHex ( secureArray ), QString( "63636363636363636363" ) );
    CHECK( QCA::arrayToHex ( detachArray1 ), QString( "66666666666666666666" ) );

    QSecureArray detachArray2 = secureArray; // currently the same
    CHECK( QCA::arrayToHex ( detachArray2 ), QString( "63636363636363636363" ) );
    detachArray2.detach(); //explicit detach
    for (unsigned int i = 0; i < detachArray2.size(); i++) {
	detachArray2.data()[i] = 0x67; 
    }
    CHECK( QCA::arrayToHex ( secureArray ), QString( "63636363636363636363" ) );
    CHECK( QCA::arrayToHex ( detachArray2 ), QString( "67676767676767676767" ) );

    QSecureArray detachArray3 = secureArray.copy(); // assign and detach in one
    CHECK( QCA::arrayToHex ( detachArray3 ), QString( "63636363636363636363" ) );
    for (unsigned int i = 0; i < detachArray3.size(); i++) {
	detachArray3.data()[i] = 0x68; 
    }
    CHECK( QCA::arrayToHex ( secureArray ), QString( "63636363636363636363" ) );
    CHECK( QCA::arrayToHex ( detachArray3 ), QString( "68686868686868686868" ) );


    // test for resizing
    QSecureArray resizeArray = emptyArray;
    CHECK( resizeArray.size(), (unsigned int)0 );
    resizeArray.resize(20);
    CHECK( resizeArray.size(), (unsigned int)20 );
    resizeArray.resize(40);
    CHECK( resizeArray.size(), (unsigned int)40 );
    resizeArray.resize(10);
    CHECK( resizeArray.size(), (unsigned int)10 );


    // test for append
    QSecureArray appendArray = secureArray;
    appendArray.append( QSecureArray() );
    CHECK( QCA::arrayToHex( secureArray), QCA::arrayToHex( appendArray ) );
    appendArray.append( secureArray );
    CHECK( QCA::arrayToHex ( secureArray ), QString( "63636363636363636363" ) );
    CHECK( QCA::arrayToHex ( appendArray ), QString( "6363636363636363636363636363636363636363" ) );
    QSecureArray appendArray2 = secureArray;
    CHECK( QCA::arrayToHex ( appendArray2.append(secureArray) ), QString( "6363636363636363636363636363636363636363" ) );

    // test for a possible problem with operator[]
    CHECK( (secureArray[0] == (char)0x63), true );
}

