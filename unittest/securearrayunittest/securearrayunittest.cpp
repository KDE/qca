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

class SecureArrayUnitTest : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void cleanupTestCase();
    void testAll();

private:
    QCA::Initializer* m_init;
};


void SecureArrayUnitTest::initTestCase()
{
    m_init = new QCA::Initializer;
#include "../fixpaths.include"
}

void SecureArrayUnitTest::cleanupTestCase()
{
    delete m_init;
}


void SecureArrayUnitTest::testAll()
{
    QCA::SecureArray emptyArray;
    QCOMPARE( emptyArray.size(), 0 );
    QVERIFY( emptyArray.isEmpty() );

    QCA::SecureArray testArray(10);
    QCOMPARE( testArray.size(), 10 );
    QCOMPARE( testArray.isEmpty(), false );

    QCA::SecureArray testArray64(64);
    QCOMPARE( testArray64.size(), 64 );
    QCOMPARE( testArray64.isEmpty(), false );

    //testArray.fill( 'a' );
    for (int i = 0; i < testArray.size(); i++) {
	testArray[ i ] = 0x61;
    }
    QCOMPARE( QCA::arrayToHex( testArray.toByteArray() ), QString( "61616161616161616161" ) );

    testArray.fill( 'b' );
    testArray[7] = 0x00;
    QCOMPARE( QCA::arrayToHex( testArray.toByteArray() ), QString( "62626262626262006262" ) );

    QByteArray byteArray(10, 'c');
    QCA::SecureArray secureArray( byteArray );
    QCOMPARE( secureArray.size(), 10 );
    QCOMPARE( QCA::arrayToHex ( secureArray.toByteArray() ), QString( "63636363636363636363" ) );
    byteArray.fill( 'd' );
    // it should be a copy, so no effect
    QCOMPARE( QCA::arrayToHex ( secureArray.toByteArray() ), QString( "63636363636363636363" ) );

    QCA::SecureArray copyArray( secureArray );
    QCOMPARE( QCA::arrayToHex ( copyArray.toByteArray() ), QString( "63636363636363636363" ) );
    copyArray.fill(0x64);
    QCOMPARE( QCA::arrayToHex ( copyArray.toByteArray() ), QString( "64646464646464646464" ) );
    QCOMPARE( QCA::arrayToHex ( secureArray.toByteArray() ), QString( "63636363636363636363" ) );

    // test for detaching
    QCA::SecureArray detachArray1 = secureArray; // currently the same
    QCOMPARE( QCA::arrayToHex ( detachArray1.toByteArray() ), QString( "63636363636363636363" ) );
    for (int i = 0; i < detachArray1.size(); i++) {
	detachArray1[i] = 0x66; // implicit detach
    }
    QCOMPARE( QCA::arrayToHex ( secureArray.toByteArray() ), QString( "63636363636363636363" ) );
    QCOMPARE( QCA::arrayToHex ( detachArray1.toByteArray() ), QString( "66666666666666666666" ) );

    QCA::SecureArray detachArray2 = secureArray; // currently the same
    QCOMPARE( QCA::arrayToHex ( detachArray2.toByteArray() ), QString( "63636363636363636363" ) );
    //implicit detach
    for (int i = 0; i < detachArray2.size(); i++) {
	detachArray2.data()[i] = 0x67;
    }
    QCOMPARE( QCA::arrayToHex ( secureArray.toByteArray() ), QString( "63636363636363636363" ) );
    QCOMPARE( QCA::arrayToHex ( detachArray2.toByteArray() ), QString( "67676767676767676767" ) );

    QCA::SecureArray detachArray3 = secureArray; // implicitly shared copy
    QCOMPARE( QCA::arrayToHex ( detachArray3.toByteArray() ), QString( "63636363636363636363" ) );
    for (int i = 0; i < detachArray3.size(); i++) {
	detachArray3.data()[i] = 0x68;
    }
    QCOMPARE( QCA::arrayToHex ( secureArray.toByteArray() ), QString( "63636363636363636363" ) );
    QCOMPARE( QCA::arrayToHex ( detachArray3.toByteArray() ), QString( "68686868686868686868" ) );


    // test for resizing
    QCA::SecureArray resizeArray = emptyArray;
    QCOMPARE( resizeArray.size(), 0 );
    resizeArray.resize(20);
    QCOMPARE( resizeArray.size(), 20 );
    resizeArray.resize(40);
    QCOMPARE( resizeArray.size(), 40 );
    resizeArray.resize(10);
    QCOMPARE( resizeArray.size(), 10 );


    // test for append
    QCA::SecureArray appendArray = secureArray;
    appendArray.append( QCA::SecureArray() );
    QCOMPARE( QCA::arrayToHex( secureArray.toByteArray() ), QCA::arrayToHex( appendArray.toByteArray() ) );
    appendArray.append( secureArray );
    QCOMPARE( QCA::arrayToHex ( secureArray.toByteArray() ), QString( "63636363636363636363" ) );
    QCOMPARE( QCA::arrayToHex ( appendArray.toByteArray() ), QString( "6363636363636363636363636363636363636363" ) );
    QCA::SecureArray appendArray2 = secureArray;
    QCOMPARE( QCA::arrayToHex ( appendArray2.append(secureArray).toByteArray() ), QString( "6363636363636363636363636363636363636363" ) );

    // test for a possible problem with operator[]
    QVERIFY( (secureArray[0] == (char)0x63) );
}

QTEST_MAIN(SecureArrayUnitTest)

#include "securearrayunittest.moc"

