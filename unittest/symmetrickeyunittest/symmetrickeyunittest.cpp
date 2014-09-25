/**
 * Copyright (C)  2004, 2006  Brad Hards <bradh@frogmouth.net>
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

class SymmetricKeyUnitTest : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void cleanupTestCase();
    void test1();
    void weakKey_data();
    void weakKey();
private:
    QCA::Initializer* m_init;
};

void SymmetricKeyUnitTest::initTestCase()
{
    m_init = new QCA::Initializer;
}

void SymmetricKeyUnitTest::cleanupTestCase()
{
    delete m_init;
}

void SymmetricKeyUnitTest::test1()
{
    QCA::SymmetricKey emptyKey;
    QCOMPARE( emptyKey.size(), 0 );

    QCA::SymmetricKey randomKey(10);
    QCOMPARE( randomKey.size(),10 );

    QByteArray byteArray(10, 'c');
    QCA::SecureArray secureArray( byteArray );
    QCA::SymmetricKey keyArray = secureArray;
    QCOMPARE( secureArray.size(), 10 );
    QCOMPARE( keyArray.size(), secureArray.size() );
    QCOMPARE( QCA::arrayToHex ( keyArray.toByteArray() ), QString( "63636363636363636363" ) );
    QCOMPARE( QCA::arrayToHex ( secureArray.toByteArray() ), QString( "63636363636363636363" ) );
    keyArray[3] = 0x00; // test keyArray detaches OK
    QCOMPARE( QCA::arrayToHex ( keyArray.toByteArray() ), QString( "63636300636363636363" ) );
    QCOMPARE( QCA::arrayToHex ( secureArray.toByteArray() ), QString( "63636363636363636363" ) );

    QCA::SymmetricKey anotherKey;
    anotherKey = keyArray;
    QCOMPARE( QCA::arrayToHex ( anotherKey.toByteArray() ), QString( "63636300636363636363" ) );
    QCA::SymmetricKey bigKey( 100 );
    anotherKey = bigKey;
    QCOMPARE( anotherKey.size(), 100 );
    anotherKey = secureArray;
    QCOMPARE( QCA::arrayToHex ( secureArray.toByteArray() ), QString( "63636363636363636363" ) );
    QCOMPARE( anotherKey.size(), 10 );
    anotherKey = emptyKey;
    QCOMPARE( anotherKey.size(), 0 );
}

// These are from the Botan test suite
void SymmetricKeyUnitTest::weakKey_data()
{
    QTest::addColumn<QByteArray>("keyText");
    QTest::addColumn<bool>("isWeak");


    QTest::newRow("") << QByteArray("ffffffffffffffff") << true;
    QTest::newRow("") << QByteArray("0000000000000000") << true;
    QTest::newRow("") << QByteArray("d5d44ff720683d0d") << false;
    QTest::newRow("") << QByteArray("d5d44ff720683d0d") << false;
    QTest::newRow("") << QByteArray("1046913489980131") << false;
    QTest::newRow("") << QByteArray("1007103489988020") << false;
    QTest::newRow("") << QByteArray("10071034c8980120") << false;
    QTest::newRow("") << QByteArray("1046103489988020") << false;

}


void SymmetricKeyUnitTest::weakKey()
{
    QFETCH( QByteArray, keyText );
    QFETCH( bool, isWeak );

    QCA::SymmetricKey key( QCA::hexToArray( QByteArray( keyText ) ) );
    QCOMPARE( key.isWeakDESKey(), isWeak );
}

QTEST_MAIN(SymmetricKeyUnitTest)

#include "symmetrickeyunittest.moc"

