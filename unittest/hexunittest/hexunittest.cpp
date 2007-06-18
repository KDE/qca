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

class HexUnitTest : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void cleanupTestCase();
    void testHexString_data();
    void testHexString();
    void testIncrementalUpdate();
    void testBrokenInput();
private:
    QCA::Initializer* m_init;
};

void HexUnitTest::initTestCase()
{
    m_init = new QCA::Initializer;
#include "../fixpaths.include"
}

void HexUnitTest::cleanupTestCase()
{
    delete m_init;
}

void HexUnitTest::testHexString_data()
{
    QTest::addColumn<QString>("raw");
    QTest::addColumn<QString>("encoded");

    QTest::newRow("abcd") << QString("abcd") << QString("61626364");
    QTest::newRow("ABCD") << QString("ABCD") << QString("41424344");
    QTest::newRow("empty") << QString("") << QString("");
    QTest::newRow("abcddef") << QString("abcddef") << QString("61626364646566");
    QTest::newRow("empty too") << QString("\0") << QString("");   // Empty QString.
    QTest::newRow("BEL") << QString("\a") << QString("07"); // BEL
    QTest::newRow("BS") << QString("\b") << QString("08"); // BS
    QTest::newRow("HT") << QString("\t") << QString("09"); // HT
    QTest::newRow("LF") << QString("\n") << QString("0a"); // LF
    QTest::newRow("VT") << QString("\v") << QString("0b"); // VT
    QTest::newRow("FF") << QString("\f") << QString("0c"); // FF
    QTest::newRow("CR") << QString("\r") << QString("0d"); // CR
    QTest::newRow("bug126735") << QString("@ABCDEFGHIJKLMNO") << QString("404142434445464748494a4b4c4d4e4f");
}

void HexUnitTest::testHexString()
{
    QCA::Hex hexObject;
    QFETCH(QString, raw);
    QFETCH(QString, encoded);
    QCOMPARE( hexObject.encodeString(raw), encoded);
    QCOMPARE( hexObject.decodeString(encoded), raw);
}

void HexUnitTest::testIncrementalUpdate()
{
    QCA::Hex hexObject;

    hexObject.setup(QCA::Encode);
    hexObject.clear();
    QCA::SecureArray result1 = hexObject.update(QCA::SecureArray("ab"));
    QVERIFY( hexObject.ok() );
    QCOMPARE( result1[0], '6' );
    QCOMPARE( result1[1], '1' );
    QCOMPARE( result1[2], '6' );
    QCOMPARE( result1[3], '2' );
    QCA::SecureArray result2 = hexObject.update(QCA::SecureArray("cd"));
    QCOMPARE( hexObject.ok(), true );
    QCOMPARE( result2[0], '6' );
    QCOMPARE( result2[1], '3' );
    QCOMPARE( result2[2], '6' );
    QCOMPARE( result2[3], '4' );
    QCOMPARE( QCA::SecureArray(), QCA::SecureArray(hexObject.final()) );
    QCOMPARE( hexObject.ok(), true );
}

void HexUnitTest::testBrokenInput()
{
    QCA::Hex hexObject;

    hexObject.setup(QCA::Decode);
    hexObject.update(QCA::SecureArray("-="));
    QCOMPARE(hexObject.ok(), false);
}

QTEST_MAIN(HexUnitTest)

#include "hexunittest.moc"
