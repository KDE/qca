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

class StaticUnitTest : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void initTestCase();
    void cleanupTestCase();
    void hexConversions();
    void capabilities();
    void secureMemory();

private:
    QCA::Initializer *m_init;
};

void StaticUnitTest::initTestCase()
{
    m_init = new QCA::Initializer;
}

void StaticUnitTest::cleanupTestCase()
{
    delete m_init;
}

void StaticUnitTest::hexConversions()
{
    QByteArray test(10, 'a');

    QCOMPARE(QCA::arrayToHex(test), QStringLiteral("61616161616161616161"));

    test.fill('b');
    test[7] = 0x00;

    QCOMPARE(test == QCA::hexToArray(QStringLiteral("62626262626262006262")), true);

    QCA::SecureArray testArray(10);
    // testArray.fill( 'a' );
    for (int i = 0; i < testArray.size(); i++) {
        testArray[i] = 0x61;
    }
    QCOMPARE(QCA::arrayToHex(testArray.toByteArray()), QStringLiteral("61616161616161616161"));
    // testArray.fill( 'b' );
    for (int i = 0; i < testArray.size(); i++) {
        testArray[i] = 0x62;
    }
    testArray[6] = 0x00;
    QCOMPARE(testArray == QCA::hexToArray(QStringLiteral("62626262626200626262")), true);

    QCOMPARE(testArray == QCA::hexToArray(QCA::arrayToHex(testArray.toByteArray())), true);

    testArray[9] = 0x00;
    QCOMPARE(testArray == QCA::hexToArray(QCA::arrayToHex(testArray.toByteArray())), true);
}

void StaticUnitTest::capabilities()
{
    // capabilities are reported as a list - that is a problem for
    // doing a direct comparison, since they change
    // We try to work around that using contains()
    QStringList defaultCapabilities = QCA::defaultFeatures();
    QVERIFY(defaultCapabilities.contains(QStringLiteral("random")));
    QVERIFY(defaultCapabilities.contains(QStringLiteral("sha1")));
    QVERIFY(defaultCapabilities.contains(QStringLiteral("md5")));

    QStringList capList;
    capList << QStringLiteral("random") << QStringLiteral("sha1");
    QCOMPARE(QCA::isSupported(capList), true);
    capList.append(QStringLiteral("noSuch"));
    QCOMPARE(QCA::isSupported(capList), false);
    capList.clear();
    capList.append(QStringLiteral("noSuch"));
    QCOMPARE(QCA::isSupported(capList), false);
}

void StaticUnitTest::secureMemory()
{
    // this should be reliably true
    QCOMPARE(QCA::haveSecureMemory(), true);
}

QTEST_MAIN(StaticUnitTest)

#include "staticunittest.moc"
