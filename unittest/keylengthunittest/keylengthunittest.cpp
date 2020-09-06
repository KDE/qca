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

#include <limits>

#ifdef QT_STATICPLUGIN
#include "import_plugins.h"
#endif

class KeyLengthUnitTest : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void initTestCase();
    void cleanupTestCase();
    void doTest();

private:
    QCA::Initializer *m_init;
};

void KeyLengthUnitTest::initTestCase()
{
    m_init = new QCA::Initializer;
}

void KeyLengthUnitTest::cleanupTestCase()
{
    QCA::unloadAllPlugins();
    delete m_init;
}

void KeyLengthUnitTest::doTest()
{
    QCA::KeyLength keylen1(0, 0, 0);
    QCOMPARE(keylen1.minimum(), 0);
    QCOMPARE(keylen1.maximum(), 0);
    QCOMPARE(keylen1.multiple(), 0);

    QCA::KeyLength keylen2(3, 40, 1);
    QCOMPARE(keylen2.minimum(), 3);
    QCOMPARE(keylen2.maximum(), 40);
    QCOMPARE(keylen2.multiple(), 1);

    QCA::KeyLength keylen3(1, INT_MAX, 1);
    QCOMPARE(keylen3.minimum(), 1);
    QCOMPARE(keylen3.maximum(), INT_MAX);
    QCOMPARE(keylen3.multiple(), 1);
}

QTEST_MAIN(KeyLengthUnitTest)

#include "keylengthunittest.moc"
