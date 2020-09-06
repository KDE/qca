/**
 * Copyright (C)  2006  Brad Hards <bradh@frogmouth.net>
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

class KeyStore : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void initTestCase();
    void cleanupTestCase();
    void nullKeystore();

private:
    QCA::Initializer *m_init;
};

void KeyStore::initTestCase()
{
    m_init = new QCA::Initializer;
}

void KeyStore::cleanupTestCase()
{
    QCA::unloadAllPlugins();
    delete m_init;
}

void KeyStore::nullKeystore()
{
    QCA::KeyStoreManager manager;
    if (QCA::isSupported("keystore")) {
        QCA::KeyStore nullStore(QStringLiteral("null store"), &manager);
        QVERIFY(nullStore.isValid());

        QVERIFY(nullStore.entryList().isEmpty());

        QCOMPARE(nullStore.type(), QCA::KeyStore::User);

        QCOMPARE(nullStore.id(), QStringLiteral("null store"));
        QCOMPARE(nullStore.holdsTrustedCertificates(), false);
        QCOMPARE(nullStore.holdsIdentities(), false);
        QCOMPARE(nullStore.holdsPGPPublicKeys(), false);
    }
}

QTEST_MAIN(KeyStore)

#include "keystore.moc"
