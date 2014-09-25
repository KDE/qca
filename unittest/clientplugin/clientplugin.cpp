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
#include <QtCore/QPointer>
#include <QtTest/QtTest>

#ifdef QT_STATICPLUGIN
#include "import_plugins.h"
#endif

class ClientPlugin : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void cleanupTestCase();
    void testInsertRemovePlugin();

private:
    QCA::Initializer* m_init;

};

void ClientPlugin::initTestCase()
{
    m_init = new QCA::Initializer;
}

void ClientPlugin::cleanupTestCase()
{
    delete m_init;
}

const QString providerName = "testClientSideProvider";

class TestClientProvider : public QObject, public QCA::Provider
{
        Q_OBJECT

public:
        int qcaVersion() const
        {
                return QCA_VERSION;
        }

        QString name() const
        {
                return providerName;
        }

        QStringList features() const
        {
                QStringList list;
                list += "testClientSideProviderFeature1";
                list += "testClientSideProviderFeature2";
                return list;
        }

        Provider::Context *createContext(const QString &type)
        {
            if(type == "testClientSideProviderFeature1")
                // return new Feature1Context(this);
		return 0;
            else if (type == "testClientSideProviderFeature2")
		//  return new Feature2Context(this);
		return 0;
            else
                return 0;
        }
};

void ClientPlugin::testInsertRemovePlugin()
{
    QPointer<TestClientProvider> provider = new TestClientProvider;

    QVERIFY(QCA::insertProvider(provider, 10));
    QCOMPARE(QCA::findProvider(providerName), provider.data());
    QCOMPARE(QCA::providerPriority(providerName), 10);

    QVERIFY(QCA::unloadProvider(providerName));
    QCOMPARE(QCA::findProvider(providerName), static_cast<QCA::Provider *>(0));
    QVERIFY(provider.isNull());
}

QTEST_MAIN(ClientPlugin)

#include "clientplugin.moc"

