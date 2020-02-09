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

#include "clientplugin.h"

#include <QtCrypto>
#include <QtCore/QPointer>
#include <QtTest/QtTest>

#ifdef QT_STATICPLUGIN
#include "import_plugins.h"
#endif

void ClientPlugin::initTestCase()
{
    m_init = new QCA::Initializer;
}

void ClientPlugin::cleanupTestCase()
{
    delete m_init;
}

static const QLatin1String providerName("testClientSideProvider");

class TestClientProvider : public QObject, public QCA::Provider
{
    Q_OBJECT
public:
        int qcaVersion() const override
        {
                return QCA_VERSION;
        }

        QString name() const override
        {
                return providerName;
        }

        QStringList features() const override
        {
                QStringList list;
                list += QStringLiteral("testClientSideProviderFeature1");
                list += QStringLiteral("testClientSideProviderFeature2");
                return list;
        }

        Provider::Context *createContext(const QString &type) override
        {
            if(type == QLatin1String("testClientSideProviderFeature1"))
                // return new Feature1Context(this);
		return nullptr;
            else if (type == QLatin1String("testClientSideProviderFeature2"))
		//  return new Feature2Context(this);
		return nullptr;
            else
                return nullptr;
        }
};

void ClientPlugin::testInsertRemovePlugin()
{
    QPointer<TestClientProvider> provider = new TestClientProvider;

    QVERIFY(QCA::insertProvider(provider, 10));
    QCOMPARE(QCA::findProvider(providerName), provider.data());
    QCOMPARE(QCA::providerPriority(providerName), 10);

    QVERIFY(QCA::unloadProvider(providerName));
    QCOMPARE(QCA::findProvider(providerName), static_cast<QCA::Provider *>(nullptr));
    QVERIFY(provider.isNull());
}

QTEST_MAIN(ClientPlugin)

#include "clientplugin.moc"
