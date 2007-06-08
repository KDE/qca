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

class ClientPlugin : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void cleanupTestCase();
    void testInsertPlugin();

private:
    QCA::Initializer* m_init;

};

void ClientPlugin::initTestCase()
{
    m_init = new QCA::Initializer;
#include "../fixpaths.include"
}

void ClientPlugin::cleanupTestCase()
{
    delete m_init;
}

class TestClientProvider : public QCA::Provider
{
public:
        int qcaVersion() const
        {
                return QCA_VERSION;
        }

        QString name() const
        {
                return "testClientSideProvider";
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

void ClientPlugin::testInsertPlugin()
{
    QCA::insertProvider(new TestClientProvider, 0);
}

QTEST_MAIN(ClientPlugin)

#include "clientplugin.moc"

