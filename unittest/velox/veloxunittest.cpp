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

#include <QTcpSocket>
#include <QtCrypto>
#include <QtTest/QtTest>

#ifdef QT_STATICPLUGIN
#include "import_plugins.h"
#endif

class TlsTest : public QObject
{
    Q_OBJECT
public:
    TlsTest()
    {
        sock = new QTcpSocket(this);
        connect(sock, &QTcpSocket::connected, this, &TlsTest::sock_connected);
        connect(sock, &QTcpSocket::readyRead, this, &TlsTest::sock_readyRead);

        ssl = new QCA::TLS(this);
        connect(ssl, &QCA::TLS::handshaken, this, &TlsTest::ssl_handshaken);
        connect(ssl, &QCA::TLS::readyReadOutgoing, this, &TlsTest::ssl_readyReadOutgoing);

        sync = new QCA::Synchronizer(this);
    }

    ~TlsTest() override
    {
        delete ssl;
        delete sock;
    }

    void start(const QString &_host, int port)
    {
        host = _host;
        sock->connectToHost(host, port);
    }

    void waitForHandshake(int timeout = 20000)
    {
        sync->waitForCondition(timeout);
    }

    bool isHandshaken()
    {
        return ssl->isHandshaken();
    }

private Q_SLOTS:
    void sock_connected()
    {
        QCA::CertificateCollection rootCerts;
        QCA::ConvertResult         resultRootCert;
        QCA::Certificate rootCert = QCA::Certificate::fromPEMFile(QStringLiteral("root.crt"), &resultRootCert);
        QCOMPARE(resultRootCert, QCA::ConvertGood);
        rootCerts.addCertificate(rootCert);

        ssl->setTrustedCertificates(rootCerts);

        ssl->startClient(host);
    }

    void sock_readyRead()
    {
        ssl->writeIncoming(sock->readAll());
    }

    void ssl_handshaken()
    {
        QCA::TLS::IdentityResult r = ssl->peerIdentityResult();

        QCOMPARE(r, QCA::TLS::Valid);

        sync->conditionMet();
    }

    void ssl_readyReadOutgoing()
    {
        sock->write(ssl->readOutgoing());
    }

private:
    QString            host;
    QTcpSocket *       sock;
    QCA::TLS *         ssl;
    QCA::Certificate   cert;
    QCA::Synchronizer *sync;
};

class VeloxUnitTest : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void initTestCase();
    void cleanupTestCase();
    void sniAlice();
    void sniBob();
    void sniCarol();
    void sniDave();
    void sniMallory();
    void sniIvan();

private:
    QCA::Initializer *         m_init;
    QCA::CertificateCollection rootCerts;
};

void VeloxUnitTest::initTestCase()
{
    m_init = new QCA::Initializer;
}

void VeloxUnitTest::cleanupTestCase()
{
    delete m_init;
}

void VeloxUnitTest::sniAlice()
{
    if (!QCA::isSupported("tls", QStringLiteral("qca-ossl")))
        QWARN("TLS not supported for qca-ossl");
    else {
        TlsTest *s = new TlsTest;
        s->start(QStringLiteral("alice.sni.velox.ch"), 443);
        s->waitForHandshake();
        QVERIFY(s->isHandshaken());
    }
}

void VeloxUnitTest::sniBob()
{
    if (!QCA::isSupported("tls", QStringLiteral("qca-ossl")))
        QWARN("TLS not supported for qca-ossl");
    else {
        TlsTest *s = new TlsTest;
        s->start(QStringLiteral("bob.sni.velox.ch"), 443);
        s->waitForHandshake();
        QVERIFY(s->isHandshaken());
    }
}

void VeloxUnitTest::sniCarol()
{
    if (!QCA::isSupported("tls", QStringLiteral("qca-ossl")))
        QWARN("TLS not supported for qca-ossl");
    else {
        TlsTest *s = new TlsTest;
        s->start(QStringLiteral("carol.sni.velox.ch"), 443);
        s->waitForHandshake();
        QVERIFY(s->isHandshaken());
    }
}

void VeloxUnitTest::sniDave()
{
    if (!QCA::isSupported("tls", QStringLiteral("qca-ossl")))
        QWARN("TLS not supported for qca-ossl");
    else {
        TlsTest *s = new TlsTest;
        s->start(QStringLiteral("dave.sni.velox.ch"), 443);
        s->waitForHandshake();
        QVERIFY(s->isHandshaken());
    }
}

void VeloxUnitTest::sniMallory()
{
    if (!QCA::isSupported("tls", QStringLiteral("qca-ossl")))
        QWARN("TLS not supported for qca-ossl");
    else {
        TlsTest *s = new TlsTest;
        s->start(QStringLiteral("mallory.sni.velox.ch"), 443);
        s->waitForHandshake();
        QVERIFY(s->isHandshaken());
    }
}

void VeloxUnitTest::sniIvan()
{
    if (!QCA::isSupported("tls", QStringLiteral("qca-ossl")))
        QWARN("TLS not supported for qca-ossl");
    else {
        TlsTest *s = new TlsTest;
        s->start(QStringLiteral("ivan.sni.velox.ch"), 443);
        s->waitForHandshake();
        QVERIFY(s->isHandshaken());
    }
}

QTEST_MAIN(VeloxUnitTest)

#include "veloxunittest.moc"
