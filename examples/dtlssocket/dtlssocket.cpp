/*
 Copyright (C) 2007 Justin Karneges <justin@affinix.com>
 Copyright (C) 2020 Sergey Ilinykh <rion4ik@gmail.com>

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
 AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "dtlssocket.h"

#include <QCoreApplication>
#include <QTimer>
#include <QUdpSocket>

#ifdef QT_STATICPLUGIN
#include "import_plugins.h"
#endif

#define DTLS_DEBUG qDebug

// clang-format off
/*
 openssl req -x509 -nodes -newkey rsa:4096 -keyout "server.key" -out "server.pem" \
   -days 3650 -subj "/C=US/O=Home/CN=127.0.0.1"

 To start native OpenSSL DTLS server instead of "dtlssocket -s":
  openssl s_server -dtls -key server.key -port 9753
*/
char pemdata_cert[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIFQTCCAymgAwIBAgIUEgnPPibWTHIyheSYkmfDi0lzZ78wDQYJKoZIhvcNAQEL\n"
"BQAwMDELMAkGA1UEBhMCVVMxDTALBgNVBAoMBEhvbWUxEjAQBgNVBAMMCTEyNy4w\n"
"LjAuMTAeFw0yMDA4MzAyMDQxMDZaFw0zMDA4MjgyMDQxMDZaMDAxCzAJBgNVBAYT\n"
"AlVTMQ0wCwYDVQQKDARIb21lMRIwEAYDVQQDDAkxMjcuMC4wLjEwggIiMA0GCSqG\n"
"SIb3DQEBAQUAA4ICDwAwggIKAoICAQDARKu0xWGGPV2NSrRqTV8lLXzSbwIDYU1v\n"
"pDeiMTlEW+Os3E1AEs5xuYPcO/u5HNl+xgSz12Jo8rgrtAfLmnrlKO5C1t7wpDLb\n"
"nNCcyCbIqIVUsiUcky0dZsOzI6sCFpOT1bL/Q78M4r5xzm/Djhncg6lj4tr5S0jW\n"
"5F6iw39SqkuVTF9LpVkBxOrO8xySnYwkLppzvpQEnOZjxkk14pTLftLfO8fJw43f\n"
"57vr3CqFmXoX4A6qPOtLObJmmvNBADFYKXVQCP4nW2jZXULRJYw5dVzZpSld06zz\n"
"u0Yid6sdRCQkmuU472RurPltgH+Ijmkz1LJUlhv6LiBxpomfM4v4Z8+nM9+FSzgF\n"
"g2aiV+1QqkK4JIqJqAGFeDfSzWYLJKgSvtQLrO/Q0CImGNv+zOaSJNEBDcEJpW2a\n"
"fSLLpxE4zgEQaDm8cSMTTy0oVnpXuGMkMNB+aHwO6oH4aMEf0Lj8YRBMPgqpzV2F\n"
"CrhH/vlSR5gJt9u7EMHGXFv1nRywTvL0HvL1g3W+KnoCENavyR8hejdpDknv6ULZ\n"
"6itG8LASs+Z2JZ7PhNRVDfFSTWJ9DxCbr4j1RrN4VjrZxuhNDMnCYUJhqKx9Zj1p\n"
"52VF2y+TswjhKoOUUKej15hpH2eBXQhxgGLdGz/1mYG445QqbIk13x/U905xgoxZ\n"
"AwhlrTOcVwIDAQABo1MwUTAdBgNVHQ4EFgQUwVSZ9CijyeuXpeldHzSI2gI7DKsw\n"
"HwYDVR0jBBgwFoAUwVSZ9CijyeuXpeldHzSI2gI7DKswDwYDVR0TAQH/BAUwAwEB\n"
"/zANBgkqhkiG9w0BAQsFAAOCAgEAtSWM+nd/GZtYygdOfCWW9Nibg0CdgLBn2uG1\n"
"l5cutmGWMdwjO0gzImPuAK5EaKrlQr/IByc+n31sK0GFIh++3aI9VXY6yLAiwa2/\n"
"I+jnmNwwZ8kl4vGY8fYRXNF9l4URUfB+mqonkUf7rblZNecsQXNo3mJ39dWOZu97\n"
"2n5e7OUUw8J4PAOVICVXkxsi/l4W3nFRSzQPtoi5mtfSphHSS8TvKvDEdk90lHzp\n"
"+b3V50urRPwzq7Oz0ez3Al575nFw1dWvFFSnJmESytLP2KBJJZ+ZZ64htaAwYd24\n"
"47BMG3iIMfT5Z7BJbci7qQ7NzlwacQouVOXQwtYR451lsNBNoX6TB/VoFD1EM/mu\n"
"DGRDs1vo2eqBKR0z7D14gH4oDri/mUxhcjx1NScjG4ul8muQszjp87ym9+vfuYNi\n"
"D5vLkMqfUOrApbEYh7iat9UBpJ2c86WpzNvos/ycLpIJOHxLOEvXwddXm9FIUzbq\n"
"jg49wcKw7wlCASkhmyX2TDmBf6+XCgT3Mt02C8EVFcCOW/yyKaBFgZUM7NvvI5zy\n"
"zIOl0fEphMIQzBUQaHEw0pVfec8qGUmS+hsARG7Dia5lsm7n1zU1mE13w1Qb2QHh\n"
"37Oy4WwfgSVfPImjoNcxmMmVw+wv4UC9bd0f6RkWh7FibCIX56Bv9Ls3qA1BnuWf\n"
"BtTWLG8=\n"
"-----END CERTIFICATE-----";

char pemdata_privkey[] =
"-----BEGIN PRIVATE KEY-----\n"
"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\n"
"KJM26aBJvxTcz60cqyRKGfn4fnSIehJy\n"
"-----END PRIVATE KEY-----";
// clang-format on

void SimpleLogger::logTextMessage(const QString &message, QCA::Logger::Severity severity)
{
    Q_UNUSED(severity)
    qDebug() << message;
}

void SimpleLogger::logBinaryMessage(const QByteArray &blob, QCA::Logger::Severity severity)
{
    Q_UNUSED(severity)
    qDebug() << "data: " << blob;
}

class DTLSSocket::Private : public QObject
{
    Q_OBJECT
public:
    DTLSSocket      *q;
    QUdpSocket      *sock = nullptr;
    QCA::TLS        *tls;
    QCA::Certificate cert;
    QCA::PrivateKey  privkey;
    QHostAddress     dstHost;
    quint16          dstPort    = 0;
    bool             serverMode = false;

    Private(DTLSSocket *_q)
        : QObject(_q)
        , q(_q)
    {
        cert    = QCA::Certificate::fromPEM(QString::fromLatin1(pemdata_cert));
        privkey = QCA::PrivateKey::fromPEM(QString::fromLatin1(pemdata_privkey));

        tls = new QCA::TLS(QCA::TLS::Datagram, this);
        connect(tls, &QCA::TLS::certificateRequested, tls, &QCA::TLS::continueAfterStep);
        connect(tls, &QCA::TLS::handshaken, this, &DTLSSocket::Private::tls_handshaken);
        connect(tls, &QCA::TLS::readyRead, this, &DTLSSocket::Private::tls_readyRead);
        connect(tls, &QCA::TLS::readyReadOutgoing, this, &DTLSSocket::Private::tls_readyReadOutgoing);
        connect(tls, &QCA::TLS::closed, this, &DTLSSocket::Private::tls_closed);
        connect(tls, &QCA::TLS::error, this, &DTLSSocket::Private::tls_error);

        QCA::CertificateCollection rootCerts = QCA::systemStore();
        rootCerts.addCertificate(cert);
        tls->setTrustedCertificates(rootCerts);
    }

    void connectToServer(const QHostAddress &host, quint16 port)
    {
        serverMode = false;
        dstHost    = host;
        dstPort    = port;
        sock       = new QUdpSocket(this);
        connect(sock, &QUdpSocket::readyRead, this, &DTLSSocket::Private::sock_readyRead);
#if QT_VERSION >= QT_VERSION_CHECK(5, 15, 0)
        connect(sock, &QUdpSocket::errorOccurred, this, [this]() {
            qDebug("socket failed: %s", qPrintable(sock->errorString()));
        });
#else
        connect(sock,
                QOverload<QAbstractSocket::SocketError>::of(&QUdpSocket::error),
                this,
                [this](QAbstractSocket::SocketError) { qDebug("socket failed: %s", qPrintable(sock->errorString())); });
#endif

        sock->bind();
        sock->connectToHost(host, port);
        tls->startClient(host.toString());
    }

private Q_SLOTS:
    void sock_readyRead()
    {
        while (sock->hasPendingDatagrams()) {
            QByteArray ba;
            ba.resize(sock->pendingDatagramSize());
            SourceAddress source;
            if (sock->readDatagram(ba.data(), ba.size(), &source.host, &source.port) == -1) {
                qDebug("Failed to read datagram");
                continue;
            }
            tls->writeIncoming(ba);
        }
    }

    void sock_bytesWritten(qint64 x)
    {
        Q_UNUSED(x);
        DTLS_DEBUG("sock bytes written: %d\n", (int)x);
    }

    void sock_error(QAbstractSocket::SocketError x)
    {
        DTLS_DEBUG("sock error: %d\n", x);
        // if ssl resultsReady() was alreay enquued we have to stop after it
        QTimer::singleShot(0, this, [x, this]() { Q_EMIT q->errorOccurred(x); });
    }

    void tls_handshaken()
    {
        DTLS_DEBUG("tls handshaken");
        auto peerIdentity = tls->peerIdentityResult();
        if (peerIdentity != QCA::TLS::Valid && !(serverMode && peerIdentity == QCA::TLS::NoCertificate)) {
            qWarning("peer identity not valid: %d", int(tls->peerIdentityResult()));
            if (!serverMode)
                sock->abort();
            tls->reset();
            emit q->errorOccurred(tls->peerIdentityResult() == QCA::TLS::NoCertificate
                                      ? QAbstractSocket::SslHandshakeFailedError
                                      : QAbstractSocket::SslInvalidUserDataError);
            return;
        }
        DTLS_DEBUG("valid");
        tls->continueAfterStep();

        emit q->connected();
    }

    void tls_readyRead()
    {
        DTLS_DEBUG("tls ready read");
        emit q->readyRead();
    }

    void tls_readyReadOutgoing()
    {
        DTLS_DEBUG("dtls ready read outgoing");
        QByteArray buf;
        while ((buf = tls->readOutgoing()).size() > 0) {
            DTLS_DEBUG("%d bytes\n", int(buf.size()));
            sock->writeDatagram(buf, dstHost, dstPort);
        }
    }

    void tls_closed()
    {
        DTLS_DEBUG("dtls closed");
    }

    void tls_error()
    {
        DTLS_DEBUG("dtls error: %d", tls->errorCode());
    }
};

DTLSSocket::DTLSSocket(QObject *parent)
    : QObject(parent)
{
    d = new Private(this);
}

DTLSSocket::~DTLSSocket()
{
    delete d;
}

void DTLSSocket::connectToServer(const QHostAddress &host, quint16 port)
{
    d->connectToServer(host, port);
}

QCA::TLS *DTLSSocket::tls()
{
    return d->tls;
}

void DTLSSocket::startServer(QUdpSocket *socket, const SourceAddress &destination)
{
    d->serverMode = true;
    d->sock       = socket;
    d->tls->setCertificate(d->cert, d->privkey);
    d->tls->startServer();
    d->dstHost = destination.host;
    d->dstPort = destination.port;
}

QByteArray DTLSSocket::readDatagram()
{
    QByteArray a = d->tls->read();
    DTLS_DEBUG("%s", a.data());
    return a;
}

void DTLSSocket::writeDatagram(const QByteArray &data)
{
    DTLS_DEBUG("write %d bytes\n", int(data.size()));
    d->tls->write(data);
}

void DTLSSocket::handleIncomingSocketData(const QByteArray &data)
{
    d->tls->writeIncoming(data);
}

// ----------------
// DTLSServer
// ----------------
DTLSServer::DTLSServer(QObject *parent)
    : QObject(parent)
{
    socket = new QUdpSocket(this);
    connect(socket, &QUdpSocket::readyRead, this, &DTLSServer::sock_readyRead);
#if QT_VERSION >= QT_VERSION_CHECK(5, 15, 0)
    connect(socket, &QUdpSocket::errorOccurred, this, [this]() {
        qDebug("socket failed: %s", qPrintable(socket->errorString()));
        qApp->quit();
    });
#else
    connect(socket,
            QOverload<QAbstractSocket::SocketError>::of(&QUdpSocket::error),
            this,
            [this](QAbstractSocket::SocketError) {
                qDebug("socket failed: %s", qPrintable(socket->errorString()));
                qApp->quit();
            });
#endif
}

bool DTLSServer::start(const QHostAddress &address, quint16 port, QAbstractSocket::BindMode mode)
{
    return socket->bind(address, port, mode);
}

void DTLSServer::sock_readyRead()
{
    while (socket->hasPendingDatagrams()) {
        QByteArray ba;
        ba.resize(socket->pendingDatagramSize());
        SourceAddress source;
        if (socket->readDatagram(ba.data(), ba.size(), &source.host, &source.port) == -1) {
            qDebug("Failed to read datagram");
            continue;
        }
        auto dtlsSocket = clientSockets.value(source);
        if (!dtlsSocket) {
            dtlsSocket = new DTLSSocket(this);
            clientSockets.insert(source, dtlsSocket);
            dtlsSocket->startServer(socket, source);
            Q_EMIT incomingConnection(dtlsSocket);
            connect(
                dtlsSocket, &DTLSSocket::connected, this, [dtlsSocket, this]() { Q_EMIT sessionReady(dtlsSocket); });
        }
        dtlsSocket->handleIncomingSocketData(ba);
    }
}

#include "dtlssocket.moc"
