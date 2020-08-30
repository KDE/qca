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
char pemdata_cert[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICeTCCAeKgAwIBAgIRAKKKnOj6Aarmwf0phApitVAwDQYJKoZIhvcNAQEFBQAw\n"
    "ODELMAkGA1UEBhMCVVMxFDASBgNVBAoTC0V4YW1wbGUgT3JnMRMwEQYDVQQDEwpF\n"
    "eGFtcGxlIENBMB4XDTA2MDMxNTA3MDU1MloXDTA3MDMxNTA3MDU1MlowOjEVMBMG\n"
    "A1UEAxMMRXhhbXBsZSBVc2VyMQswCQYDVQQGEwJVUzEUMBIGA1UEChMLRXhhbXBs\n"
    "ZSBPcmcwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAPkKn0FfHMvRZv+3uFcw\n"
    "VrOadJmANzLVeVW/DHZp4CXokXSksM66ZMqFuQRBk5rnIZZpZmVp1tTRDVt9sEAY\n"
    "YNa8CRM4HXkVlU0lCKdey18CSq2VuSvNtw8dDpoBmQt3nr9tePvKHnpS3nm6YjR2\n"
    "NEvIKt1P4mHzYXLmwoF24C1bAgMBAAGjgYAwfjAdBgNVHQ4EFgQUmQIdzyDaPYWF\n"
    "fPJ8PPOOm1eSsucwHwYDVR0jBBgwFoAUkCglAizTO7iqwLeaO6r/8kJuqhMwDAYD\n"
    "VR0TAQH/BAIwADAeBgNVHREEFzAVgRNleGFtcGxlQGV4YW1wbGUuY29tMA4GA1Ud\n"
    "DwEB/wQEAwIF4DANBgkqhkiG9w0BAQUFAAOBgQAuhbiUgy2a++EUccaonID7eTJZ\n"
    "F3D5qXMqUpQxlYxU8du+9AxDD7nFxTMkQC2pzfmEc1znRNmJ1ZeLRL72VYsVndcT\n"
    "psyM8ABkvPp1d2jWIyccVjGpt+/RN5IPKm/YIbtIZcywvWuXrOp1lanVmppLfPnO\n"
    "6yneBkC9iqjOv/+Q+A==\n"
    "-----END CERTIFICATE-----\n";

char pemdata_privkey[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAPkKn0FfHMvRZv+3\n"
    "uFcwVrOadJmANzLVeVW/DHZp4CXokXSksM66ZMqFuQRBk5rnIZZpZmVp1tTRDVt9\n"
    "sEAYYNa8CRM4HXkVlU0lCKdey18CSq2VuSvNtw8dDpoBmQt3nr9tePvKHnpS3nm6\n"
    "YjR2NEvIKt1P4mHzYXLmwoF24C1bAgMBAAECgYEAyIjJHDaeVXDU42zovyxpZE4n\n"
    "PcOEryY+gdFJE8DFgUD4f1huFsj4iCuNg+PaG42p+hf9IARNvSho/RcEaVg4AJrV\n"
    "jRP8r7fSqcIGr6lGuvDFFv3SU5ddy84g5oqLYGKvuPSHMGfVsZSxAwOrzD4bH19L\n"
    "SNqtNcpdBsBd7ZiEE4ECQQD/oJGui9D5Dx3QVcS+QV4F8wuyN9jYIANmX/17o0fl\n"
    "BL0bwRU4RICwadrcybi5N0JQLIYSUm2HGqNvAJbtnuQxAkEA+WeYLLYPeawcy+WU\n"
    "kGcOR7BUjHiG71+6cvU4XIDW2bezA04fqWXkZRFAwHTMpQb785/XalFftgS21kql\n"
    "8yLDSwJAHkeT2hwftdDPlEUEmBDAJW5DvWmWGwu3u2G1cfbGZl9oUyhM7ixXHg57\n"
    "6VlPs0jTZxHPE86FwNIr99MXDbCbkQJBAMDFOJK+ecGirXNP1P+0GA6DFSap9inJ\n"
    "BRTbwx+EmgwX966DUOefEOSpbDIVVSPs/Qr2LgtIMEFA7Y0+j3wZD3cCQBsTwccd\n"
    "ASQx59xakpq11eOlTYz14rjwodr4QMyj26WxEPJtz7hKokx/+EH6fWuPIUSrROM5\n"
    "07y2gaVbYxtis0s=\n"
    "-----END PRIVATE KEY-----\n";
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
    DTLSSocket *     q;
    QUdpSocket *     sock = nullptr;
    QCA::TLS *       tls;
    QString          host;
    bool             encrypted = false;
    bool             error     = false;
    bool             waiting   = false;
    QCA::Certificate cert;
    QCA::PrivateKey  privkey;
    QHostAddress     dstHost;
    quint16          dstPort = 0;

    Private(DTLSSocket *_q) : QObject(_q), q(_q)
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
        tls->setTrustedCertificates(QCA::systemStore());
        encrypted = false;
        error     = false;
        waiting   = false;
    }

    void connectToServer(const QHostAddress &host, quint16 port)
    {
        dstHost = host;
        dstPort = port;
        sock    = new QUdpSocket(this);
        connect(sock, &QUdpSocket::readyRead, this, &DTLSSocket::Private::sock_readyRead);
#if QT_VERSION >= QT_VERSION_CHECK(5, 15, 0)
        connect(sock, &QUdpSocket::errorOccurred, this,
                [this]() { qDebug("socket failed: %s", qPrintable(sock->errorString())); });
#else
        connect(sock, QOverload<QAbstractSocket::SocketError>::of(&QUdpSocket::error), this,
                [this](QAbstractSocket::SocketError) { qDebug("socket failed: %s", qPrintable(sock->errorString())); });
#endif

        QCA::CertificateCollection rootCerts = QCA::systemStore();

        // We add this one to show how, and to make it work with
        // the server example.
        rootCerts.addCertificate(cert);

        if (!QCA::haveSystemStore())
            qWarning("Warning: no root certs");
        else
            tls->setTrustedCertificates(rootCerts);

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
        DTLS_DEBUG("tls handshaken"); /*
         if (tls->peerIdentityResult() != QCA::TLS::Valid) {
             qWarning("peer identity not valid: %d", int(tls->peerIdentityResult()));
             sock->abort();
             tls->reset();
             error = true;
         } else {
             DTLS_DEBUG("valid");*/
        encrypted = true;
        tls->continueAfterStep();
        //}
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
            DTLS_DEBUG("%d bytes\n", buf.size());
            sock->writeDatagram(buf, dstHost, dstPort);
        }
    }

    void tls_closed() { DTLS_DEBUG("dtls closed"); }

    void tls_error() { DTLS_DEBUG("dtls error: %d", tls->errorCode()); }
};

DTLSSocket::DTLSSocket(QObject *parent) : QObject(parent) { d = new Private(this); }

DTLSSocket::~DTLSSocket() { delete d; }

void DTLSSocket::connectToServer(const QHostAddress &host, quint16 port) { d->connectToServer(host, port); }

QCA::TLS *DTLSSocket::tls() { return d->tls; }

void DTLSSocket::startServer(QUdpSocket *socket, const SourceAddress &destination)
{
    d->sock = socket;
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
    DTLS_DEBUG("write %d bytes\n", data.size());
    d->tls->write(data);
}

void DTLSSocket::handleIncomingSocketData(const QByteArray &data) { d->tls->writeIncoming(data); }

// ----------------
// DTLSServer
// ----------------
DTLSServer::DTLSServer(QObject *parent) : QObject(parent)
{
    socket = new QUdpSocket(this);
    connect(socket, &QUdpSocket::readyRead, this, &DTLSServer::sock_readyRead);
#if QT_VERSION >= QT_VERSION_CHECK(5, 15, 0)
    connect(socket, &QUdpSocket::errorOccurred, this, [this]() {
        qDebug("socket failed: %s", qPrintable(socket->errorString()));
        qApp->quit();
    });
#else
    connect(socket, QOverload<QAbstractSocket::SocketError>::of(&QUdpSocket::error), this,
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
            connect(dtlsSocket, &DTLSSocket::connected, this,
                    [dtlsSocket, this]() { Q_EMIT sessionReady(dtlsSocket); });
        }
        dtlsSocket->handleIncomingSocketData(ba);
    }
}

#include "dtlssocket.moc"
