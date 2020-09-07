/*
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

#ifndef TLSSOCKET_H

#include <QAbstractSocket>
#include <QHostAddress>
#include <QIODevice>
#include <QtCrypto>

struct SourceAddress
{
    QHostAddress host;
    quint16      port;

    bool operator==(const SourceAddress &other) const
    {
        return host == other.host && port == other.port;
    }
};

class QUdpSocket;
class SimpleLogger : public QCA::AbstractLogDevice
{
    Q_OBJECT
public:
    SimpleLogger(QObject *parent)
        : QCA::AbstractLogDevice(QLatin1String("simplelogger"), parent)
    {
    }

    void logTextMessage(const QString &message, QCA::Logger::Severity severity) override;
    void logBinaryMessage(const QByteArray &blob, QCA::Logger::Severity severity) override;
};

class DTLSSocket : public QObject
{
    Q_OBJECT
public:
    DTLSSocket(QObject *parent = nullptr);
    ~DTLSSocket() override;

    void connectToServer(const QHostAddress &host, quint16 port);
    void startServer(QUdpSocket *socket, const SourceAddress &destination);

    QCA::TLS *tls();

    QByteArray readDatagram();
    void       writeDatagram(const QByteArray &data);
Q_SIGNALS:
    void connected();
    void errorOccurred(QAbstractSocket::SocketError);
    void readyRead();

private:
    class Private;
    friend class Private;
    Private *d;
    friend class DTLSServer;
    void handleIncomingSocketData(const QByteArray &data);
};

Q_DECL_PURE_FUNCTION inline uint qHash(const SourceAddress &addr, uint seed = 0) Q_DECL_NOTHROW
{
    return qHash(addr.host, seed) ^ qHash(addr.port, seed);
}

class DTLSServer : public QObject
{
    Q_OBJECT
public:
    DTLSServer(QObject *parent = nullptr);
    bool start(const QHostAddress &      address,
               quint16                   port = 0,
               QAbstractSocket::BindMode mode = QAbstractSocket::DefaultForPlatform);
Q_SIGNALS:
    void incomingConnection(DTLSSocket *);
    void sessionReady(DTLSSocket *);
private Q_SLOTS:
    void sock_readyRead();

private:
    QUdpSocket *                       socket;
    QHash<SourceAddress, DTLSSocket *> clientSockets;
};

#endif
