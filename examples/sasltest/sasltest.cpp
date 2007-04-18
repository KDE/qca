/*
 Copyright (C) 2003-2006 Justin Karneges <justin@affinix.com>, Michail Pishchagin

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

#include <QCoreApplication>
#include <QTimer>
#include <QTcpSocket>
#include <QTcpServer>
#include <stdio.h>

#ifdef Q_OS_UNIX
#include <unistd.h>
#endif

// QtCrypto has the declarations for all of QCA
#include <QtCrypto>

#define PROTO_NAME "foo"
#define PROTO_PORT 8001

static QString prompt(const QString &s)
{
    printf("* %s ", s.toLatin1().data());
    fflush(stdout);
    char line[256];
    fgets(line, 255, stdin);
    QString result = line;
    if(result[result.length()-1] == '\n')
        result.truncate(result.length()-1);
    return result;
}

class ClientTest : public QObject
{
    Q_OBJECT
public:
    ClientTest()
    {
        sock = new QTcpSocket;
        connect(sock, SIGNAL(connected()), SLOT(sock_connected()));
        connect(sock, SIGNAL(disconnected()), SLOT(sock_connectionClosed()));
        connect(sock, SIGNAL(readyRead()), SLOT(sock_readyRead()));
        connect(sock, SIGNAL(error(QAbstractSocket::SocketError)), SLOT(sock_error(QAbstractSocket::SocketError)));

        sasl = new QCA::SASL;
        connect(sasl, SIGNAL(clientStarted(bool, const QByteArray &)), SLOT(sasl_clientFirstStep(bool, const QByteArray &)));
        connect(sasl, SIGNAL(nextStep(const QByteArray &)), SLOT(sasl_nextStep(const QByteArray &)));
        connect(sasl, SIGNAL(needParams(const QCA::SASL::Params &)), SLOT(sasl_needParams(const QCA::SASL::Params &)));
        connect(sasl, SIGNAL(authenticated()), SLOT(sasl_authenticated()));
        connect(sasl, SIGNAL(readyRead()), SLOT(sasl_readyRead()));
        connect(sasl, SIGNAL(readyReadOutgoing()), SLOT(sasl_readyReadOutgoing()));
        connect(sasl, SIGNAL(error()), SLOT(sasl_error()));
    }

    void start(const QString &_host, int port, const QString &user="", const QString &pass="")
    {
        mode = 0;
        host = _host;
        sock->connectToHost(host, port);
        sasl->setConstraints((QCA::SASL::AuthFlags)(QCA::SASL::AllowPlain | QCA::SASL::AllowAnonymous), 0, 256);

        if(!user.isEmpty()) {
            sasl->setUsername(user);
            sasl->setAuthzid(user);
        }
        if(!pass.isEmpty())
            sasl->setPassword(pass.toUtf8());
    }

    ~ClientTest()
    {
        delete sock;
        delete sasl;
    }

signals:
    void quit();

private slots:
    void sock_connected()
    {
        printf("Connected to server.  Awaiting mechanism list...\n");
    }

    void sock_connectionClosed()
    {
        printf("Connection closed by peer.\n");
        quit();
    }

    void sock_error(QAbstractSocket::SocketError x)
    {
        printSocketError(x);
        quit();
    }

    void sock_readyRead()
    {
        if(mode == 2) {
            int avail = sock->bytesAvailable();
            QByteArray a(avail, 0);
            int n = sock->read(a.data(), a.size());
            a.resize(n);
            printf("Read %d bytes\n", a.size());
            sasl->writeIncoming(a);
        }
        else {
            if(sock->canReadLine()) {
                QString line = sock->readLine();
                line.truncate(line.length()-1); // chop the newline
                handleLine(line);
            }
        }
    }

    void sasl_clientFirstStep(bool clientInit, const QByteArray &clientInitData)
    {
        ++mode;
        printf("Choosing mech: %s\n", sasl->mechanism().toLatin1().data());
        QString line = sasl->mechanism();
        if(clientInit) {
            line += ' ';
            line += arrayToString(clientInitData);
        }
        sendLine(line);
    }

    void sasl_nextStep(const QByteArray &stepData)
    {
        QString line = "C";
        if(!stepData.isEmpty()) {
            line += ',';
            line += arrayToString(stepData);
        }
        sendLine(line);
    }

    void sasl_needParams(const QCA::SASL::Params &params)
    {
        QString username;
        if(params.user || params.authzid)
            username = prompt("Username:");
        if(params.user) {
            sasl->setUsername(username);
        }
        if(params.authzid) {
            sasl->setAuthzid(username);
        }
        if(params.pass) {
            sasl->setPassword(prompt("Password (not hidden!):").toUtf8());
        }
        if(params.realm) {
            sasl->setRealm(prompt("Realm:"));
        }
        sasl->continueAfterParams();
    }

    void sasl_authenticated()
    {
        printf("SASL success!\n");
        printf("SSF: %d\n", sasl->ssf());
    }

    void sasl_readyRead()
    {
        QByteArray a = sasl->read();
        int oldsize = inbuf.size();
        inbuf.resize(oldsize + a.size());
        memcpy(inbuf.data() + oldsize, a.data(), a.size());
        processInbuf();
    }

    void sasl_readyReadOutgoing()
    {
        QByteArray a = sasl->readOutgoing();
        sock->write(a.data(), a.size());
    }

    void sasl_error()
    {
        printf("SASL error! Auth Condition = %d.\n", sasl->authCondition());
        quit();
        return;
    }

private:
    QTcpSocket *sock;
    QCA::SASL *sasl;
    int mode;
    QString host;
    QByteArray inbuf;

    QString arrayToString(const QByteArray &ba)
    {
        QCA::Base64 encoder;
        return encoder.arrayToString(ba);
    }

    QByteArray stringToArray(const QString &s)
    {
        QCA::Base64 decoder(QCA::Decode);
        return decoder.stringToArray(s).toByteArray();
    }

    void sendLine(const QString &line)
    {
        printf("Writing: {%s}\n", line.toUtf8().data());
        QString s = line + '\n';
        QByteArray a = s.toUtf8();
        if(mode == 2)
            sasl->write(a);
        else
            sock->write(a.data(), a.length());
    }

    void printSocketError(QAbstractSocket::SocketError x)
    {
        QString s;
        if(x == QAbstractSocket::ConnectionRefusedError)
            s = "connection refused or timed out";
        else if(x == QAbstractSocket::RemoteHostClosedError)
            s = "remote host closed the connection";
        else if(x == QAbstractSocket::HostNotFoundError)
            s = "host not found";
        else if(x == QAbstractSocket::SocketAccessError)
            s = "access error";
        else if(x == QAbstractSocket::SocketResourceError)
            s = "too many sockets";
        else if(x == QAbstractSocket::SocketTimeoutError)
            s = "operation timed out";
        else if(x == QAbstractSocket::DatagramTooLargeError)
            s = "datagram was larger than system limit";
        else if(x == QAbstractSocket::NetworkError)
            s = "network error";
        else if(x == QAbstractSocket::AddressInUseError)
            s = "address is already in use";
        else if(x == QAbstractSocket::SocketAddressNotAvailableError)
            s = "address does not belong to the host";
        else if(x == QAbstractSocket::UnsupportedSocketOperationError)
            s = "operation is not supported by the local operating system";
        else
            s = "unknown socket error";
        printf("Socket error: %s\n", s.toLatin1().data());
    }

    void processInbuf()
    {
        QStringList list;
        for(int n = 0; n < (int)inbuf.size(); ++n) {
            if(inbuf[n] == '\n') {
                list += QString::fromUtf8(inbuf.data(), n);

                char *p = inbuf.data();
                ++n;
                int x = inbuf.size() - n;
                memmove(p, p + n, x);
                inbuf.resize(x);

                // start over, basically
                n = -1;
            }
        }

        foreach(QString line, list)
            handleLine(line);
    }

    void handleLine(const QString &line)
    {
        printf("Reading: [%s]\n", line.toLatin1().data());
        if(mode == 0) {
            // first line is the method list
            QStringList mechlist = line.split(' ');
            sasl->startClient(PROTO_NAME, host, mechlist);
        }
        else if(mode == 1) {
            QString type, rest;
            int n = line.indexOf(',');
            if(n != -1) {
                type = line.mid(0, n);
                rest = line.mid(n+1);
            }
            else {
                type = line;
                rest = "";
            }

            if(type == "C") {
                sasl->putStep(stringToArray(rest));
            }
            else if(type == "E") {
                printf("Authentication failed.\n");
                quit();
                return;
            }
            else if(type == "A") {
                printf("Authentication success.\n");
                ++mode;
                sock_readyRead(); // any extra data?
                return;
            }
            else {
                printf("Bad format from peer, closing.\n");
                quit();
                return;
            }
        }
    }
};

#include "sasltest.moc"

void usage()
{
    printf("usage: sasltest host [user] [pass]\n");
}

int main(int argc, char **argv)
{
    QCA::Initializer init;
    QCoreApplication app(argc, argv);

    QString host, user, pass;
    QString str = "Hello, World";
    if(argc < 2) {
        usage();
        return 0;
    }
    host = argv[1];
    if(argc >= 3)
        user = argv[2];
    if(argc >= 4)
        pass = argv[3];

    if(!QCA::isSupported("sasl")) {
        printf("SASL not supported!\n");
        return 1;
    }

    ClientTest *c = new ClientTest;
    QObject::connect(c, SIGNAL(quit()), &app, SLOT(quit()));
    c->start(host, PROTO_PORT, user, pass);
    app.exec();
    delete c;

    return 0;
}
