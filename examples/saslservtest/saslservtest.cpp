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

#define PROTO_NAME "qcatest"
#define PROTO_PORT 8001

class ServerTest : public QTcpServer
{
	Q_OBJECT
public:
	ServerTest(const QString &_str, const QString &_host, int _port) : port(_port)
	{
		sock = 0;
		sasl = 0;

                connect(this, SIGNAL(newConnection()), SLOT(serv_newConnection()));
		realm.clear();
		str = _str;
		host = _host;
	}

    	~ServerTest()
	{
		delete sock;
		delete sasl;
	}

	void start()
	{
		if(!listen(QHostAddress::Any, port)) {
			printf("Error binding to port %d!\n", port);
			QTimer::singleShot(0, this, SIGNAL(quit()));
			return;
		}

		/*char myhostname[256];
		int r = gethostname(myhostname, sizeof(myhostname)-1);
		if(r == -1) {
			printf("Error getting hostname!\n");
			QTimer::singleShot(0, this, SIGNAL(quit()));
			return;
		}
		host = myhostname;*/

		printf("Listening on %s:%d ...\n", host.toLatin1().data(), port);
	}

private slots:
	void serv_newConnection()
	{
		// Note: only 1 connection supported at a time in this example!
		if(sock) {
			delete nextPendingConnection();
			printf("Connection ignored, already have one active.\n");
			return;
		}

		printf("Connection received!  Starting SASL handshake...\n");

		sock = nextPendingConnection();
		connect(sock, SIGNAL(disconnected()), SLOT(sock_connectionClosed()));
		connect(sock, SIGNAL(readyRead()), SLOT(sock_readyRead()));
		connect(sock, SIGNAL(error(QAbstractSocket::SocketError)), SLOT(sock_error(QAbstractSocket::SocketError)));
		connect(sock, SIGNAL(bytesWritten(qint64)), SLOT(sock_bytesWritten(qint64)));

		sasl = new QCA::SASL;
		connect(sasl, SIGNAL(authCheck(const QString &, const QString &)), SLOT(sasl_authCheck(const QString &, const QString &)));
		connect(sasl, SIGNAL(nextStep(const QByteArray &)), SLOT(sasl_nextStep(const QByteArray &)));
		connect(sasl, SIGNAL(authenticated()), SLOT(sasl_authenticated()));
		connect(sasl, SIGNAL(readyRead()), SLOT(sasl_readyRead()));
		connect(sasl, SIGNAL(readyReadOutgoing()), SLOT(sasl_readyReadOutgoing()));
		connect(sasl, SIGNAL(error()), SLOT(sasl_error()));
		connect(sasl, SIGNAL(serverStarted()), SLOT(sasl_serverStarted()));

		mode = 0;
		inbuf.resize(0);

		sasl->setConstraints((QCA::SASL::AuthFlags)(QCA::SASL::AllowPlain | QCA::SASL::AllowAnonymous), 0, 256);

		sasl->startServer(PROTO_NAME, host, realm);
	}

signals:
	void quit();

private slots:
	void sasl_serverStarted()
	{
		sendLine(sasl->mechanismList().join(" "));
	}

	void sock_connectionClosed()
	{
		printf("Connection closed by peer.\n");
		close();
	}

	void sock_error(QAbstractSocket::SocketError x)
	{
		printSocketError(x);
		close();
	}

	void sock_readyRead()
	{
		if(sock->canReadLine()) {
			QString line = sock->readLine();
			line.truncate(line.length()-1); // chop the newline
			handleLine(line);
		}
	}

	void sock_bytesWritten(qint64 x)
	{
		if(mode == 2) {
			toWrite -= x;
			if(toWrite <= 0) {
				printf("Sent, closing.\n");
				close();
			}
		}
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

	void sasl_authCheck(const QString &user, const QString &authzid)
	{
		printf("AuthCheck: User: [%s], Authzid: [%s]\n", user.toLatin1().data(), authzid.toLatin1().data());
		sasl->continueAfterAuthCheck();
	}

	void sasl_authenticated()
	{
		sendLine("A");
		printf("Authentication success.\n");
		++mode;
		printf("SSF: %d\n", sasl->ssf());
		sendLine(str);
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
		toWrite = a.size();
		sock->write(a.data(), a.size());
	}

	void sasl_error()
	{
		QCA::SASL::Error x = sasl->errorCode();
		if(x == QCA::SASL::ErrorInit) {
			printf("Problem starting up SASL\n");
			quit();
		}
		else if(x == QCA::SASL::ErrorHandshake) {
			sendLine("E");
			printf("Authentication failed. AuthCondition = %d.\n", sasl->authCondition());
                        if ( sasl->authCondition() == QCA::SASL::NoUser ) {
                            printf( "No user!\n" );
                        }
			close();
		}
		else if(x == QCA::SASL::ErrorCrypt) {
			printf("SASL security layer error!\n");
			close();
		}
	}


private:
	QString host, realm;
	int port;
	QString str;
	QByteArray inbuf;
	int toWrite;
    	QTcpSocket *sock;
	QCA::SASL *sasl;
	int mode;


	void processInbuf()
	{
	}

	void handleLine(const QString &line)
	{
		printf("Reading: [%s]\n", line.toLatin1().data());
		if(mode == 0) {
			int n = line.indexOf(' ');
			if(n != -1) {
				QString mech = line.mid(0, n);
				QString rest = line.mid(n+1).toUtf8();
				sasl->putServerFirstStep(mech, stringToArray(rest));
			}
			else
				sasl->putServerFirstStep(line);
			++mode;
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
			else {
				printf("Bad format from peer, closing.\n");
				close();
				return;
			}
		}
	}

	void close()
	{
		delete sasl;
		sock->deleteLater();
		sock = 0;
		sasl = 0;
	}

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
};

#include "saslservtest.moc"

void usage()
{
	printf("usage: saslservtest domain [message]\n");
}

int main(int argc, char **argv)
{
	QCA::Initializer init;
	QCoreApplication app(argc, argv);

	if(argc < 2)
	{
		usage();
		return 0;
	}

	QString host = argv[1];
	QString str = "Hello, World";
	if(argc >= 3)
		str = argv[2];

	if(!QCA::isSupported("sasl")) {
		printf("SASL not supported!\n");
		return 1;
	}

	QCA::setAppName("saslservtest");

        ServerTest *s = new ServerTest(str, host, PROTO_PORT);
        QObject::connect(s, SIGNAL(quit()), &app, SLOT(quit()));
        s->start();
        app.exec();
        delete s;

	return 0;
}
