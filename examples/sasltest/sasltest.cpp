/*
 Copyright (C) 2003 Justin Karneges

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

// TODO: this code needs to be updated for QCA2
#include<qapplication.h>
#include<qtimer.h>
#include<qsocket.h>
#include<qserversocket.h>
#include<stdio.h>

#ifdef Q_OS_UNIX
#include<unistd.h>
#endif

#include"base64.h"
#include"qca.h"

#define PROTO_NAME "foo"
#define PROTO_PORT 8001

static QString prompt(const QString &s)
{
	printf("* %s ", s.latin1());
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
		sock = new QSocket;
		connect(sock, SIGNAL(connected()), SLOT(sock_connected()));
		connect(sock, SIGNAL(connectionClosed()), SLOT(sock_connectionClosed()));
		connect(sock, SIGNAL(readyRead()), SLOT(sock_readyRead()));
		connect(sock, SIGNAL(error(int)), SLOT(sock_error(int)));

		sasl = new QCA::SASL;
		connect(sasl, SIGNAL(clientFirstStep(const QString &, const QByteArray *)), SLOT(sasl_clientFirstStep(const QString &, const QByteArray *)));
		connect(sasl, SIGNAL(nextStep(const QByteArray &)), SLOT(sasl_nextStep(const QByteArray &)));
		connect(sasl, SIGNAL(needParams(bool, bool, bool, bool)), SLOT(sasl_needParams(bool, bool, bool, bool)));
		connect(sasl, SIGNAL(authenticated()), SLOT(sasl_authenticated()));
		connect(sasl, SIGNAL(readyRead()), SLOT(sasl_readyRead()));
		connect(sasl, SIGNAL(readyReadOutgoing(int)), SLOT(sasl_readyReadOutgoing(int)));
		connect(sasl, SIGNAL(error(int)), SLOT(sasl_error(int)));
	}

	~ClientTest()
	{
		delete sock;
		delete sasl;
	}

	void start(const QString &_host, int port, const QString &user="", const QString &pass="")
	{
		mode = 0;
		host = _host;
		sock->connectToHost(host, port);
		sasl->setMinimumSSF(0);
		sasl->setMaximumSSF(256);

		if(!user.isEmpty()) {
			sasl->setUsername(user);
			sasl->setAuthzid(user);
		}
		if(!pass.isEmpty())
			sasl->setPassword(pass);
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

	void sock_error(int x)
	{
		QString s;
		if(x == QSocket::ErrConnectionRefused)
			s = "connection refused or timed out";
		else if(x == QSocket::ErrHostNotFound)
			s = "host not found";
		else if(x == QSocket::ErrSocketRead)
			s = "read error";

		printf("Socket error: %s\n", s.latin1());
		quit();
	}

	void sock_readyRead()
	{
		if(mode == 2) {
			int avail = sock->bytesAvailable();
			QByteArray a(avail);
			int n = sock->readBlock(a.data(), a.size());
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

	void sasl_clientFirstStep(const QString &mech, const QByteArray *clientInit)
	{
		printf("Choosing mech: %s\n", mech.latin1());
		QString line = mech;
		if(clientInit) {
			QCString cs(clientInit->data(), clientInit->size()+1);
			line += ' ';
			line += cs;
		}
		sendLine(line);
	}

	void sasl_nextStep(const QByteArray &stepData)
	{
		QCString cs(stepData.data(), stepData.size()+1);
		QString line = "C";
		if(!stepData.isEmpty()) {
			line += ',';
			line += cs;
		}
		sendLine(line);
	}

	void sasl_needParams(bool user, bool authzid, bool pass, bool realm)
	{
		QString username;
		if(user || authzid)
			username = prompt("Username:");
		if(user) {
			sasl->setUsername(username);
		}
		if(authzid) {
			sasl->setAuthzid(username);
		}
		if(pass) {
			sasl->setPassword(prompt("Password (not hidden!) :"));
		}
		if(realm) {
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

	void sasl_readyReadOutgoing(int)
	{
		QByteArray a = sasl->readOutgoing();
		sock->writeBlock(a.data(), a.size());
	}

	void sasl_error(int)
	{
		printf("SASL error!\n");
		quit();
		return;
	}

private:
	QSocket *sock;
	QCA::SASL *sasl;
	int mode;
	QString host;
	QByteArray inbuf;

	void processInbuf()
	{
		QStringList list;
		for(int n = 0; n < (int)inbuf.size(); ++n) {
			if(inbuf[n] == '\n') {
				QCString cs(inbuf.data(), n+1);
				char *p = inbuf.data();
				++n;
				int x = inbuf.size() - n;
				memmove(p, p + n, x);
				inbuf.resize(x);
				list += QString::fromUtf8(cs);
				// start over, basically
				n = -1;
			}
		}

		for(QStringList::ConstIterator it = list.begin(); it != list.end(); ++it)
			handleLine(*it);
	}

	void handleLine(const QString &line)
	{
		printf("Reading: [%s]\n", line.latin1());
		if(mode == 0) {
			// first line is the method list
			QStringList mechlist = QStringList::split(' ', line);
			++mode;

			// kick off the client
			sasl->setAllowAnonymous(false);
			if(!sasl->startClient(PROTO_NAME, host, mechlist)) {
				printf("Error starting client!\n");
				quit();
			}
		}
		else if(mode == 1) {
			QString type, rest;
			int n = line.find(',');
			if(n != -1) {
				type = line.mid(0, n);
				rest = line.mid(n+1);
			}
			else {
				type = line;
				rest = "";
			}

			if(type == "C") {
				QCString cs = rest.latin1();
				QByteArray buf(cs.length());
				memcpy(buf.data(), cs.data(), buf.size());
				sasl->putStep(buf);
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
		else {
		}
	}

	void sendLine(const QString &line)
	{
		printf("Writing: {%s}\n", line.latin1());
		QString s = line + '\n';
		QCString cs = s.latin1();
		if(mode == 2) {
			QByteArray a(cs.length());
			memcpy(a.data(), cs.data(), a.size());
			sasl->write(a);
		}
		else
			sock->writeBlock(cs.data(), cs.length());
	}
};

class ServerTest : public QServerSocket
{
	Q_OBJECT
public:
	ServerTest(const QString &_str, int _port) : QServerSocket(_port), port(_port)
	{
		sock = 0;
		sasl = 0;
		realm = QString::null;
		str = _str;
	}

	~ServerTest()
	{
		delete sock;
		delete sasl;
	}

	void start()
	{
		if(!ok()) {
			printf("Error binding to port %d!\n", port);
			QTimer::singleShot(0, this, SIGNAL(quit()));
			return;
		}
		char myhostname[256];
		int r = gethostname(myhostname, sizeof(myhostname)-1);
		if(r == -1) {
			printf("Error getting hostname!\n");
			QTimer::singleShot(0, this, SIGNAL(quit()));
			return;
		}
		host = myhostname;
		printf("Listening on %s:%d ...\n", host.latin1(), port);
	}

	void newConnection(int s)
	{
		// Note: only 1 connection supported at a time in this example!
		if(sock) {
			QSocket tmp;
			tmp.setSocket(s);
			printf("Connection ignored, already have one active.\n");
			return;
		}

		printf("Connection received!  Starting SASL handshake...\n");

		sock = new QSocket;
		connect(sock, SIGNAL(connectionClosed()), SLOT(sock_connectionClosed()));
		connect(sock, SIGNAL(readyRead()), SLOT(sock_readyRead()));
		connect(sock, SIGNAL(error(int)), SLOT(sock_error(int)));
		connect(sock, SIGNAL(bytesWritten(int)), SLOT(sock_bytesWritten(int)));

		sasl = new QCA::SASL;
		connect(sasl, SIGNAL(authCheck(const QString &, const QString &)), SLOT(sasl_authCheck(const QString &, const QString &)));
		connect(sasl, SIGNAL(nextStep(const QByteArray &)), SLOT(sasl_nextStep(const QByteArray &)));
		connect(sasl, SIGNAL(authenticated()), SLOT(sasl_authenticated()));
		connect(sasl, SIGNAL(readyRead()), SLOT(sasl_readyRead()));
		connect(sasl, SIGNAL(readyReadOutgoing(int)), SLOT(sasl_readyReadOutgoing(int)));
		connect(sasl, SIGNAL(error(int)), SLOT(sasl_error(int)));

		sock->setSocket(s);
		mode = 0;
		inbuf.resize(0);

		sasl->setMinimumSSF(0);
		sasl->setMaximumSSF(256);

		QStringList mechlist;
		if(!sasl->startServer(PROTO_NAME, host, realm, &mechlist)) {
			printf("Error starting server!\n");
			quit();
		}
		QString str;
		bool first = true;
		for(QStringList::ConstIterator it = mechlist.begin(); it != mechlist.end(); ++it) {
			if(!first)
				str += ' ';
			str += *it;
			first = false;
		}
		sendLine(str);
	}

signals:
	void quit();

private slots:
	void sock_connectionClosed()
	{
		printf("Connection closed by peer.\n");
		close();
	}

	void sock_error(int x)
	{
		QString s;
		if(x == QSocket::ErrConnectionRefused)
			s = "connection refused or timed out";
		else if(x == QSocket::ErrHostNotFound)
			s = "host not found";
		else if(x == QSocket::ErrSocketRead)
			s = "read error";

		printf("Socket error: %s\n", s.latin1());
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

	void sock_bytesWritten(int x)
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
		QCString cs(stepData.data(), stepData.size()+1);
		QString line = "C";
		if(!stepData.isEmpty()) {
			line += ',';
			line += cs;
		}
		sendLine(line);
	}

	void sasl_authCheck(const QString &user, const QString &authzid)
	{
		printf("AuthCheck: User: [%s], Authzid: [%s]\n", user.latin1(), authzid.latin1());
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

	void sasl_readyReadOutgoing(int)
	{
		QByteArray a = sasl->readOutgoing();
		toWrite = a.size();
		sock->writeBlock(a.data(), a.size());
	}

	void sasl_error(int x)
	{
		if(x == QCA::SASL::ErrAuth) {
			sendLine("E");
			printf("Authentication failed.\n");
			close();
		}
		else {
			printf("SASL security layer error!\n");
			close();
		}
	}

private:
	QSocket *sock;
	QCA::SASL *sasl;
	QString host, realm;
	int port;
	int mode;
	QString str;
	QByteArray inbuf;
	int toWrite;

	void processInbuf()
	{
	}

	void handleLine(const QString &line)
	{
		printf("Reading: [%s]\n", line.latin1());
		if(mode == 0) {
			int n = line.find(' ');
			if(n != -1) {
				QString mech = line.mid(0, n);
				QCString cs = line.mid(n+1).latin1();
				QByteArray clientInit(cs.length());
				memcpy(clientInit.data(), cs.data(), clientInit.size());
				sasl->putServerFirstStep(mech, clientInit);
			}
			else
				sasl->putServerFirstStep(line);
			++mode;
		}
		else if(mode == 1) {
			QString type, rest;
			int n = line.find(',');
			if(n != -1) {
				type = line.mid(0, n);
				rest = line.mid(n+1);
			}
			else {
				type = line;
				rest = "";
			}

			if(type == "C") {
				QCString cs = rest.latin1();
				QByteArray buf(cs.length());
				memcpy(buf.data(), cs.data(), buf.size());
				sasl->putStep(buf);
			}
			else {
				printf("Bad format from peer, closing.\n");
				close();
				return;
			}
		}
	}

	void sendLine(const QString &line)
	{
		printf("Writing: {%s}\n", line.latin1());
		QString s = line + '\n';
		QCString cs = s.latin1();
		if(mode == 2) {
			QByteArray a(cs.length());
			memcpy(a.data(), cs.data(), a.size());
			sasl->write(a);
		}
		else
			sock->writeBlock(cs.data(), cs.length());
	}

	void close()
	{
		sock->deleteLater();
		sock = 0;
		delete sasl;
		sasl = 0;
	}
};

#include"sasltest.moc"

void usage()
{
	printf("usage: sasltest client [host] [user] [pass]\n");
	printf("       sasltest server [string]\n\n");
}

int main(int argc, char **argv)
{
	QApplication app(argc, argv, false);

	QString host, user, pass;
	QString str = "Hello, World";
	bool server;
	if(argc < 2) {
		usage();
		return 0;
	}
	QString arg = argv[1];
	if(arg == "client") {
		if(argc < 3) {
			usage();
			return 0;
		}
		host = argv[2];
		if(argc >= 4)
			user = argv[3];
		if(argc >= 5)
			pass = argv[4];
		server = false;
	}
	else if(arg == "server") {
		if(argc >= 3)
			str = argv[2];
		server = true;
	}
	else {
		usage();
		return 0;
	}

	if(!QCA::isSupported(QCA::CAP_SASL)) {
		printf("SASL not supported!\n");
		return 1;
	}

	if(server) {
		ServerTest *s = new ServerTest(str, PROTO_PORT);
		QObject::connect(s, SIGNAL(quit()), &app, SLOT(quit()));
		s->start();
		app.exec();
		delete s;
	}
	else {
		ClientTest *c = new ClientTest;
		QObject::connect(c, SIGNAL(quit()), &app, SLOT(quit()));
		c->start(host, PROTO_PORT, user, pass);
		app.exec();
		delete c;
	}

	return 0;
}
