#include<qapplication.h>
#include<qtimer.h>
#include<qsocket.h>
#include<qserversocket.h>
#include<stdio.h>
#include"base64.h"
#include"qca.h"

static QString prompt(const QString &s)
{
	printf("%s ", s.latin1());
	fflush(stdout);
	char line[256];
	fgets(line, 255, stdin);
	QString result = line;
	if(result[result.length()-1] == '\n')
		result.truncate(result.length()-1);
	printf("result: [%s]\n", result.latin1());
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
		connect(sasl, SIGNAL(authenticated(bool)), SLOT(sasl_authenticated(bool)));
	}

	~ClientTest()
	{
		delete sock;
		delete sasl;
	}

	void start(const QString &_host, int port)
	{
		mode = 0;
		host = _host;
		sock->connectToHost(host, port);
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
			s = "connection refused / timed out";
		else if(x == QSocket::ErrHostNotFound)
			s = "host not found";
		else if(x == QSocket::ErrSocketRead)
			s = "read error";

		printf("socket error: %s\n", s.latin1());
		quit();
	}

	void sock_readyRead()
	{
		if(sock->canReadLine()) {
			QString line = sock->readLine();
			line.truncate(line.length()-1); // chop the newline
			handleLine(line);
		}
	}

	void sasl_clientFirstStep(const QString &mech, const QByteArray *clientInit)
	{
		printf("choosing mech: %s\n", mech.latin1());
		QString line = mech;
		if(clientInit) {
			QCString cs(clientInit->data(), clientInit->size()+1);
			printf("clientInit: %s\n", cs.data());
			line += ' ';
			line += cs;
		}
		sendLine(line);
	}

	void sasl_nextStep(const QByteArray &stepData)
	{
		QCString cs(stepData.data(), stepData.size()+1);
		printf("nextStep: [%s]\n", cs.data());
		QString line = "C,";
		line += cs;
		sendLine(line);
	}

	void sasl_needParams(bool auth, bool user, bool pass, bool realm)
	{
		if(auth) {
			sasl->setAuthname(prompt("Authname:"));
		}
		if(user) {
			sasl->setUsername(prompt("Username:"));
		}
		if(pass) {
			sasl->setPassword(prompt("Password (not hidden!) :"));
		}
		if(realm) {
			sasl->setRealm(prompt("Realm:"));
		}
		sasl->continueAfterParams();
	}

	void sasl_authenticated(bool ok)
	{
		if(ok)
			sendLine("A,Success");
		else
			sendLine("E,Error");
		printf("authentication %s!\n", ok ? "success" : "failed");
	}

private:
	QSocket *sock;
	QCA::SASL *sasl;
	int mode;
	QString host;

	void handleLine(const QString &line)
	{
		printf("reading: [%s]\n", line.latin1());
		if(mode == 0) {
			// first line is the method list
			QStringList mechlist = QStringList::split(' ', line);
			++mode;

			// kick off the client
			if(!sasl->startClient("foo", host, mechlist)) {
				printf("Error starting client!\n");
				quit();
			}
		}
		else if(mode == 1) {
			int n = line.find(',');
			if(n == -1) {
				printf("bad format\n");
				quit();
				return;
			}
			QString type = line.mid(0, n);
			if(type == "C") {
				QString rest = line.mid(n+1);
				QCString cs = rest.latin1();
				QByteArray buf(cs.length());
				memcpy(buf.data(), cs.data(), buf.size());
				sasl->putStep(buf);
			}
			else if(type == "E") {
				printf("peer error\n");
				quit();
				return;
			}
			else if(type == "A") {
				printf("peer says we are authenticated\n");
				quit();
				return;
			}
			else {
				printf("bad format2\n");
				quit();
				return;
			}
		}
	}

	void sendLine(const QString &line)
	{
		printf("writing: {%s}\n", line.latin1());
		QString s = line + '\n';
		QCString cs = s.latin1();
		sock->writeBlock(cs.data(), cs.length());
	}
};

class ServerTest : public QServerSocket
{
	Q_OBJECT
public:
	ServerTest(const QString &_host, int _port) : QServerSocket(_port), host(_host), port(_port)
	{
		sock = new QSocket;
		connect(sock, SIGNAL(connectionClosed()), SLOT(sock_connectionClosed()));
		connect(sock, SIGNAL(readyRead()), SLOT(sock_readyRead()));
		connect(sock, SIGNAL(error(int)), SLOT(sock_error(int)));

		sasl = new QCA::SASL;
		connect(sasl, SIGNAL(nextStep(const QByteArray &)), SLOT(sasl_nextStep(const QByteArray &)));
		connect(sasl, SIGNAL(authenticated(bool)), SLOT(sasl_authenticated(bool)));
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
		printf("Listening on port %d ...\n", port);
		mode = 0;
	}

	void newConnection(int s)
	{
		// Note: only 1 connection supported at a time in this example!
		if(sock->isOpen()) {
			QSocket tmp;
			tmp.setSocket(s);
			printf("throwing away extra connection\n");
			return;
		}
		sock->setSocket(s);
		printf("Connection received!  Starting SASL handshake...\n");
		QStringList mechlist;
		if(!sasl->startServer("foo", host, QString::null, &mechlist)) {
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
		quit();
	}

	void sock_error(int x)
	{
		QString s;
		if(x == QSocket::ErrConnectionRefused)
			s = "connection refused / timed out";
		else if(x == QSocket::ErrHostNotFound)
			s = "host not found";
		else if(x == QSocket::ErrSocketRead)
			s = "read error";

		printf("socket error: %s\n", s.latin1());
		quit();
	}

	void sock_readyRead()
	{
		if(sock->canReadLine()) {
			QString line = sock->readLine();
			line.truncate(line.length()-1); // chop the newline
			handleLine(line);
		}
	}

	void sasl_nextStep(const QByteArray &stepData)
	{
		QCString cs(stepData.data(), stepData.size()+1);
		printf("nextStep: [%s]\n", cs.data());
		QString line = "C,";
		line += cs;
		sendLine(line);
	}

	void sasl_authenticated(bool ok)
	{
		if(ok)
			sendLine("A,Success");
		else
			sendLine("E,Error");
		printf("authentication %s!\n", ok ? "success" : "failed");
	}

private:
	QSocket *sock;
	QCA::SASL *sasl;
	QString host;
	int port;
	int mode;

	void handleLine(const QString &line)
	{
		printf("reading: [%s]\n", line.latin1());
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
			int n = line.find(',');
			if(n == -1) {
				printf("bad format\n");
				quit();
				return;
			}
			QString type = line.mid(0, n);
			if(type == "C") {
				QString rest = line.mid(n+1);
				QCString cs = rest.latin1();
				QByteArray buf(cs.length());
				memcpy(buf.data(), cs.data(), buf.size());
				sasl->putStep(buf);
			}
			else if(type == "E") {
				printf("peer error\n");
				quit();
				return;
			}
			else if(type == "A") {
				printf("peer says we are authenticated\n");
				quit();
				return;
			}
			else {
				printf("bad format2\n");
				quit();
				return;
			}
		}
	}

	void sendLine(const QString &line)
	{
		printf("writing: {%s}\n", line.latin1());
		QString s = line + '\n';
		QCString cs = s.latin1();
		sock->writeBlock(cs.data(), cs.length());
	}
};

#include"sasltest.moc"

void usage()
{
	printf("usage: sasltest client [host]\n");
	printf("       sasltest server [host]\n\n");
}

int main(int argc, char **argv)
{
	QApplication app(argc, argv, false);

	QString host;
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
		server = false;
	}
	else if(arg == "server") {
		if(argc < 3) {
			usage();
			return 0;
		}
		host = argv[2];
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
		ServerTest *s = new ServerTest(host, 8001);
		QObject::connect(s, SIGNAL(quit()), &app, SLOT(quit()));
		s->start();
		app.exec();
		delete s;
	}
	else {
		ClientTest *c = new ClientTest;
		QObject::connect(c, SIGNAL(quit()), &app, SLOT(quit()));
		c->start(host, 8001);
		app.exec();
		delete c;
	}

	return 0;
}
