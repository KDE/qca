#include<qapplication.h>
#include<qdom.h>
#include<qfile.h>
#include<qsocket.h>
#include<qserversocket.h>
#include<qtimer.h>
#include"qca.h"

class SecureServerTest : public QServerSocket
{
	Q_OBJECT
public:
	SecureServerTest(int _port) : QServerSocket(_port), port(_port)
	{
		sock = new QSocket;
		connect(sock, SIGNAL(readyRead()), SLOT(sock_readyRead()));
		connect(sock, SIGNAL(connectionClosed()), SLOT(sock_connectionClosed()));
		connect(sock, SIGNAL(error(int)), SLOT(sock_error(int)));
		connect(sock, SIGNAL(bytesWritten(int)), SLOT(sock_bytesWritten(int)));

		ssl = new QCA::SSL;
		connect(ssl, SIGNAL(handshaken(bool)), SLOT(ssl_handshaken(bool)));
		connect(ssl, SIGNAL(readyRead()), SLOT(ssl_readyRead()));
		connect(ssl, SIGNAL(readyReadOutgoing()), SLOT(ssl_readyReadOutgoing()));

		doFinish = false;
	}

	~SecureServerTest()
	{
		delete ssl;
		delete sock;
	}

	void start()
	{
		if(!ok()) {
			printf("Error binding to port %d!\n", port);
			QTimer::singleShot(0, this, SIGNAL(quit()));
			return;
		}
		printf("Listening on port %d ...\n", port);
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
		printf("Connection received!  Starting TLS handshake...\n");
		ssl->startServer(cert, privkey);
	}

signals:
	void quit();

private slots:
	void sock_readyRead()
	{
		QByteArray buf(sock->bytesAvailable());
		int num = sock->readBlock(buf.data(), buf.size());
		if(num < (int)buf.size())
			buf.resize(num);
		ssl->writeIncoming(buf);
	}

	void sock_connectionClosed()
	{
		printf("Connection closed.\n");
	}

	void sock_bytesWritten(int x)
	{
		if(doFinish) {
			printf("Closing.\n");
			sock->close();
			doFinish = false;
		}
	}

	void sock_error(int)
	{
		printf("Socket error.\n");
	}

	void ssl_handshaken(bool b)
	{
		if(b) {
			printf("Successful SSL handshake.  Waiting for newline.\n");
		}
		else {
			printf("SSL Handshake Error!  Closing.\n");
			sock->close();
		}
	}

	void ssl_readyRead()
	{
		QByteArray a = ssl->read();
		QString str =
			"<html>\n"
			"<head><title>Test</title></head>\n"
			"<body>this is only a test</body>\n"
			"</html>\n";
		QCString cs = str.latin1();
		QByteArray b(cs.length());
		memcpy(b.data(), cs.data(), b.size());

		printf("Sending test response...\n");
		doFinish = true;
		ssl->write(b);
	}

	void ssl_readyReadOutgoing()
	{
		QByteArray a = ssl->readOutgoing();
		sock->writeBlock(a.data(), a.size());
	}

private:
	bool doFinish;
	int port;
	QSocket *sock;
	QCA::SSL *ssl;
	QCA::Cert cert;
	QCA::RSAKey privkey;
};

#include"sslservtest.moc"

int main(int argc, char **argv)
{
	QApplication app(argc, argv);
	int port = argc > 1 ? QString(argv[1]).toInt() : 8000;

	if(!QCA::isSupported(QCA::CAP_SSL)) {
		printf("SSL not supported!\n");
		return 1;
	}

	SecureServerTest *s = new SecureServerTest(port);
	QObject::connect(s, SIGNAL(quit()), &app, SLOT(quit()));
	s->start();
	app.exec();
	delete s;

	return 0;
}
