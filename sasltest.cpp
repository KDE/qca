#include<qapplication.h>
#include"qca.h"

class SASLTest : public QObject
{
	Q_OBJECT
public:
	SASLTest()
	{
		/*sock = new QSocket;
		connect(sock, SIGNAL(connected()), SLOT(sock_connected()));
		connect(sock, SIGNAL(readyRead()), SLOT(sock_readyRead()));
		connect(sock, SIGNAL(connectionClosed()), SLOT(sock_connectionClosed()));
		connect(sock, SIGNAL(error(int)), SLOT(sock_error(int)));

		ssl = new QCA::SSL;
		connect(ssl, SIGNAL(handshaken(bool)), SLOT(ssl_handshaken(bool)));
		connect(ssl, SIGNAL(readyRead()), SLOT(ssl_readyRead()));
		connect(ssl, SIGNAL(readyReadOutgoing()), SLOT(ssl_readyReadOutgoing()));

		rootCerts.setAutoDelete(true);
		rootCerts = getRootCerts();
		//printf("deleting\n");
		//rootCerts.clear();*/
	}

	~SASLTest()
	{
		/*delete ssl;
		delete sock;*/
	}

	/*void start(const QString &_host)
	{
		int n = _host.find(':');
		int port;
		if(n != -1) {
			host = _host.mid(0, n);
			port = _host.mid(n+1).toInt();
		}
		else {
			host = _host;
			port = 443;
		}

		printf("Trying %s:%d...\n", host.latin1(), port);
		sock->connectToHost(host, port);
	}*/

signals:
	void quit();

/*private slots:
	void sock_connected()
	{
		printf("Connected, starting TLS handshake...\n");
		ssl->startClient(host, rootCerts);
	}

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
		printf("\nConnection closed.\n");
		quit();
	}

	void sock_error(int)
	{
		printf("\nSocket error.\n");
		quit();
	}

	void ssl_handshaken(bool b)
	{
		if(b) {
			cert = ssl->peerCertificate();
			int vr = ssl->certificateValidityResult();

			printf("Successful SSL handshake.\n");
			if(!cert.isNull())
				showCertInfo(cert);
			if(vr == QCA::SSL::Valid)
				printf("Valid certificate.\n");
			else
				printf("Invalid certificate: %s\n", resultToString(vr).latin1());

			printf("Let's try a GET request now.\n");
			QString req = "GET / HTTP/1.0\nHost: " + host + "\n\n";
			QCString cs = req.latin1();
			QByteArray buf(cs.length());
			memcpy(buf.data(), cs.data(), buf.size());
			ssl->write(buf);
		}
		else {
			printf("SSL Handshake Error!\n");
			quit();
		}
	}

	void ssl_readyRead()
	{
		QByteArray a = ssl->read();
		QCString cs;
		cs.resize(a.size()+1);
		memcpy(cs.data(), a.data(), a.size());
		printf("%s", cs.data());
	}

	void ssl_readyReadOutgoing()
	{
		QByteArray a = ssl->readOutgoing();
		sock->writeBlock(a.data(), a.size());
	}

private:
	QString host;
	QSocket *sock;
	QCA::SSL *ssl;
	QCA::Cert cert;
	QPtrList<QCA::Cert> rootCerts;*/
};

#include"sasltest.moc"

int main(int argc, char **argv)
{
	QApplication app(argc, argv, false);

	if(!QCA::isSupported(QCA::CAP_SASL)) {
		printf("SASL not supported!\n");
		return 1;
	}

	SASLTest *s = new SASLTest;
	QObject::connect(s, SIGNAL(quit()), &app, SLOT(quit()));
	//s->start(host);
	app.exec();
	delete s;

	return 0;
}
