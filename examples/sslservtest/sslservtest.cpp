#include<qapplication.h>
#include<qfile.h>
#include<qsocket.h>
#include<qserversocket.h>
#include<qvaluelist.h>
#include<qtimer.h>
#include"qca.h"

char pemdata_cert[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIDbjCCAtegAwIBAgIBADANBgkqhkiG9w0BAQQFADCBhzELMAkGA1UEBhMCVVMx\n"
	"EzARBgNVBAgTCkNhbGlmb3JuaWExDzANBgNVBAcTBklydmluZTEYMBYGA1UEChMP\n"
	"RXhhbXBsZSBDb21wYW55MRQwEgYDVQQDEwtleGFtcGxlLmNvbTEiMCAGCSqGSIb3\n"
	"DQEJARYTZXhhbXBsZUBleGFtcGxlLmNvbTAeFw0wMzA3MjQwNzMwMDBaFw0wMzA4\n"
	"MjMwNzMwMDBaMIGHMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEP\n"
	"MA0GA1UEBxMGSXJ2aW5lMRgwFgYDVQQKEw9FeGFtcGxlIENvbXBhbnkxFDASBgNV\n"
	"BAMTC2V4YW1wbGUuY29tMSIwIAYJKoZIhvcNAQkBFhNleGFtcGxlQGV4YW1wbGUu\n"
	"Y29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCobzCF268K2sRp473gvBTT\n"
	"4AgSL1kjeF8N57vxS1P8zWrWMXNs4LuH0NRZmKTajeboy0br8xw+smIy3AbaKAwW\n"
	"WZToesxebu3m9VeA8dqWyOaUMjoxAcgVYesgVaMpjRe7fcWdJnX1wJoVVPuIcO8m\n"
	"a+AAPByfTORbzpSTmXAQAwIDAQABo4HnMIHkMB0GA1UdDgQWBBTvFierzLmmYMq0\n"
	"cB/+5rK1bNR56zCBtAYDVR0jBIGsMIGpgBTvFierzLmmYMq0cB/+5rK1bNR566GB\n"
	"jaSBijCBhzELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExDzANBgNV\n"
	"BAcTBklydmluZTEYMBYGA1UEChMPRXhhbXBsZSBDb21wYW55MRQwEgYDVQQDEwtl\n"
	"eGFtcGxlLmNvbTEiMCAGCSqGSIb3DQEJARYTZXhhbXBsZUBleGFtcGxlLmNvbYIB\n"
	"ADAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBAUAA4GBAGqGhXf7xNOnYNtFO7gz\n"
	"K6RdZGHFI5q1DAEz4hhNBC9uElh32XGX4wN7giz3zLC8v9icL/W4ff/K5NDfv3Gf\n"
	"gQe/+Wo9Be3H3ul6uwPPFnx4+PIOF2a5TW99H9smyxWdNjnFtcUte4al3RszcMWG\n"
	"x3iqsWosGtj6F+ridmKoqKLu\n"
	"-----END CERTIFICATE-----\n";

char pemdata_privkey[] =
	"-----BEGIN RSA PRIVATE KEY-----\n"
	"MIICXAIBAAKBgQCobzCF268K2sRp473gvBTT4AgSL1kjeF8N57vxS1P8zWrWMXNs\n"
	"4LuH0NRZmKTajeboy0br8xw+smIy3AbaKAwWWZToesxebu3m9VeA8dqWyOaUMjox\n"
	"AcgVYesgVaMpjRe7fcWdJnX1wJoVVPuIcO8ma+AAPByfTORbzpSTmXAQAwIDAQAB\n"
	"AoGAP83u+aYghuIcaWhmM03MLf69z/WztKYSi/fu0BcS977w67bL3MC9CVPoPRB/\n"
	"0nLSt/jZIuRzHKUCYfXLerSU7v0oXDTy6GPzWMh/oXIrpF0tYNbwWF7LSq2O2gGZ\n"
	"XtA9MSmUNNJaKzQQeXjqdVFOY8A0Pho+k2KByBiCi+ChkcECQQDRUuyX0+PKJtA2\n"
	"M36BOTFpy61BAv+JRlXUnHuevOfQWl6NR6YGygqCyH1sWtP1sa9S4wWys3DFH+5A\n"
	"DkuAqk7zAkEAzf4eUH2hp5CIMsXH+WpIzKj09oY1it2CAKjVq4rUELf8iXvmGoFl\n"
	"000spua4MjHNUYm7LR0QaKesKrMyGZUesQJAL8aLdYPJI+SD9Tr/jqLtIkZ4frQe\n"
	"eshw4pvsoyheiHF3zyshO791crAr4EVCx3sMlxB1xnmqLXPCPyCEHxO//QJBAIBY\n"
	"IYkjDZJ6ofGIe1UyXJNvfdkPu9J+ut4wU5jjEcgs6mK62J6RGuFxhy2iOQfFMdjo\n"
	"yL+OCUg7mDCun7uCxrECQAtSvnLOFMjO5qExRjFtwi+b1rcSekd3Osk/izyRFSzg\n"
	"Or+AL56/EKfiogNnFipgaXIbb/xj785Cob6v96XoW1I=\n"
	"-----END RSA PRIVATE KEY-----\n";

class LayerTracker
{
public:
	struct Item
	{
		int plain;
		int encoded;
	};

	LayerTracker()
	{
		p = 0;
	}

	void reset()
	{
		p = 0;
		list.clear();
	}

	void addPlain(int plain)
	{
		p += plain;
	}

	void specifyEncoded(int encoded, int plain)
	{
		// can't specify more bytes than we have
		if(plain > p)
			plain = p;
		p -= plain;
		Item i;
		i.plain = plain;
		i.encoded = encoded;
		list += i;
	}

	int finished(int encoded)
	{
		int plain = 0;
		for(QValueList<Item>::Iterator it = list.begin(); it != list.end();) {
			Item &i = *it;

			// not enough?
			if(encoded < i.encoded) {
				i.encoded -= encoded;
				break;
			}

			encoded -= i.encoded;
			plain += i.plain;
			it = list.remove(it);
		}
		return plain;
	}

	int p;
	QValueList<Item> list;
};

class SecureServerTest : public QServerSocket
{
	Q_OBJECT
public:
	enum { Idle, Handshaking, Active, Closing };

	SecureServerTest(int _port) : QServerSocket(_port), port(_port)
	{
		sock = new QSocket;
		connect(sock, SIGNAL(readyRead()), SLOT(sock_readyRead()));
		connect(sock, SIGNAL(connectionClosed()), SLOT(sock_connectionClosed()));
		connect(sock, SIGNAL(error(int)), SLOT(sock_error(int)));
		connect(sock, SIGNAL(bytesWritten(int)), SLOT(sock_bytesWritten(int)));

		ssl = new QCA::TLS;
		connect(ssl, SIGNAL(handshaken()), SLOT(ssl_handshaken()));
		connect(ssl, SIGNAL(readyRead()), SLOT(ssl_readyRead()));
		connect(ssl, SIGNAL(readyReadOutgoing(int)), SLOT(ssl_readyReadOutgoing(int)));
		connect(ssl, SIGNAL(closed()), SLOT(ssl_closed()));
		connect(ssl, SIGNAL(error(int)), SLOT(ssl_error(int)));

		cert.fromPEM(pemdata_cert);
		privkey.fromPEM(pemdata_privkey);

		mode = Idle;
	}

	~SecureServerTest()
	{
		delete ssl;
		delete sock;
	}

	void start()
	{
		if(cert.isNull() || privkey.isNull()) {
			printf("Error loading cert and/or private key!\n");
			QTimer::singleShot(0, this, SIGNAL(quit()));
			return;
		}
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
		mode = Handshaking;
		sock->setSocket(s);
		printf("Connection received!  Starting TLS handshake...\n");
		ssl->setCertificate(cert, privkey);
		ssl->startServer();
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
		if(mode == Active && sent) {
			int bytes = layer.finished(x);
			bytesLeft -= bytes;

			if(bytesLeft == 0) {
				mode = Closing;
				printf("SSL shutdown\n");
				ssl->close();
			}
		}
	}

	void sock_error(int)
	{
		printf("Socket error.\n");
	}

	void ssl_handshaken()
	{
		printf("Successful SSL handshake.  Waiting for newline.\n");
		layer.reset();
		bytesLeft = 0;
		sent = false;
		mode = Active;
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
		sent = true;
		layer.addPlain(b.size());
		ssl->write(b);
	}

	void ssl_readyReadOutgoing(int plainBytes)
	{
		QByteArray a = ssl->readOutgoing();
		layer.specifyEncoded(a.size(), plainBytes);
		sock->writeBlock(a.data(), a.size());
	}

	void ssl_closed()
	{
		printf("Closing.\n");
		sock->close();
	}

	void ssl_error(int x)
	{
		if(x == QCA::TLS::ErrHandshake) {
			printf("SSL Handshake Error!  Closing.\n");
			sock->close();
		}
		else {
			printf("SSL Error!  Closing.\n");
			sock->close();
		}
	}

private:
	int port;
	QSocket *sock;
	QCA::TLS *ssl;
	QCA::Cert cert;
	QCA::RSAKey privkey;

	bool sent;
	int mode;
	int bytesLeft;
	LayerTracker layer;
};

#include"sslservtest.moc"

int main(int argc, char **argv)
{
	QApplication app(argc, argv, false);
	int port = argc > 1 ? QString(argv[1]).toInt() : 8000;

	if(!QCA::isSupported(QCA::CAP_TLS)) {
		printf("TLS not supported!\n");
		return 1;
	}

	SecureServerTest *s = new SecureServerTest(port);
	QObject::connect(s, SIGNAL(quit()), &app, SLOT(quit()));
	s->start();
	app.exec();
	delete s;

	return 0;
}
