#include<qapplication.h>
#include<qdom.h>
#include<qfile.h>
#include<qsocket.h>
#include<qptrlist.h>
#include"base64.h"
#include"qca.h"

QCA::Cert readCertXml(const QDomElement &e)
{
	QCA::Cert cert;
	// there should be one child data tag
	QDomElement data = e.elementsByTagName("data").item(0).toElement();
	if(!data.isNull())
		cert.fromDER(Base64::stringToArray(data.text()));
	return cert;
}

void showCertInfo(const QCA::Cert &cert)
{
	printf("-- Cert --\n");
	printf(" CN: %s\n", cert.subject()["CN"].latin1());
	printf(" Valid from: %s, until %s\n",
		cert.notBefore().toString().latin1(),
		cert.notAfter().toString().latin1());
	printf(" PEM:\n%s\n", cert.toPEM().latin1());
}

QPtrList<QCA::Cert> getRootCerts(const QString &store)
{
	QPtrList<QCA::Cert> list;

	// open the Psi rootcerts file
	QFile f(store);
	if(!f.open(IO_ReadOnly)) {
		printf("unable to open %s\n", f.name().latin1());
		return list;
	}
	QDomDocument doc;
	doc.setContent(&f);
	f.close();

	QDomElement base = doc.documentElement();
	if(base.tagName() != "store") {
		printf("wrong format of %s\n", f.name().latin1());
		return list;
	}
	QDomNodeList cl = base.elementsByTagName("certificate");
	if(cl.count() == 0) {
		printf("no certs found in %s\n", f.name().latin1());
		return list;
	}

	int num = 0;
	for(int n = 0; n < (int)cl.count(); ++n) {
		QCA::Cert *cert = new QCA::Cert(readCertXml(cl.item(n).toElement()));
		if(cert->isNull()) {
			printf("error reading cert\n");
			delete cert;
			continue;
		}

		++num;
		list.append(cert);
	}
	printf("imported %d root certs\n", num);

	return list;
}

QString resultToString(int result)
{
	QString s;
	switch(result) {
		case QCA::TLS::NoCert:
			s = QObject::tr("No certificate presented.");
			break;
		case QCA::TLS::Valid:
			break;
		case QCA::TLS::HostMismatch:
			s = QObject::tr("Hostname mismatch.");
			break;
		case QCA::TLS::Rejected:
			s = QObject::tr("Root CA rejects the specified purpose.");
			break;
		case QCA::TLS::Untrusted:
			s = QObject::tr("Not trusted for the specified purpose.");
			break;
		case QCA::TLS::SignatureFailed:
			s = QObject::tr("Invalid signature.");
			break;
		case QCA::TLS::InvalidCA:
			s = QObject::tr("Invalid CA certificate.");
			break;
		case QCA::TLS::InvalidPurpose:
			s = QObject::tr("Invalid certificate purpose.");
			break;
		case QCA::TLS::SelfSigned:
			s = QObject::tr("Certificate is self-signed.");
			break;
		case QCA::TLS::Revoked:
			s = QObject::tr("Certificate has been revoked.");
			break;
		case QCA::TLS::PathLengthExceeded:
			s = QObject::tr("Maximum cert chain length exceeded.");
			break;
		case QCA::TLS::Expired:
			s = QObject::tr("Certificate has expired.");
			break;
		case QCA::TLS::Unknown:
		default:
			s = QObject::tr("General validation error.");
			break;
	}
	return s;
}

class SecureTest : public QObject
{
	Q_OBJECT
public:
	SecureTest()
	{
		sock = new QSocket;
		connect(sock, SIGNAL(connected()), SLOT(sock_connected()));
		connect(sock, SIGNAL(readyRead()), SLOT(sock_readyRead()));
		connect(sock, SIGNAL(connectionClosed()), SLOT(sock_connectionClosed()));
		connect(sock, SIGNAL(error(int)), SLOT(sock_error(int)));

		ssl = new QCA::TLS;
		connect(ssl, SIGNAL(handshaken()), SLOT(ssl_handshaken()));
		connect(ssl, SIGNAL(readyRead()), SLOT(ssl_readyRead()));
		connect(ssl, SIGNAL(readyReadOutgoing(int)), SLOT(ssl_readyReadOutgoing(int)));
		connect(ssl, SIGNAL(closed()), SLOT(ssl_closed()));
		connect(ssl, SIGNAL(error(int)), SLOT(ssl_error(int)));

		rootCerts.setAutoDelete(true);
		rootCerts = getRootCerts("/usr/local/share/psi/certs/rootcert.xml");
	}

	~SecureTest()
	{
		delete ssl;
		delete sock;
	}

	void start(const QString &_host)
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
	}

signals:
	void quit();

private slots:
	void sock_connected()
	{
		printf("Connected, starting TLS handshake...\n");
		ssl->setCertificateStore(rootCerts);
		ssl->startClient(host);
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

	void ssl_handshaken()
	{
		cert = ssl->peerCertificate();
		int vr = ssl->certificateValidityResult();

		printf("Successful SSL handshake.\n");
		if(!cert.isNull())
			showCertInfo(cert);
		if(vr == QCA::TLS::Valid)
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

	void ssl_readyRead()
	{
		QByteArray a = ssl->read();
		QCString cs;
		cs.resize(a.size()+1);
		memcpy(cs.data(), a.data(), a.size());
		printf("%s", cs.data());
	}

	void ssl_readyReadOutgoing(int)
	{
		QByteArray a = ssl->readOutgoing();
		sock->writeBlock(a.data(), a.size());
	}

	void ssl_closed()
	{
		printf("SSL session closed\n");
	}

	void ssl_error(int x)
	{
		if(x == QCA::TLS::ErrHandshake) {
			printf("SSL Handshake Error!\n");
			quit();
		}
		else {
			printf("SSL Error!\n");
			quit();
		}
	}

private:
	QString host;
	QSocket *sock;
	QCA::TLS *ssl;
	QCA::Cert cert;
	QPtrList<QCA::Cert> rootCerts;
};

#include"ssltest.moc"

int main(int argc, char **argv)
{
	QApplication app(argc, argv, false);
	QString host = argc > 1 ? argv[1] : "andbit.net";

	if(!QCA::isSupported(QCA::CAP_TLS)) {
		printf("TLS not supported!\n");
		return 1;
	}

	SecureTest *s = new SecureTest;
	QObject::connect(s, SIGNAL(quit()), &app, SLOT(quit()));
	s->start(host);
	app.exec();
	delete s;

	return 0;
}
