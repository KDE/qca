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

QPtrList<QCA::Cert> getRootCerts()
{
	QPtrList<QCA::Cert> list;

	// open the Psi rootcerts file
	QFile f("/usr/local/share/psi/certs/rootcert.xml");
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
		case QCA::SSL::NoCert:
			s = QObject::tr("The server did not present a certificate.");
			break;
		case QCA::SSL::Valid:
			break;
		case QCA::SSL::HostMismatch:
			s = QObject::tr("The hostname does not match the one the certificate was issued to.");
			break;
		case QCA::SSL::Rejected:
			s = QObject::tr("Root CA is marked to reject the specified purpose.");
			break;
		case QCA::SSL::Untrusted:
			s = QObject::tr("Certificate not trusted for the required purpose.");
			break;
		case QCA::SSL::SignatureFailed:
			s = QObject::tr("Invalid signature.");
			break;
		case QCA::SSL::InvalidCA:
			s = QObject::tr("Invalid CA certificate.");
			break;
		case QCA::SSL::InvalidPurpose:
			s = QObject::tr("Invalid certificate purpose.");
			break;
		case QCA::SSL::SelfSigned:
			s = QObject::tr("Certificate is self-signed.");
			break;
		case QCA::SSL::Revoked:
			s = QObject::tr("Certificate has been revoked.");
			break;
		case QCA::SSL::PathLengthExceeded:
			s = QObject::tr("Maximum certificate chain length exceeded.");
			break;
		case QCA::SSL::Expired:
			s = QObject::tr("Certificate has expired.");
			break;
		case QCA::SSL::Unknown:
		default:
			s = QObject::tr("General certificate validation error.");
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

		ssl = new QCA::SSL;
		connect(ssl, SIGNAL(handshaken(bool)), SLOT(ssl_handshaken(bool)));
		connect(ssl, SIGNAL(readyRead()), SLOT(ssl_readyRead()));
		connect(ssl, SIGNAL(readyReadOutgoing()), SLOT(ssl_readyReadOutgoing()));

		rootCerts = getRootCerts();
	}

	~SecureTest()
	{
		delete ssl;
		rootCerts.setAutoDelete(true);
		rootCerts.clear();
		delete sock;
	}

	void start(const QString &_host)
	{
		host = _host;
		printf("Trying %s:443...\n", host.latin1());
		sock->connectToHost(host, 443);
	}

signals:
	void quit();

private slots:
	void sock_connected()
	{
		printf("Connected, starting TLS handshake...\n");
		ssl->begin(host, rootCerts);
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
	QPtrList<QCA::Cert> rootCerts;
};

#include"ssltest.moc"

int main(int argc, char **argv)
{
	QApplication app(argc, argv);
	QString host = argc > 1 ? argv[1] : "andbit.net";

	if(!QCA::isSupported(QCA::CAP_SSL)) {
		printf("SSL not supported!\n");
		return 1;
	}

	SecureTest *s = new SecureTest;
	QObject::connect(s, SIGNAL(quit()), &app, SLOT(quit()));
	s->start(host);
	app.exec();
	delete s;

	return 0;
}
