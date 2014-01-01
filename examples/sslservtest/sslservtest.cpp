/*
 Copyright (C) 2003 Justin Karneges <justin@affinix.com>
 Copyright (C) 2006 Brad Hards <bradh@frogmouth.net>

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

#include <QtCrypto>

#include <QCoreApplication>
#include <QDebug>
#include <QHostAddress>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTimer>

#ifdef QT_STATICPLUGIN
#include "import_plugins.h"
#endif

char pemdata_cert[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIICeTCCAeKgAwIBAgIRAKKKnOj6Aarmwf0phApitVAwDQYJKoZIhvcNAQEFBQAw\n"
	"ODELMAkGA1UEBhMCVVMxFDASBgNVBAoTC0V4YW1wbGUgT3JnMRMwEQYDVQQDEwpF\n"
	"eGFtcGxlIENBMB4XDTA2MDMxNTA3MDU1MloXDTA3MDMxNTA3MDU1MlowOjEVMBMG\n"
	"A1UEAxMMRXhhbXBsZSBVc2VyMQswCQYDVQQGEwJVUzEUMBIGA1UEChMLRXhhbXBs\n"
	"ZSBPcmcwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAPkKn0FfHMvRZv+3uFcw\n"
	"VrOadJmANzLVeVW/DHZp4CXokXSksM66ZMqFuQRBk5rnIZZpZmVp1tTRDVt9sEAY\n"
	"YNa8CRM4HXkVlU0lCKdey18CSq2VuSvNtw8dDpoBmQt3nr9tePvKHnpS3nm6YjR2\n"
	"NEvIKt1P4mHzYXLmwoF24C1bAgMBAAGjgYAwfjAdBgNVHQ4EFgQUmQIdzyDaPYWF\n"
	"fPJ8PPOOm1eSsucwHwYDVR0jBBgwFoAUkCglAizTO7iqwLeaO6r/8kJuqhMwDAYD\n"
	"VR0TAQH/BAIwADAeBgNVHREEFzAVgRNleGFtcGxlQGV4YW1wbGUuY29tMA4GA1Ud\n"
	"DwEB/wQEAwIF4DANBgkqhkiG9w0BAQUFAAOBgQAuhbiUgy2a++EUccaonID7eTJZ\n"
	"F3D5qXMqUpQxlYxU8du+9AxDD7nFxTMkQC2pzfmEc1znRNmJ1ZeLRL72VYsVndcT\n"
	"psyM8ABkvPp1d2jWIyccVjGpt+/RN5IPKm/YIbtIZcywvWuXrOp1lanVmppLfPnO\n"
	"6yneBkC9iqjOv/+Q+A==\n"
	"-----END CERTIFICATE-----\n";

char pemdata_privkey[] =
	"-----BEGIN PRIVATE KEY-----\n"
	"MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAPkKn0FfHMvRZv+3\n"
	"uFcwVrOadJmANzLVeVW/DHZp4CXokXSksM66ZMqFuQRBk5rnIZZpZmVp1tTRDVt9\n"
	"sEAYYNa8CRM4HXkVlU0lCKdey18CSq2VuSvNtw8dDpoBmQt3nr9tePvKHnpS3nm6\n"
	"YjR2NEvIKt1P4mHzYXLmwoF24C1bAgMBAAECgYEAyIjJHDaeVXDU42zovyxpZE4n\n"
	"PcOEryY+gdFJE8DFgUD4f1huFsj4iCuNg+PaG42p+hf9IARNvSho/RcEaVg4AJrV\n"
	"jRP8r7fSqcIGr6lGuvDFFv3SU5ddy84g5oqLYGKvuPSHMGfVsZSxAwOrzD4bH19L\n"
	"SNqtNcpdBsBd7ZiEE4ECQQD/oJGui9D5Dx3QVcS+QV4F8wuyN9jYIANmX/17o0fl\n"
	"BL0bwRU4RICwadrcybi5N0JQLIYSUm2HGqNvAJbtnuQxAkEA+WeYLLYPeawcy+WU\n"
	"kGcOR7BUjHiG71+6cvU4XIDW2bezA04fqWXkZRFAwHTMpQb785/XalFftgS21kql\n"
	"8yLDSwJAHkeT2hwftdDPlEUEmBDAJW5DvWmWGwu3u2G1cfbGZl9oUyhM7ixXHg57\n"
	"6VlPs0jTZxHPE86FwNIr99MXDbCbkQJBAMDFOJK+ecGirXNP1P+0GA6DFSap9inJ\n"
	"BRTbwx+EmgwX966DUOefEOSpbDIVVSPs/Qr2LgtIMEFA7Y0+j3wZD3cCQBsTwccd\n"
	"ASQx59xakpq11eOlTYz14rjwodr4QMyj26WxEPJtz7hKokx/+EH6fWuPIUSrROM5\n"
	"07y2gaVbYxtis0s=\n"
	"-----END PRIVATE KEY-----\n";

class SecureServer : public QObject
{
    Q_OBJECT

public:
    enum { Idle, Handshaking, Active, Closing };

    SecureServer(quint16 _port) : port(_port)
    {
	server = new QTcpServer;
	connect( server, SIGNAL(newConnection()), SLOT(server_handleConnection()) );

	ssl = new QCA::TLS;
	connect(ssl, SIGNAL(handshaken()), SLOT(ssl_handshaken()));
	connect(ssl, SIGNAL(readyRead()), SLOT(ssl_readyRead()));
	connect(ssl, SIGNAL(readyReadOutgoing()), SLOT(ssl_readyReadOutgoing()));
	connect(ssl, SIGNAL(closed()), SLOT(ssl_closed()));
	connect(ssl, SIGNAL(error()), SLOT(ssl_error()));

	cert = QCA::Certificate::fromPEM(pemdata_cert);
	privkey = QCA::PrivateKey::fromPEM(pemdata_privkey);

	mode = Idle;
    }

    ~SecureServer()
    {
	delete ssl;
	delete server;
    }

    void start()
    {
	if(cert.isNull()) {
	    qDebug() << "Error loading cert!";
	    QTimer::singleShot(0, this, SIGNAL(quit()));
	    return;
	}
	if(privkey.isNull()) {
	    qDebug() << "Error loading private key!";
	    QTimer::singleShot(0, this, SIGNAL(quit()));
	    return;
	}
	if(false == server->listen(QHostAddress::Any, port)) {
	    qDebug() << "Error binding to port " << port;
	    QTimer::singleShot(0, this, SIGNAL(quit()));
	    return;
	}
	qDebug() << "Listening on port" << port;
    }

signals:
    void quit();

private slots:
    void sock_readyRead()
    {
	QByteArray buf(sock->bytesAvailable(), 0x00);

	int num = sock->read(buf.data(), buf.size());

	if ( -1 == num )
	    qDebug() << "Error reading data from socket";

	if (num < buf.size() )
	    buf.resize(num);

	ssl->writeIncoming(buf);
    }

    void server_handleConnection()
    {
	// Note: only 1 connection supported at a time in this example!
	if(mode != Idle) {
	    QTcpSocket* tmp = server->nextPendingConnection();
	    tmp->close();
	    connect(tmp, SIGNAL(disconnected()), tmp, SLOT(deleteLater()));
	    qDebug() << "throwing away extra connection";
	    return;
	}
	mode = Handshaking;
	sock = server->nextPendingConnection();
	connect(sock, SIGNAL(readyRead()), SLOT(sock_readyRead()));
	connect(sock, SIGNAL(disconnected()), SLOT(sock_disconnected()));
	connect(sock, SIGNAL(error(QAbstractSocket::SocketError)),
		SLOT(sock_error(QAbstractSocket::SocketError)));
	connect(sock, SIGNAL(bytesWritten(qint64)), SLOT(sock_bytesWritten(qint64)));

	qDebug() << "Connection received!  Starting TLS handshake.";
	ssl->setCertificate(cert, privkey);
	ssl->startServer();
    }

    void sock_disconnected()
    {
	qDebug() << "Connection closed.";
    }

    void sock_bytesWritten(qint64 x)
    {
	if(mode == Active && sent) {
	    qint64 bytes = ssl->convertBytesWritten(x);
	    bytesLeft -= bytes;

	    if(bytesLeft == 0) {
		mode = Closing;
		qDebug() << "Data transfer complete - SSL shutting down";
		ssl->close();
	    }
	}
    }

    void sock_error(QAbstractSocket::SocketError error)
    {
	qDebug() << "Socket error: " << (unsigned) error;
    }

    void ssl_handshaken()
    {
	qDebug() << "Successful SSL handshake.  Waiting for newline.";
	bytesLeft = 0;
	sent = false;
	mode = Active;
	ssl->continueAfterStep();
    }

    void ssl_readyRead()
    {
	QByteArray a = ssl->read();
	QByteArray b =
	    "<html>\n"
	    "<head><title>Test</title></head>\n"
	    "<body>this is only a test</body>\n"
	    "</html>\n";

	qDebug() << "Sending test response.";
	sent = true;
	ssl->write(b);
    }

    void ssl_readyReadOutgoing()
    {
	int plainBytes;
	QByteArray outgoingData = ssl->readOutgoing(&plainBytes);
	sock->write( outgoingData );
    }

    void ssl_closed()
    {
	qDebug() << "Closing socket.";
	sock->close();
	mode = Idle;
    }

    void ssl_error()
    {
	if(ssl->errorCode() == QCA::TLS::ErrorHandshake) {
	    qDebug() << "SSL Handshake Error!  Closing.";
	    sock->close();
	}
	else {
	    qDebug() << "SSL Error!  Closing.";
	    sock->close();
	}
	mode = Idle;
    }

private:
    quint16 port;
    QTcpServer *server;
    QTcpSocket *sock;
    QCA::TLS *ssl;
    QCA::Certificate cert;
    QCA::PrivateKey privkey;

    bool sent;
    int mode;
    qint64 bytesLeft;
};

#include "sslservtest.moc"

int main(int argc, char **argv)
{
    QCA::Initializer init;

    QCoreApplication app(argc, argv);
    int port = argc > 1 ? QString(argv[1]).toInt() : 8000;

    if(!QCA::isSupported("tls")) {
	qDebug() << "TLS not supported!";
	return 1;
    }

    SecureServer *server = new SecureServer(port);
    QObject::connect(server, SIGNAL(quit()), &app, SLOT(quit()));
    server->start();
    app.exec();
    delete server;

    return 0;
}
