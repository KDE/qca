/*
 Copyright (C) 2003-2008  Justin Karneges <justin@affinix.com>
 Copyright (C) 2006  Michail Pishchagin

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

// QtCrypto has the declarations for all of QCA
#include <QtCrypto>

#ifdef QT_STATICPLUGIN
#include "import_plugins.h"
#endif

static QString prompt(const QString &s)
{
	printf("* %s ", qPrintable(s));
	fflush(stdout);
	char line[256];
	fgets(line, 255, stdin);
	QString result = line;
	if(result[result.length()-1] == '\n')
		result.truncate(result.length()-1);
	return result;
}

static QString socketErrorToString(QAbstractSocket::SocketError x)
{
	QString s;
	switch(x)
	{
		case QAbstractSocket::ConnectionRefusedError:
			s = "connection refused or timed out"; break;
		case QAbstractSocket::RemoteHostClosedError:
			s = "remote host closed the connection"; break;
		case QAbstractSocket::HostNotFoundError:
			s = "host not found"; break;
		case QAbstractSocket::SocketAccessError:
			s = "access error"; break;
		case QAbstractSocket::SocketResourceError:
			s = "too many sockets"; break;
		case QAbstractSocket::SocketTimeoutError:
			s = "operation timed out"; break;
		case QAbstractSocket::DatagramTooLargeError:
			s = "datagram was larger than system limit"; break;
		case QAbstractSocket::NetworkError:
			s = "network error"; break;
		case QAbstractSocket::AddressInUseError:
			s = "address is already in use"; break;
		case QAbstractSocket::SocketAddressNotAvailableError:
			s = "address does not belong to the host"; break;
		case QAbstractSocket::UnsupportedSocketOperationError:
			s = "operation is not supported by the local operating system"; break;
		default:
			s = "unknown socket error"; break;
	}
	return s;
}

static QString saslAuthConditionToString(QCA::SASL::AuthCondition x)
{
	QString s;
	switch(x)
	{
		case QCA::SASL::NoMechanism:
			s = "no appropriate mechanism could be negotiated"; break;
		case QCA::SASL::BadProtocol:
			s = "bad SASL protocol"; break;
		case QCA::SASL::BadServer:
			s = "server failed mutual authentication"; break;
		// AuthFail or unknown (including those defined for server only)
		default:
			s = "generic authentication failure"; break;
	};
	return s;
}

class ClientTest : public QObject
{
	Q_OBJECT

private:
	QString host, proto, authzid, realm, user, pass;
	int port;
	bool no_authzid, no_realm;
	int mode; // 0 = receive mechanism list, 1 = sasl negotiation, 2 = app
	QTcpSocket *sock;
	QCA::SASL *sasl;
	QByteArray inbuf;
	bool sock_done;
	int waitCycles;

public:
	ClientTest(const QString &_host, int _port, const QString &_proto, const QString &_authzid, const QString &_realm, const QString &_user, const QString &_pass, bool _no_authzid, bool _no_realm) :
		host(_host),
		proto(_proto),
		authzid(_authzid),
		realm(_realm),
		user(_user),
		pass(_pass),
		port(_port),
		no_authzid(_no_authzid),
		no_realm(_no_realm),
		sock_done(false),
		waitCycles(0)
	{
		sock = new QTcpSocket(this);
		connect(sock, SIGNAL(connected()), SLOT(sock_connected()));
		connect(sock, SIGNAL(readyRead()), SLOT(sock_readyRead()));
		connect(sock, SIGNAL(error(QAbstractSocket::SocketError)), SLOT(sock_error(QAbstractSocket::SocketError)));

		sasl = new QCA::SASL(this);
		connect(sasl, SIGNAL(clientStarted(bool, const QByteArray &)), SLOT(sasl_clientFirstStep(bool, const QByteArray &)));
		connect(sasl, SIGNAL(nextStep(const QByteArray &)), SLOT(sasl_nextStep(const QByteArray &)));
		connect(sasl, SIGNAL(needParams(const QCA::SASL::Params &)), SLOT(sasl_needParams(const QCA::SASL::Params &)));
		connect(sasl, SIGNAL(authenticated()), SLOT(sasl_authenticated()));
		connect(sasl, SIGNAL(readyRead()), SLOT(sasl_readyRead()));
		connect(sasl, SIGNAL(readyReadOutgoing()), SLOT(sasl_readyReadOutgoing()));
		connect(sasl, SIGNAL(error()), SLOT(sasl_error()));
	}

public slots:
	void start()
	{
		mode = 0; // mech list mode

		int flags = 0;
		flags |= QCA::SASL::AllowPlain;
		flags |= QCA::SASL::AllowAnonymous;
		sasl->setConstraints((QCA::SASL::AuthFlags)flags, 0, 256);

		if(!user.isEmpty())
			sasl->setUsername(user);
		if(!authzid.isEmpty())
			sasl->setAuthzid(authzid);
		if(!pass.isEmpty())
			sasl->setPassword(pass.toUtf8());
		if(!realm.isEmpty())
			sasl->setRealm(realm);

		printf("Connecting to %s:%d, for protocol %s\n", qPrintable(host), port, qPrintable(proto));
		sock->connectToHost(host, port);
	}

signals:
	void quit();

private slots:
	void sock_connected()
	{
		printf("Connected to server.  Awaiting mechanism list...\n");
	}

	void sock_error(QAbstractSocket::SocketError x)
	{
		if(x == QAbstractSocket::RemoteHostClosedError)
		{
			if(mode == 2) // app mode, where disconnect means completion
			{
				sock_done = true;
				tryFinished();
				return;
			}
			else // any other mode, where disconnect is an error
			{
				printf("Error: server closed connection unexpectedly.\n");
				emit quit();
				return;
			}
		}

		printf("Error: socket: %s\n", qPrintable(socketErrorToString(x)));
		emit quit();
	}

	void sock_readyRead()
	{
		if(mode == 2) // app mode
		{
			QByteArray a = sock->readAll();
			printf("Read %d bytes\n", a.size());

			// there is a possible flaw in the qca 2.0 api, in
			//   that if sasl data is received from the peer
			//   followed by a disconnect from the peer, there is
			//   no clear approach to salvaging the bytes.  tls is
			//   not affected because tls has the concept of
			//   closing a session.  with sasl, there is no
			//   closing, and since the qca api is asynchronous,
			//   we could potentially wait forever for decoded
			//   data, if the last write was a partial packet.
			//
			// for now, we can perform a simple workaround of
			//   waiting at least three event loop cycles for
			//   decoded data before giving up and assuming the
			//   last write was partial.  the fact is, all current
			//   qca sasl providers respond within this time
			//   frame, so this fix should work fine for now.  in
			//   qca 2.1, we should revise the api to handle this
			//   situation better.
			//
			// further note: i guess this only affects application
			//   protocols that have no close message of their
			//   own, and rely on the tcp-level close.  examples
			//   are http, and of course this qcatest protocol.
			if(waitCycles == 0)
			{
				waitCycles = 3;
				QMetaObject::invokeMethod(this, "waitWriteIncoming", Qt::QueuedConnection);
			}

			sasl->writeIncoming(a);
		}
		else // mech list or sasl negotiation mode
		{
			if(sock->canReadLine())
			{
				QString line = sock->readLine();
				line.truncate(line.length() - 1); // chop the newline
				handleLine(line);
			}
		}
	}

	void sasl_clientFirstStep(bool clientInit, const QByteArray &clientInitData)
	{
		printf("Choosing mech: %s\n", qPrintable(sasl->mechanism()));
		QString line = sasl->mechanism();
		if(clientInit)
		{
			line += ' ';
			line += arrayToString(clientInitData);
		}
		sendLine(line);
	}

	void sasl_nextStep(const QByteArray &stepData)
	{
		QString line = "C";
		if(!stepData.isEmpty())
		{
			line += ',';
			line += arrayToString(stepData);
		}
		sendLine(line);
	}

	void sasl_needParams(const QCA::SASL::Params &params)
	{
		if(params.needUsername())
		{
			user = prompt("Username:");
			sasl->setUsername(user);
		}

		if(params.canSendAuthzid() && !no_authzid)
		{
			authzid = prompt("Authorize As (enter to skip):");
			if(!authzid.isEmpty())
				sasl->setAuthzid(authzid);
		}

		if(params.needPassword())
		{
			QCA::ConsolePrompt prompt;
			prompt.getHidden("* Password");
			prompt.waitForFinished();
			QCA::SecureArray pass = prompt.result();
			sasl->setPassword(pass);
		}

		if(params.canSendRealm() && !no_realm)
		{
			QStringList realms = sasl->realmList();
			printf("Available realms:\n");
			if(realms.isEmpty())
				printf("  (none specified)\n");
			foreach(const QString &s, realms)
				printf("  %s\n", qPrintable(s));
			realm = prompt("Realm (enter to skip):");
			if(!realm.isEmpty())
				sasl->setRealm(realm);
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
		inbuf += a;
		processInbuf();
	}

	void sasl_readyReadOutgoing()
	{
		QByteArray a = sasl->readOutgoing();
		sock->write(a);
	}

	void sasl_error()
	{
		int e = sasl->errorCode();
		if(e == QCA::SASL::ErrorInit)
			printf("Error: sasl: initialization failed.\n");
		else if(e == QCA::SASL::ErrorHandshake)
			printf("Error: sasl: %s.\n", qPrintable(saslAuthConditionToString(sasl->authCondition())));
		else if(e == QCA::SASL::ErrorCrypt)
			printf("Error: sasl: broken security layer.\n");
		else
			printf("Error: sasl: unknown error.\n");

		emit quit();
	}

	void waitWriteIncoming()
	{
		--waitCycles;
		if(waitCycles > 0)
		{
			QMetaObject::invokeMethod(this, "waitWriteIncoming", Qt::QueuedConnection);
			return;
		}

		tryFinished();
	}

private:
	void tryFinished()
	{
		if(sock_done && waitCycles == 0)
		{
			printf("Finished, server closed connection.\n");

			// if we give up on waiting for a response to
			//   writeIncoming, then it might come late.  in
			//   theory this shouldn't happen if we wait enough
			//   cycles, but if one were to arrive then it could
			//   occur between the request to quit the app and
			//   the actual quit of the app.  to assist with
			//   debugging, then, we'll explicitly stop listening
			//   for signals here.  otherwise the response may
			//   still be received and displayed, giving a false
			//   sense of correctness.
			sasl->disconnect(this);

			emit quit();
		}
	}

	QString arrayToString(const QByteArray &ba)
	{
		return QCA::Base64().arrayToString(ba);
	}

	QByteArray stringToArray(const QString &s)
	{
		return QCA::Base64().stringToArray(s).toByteArray();
	}

	void sendLine(const QString &line)
	{
		printf("Writing: {%s}\n", qPrintable(line));
		QString s = line + '\n';
		QByteArray a = s.toUtf8();
		if(mode == 2) // app mode
			sasl->write(a); // write to sasl
		else // mech list or sasl negotiation
			sock->write(a); // write to socket
	}

	void processInbuf()
	{
		// collect completed lines from inbuf
		QStringList list;
		int at;
		while((at = inbuf.indexOf('\n')) != -1)
		{
			list += QString::fromUtf8(inbuf.mid(0, at));
			inbuf = inbuf.mid(at + 1);
		}

		// process the lines
		foreach(const QString &line, list)
			handleLine(line);
	}

	void handleLine(const QString &line)
	{
		printf("Reading: [%s]\n", qPrintable(line));
		if(mode == 0)
		{
			// first line is the method list
			QStringList mechlist = line.split(' ');
			mode = 1; // switch to sasl negotiation mode
			sasl->startClient(proto, host, mechlist);
		}
		else if(mode == 1)
		{
			QString type, rest;
			int n = line.indexOf(',');
			if(n != -1)
			{
				type = line.mid(0, n);
				rest = line.mid(n + 1);
			}
			else
				type = line;
	
			if(type == "C")
			{
				sasl->putStep(stringToArray(rest));
			}
			else if(type == "E")
			{
				if(!rest.isEmpty())
					printf("Error: server says: %s.\n", qPrintable(rest));
				else
					printf("Error: server error, unspecified.\n");
				emit quit();
				return;
			}
			else if(type == "A")
			{
				printf("Authentication success.\n");
				mode = 2; // switch to app mode

				// at this point, the server may send us text
				//   lines for us to display and then close.

				sock_readyRead(); // any extra data?
				return;
			}
			else
			{
				printf("Error: Bad format from peer, closing.\n");
				emit quit();
				return;
			}
		}
	}
};

void usage()
{
	printf("usage: saslclient (options) host(:port) (user) (pass)\n");
	printf("options: --proto=x, --authzid=x, --realm=x\n");
}

int main(int argc, char **argv)
{
	QCA::Initializer init;
	QCoreApplication qapp(argc, argv);

	QStringList args = qapp.arguments();
	args.removeFirst();

	// options
	QString proto = "qcatest"; // default protocol
	QString authzid, realm;
	bool no_authzid = false;
	bool no_realm = false;
	for(int n = 0; n < args.count(); ++n)
	{
		if(!args[n].startsWith("--"))
			continue;

		QString opt = args[n].mid(2);
		QString var, val;
		int at = opt.indexOf('=');
		if(at != -1)
		{
			var = opt.mid(0, at);
			val = opt.mid(at + 1);
		}
		else
			var = opt;

		if(var == "proto")
		{
			proto = val;
		}
		else if(var == "authzid")
		{
			// specifying empty authzid means force unspecified
			if(val.isEmpty())
				no_authzid = true;
			else
				authzid = val;
		}
		else if(var == "realm")
		{
			// specifying empty realm means force unspecified
			if(val.isEmpty())
				no_realm = true;
			else
				realm = val;
		}

		args.removeAt(n);
		--n; // adjust position
	}

	if(args.count() < 1)
	{
		usage();
		return 0;
	}

	QString host, user, pass;
	int port = 8001; // default port

	QString hostinput = args[0];
	if(args.count() >= 2)
		user = args[1];
	if(args.count() >= 3)
		pass = args[2];

	int at = hostinput.indexOf(':');
	if(at != -1)
	{
		host = hostinput.mid(0, at);
		port = hostinput.mid(at + 1).toInt();
	}
	else
		host = hostinput;

	if(!QCA::isSupported("sasl"))
	{
		printf("Error: SASL support not found.\n");
		return 1;
	}

	ClientTest client(host, port, proto, authzid, realm, user, pass, no_authzid, no_realm);
	QObject::connect(&client, SIGNAL(quit()), &qapp, SLOT(quit()));
	QTimer::singleShot(0, &client, SLOT(start()));
	qapp.exec();

	return 0;
}

#include "saslclient.moc"
