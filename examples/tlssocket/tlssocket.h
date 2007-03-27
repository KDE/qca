#ifndef TLSSOCKET_H

#include <QtCore>
#include <QtCrypto>
#include <QTcpSocket>

class TLSSocket : public QTcpSocket
{
public:
	TLSSocket(QObject *parent = 0);
	~TLSSocket();

	void connectToHostEncrypted(const QString &host, quint16 port);
	QCA::TLS *tls();

	bool waitForReadyRead(int msecs = -1);

protected:
	// from qiodevice
	virtual qint64 readData(char *data, qint64 maxlen);
	virtual qint64 writeData(const char *data, qint64 len);

private:
	class Private;
	friend class Private;
	Private *d;
};

#endif
