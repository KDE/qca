#include"qcaopenssl.h"

extern "C"
{
#include<sasl/sasl.h>
}

#include<qhostaddress.h>
#include<qstringlist.h>

static void clearNeedParams(QCA_SASLNeedParams *np)
{
	np->auth = false;
	np->user = false;
	np->pass = false;
	np->realm = false;
}

class SASLContext : public QCA_SASLContext
{
public:
	sasl_conn_t *con;
	sasl_interact_t *need;
	QStringList methods;

	SASLContext()
	{
		con = 0;
	}

	~SASLContext()
	{
	}

	bool startClient(const char *service, const QString &host, const QStringList &_methods, const QHostAddress &localAddr, int localPort, const QHostAddress &remoteAddr, int remotePort, bool allowPlain)
	{
		const char *la = NULL;
		const char *ra = NULL;
		if(localPort != -1)
			la = (localAddr.toString() + ';' + QString::number(localPort)).latin1();
		if(remotePort != -1)
			ra = (remoteAddr.toString() + ';' + QString::number(remotePort)).latin1();
		int r = sasl_client_new(service, host.latin1(), la, ra, NULL, 0, &con);
		if(r != SASL_OK)
			return false;

		int sf = 0;
		if(!allowPlain)
			sf |= SASL_SEC_NOPLAINTEXT;

		// set security properties
		sasl_security_properties_t secprops;
		secprops.min_ssf = 0;
		secprops.max_ssf = 256;
		secprops.maxbufsize = 8192;
		secprops.property_names = NULL;
		secprops.property_values = NULL;
		secprops.security_flags = sf;
		sasl_setprop(con, SASL_SEC_PROPS, &secprops);

		QStringList methods = _methods;
		return true;
	}

	int firstStep(char **meth, char **out, unsigned int *outlen, QCA_SASLNeedParams *np)
	{
		clearNeedParams(np);
		bool supportClientSendFirst = true;

		QString list;
		bool first = true;
		for(QStringList::ConstIterator it = methods.begin(); it != methods.end(); ++it) {
			if(!first)
				list += ' ';
			else
				first = false;
			list += (*it);
		}

		need = NULL;
		const char *clientout, *mech;
		unsigned int len;
		int r;

		if(supportClientSendFirst)
			r = sasl_client_start(con, list.latin1(), &need, &clientout, &len, &mech);
		else
			r = sasl_client_start(con, list.latin1(), &need, NULL, &len, &mech);
		if(r == SASL_INTERACT) {
			for(int n = 0; need[n].id != SASL_CB_LIST_END; ++n) {
				if(need[n].id == SASL_CB_AUTHNAME)
					np->auth = true;
				if(need[n].id == SASL_CB_USER)
					np->user = true;
				if(need[n].id == SASL_CB_PASS)
					np->pass = true;
				if(need[n].id == SASL_CB_GETREALM)
					np->realm = true;
			}
			return NeedParams;
		}
		else if(r != SASL_OK && r != SASL_CONTINUE)
			return Error;

		*meth = strdup(mech);
		if(supportClientSendFirst && clientout) {
			*out = (char *)malloc(len);
			*outlen = len;
			memcpy(*out, clientout, len);
		}

		if(r == SASL_OK)
			return Success;
		else
			return Continue;
	}

	int nextStep(const char *in, unsigned int len, char **out, unsigned int *outlen, QCA_SASLNeedParams *np)
	{
		return Error;
	}

	void setAuthname(const QString &)
	{
	}

	void setUsername(const QString &)
	{
	}

	void setPassword(const QString &)
	{
	}

	void setRealm(const QString &)
	{
	}
};

class QCACyrusSASL : public QCAProvider
{
public:
	QCACyrusSASL() {}
	~QCACyrusSASL() {}

	int capabilities() const
	{
		return QCA::CAP_SASL;
	}

	void *context(int cap)
	{
		if(cap == QCA::CAP_SASL)
			return new SASLContext;
		return 0;
	}
};

#ifdef QCA_PLUGIN
QCAProvider *createProvider()
#else
QCAProvider *createProviderCyrusSASL();
#endif
{
	return (new QCACyrusSASL);
}

/*
static int ref=0;

class QSASL::Private
{
public:
	Private()
	{
		con = 0;
		bs = 0;
		allowPlain = true;
	}

	static int scb_getsimple(Private *d, int id, const char **result, unsigned *)
	{
		if(id == SASL_CB_AUTHNAME) {
			fprintf(stderr, "scb: authname\n");
			if(result)
				(*result) = d->user.latin1();
		}
		else if(id == SASL_CB_USER) {
			fprintf(stderr, "scb: user\n");
			if(result)
				(*result) = d->user.latin1();
		}

		return SASL_OK;
	}

	static int scb_getrealm(Private *d, int, const char **, const char **result)
	{
		fprintf(stderr, "scb: realm\n");
		if(result)
			(*result) = d->realm.latin1();
		return SASL_OK;
	}

	static int scb_getpass(sasl_conn_t *, Private *d, int, sasl_secret_t **psecret)
	{
		fprintf(stderr, "scb: pass\n");
		if(psecret) {
			d->ps.len = 3;
			memcpy(d->ps.data, d->pass.latin1(), d->pass.length());
			(*psecret) = (sasl_secret_t *)&d->ps;
		}
		return SASL_OK;
	}

	struct
	{
		unsigned long len;
		unsigned char data[256];
	} ps;
	sasl_callback_t *callbacks;
	sasl_conn_t *con;

	QString service, host;
	QString user, pass, realm;
	QHostAddress localAddr, remoteAddr;
	int localPort, remotePort;
	QString methods;

	ByteStream *bs;
	bool authed;
	int security;
	int sasl_maxoutbuf;
	bool allowPlain;
};

QSASL::QSASL(QObject *parent)
:ByteStream(parent)
{
	d = new Private;

	if(ref == 0)
		sasl_client_init(NULL);
	++ref;

	d->callbacks = new sasl_callback_t[5];

	d->callbacks[0].id = SASL_CB_GETREALM;
	d->callbacks[0].proc = (int(*)())Private::scb_getrealm;
	d->callbacks[0].context = d;

	d->callbacks[1].id = SASL_CB_USER;
	d->callbacks[1].proc = (int(*)())Private::scb_getsimple;
	d->callbacks[1].context = d;

	d->callbacks[2].id = SASL_CB_AUTHNAME;
	d->callbacks[2].proc = (int(*)())Private::scb_getsimple;
	d->callbacks[2].context = d;

	d->callbacks[3].id = SASL_CB_PASS;
	d->callbacks[3].proc = (int(*)())Private::scb_getpass;
	d->callbacks[3].context = d;

	d->callbacks[4].id = SASL_CB_LIST_END;
	d->callbacks[4].proc = NULL;
	d->callbacks[4].context = NULL;

	reset();
}

QSASL::~QSASL()
{
	reset();
	delete d->callbacks;

	--ref;
	if(ref == 0)
		sasl_done();
	delete d;
}

QString QSASL::service() const
{
	return d->service;
}

QString QSASL::host() const
{
	return d->host;
}

QString QSASL::user() const
{
	return d->user;
}

QString QSASL::pass() const
{
	return d->pass;
}

QString QSASL::realm() const
{
	return d->realm;
}

bool QSASL::allowPlainText() const
{
	return d->allowPlain;
}

void QSASL::setServiceHost(const QString &service, const QString &host)
{
	d->service = service;
	d->host = host;
}

void QSASL::setUserPass(const QString &user, const QString &pass)
{
	d->user = user;
	d->pass = pass;
}

void QSASL::setRealm(const QString &realm)
{
	d->realm = realm;
}

void QSASL::setLocalIP(const QHostAddress &addr, Q_UINT16 port)
{
	d->localAddr = addr;
	d->localPort = port;
}

void QSASL::setRemoteIP(const QHostAddress &addr, Q_UINT16 port)
{
	d->remoteAddr = addr;
	d->remotePort = port;
}

void QSASL::setAllowPlainText(bool b)
{
	d->allowPlain = b;
}

void QSASL::reset()
{
	setByteStream(0);
	if(d->con) {
		sasl_dispose(&d->con);
		d->con = 0;
	}
	d->service = "";
	d->host = "";
	d->user = "";
	d->pass = "";
	d->realm = "";
	d->authed = false;
	d->security = 0;
	d->sasl_maxoutbuf = 0;

	d->localPort = -1;
	d->remotePort = -1;

	d->methods = "";

	clearReadBuffer();
	clearWriteBuffer();
}

void QSASL::handle_step(int code, const char *clientout, unsigned int len)
{
	if(code == SASL_OK) {
		fprintf(stderr, "QSASL: Success\n");
		const int *ssfp;
		int r = sasl_getprop(d->con, SASL_SSF, (const void **)&ssfp);
		if(r == SASL_OK)
			d->security = *ssfp;
		sasl_getprop(d->con, SASL_MAXOUTBUF, (const void **)&d->sasl_maxoutbuf);
		authenticated();
	}
	else if(code == SASL_CONTINUE) {
		if(clientout) {
			QByteArray a;
			if(clientout) {
				a.resize(len);
				memcpy(a.data(), clientout, len);
			}
			fprintf(stderr, "QSASL: must send [%s]\n", a.data());
			fprintf(stderr, "QSASL: %s\n", Base64::arrayToString(a).latin1());
			replyReady(a);
		}
	}
}

void QSASL::putChallenge(const QByteArray &msg)
{
	if(!d->con)
		return;

	sasl_interact_t *need = NULL;
	const char *clientout;
	unsigned int len;
	int r = sasl_client_step(d->con, msg.data(), msg.size(), &need, &clientout, &len);
	if(r != SASL_OK && r != SASL_CONTINUE) {
		fprintf(stderr, "QSASL: error\n");
		error(ErrSASL);
		return;
	}

	handle_step(r, clientout, len);
}

ByteStream *QSASL::byteStream() const
{
	return d->bs;
}

void QSASL::setByteStream(ByteStream *bs)
{
	if(d->bs) {
		disconnect(d->bs, SIGNAL(readyRead()), this, SLOT(bs_readyRead()));
		disconnect(d->bs, SIGNAL(bytesWritten(int)), this, SLOT(bs_bytesWritten(int)));
	}
	d->bs = bs;
	if(d->bs) {
		connect(d->bs, SIGNAL(readyRead()), SLOT(bs_readyRead()));
		connect(d->bs, SIGNAL(bytesWritten(int)), SLOT(bs_bytesWritten(int)));
	}
}

bool QSASL::isOpen() const
{
	return d->authed;
}

void QSASL::write(const QByteArray &a)
{
	if(!d->authed || !d->bs)
		return;
	else
		ByteStream::write(a);
}

int QSASL::tryWrite()
{
	if(!d->bs)
		return -1;

	// take a section of the write buffer
	int size = d->sasl_maxoutbuf;
	QByteArray a = takeWrite(size);

	if(d->security > 0) {
		const char *out;
		unsigned int len;
		int r = sasl_encode(d->con, a.data(), a.size(), &out, &len);
		if(r != SASL_OK) {
			error(ErrWrite);
			return -1;
		}
		QByteArray b(len);
		memcpy(b.data(), out, len);
		d->bs->write(b);
	}
	else
		d->bs->write(a);

	bytesWritten(size);
	return size;
}

void QSASL::bs_readyRead()
{
	if(!d->bs)
		return;

	QByteArray a = d->bs->read(8192);
	if(d->security > 0) {
		const char *out;
		unsigned int len;
		int r = sasl_decode(d->con, a.data(), a.size(), &out, &len);
		if(r != SASL_OK) {
			reset();
			error(ErrRead);
			return;
		}
		QByteArray b(len);
		memcpy(b.data(), out, len);
		if(!b.isEmpty()) {
			appendRead(b);
			readyRead();
		}
	}
	else {
		appendRead(a);
		readyRead();
	}
}

void QSASL::bs_bytesWritten(int)
{
	if(bytesToWrite() > 0)
		tryWrite();
}

bool QSASL::isSecure() const
{
	return (d->security > 0 ? true: false);
}
*/
