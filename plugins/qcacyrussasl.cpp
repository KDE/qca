/*
 * qcacyrussasl.cpp - Cyrus SASL 2 plugin for QCA
 * Copyright (C) 2003  Justin Karneges
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include"qcaopenssl.h"

extern "C"
{
#include<sasl/sasl.h>
}

#include<qhostaddress.h>
#include<qstringlist.h>
#include<qptrlist.h>
#include<qfile.h>
#include<qthread.h>

#define SASL_BUFSIZE 8192

class QCACyrusSASL : public QCAProvider
{
public:
	QCACyrusSASL();
	~QCACyrusSASL();

	int capabilities() const;
	void *context(int cap);

	bool client_init;
	bool server_init;
	QString appname;
};

class SASLParams
{
public:
	SASLParams()
	{
		results.setAutoDelete(true);
		reset();
	}

	void reset()
	{
		resetNeed();
		resetHave();
		results.clear();
	}

	void resetNeed()
	{
		need.auth = false;
		need.user = false;
		need.pass = false;
		need.realm = false;
	}

	void resetHave()
	{
		have.auth = false;
		have.user = false;
		have.pass = false;
		have.realm = false;
	}

	void setAuthname(const QString &s)
	{
		have.auth = true;
		auth = s;
	}

	void setUsername(const QString &s)
	{
		have.user = true;
		user = s;
	}

	void setPassword(const QString &s)
	{
		have.pass = true;
		pass = s;
	}

	void setRealm(const QString &s)
	{
		have.realm = true;
		realm = s;
	}

	void applyInteract(sasl_interact_t *needp)
	{
		for(int n = 0; needp[n].id != SASL_CB_LIST_END; ++n) {
			if(needp[n].id == SASL_CB_AUTHNAME)
				need.auth = true;
			if(needp[n].id == SASL_CB_USER)
				need.user = true;
			if(needp[n].id == SASL_CB_PASS)
				need.pass = true;
			if(needp[n].id == SASL_CB_GETREALM)
				need.realm = true;
		}
	}

	void extractHave(sasl_interact_t *need)
	{
		for(int n = 0; need[n].id != SASL_CB_LIST_END; ++n) {
			if(need[n].id == SASL_CB_AUTHNAME && have.auth)
				setValue(&need[n], auth);
			if(need[n].id == SASL_CB_USER && have.user)
				setValue(&need[n], user);
			if(need[n].id == SASL_CB_PASS && have.pass)
				setValue(&need[n], pass);
			if(need[n].id == SASL_CB_GETREALM && have.realm)
				setValue(&need[n], realm);
		}
	}

	bool missingAny() const
	{
		if((need.auth && !have.auth) || (need.user && !have.user) || (need.pass && !have.pass) || (need.realm && !have.realm))
			return true;
		return false;
	}

	void setValue(sasl_interact_t *i, const QString &s)
	{
		if(i->result)
			return;
		QCString cs = s.utf8();
		int len = cs.length();
		char *p = new char[len+1];
		memcpy(p, cs.data(), len);
		p[len] = 0;
		i->result = p;
		i->len = len;

		// record this
		results.append(p);
	}

	QPtrList<void> results;
	QCA_SASLNeedParams need;
	QCA_SASLNeedParams have;
	QString auth, user, pass, realm;
};

static QByteArray makeByteArray(const void *in, unsigned int len)
{
	QByteArray buf(len);
	memcpy(buf.data(), in, len);
	return buf;
}

static QString addrString(const QCA_SASLHostPort &hp)
{
	return (hp.addr.toString() + ';' + QString::number(hp.port));
}

static QString methodsToString(const QStringList &methods)
{
	QString list;
	bool first = true;
	for(QStringList::ConstIterator it = methods.begin(); it != methods.end(); ++it) {
		if(!first)
			list += ' ';
		else
			first = false;
		list += (*it);
	}
	return list;
}

// needed to give interactive behavior to a callback-based function
class ServerStepThread : public QThread
{
public:
	ServerStepThread()
	{
	}

	void run()
	{
		//int r = sasl_server_start(con, in_mech.latin1(), clientin, clientinlen, &serverout, &serveroutlen);
	}
};

class SASLContext : public QCA_SASLContext
{
public:
	QCACyrusSASL *g;
	ServerStepThread *sst;

	// core props
	QString service, host;
	QString localAddr, remoteAddr;

	// security props
	int secflags;
	int ssf_min, ssf_max;
	QString ext_authid;
	int ext_ssf;

	sasl_conn_t *con;
	sasl_interact_t *need;
	int ssf, maxoutbuf;
	QStringList mechlist;
	sasl_callback_t *callbacks;

	// state
	bool servermode;
	int step;
	bool in_sendFirst;
	QByteArray in_buf;
	QString in_mech;
	bool in_useClientInit;
	QByteArray in_clientInit;
	QString out_mech;
	bool out_useClientInit;
	QByteArray out_clientInit;
	QByteArray out_buf;

	SASLParams params;
	QString sc_authname, sc_username;

	SASLContext(QCACyrusSASL *_g)
	{
		g = _g;
		con = 0;
		callbacks = 0;
		sst = 0;

		reset();
	}

	~SASLContext()
	{
		reset();
	}

	void reset()
	{
		resetState();
		resetParams();
	}

	void resetState()
	{
		if(sst) {
			// only would happen if the user forgot to call setAuth, so let's do it now
			setAuth(false);
		}
		if(con) {
			sasl_dispose(&con);
			con = 0;
		}
		need = 0;
		if(callbacks) {
			delete callbacks;
			callbacks = 0;
		}

		localAddr = "";
		remoteAddr = "";
		mechlist.clear();
		ssf = 0;
		maxoutbuf = 0;
		sc_authname = "";
		sc_username = "";
	}

	void resetParams()
	{
		params.reset();
		secflags = 0;
		ssf_min = 0;
		ssf_max = 0;
		ext_authid = "";
		ext_ssf = 0;
	}

	void setCoreProps(const QString &_service, const QString &_host, QCA_SASLHostPort *la, QCA_SASLHostPort *ra)
	{
		service = _service;
		host = _host;
		localAddr = la ? addrString(*la) : "";
		remoteAddr = ra ? addrString(*ra) : "";
	}

	void setSecurityProps(bool noPlain, bool noActive, bool noDict, bool noAnon, bool reqForward, bool reqCreds, bool reqMutual, int ssfMin, int ssfMax, const QString &_ext_authid, int _ext_ssf)
	{
		int sf = 0;
		if(noPlain)
			sf |= SASL_SEC_NOPLAINTEXT;
		if(noActive)
			sf |= SASL_SEC_NOACTIVE;
		if(noDict)
			sf |= SASL_SEC_NODICTIONARY;
		if(noAnon)
			sf |= SASL_SEC_NOANONYMOUS;
		if(reqForward)
			sf |= SASL_SEC_FORWARD_SECRECY;
		if(reqCreds)
			sf |= SASL_SEC_PASS_CREDENTIALS;
		if(reqMutual)
			sf |= SASL_SEC_MUTUAL_AUTH;
		secflags = sf;
		ssf_min = ssfMin;
		ssf_max = ssfMax;
		ext_authid = _ext_authid;
		ext_ssf = _ext_ssf;
	}

	static int scb_checkauth(sasl_conn_t *, void *context, const char *requested_user, unsigned, const char *auth_identity, unsigned, const char *, unsigned, struct propctx *)
	{
		SASLContext *that = (SASLContext *)context;
		QString authname = auth_identity;
		QString username = requested_user;
		/*if(that->authCallback) {
			if(that->authCallback(authname, username, that))
				return SASL_OK;
			else
				return SASL_NOAUTHZ;
		}
		else*/
			return SASL_OK;
	}

	bool setsecprops()
	{
		sasl_security_properties_t secprops;
		secprops.min_ssf = ssf_min;
		secprops.max_ssf = ssf_max;
		secprops.maxbufsize = SASL_BUFSIZE;
		secprops.property_names = NULL;
		secprops.property_values = NULL;
		secprops.security_flags = secflags;
		int r = sasl_setprop(con, SASL_SEC_PROPS, &secprops);
		if(r != SASL_OK)
			return false;

		if(!ext_authid.isEmpty()) {
			const char *authid = ext_authid.latin1();
			sasl_ssf_t ssf = ext_ssf;
			r = sasl_setprop(con, SASL_SSF_EXTERNAL, &ssf);
			if(r != SASL_OK)
				return false;
			r = sasl_setprop(con, SASL_AUTH_EXTERNAL, &authid);
			if(r != SASL_OK)
				return false;
		}

		return true;
	}

	void getssfparams()
	{
		const int *ssfp;
		int r = sasl_getprop(con, SASL_SSF, (const void **)&ssfp);
		if(r == SASL_OK)
			ssf = *ssfp;
		sasl_getprop(con, SASL_MAXOUTBUF, (const void **)&maxoutbuf);
	}

	int security() const
	{
		return ssf;
	}

	bool clientStart(const QStringList &_mechlist)
	{
		resetState();

		if(!g->client_init) {
			sasl_client_init(NULL);
			g->client_init = true;
		}

		callbacks = new sasl_callback_t[5];

		callbacks[0].id = SASL_CB_GETREALM;
		callbacks[0].proc = 0;
		callbacks[0].context = 0;

		callbacks[1].id = SASL_CB_USER;
		callbacks[1].proc = 0;
		callbacks[1].context = 0;

		callbacks[2].id = SASL_CB_AUTHNAME;
		callbacks[2].proc = 0;
		callbacks[2].context = 0;

		callbacks[3].id = SASL_CB_PASS;
		callbacks[3].proc = 0;
		callbacks[3].context = 0;

		callbacks[4].id = SASL_CB_LIST_END;
		callbacks[4].proc = 0;
		callbacks[4].context = 0;

		int r = sasl_client_new(service.latin1(), host.latin1(), localAddr.isEmpty() ? 0 : localAddr.latin1(), remoteAddr.isEmpty() ? 0 : remoteAddr.latin1(), callbacks, 0, &con);
		if(r != SASL_OK)
			return false;

		if(!setsecprops())
			return false;

		mechlist = _mechlist;
		servermode = false;
		step = 0;
		return true;
	}

	int clientFirstStep(bool allowClientSendFirst)
	{
		in_sendFirst = allowClientSendFirst;
		return clientTryAgain();
	}

	bool serverStart(const QString &realm, QStringList *mechlist, const QString &name)
	{
		resetState();

		g->appname = name;
		if(!g->server_init) {
			sasl_server_init(NULL, QFile::encodeName(g->appname));
			g->server_init = true;
		}

		callbacks = new sasl_callback_t[2];

		callbacks[0].id = SASL_CB_PROXY_POLICY;
		callbacks[0].proc = (int(*)())scb_checkauth;
		callbacks[0].context = this;

		callbacks[1].id = SASL_CB_LIST_END;
		callbacks[1].proc = 0;
		callbacks[1].context = 0;

		int r = sasl_server_new(service.latin1(), host.latin1(), realm.latin1(), localAddr.isEmpty() ? 0 : localAddr.latin1(), remoteAddr.isEmpty() ? 0 : remoteAddr.latin1(), callbacks, 0, &con);
		if(r != SASL_OK)
			return false;

		if(!setsecprops())
			return false;

		const char *ml;
		r = sasl_listmech(con, 0, NULL, " ", NULL, &ml, 0, 0);
		if(r != SASL_OK)
			return false;
		*mechlist = QStringList::split(' ', ml);
		servermode = true;
		step = 0;
		return true;
	}

	int serverFirstStep(const QString &mech, const QByteArray *in)
	{
		in_mech = mech;
		if(in) {
			in_useClientInit = true;
			in_clientInit = in->copy();
		}
		else
			in_useClientInit = false;
		return serverTryAgain();
	}

	QCA_SASLNeedParams clientParamsNeeded() const
	{
		return params.need;
	}

	void setClientParams(const QString *auth, const QString *user, const QString *pass, const QString *realm)
	{
		if(auth)
			params.setAuthname(*auth);
		if(user)
			params.setUsername(*user);
		if(pass)
			params.setPassword(*pass);
		if(realm)
			params.setRealm(*realm);
	}

	QString authname() const
	{
		return sc_authname;
	}

	QString username() const
	{
		return sc_username;
	}

	void setAuth(bool)
	{
		if(!sst)
			return;

		// TODO: send the decision to the thread
		sst->wait();
		delete sst;
		sst = 0;
	}

	int nextStep(const QByteArray &in)
	{
		in_buf = in.copy();
		return tryAgain();
	}

	int tryAgain()
	{
		if(servermode)
			return serverTryAgain();
		else
			return clientTryAgain();
	}

	QString mech() const
	{
		return out_mech;
	}

	const QByteArray *clientInit() const
	{
		if(out_useClientInit)
			return &out_clientInit;
		else
			return 0;
	}

	QByteArray result() const
	{
		return out_buf;
	}

	int clientTryAgain()
	{
		if(step == 0) {
			const char *clientout, *m;
			unsigned int clientoutlen;

			need = 0;
			QString list = methodsToString(mechlist);
			int r;
			while(1) {
				if(need)
					params.extractHave(need);
				if(in_sendFirst)
					r = sasl_client_start(con, list.latin1(), &need, &clientout, &clientoutlen, &m);
				else
					r = sasl_client_start(con, list.latin1(), &need, NULL, NULL, &m);
				if(r != SASL_INTERACT)
					break;

				params.applyInteract(need);
				if(params.missingAny())
					return NeedParams;
			}
			if(r != SASL_OK && r != SASL_CONTINUE)
				return Error;

			out_mech = m;
			if(in_sendFirst && clientout) {
				out_clientInit = makeByteArray(clientout, clientoutlen);
				out_useClientInit = true;
			}
			else
				out_useClientInit = false;

			++step;

			if(r == SASL_OK) {
				getssfparams();
				return Success;
			}
			else
				return Continue;
		}
		else {
			const char *clientout;
			unsigned int clientoutlen;
			int r;
			while(1) {
				if(need)
					params.extractHave(need);
				r = sasl_client_step(con, in_buf.data(), in_buf.size(), &need, &clientout, &clientoutlen);
				if(r != SASL_INTERACT)
					break;

				params.applyInteract(need);
				if(params.missingAny())
					return NeedParams;
			}
			if(r != SASL_OK && r != SASL_CONTINUE)
				return Error;
			out_buf = makeByteArray(clientout, clientoutlen);
			if(r == SASL_OK) {
				getssfparams();
				return Success;
			}
			else
				return Continue;
		}
	}

	int serverTryAgain()
	{
		if(step == 0) {
			const char *clientin = 0;
			unsigned int clientinlen = 0;
			if(in_useClientInit) {
				clientin = in_clientInit.data();
				clientinlen = in_clientInit.size();
			}
			const char *serverout;
			unsigned int serveroutlen;
			int r = sasl_server_start(con, in_mech.latin1(), clientin, clientinlen, &serverout, &serveroutlen);
			if(r != SASL_OK && r != SASL_CONTINUE)
				return Error;
			out_buf = makeByteArray(serverout, serveroutlen);

			++step;

			if(r == SASL_OK) {
				getssfparams();
				return Success;
			}
			else
				return Continue;
		}
		else {
			const char *serverout;
			unsigned int serveroutlen;
			int r = sasl_server_step(con, in_buf.data(), in_buf.size(), &serverout, &serveroutlen);
			if(r != SASL_OK && r != SASL_CONTINUE)
				return Error;
			if(r == SASL_OK) {
				out_buf.resize(0);
				getssfparams();
				return Success;
			}
			out_buf = makeByteArray(serverout, serveroutlen);
			return Continue;
		}
	}

	bool encode(const QByteArray &in, QByteArray *out)
	{
		return sasl_endecode(in, out, true);
	}

	bool decode(const QByteArray &in, QByteArray *out)
	{
		return sasl_endecode(in, out, false);
	}

	bool sasl_endecode(const QByteArray &in, QByteArray *out, bool enc)
	{
		// no security
		if(ssf == 0) {
			*out = in.copy();
			return true;
		}

		int at = 0;
		out->resize(0);
		while(1) {
			int size = in.size() - at;
			if(size == 0)
				break;
			if(size > maxoutbuf)
				size = maxoutbuf;
			const char *outbuf;
			unsigned len;
			int r;
			if(enc)
				r = sasl_encode(con, in.data() + at, size, &outbuf, &len);
			else
				r = sasl_decode(con, in.data() + at, size, &outbuf, &len);
			if(r != SASL_OK)
				return false;
			int oldsize = out->size();
			out->resize(oldsize + len);
			memcpy(out->data() + oldsize, outbuf, len);
			at += size;
		}
		return true;
	}
};


QCACyrusSASL::QCACyrusSASL()
{
	client_init = false;
	server_init = false;
}

QCACyrusSASL::~QCACyrusSASL()
{
	if(client_init || server_init)
		sasl_done();
}

int QCACyrusSASL::capabilities() const
{
	return QCA::CAP_SASL;
}

void *QCACyrusSASL::context(int cap)
{
	if(cap == QCA::CAP_SASL)
		return new SASLContext(this);
	return 0;
}


#ifdef QCA_PLUGIN
QCAProvider *createProvider()
#else
QCAProvider *createProviderCyrusSASL()
#endif
{
	return (new QCACyrusSASL);
}
