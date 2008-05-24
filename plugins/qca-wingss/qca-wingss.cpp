/*
 * Copyright (C) 2008  Barracuda Networks, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301  USA
 *
 */

#include <QtCrypto>
#include <qcaprovider.h>
#include <QtPlugin>
#include <QMutex>
#include <QLibrary>

#ifndef FORWARD_ONLY
#include <windows.h>
#define SECURITY_WIN32
#include <Security.h>
#endif

using namespace QCA;

#define PROVIDER_NAME "qca-wingss"

namespace wingssQCAPlugin {

#if !defined(FORWARD_ONLY)

typedef void (*sspi_logger_func)(const QString &str);

class SspiPackage
{
public:
	QString name;
	quint32 caps;
	quint32 maxtok;
	quint16 version;
	quint16 rpcid;
	QString comment;
};

// logger can be set even when sspi is not loaded (this is needed so logging
//   during sspi_load/unload can be captured).  pass 0 to disable.
void sspi_set_logger(sspi_logger_func p);

void sspi_log(const QString &str);

bool sspi_load();
void sspi_unload();

// returns the available security packages.  only the first call actually
//   queries the sspi subsystem.  subsequent calls return a cached result.
QList<SspiPackage> sspi_get_packagelist();

// refresh the package list cache.  call sspi_get_packagelist afterwards to
//   get the new list.
void sspi_refresh_packagelist();

// helper functions for logging
QString SECURITY_STATUS_toString(SECURITY_STATUS i);
QString ptr_toString(const void *p);

// -----

Q_GLOBAL_STATIC(QMutex, sspi_mutex)
Q_GLOBAL_STATIC(QMutex, sspi_logger_mutex)

static QLibrary *sspi_lib = 0;
static PSecurityFunctionTable sspi = 0;
static sspi_logger_func sspi_logger;
static QList<SspiPackage> *sspi_packagelist = 0;

void sspi_log(const QString &str)
{
	QMutexLocker locker(sspi_logger_mutex());

	if(sspi_logger)
		sspi_logger(str);
}

void sspi_set_logger(sspi_logger_func p)
{
	QMutexLocker locker(sspi_logger_mutex());

	sspi_logger = p;
}

#define CASE_SS_STRING(s) case s: return #s;

static const char *SECURITY_STATUS_lookup(SECURITY_STATUS i)
{
	switch(i)
	{
		CASE_SS_STRING(SEC_E_OK);
		CASE_SS_STRING(SEC_I_COMPLETE_AND_CONTINUE);
		CASE_SS_STRING(SEC_I_COMPLETE_NEEDED);
		CASE_SS_STRING(SEC_I_CONTINUE_NEEDED);
		CASE_SS_STRING(SEC_I_INCOMPLETE_CREDENTIALS);
		CASE_SS_STRING(SEC_E_UNSUPPORTED_FUNCTION);
		CASE_SS_STRING(SEC_E_INVALID_TOKEN);
		CASE_SS_STRING(SEC_E_MESSAGE_ALTERED);
		CASE_SS_STRING(SEC_E_INSUFFICIENT_MEMORY);
		CASE_SS_STRING(SEC_E_INTERNAL_ERROR);
		CASE_SS_STRING(SEC_E_INVALID_HANDLE);
		CASE_SS_STRING(SEC_E_LOGON_DENIED);
		CASE_SS_STRING(SEC_E_NO_AUTHENTICATING_AUTHORITY);
		CASE_SS_STRING(SEC_E_NO_CREDENTIALS);
		CASE_SS_STRING(SEC_E_TARGET_UNKNOWN);
		CASE_SS_STRING(SEC_E_WRONG_PRINCIPAL);
		CASE_SS_STRING(SEC_E_BUFFER_TOO_SMALL);
		CASE_SS_STRING(SEC_E_CONTEXT_EXPIRED);
		CASE_SS_STRING(SEC_E_CRYPTO_SYSTEM_INVALID);
		CASE_SS_STRING(SEC_E_QOP_NOT_SUPPORTED);
		CASE_SS_STRING(SEC_E_INCOMPLETE_MESSAGE);
		CASE_SS_STRING(SEC_E_OUT_OF_SEQUENCE);
		default: break;
	}
	return 0;
}

QString SECURITY_STATUS_toString(SECURITY_STATUS i)
{
	const char *str = SECURITY_STATUS_lookup(i);
	if(str)
		return QString(str);
	else
		return QString::number(i);
}

QString ptr_toString(const void *p)
{
	return QString().sprintf("%p", p);
}

bool sspi_load()
{
	QMutexLocker locker(sspi_mutex());

	sspi_lib = new QLibrary("secur32");
	if(!sspi_lib->load())
	{
		delete sspi_lib;
		sspi_lib = 0;
		return false;
	}

	QString securityEntrypoint = QString::fromUtf16(SECURITY_ENTRYPOINTW);
	INIT_SECURITY_INTERFACE_W pInitSecurityInterface = (INIT_SECURITY_INTERFACE_W)(sspi_lib->resolve(securityEntrypoint.toLatin1().data()));
	if(!pInitSecurityInterface)
	{
		sspi_lib->unload();
		delete sspi_lib;
		sspi_lib = 0;
		return false;
	}

	PSecurityFunctionTable funcs = pInitSecurityInterface();
	sspi_log(QString("%1() = %2\n").arg(securityEntrypoint, ptr_toString(funcs)));
	if(!funcs)
	{
		sspi_lib->unload();
		delete sspi_lib;
		sspi_lib = 0;
		return false;
	}

	sspi = funcs;
	return true;
}

void sspi_unload()
{
	QMutexLocker locker(sspi_mutex());

	sspi_lib->unload();
	delete sspi_lib;
	sspi_lib = 0;
	sspi = 0;
}

static QList<SspiPackage> sspi_get_packagelist_direct()
{
	ULONG cPackages;
	SecPkgInfo *pPackageInfo;
	SECURITY_STATUS ret = sspi->EnumerateSecurityPackages(&cPackages, &pPackageInfo);
	sspi_log(QString("EnumerateSecurityPackages() = %1\n").arg(SECURITY_STATUS_toString(ret)));
	if(ret != SEC_E_OK)
		return QList<SspiPackage>();

	QList<SspiPackage> out;
	for(int n = 0; n < (int)cPackages; ++n)
	{
		SecPkgInfo *p = &pPackageInfo[n];
		SspiPackage i;
		i.name = QString::fromUtf16(p->Name);
		i.caps = p->fCapabilities;
		i.version = p->wVersion;
		i.rpcid = p->wRPCID;
		i.maxtok = p->cbMaxToken;
		i.comment = QString::fromUtf16(p->Comment);
		out += i;
	}

	ret = sspi->FreeContextBuffer(&pPackageInfo);
	sspi_log(QString("FreeContextBuffer() = %1\n").arg(SECURITY_STATUS_toString(ret)));

	return out;
}

static void sspi_refresh_packagelist_internal()
{
	if(sspi_packagelist)
		*sspi_packagelist = sspi_get_packagelist_direct();
	else
		sspi_packagelist = new QList<SspiPackage>(sspi_get_packagelist_direct());
}

QList<SspiPackage> sspi_get_packagelist()
{
	QMutexLocker locker(sspi_mutex());

	if(!sspi_packagelist)
		sspi_refresh_packagelist_internal();
	return *sspi_packagelist;
}

void sspi_refresh_packagelist()
{
	QMutexLocker locker(sspi_mutex());

	sspi_refresh_packagelist_internal();
}

// -----

class KerberosSession
{
public:
	bool initialized;
	bool first_step;
	QByteArray first_out_token;
	bool authed;

	QString spn;

	CredHandle user_cred;
	TimeStamp user_cred_expiry;

	CtxtHandle ctx;
	ULONG ctx_attr_req;
	ULONG ctx_attr;
	bool have_sizes;
	SecPkgContext_Sizes ctx_sizes;

	KerberosSession() :
		initialized(false),
		have_sizes(false)
	{
	}

	~KerberosSession()
	{
		if(initialized)
		{
			SECURITY_STATUS ret = sspi->DeleteSecurityContext(&ctx);
			sspi_log(QString("DeleteSecurityContext() = %1\n").arg(SECURITY_STATUS_toString(ret)));

			ret = sspi->FreeCredentialsHandle(&user_cred);
			sspi_log(QString("FreeCredentialsHandle() = %1\n").arg(SECURITY_STATUS_toString(ret)));
		}
	}

	bool init(const QString &_spn)
	{
		// ensure kerberos is available
		bool found = false;
		quint32 maxtok;
		QList<SspiPackage> packages = sspi_get_packagelist();
		sspi_log("SSPI packages:\n");
		foreach(const SspiPackage &p, packages)
		{
			bool gss = false;
			if(p.caps & SECPKG_FLAG_GSS_COMPATIBLE)
				gss = true;

			if(p.name == "Kerberos" && gss)
			{
				found = true;
				maxtok = p.maxtok;
			}

			QString gssstr = gss ? "yes" : "no";
			sspi_log(QString("  %1 (gss=%2, maxtok=%3)\n").arg(p.name, gssstr, QString::number(p.maxtok)));
		}

		if(!found)
			return false;

		SECURITY_STATUS ret = sspi->AcquireCredentialsHandle(
			(SEC_WCHAR *)0, // we want creds of logged-in user
			(SEC_WCHAR *)QString("Kerberos").utf16(),
			SECPKG_CRED_OUTBOUND,
			0, // don't need a LUID
			0, // default credentials for kerberos
			0, // not used
			0, // not used
			&user_cred,
			&user_cred_expiry);
		sspi_log(QString("AcquireCredentialsHandle() = %1\n").arg(SECURITY_STATUS_toString(ret)));
		if(ret != SEC_E_OK)
			return false;

		authed = false;
		spn = _spn;

		SecBuffer outbuf;
		outbuf.BufferType = SECBUFFER_TOKEN;
		outbuf.cbBuffer = 0;
		outbuf.pvBuffer = NULL;

		SecBufferDesc outbufdesc;
		outbufdesc.ulVersion = SECBUFFER_VERSION;
		outbufdesc.cBuffers = 1;
		outbufdesc.pBuffers = &outbuf;

		ctx_attr_req = 0;

		// not strictly required, but some SSPI calls seem to always
		//   allocate memory, so for consistency we'll explicity
		//   request to have it that way all the time
		ctx_attr_req |= ISC_REQ_ALLOCATE_MEMORY;

		// required by SASL GSSAPI RFC
		ctx_attr_req |= ISC_REQ_INTEGRITY;

		// required for security layer
		ctx_attr_req |= ISC_REQ_MUTUAL_AUTH;
		ctx_attr_req |= ISC_REQ_SEQUENCE_DETECT;

		// required for encryption
		ctx_attr_req |= ISC_REQ_CONFIDENTIALITY;

		// other options that may be of use, but we currently aren't
		//   using:
		// ISC_REQ_DELEGATE
		// ISC_REQ_REPLAY_DETECT

		ret = sspi->InitializeSecurityContext(
			&user_cred,
			0, // NULL for the first call
			(SEC_WCHAR *)spn.utf16(),
			ctx_attr_req,
			0,
			SECURITY_NETWORK_DREP,
			0, // NULL for first call
			0,
			&ctx,
			&outbufdesc,
			&ctx_attr,
			0); // don't care about expiration
		sspi_log(QString("InitializeSecurityContext(*, 0, ...) = %1\n").arg(SECURITY_STATUS_toString(ret)));
		if(ret == SEC_E_OK || ret == SEC_I_CONTINUE_NEEDED)
		{
			if(outbuf.pvBuffer)
			{
				first_out_token.resize(outbuf.cbBuffer);
				memcpy(first_out_token.data(), outbuf.pvBuffer, outbuf.cbBuffer);

				SECURITY_STATUS fret = sspi->FreeContextBuffer(outbuf.pvBuffer);
				sspi_log(QString("FreeContextBuffer() = %1\n").arg(SECURITY_STATUS_toString(fret)));
			}

			if(ret == SEC_E_OK)
				authed = true;
		}
		else
		{
			// ret was an error, or some unexpected value like
			//   SEC_I_COMPLETE_NEEDED or
			//   SEC_I_COMPLETE_AND_CONTINUE, which i believe are
			//   not used for kerberos

			ret = sspi->FreeCredentialsHandle(&user_cred);
			sspi_log(QString("FreeCredentialsHandle() = %1\n").arg(SECURITY_STATUS_toString(ret)));
			return false;
		}

		initialized = true;
		first_step = true;

		return true;
	}

	bool step(const QByteArray &in, QByteArray *out, bool *authenticated)
	{
		if(first_step)
		{
			// ignore 'in'

			*out = first_out_token;
			first_out_token.clear();

			first_step = false;
		}
		else
		{
			SecBuffer outbuf;
			outbuf.BufferType = SECBUFFER_TOKEN;
			outbuf.cbBuffer = 0;
			outbuf.pvBuffer = NULL;

			SecBufferDesc outbufdesc;
			outbufdesc.ulVersion = SECBUFFER_VERSION;
			outbufdesc.cBuffers = 1;
			outbufdesc.pBuffers = &outbuf;

			SecBuffer inbuf;
			inbuf.BufferType = SECBUFFER_TOKEN;
			inbuf.cbBuffer = in.size();
			inbuf.pvBuffer = (void *)in.data();

			SecBufferDesc inbufdesc;
			inbufdesc.ulVersion = SECBUFFER_VERSION;
			inbufdesc.cBuffers = 1;
			inbufdesc.pBuffers = &inbuf;

			SECURITY_STATUS ret = sspi->InitializeSecurityContext(
				&user_cred,
				&ctx,
				(SEC_WCHAR *)spn.utf16(),
				ctx_attr_req,
				0,
				SECURITY_NETWORK_DREP,
				&inbufdesc,
				0,
				&ctx,
				&outbufdesc,
				&ctx_attr,
				0); // don't care about expiration
			sspi_log(QString("InitializeSecurityContext(*, ctx, ...) = %1\n").arg(SECURITY_STATUS_toString(ret)));
			if(ret == SEC_E_OK || ret == SEC_I_CONTINUE_NEEDED)
			{
				if(outbuf.pvBuffer)
				{
					out->resize(outbuf.cbBuffer);
					memcpy(out->data(), outbuf.pvBuffer, outbuf.cbBuffer);

					SECURITY_STATUS fret = sspi->FreeContextBuffer(outbuf.pvBuffer);
					sspi_log(QString("FreeContextBuffer() = %1\n").arg(SECURITY_STATUS_toString(fret)));
				}
				else
					out->clear();

				if(ret == SEC_E_OK)
					authed = true;
			}
			else
			{
				// ret was an error, or some unexpected value like
				//   SEC_I_COMPLETE_NEEDED or
				//   SEC_I_COMPLETE_AND_CONTINUE, which i believe are
				//   not used for kerberos

				ret = sspi->DeleteSecurityContext(&ctx);
				sspi_log(QString("DeleteSecurityContext() = %1\n").arg(SECURITY_STATUS_toString(ret)));

				ret = sspi->FreeCredentialsHandle(&user_cred);
				sspi_log(QString("FreeCredentialsHandle() = %1\n").arg(SECURITY_STATUS_toString(ret)));

				initialized = false;
				return false;
			}
		}

		*authenticated = authed;
		return true;
	}

	bool encode(const QByteArray &in, QByteArray *out, bool encrypt)
	{
		if(!have_sizes)
		{
			SECURITY_STATUS ret = sspi->QueryContextAttributes(&ctx, SECPKG_ATTR_SIZES, &ctx_sizes);
			sspi_log(QString("QueryContextAttributes(ctx, SECPKG_ATTR_SIZES, ...) = %1\n").arg(SECURITY_STATUS_toString(ret)));
			if(ret != SEC_E_OK)
				return false;

			have_sizes = true;
		}

		// TODO: 'in' must not be larger than cbMaximumMessage of SECPKG_ATTR_STREAM_SIZES

		QByteArray tokenbuf(ctx_sizes.cbSecurityTrailer, 0);
		QByteArray padbuf(ctx_sizes.cbBlockSize, 0);

		// NOTE: we used to allocate a buffer of 1024 just in case the output
		//  data is larger than the input.  however, putty wingss doesn't
		//  seem to worry about this.  maybe output is always equal to or
		//  smaller than the input.
		//QByteArray databuf(1024, 0);
		//memcpy(databuf.data(), in.data(), in.size());
		QByteArray databuf = in;

		SecBuffer buf[3];
		buf[0].BufferType = SECBUFFER_TOKEN;
		buf[0].cbBuffer = tokenbuf.size();
		buf[0].pvBuffer = tokenbuf.data();
		buf[1].BufferType = SECBUFFER_DATA;
		buf[1].cbBuffer = databuf.size();
		buf[1].pvBuffer = databuf.data();
		buf[2].BufferType = SECBUFFER_PADDING;
		buf[2].cbBuffer = padbuf.size();
		buf[2].pvBuffer = padbuf.data();

		SecBufferDesc bufdesc;
		bufdesc.ulVersion = SECBUFFER_VERSION;
		bufdesc.cBuffers = 3;
		bufdesc.pBuffers = buf;

		SECURITY_STATUS ret = sspi->EncryptMessage(&ctx, encrypt ? 0 : SECQOP_WRAP_NO_ENCRYPT, &bufdesc, 0);
		sspi_log(QString("EncryptMessage() = %1\n").arg(SECURITY_STATUS_toString(ret)));
		if(ret != SEC_E_OK)
			return false;

		QByteArray fullbuf;
		for(int i = 0; i < (int)bufdesc.cBuffers; ++i)
			fullbuf += QByteArray((const char *)bufdesc.pBuffers[i].pvBuffer, bufdesc.pBuffers[i].cbBuffer);

		*out = fullbuf;
		return true;
	}

	// -1 = error, 0 = need more data, 1 = success
	int decode(const QByteArray &in, QByteArray *out, bool *encrypted)
	{
		SecBuffer buf[2];
		buf[0].BufferType = SECBUFFER_DATA;
		buf[0].cbBuffer = 0;
		buf[0].pvBuffer = NULL;
		buf[1].BufferType = SECBUFFER_STREAM;
		buf[1].cbBuffer = in.size();
		buf[1].pvBuffer = (void *)in.data();

		SecBufferDesc bufdesc;
		bufdesc.ulVersion = SECBUFFER_VERSION;
		bufdesc.cBuffers = 2;
		bufdesc.pBuffers = buf;

		ULONG fQOP;
		SECURITY_STATUS ret = sspi->DecryptMessage(&ctx, &bufdesc, 0, &fQOP);
		sspi_log(QString("DecryptMessage() = %1\n").arg(SECURITY_STATUS_toString(ret)));
		if(ret == SEC_E_INCOMPLETE_MESSAGE)
		{
			return 0;
		}
		else if(ret != SEC_E_OK)
		{
			return -1;
		}

		if(buf[0].pvBuffer)
		{
			out->resize(buf[0].cbBuffer);
			memcpy(out->data(), buf[0].pvBuffer, buf[0].cbBuffer);

			SECURITY_STATUS ret = sspi->FreeContextBuffer(buf[0].pvBuffer);
			sspi_log(QString("FreeContextBuffer() = %1\n").arg(SECURITY_STATUS_toString(ret)));
		}
		else
			out->clear();

		if(fQOP & SECQOP_WRAP_NO_ENCRYPT)
			*encrypted = false;
		else
			*encrypted = true;

		return 1;
	}
};

// TODO: use debug
class SaslGssapiSession
{
private:
	KerberosSession sess;
	int mode; // 0 = kerberos tokens, 1 = app packets
	bool authed;
	QByteArray inbuf;

public:
	SaslGssapiSession()
	{
	}

	~SaslGssapiSession()
	{
	}

	bool init(const QString &proto, const QString &fqdn)
	{
		mode = 0;
		authed = false;
		return sess.init(proto + '/' + fqdn);
	}

	bool step(const QByteArray &in, QByteArray *out, bool *authenticated)
	{
		if(mode == 0)
		{
			bool kerb_authed;
			if(!sess.step(in, out, &kerb_authed))
				return false;

			if(kerb_authed)
				mode = 1;

			*authenticated = false;
		}
		else if(mode == 1)
		{
			bool layerPossible = false;
			bool encryptionPossible = false;
			if(sess.ctx_attr & ISC_RET_INTEGRITY &&
				sess.ctx_attr & ISC_RET_MUTUAL_AUTH &&
				sess.ctx_attr & ISC_RET_SEQUENCE_DETECT)
			{
				layerPossible = true;

				if(sess.ctx_attr & ISC_RET_CONFIDENTIALITY)
					encryptionPossible = true;
			}

			if(layerPossible)
			{
				if(encryptionPossible)
					sspi_log("Kerberos application data protection supported (with encryption)\n");
				else
					sspi_log("Kerberos application data protection supported (without encryption)\n");
			}
			else
				sspi_log("No Kerberos application data protection supported\n");

			QByteArray decbuf;
			bool encrypted;
			if(!sess.decode(in, &decbuf, &encrypted))
				return false;

			// this packet is supposed to be not encrypted
			if(encrypted)
				return false;

			// packet must be exactly 4 bytes
			if(decbuf.size() != 4)
				return false;

			printf("[%02x%02x%02x%02x]\n", (unsigned int)decbuf[0], (unsigned int)decbuf[1], (unsigned int)decbuf[2], (unsigned int)decbuf[3]);
			unsigned char layermask = decbuf[0];
			quint32 maxsize = 0;
			maxsize += (unsigned char)decbuf[1];
			maxsize <<= 8;
			maxsize += (unsigned char)decbuf[2];
			maxsize <<= 8;
			maxsize += (unsigned char)decbuf[3];

			printf("layermask: %02x\n", (int)layermask);
			printf("maxsize:   %d\n", maxsize);

			// no layer, zero maxsize
			QByteArray obuf(4, 0);
			obuf[0] = 4;
			obuf[2] = 16;
			printf("[%02x%02x%02x%02x]\n", (unsigned int)obuf[0], (unsigned int)obuf[1], (unsigned int)obuf[2], (unsigned int)obuf[3]);

			if(!sess.encode(obuf, out, false))
				return false;

			*authenticated = true;
		}

		return true;
	}

	bool encode(const QByteArray &in, QByteArray *out)
	{
		QByteArray kerb_out;
		if(sess.encode(in, &kerb_out, true))
		{
			QByteArray sasl_out(kerb_out.size() + 4, 0);

			// SASL (not GSS!) uses a 4 byte length prefix
			quint32 len = kerb_out.size();
			sasl_out[3] = (unsigned char)(len & 0xff);
			len >>= 8;
			sasl_out[2] = (unsigned char)(len & 0xff);
			len >>= 8;
			sasl_out[1] = (unsigned char)(len & 0xff);
			len >>= 8;
			sasl_out[0] = (unsigned char)(len & 0xff);

			memcpy(sasl_out.data() + 4, kerb_out.data(), kerb_out.size());
			*out = sasl_out;
			return true;
		}
		else
			return false;
	}

	bool decode(const QByteArray &in, QByteArray *out)
	{
		inbuf += in;

		if(inbuf.size() < 4)
		{
			// need more data
			out->clear();
			return true;
		}

		// SASL (not GSS!) uses a 4 byte length prefix
		quint32 ulen = 0;
		ulen += (unsigned char)inbuf[0];
		ulen <<= 8;
		ulen += (unsigned char)inbuf[1];
		ulen <<= 8;
		ulen += (unsigned char)inbuf[2];
		ulen <<= 8;
		ulen += (unsigned char)inbuf[3];

		// FIXME: this only works for 31-bit
		int len = (int)ulen;

		if(inbuf.size() - 4 < len)
		{
			// need more data
			out->clear();
			return true;
		}

		QByteArray kerb_in = inbuf.mid(4, len);
		memmove(inbuf.data(), inbuf.data() + len + 4, inbuf.size() - len - 4);
		inbuf.resize(inbuf.size() - len - 4);

		// count incomplete packets as errors, since they are sasl framed
		bool encrypted;
		if(sess.decode(kerb_in, out, &encrypted) == 1)
			return true;
		else
			return false;
	}
};

//----------------------------------------------------------------------------
// SaslWinGss
//----------------------------------------------------------------------------
static bool wingss_available()
{
	return true;
}

class SaslWinGss : public SASLContext
{
	Q_OBJECT

public:
	SaslGssapiSession sess;
	bool authed;
	QByteArray _to_net, _to_app;
	int enc;

	SaslWinGss(Provider *p) :
		SASLContext(p)
	{
	}

	Provider::Context *clone() const
	{
		return 0;
	}

	virtual void reset()
	{
		// TODO
	}

	virtual void setup(const QString &service, const QString &host, const HostPort *local, const HostPort *remote, const QString &ext_id, int ext_ssf)
	{
		// TODO
		Q_UNUSED(local);
		Q_UNUSED(remote);
		Q_UNUSED(ext_id);
		Q_UNUSED(ext_ssf);

		sess.init(service, host);
	}

	virtual void setConstraints(SASL::AuthFlags f, int minSSF, int maxSSF)
	{
		// TODO
		Q_UNUSED(f);
		Q_UNUSED(minSSF);
		Q_UNUSED(maxSSF);
	}

	virtual void startClient(const QStringList &mechlist, bool allowClientSendFirst)
	{
		// TODO
		Q_UNUSED(allowClientSendFirst);

		if(!mechlist.contains("GSSAPI"))
		{
			// TODO: report error
			return;
		}

		authed = false;
		sess.step(QByteArray(), &_to_net, &authed); // TODO: handle error

		QMetaObject::invokeMethod(this, "resultsReady", Qt::QueuedConnection);
	}

	virtual void startServer(const QString &realm, bool disableServerSendLast)
	{
		// TODO
		Q_UNUSED(realm);
		Q_UNUSED(disableServerSendLast);
	}

	virtual void serverFirstStep(const QString &mech, const QByteArray *clientInit)
	{
		// TODO
		Q_UNUSED(mech);
		Q_UNUSED(clientInit);
	}

	virtual void nextStep(const QByteArray &from_net)
	{
		// TODO
		sess.step(from_net, &_to_net, &authed); // TODO: handle error

		QMetaObject::invokeMethod(this, "resultsReady", Qt::QueuedConnection);
	}

	virtual void tryAgain()
	{
		// TODO
	}

	virtual void update(const QByteArray &from_net, const QByteArray &from_app)
	{
		// TODO
		QByteArray a;

		sess.decode(from_net, &a); // TODO: handle error
		_to_app += a;

		sess.encode(from_app, &a); // TODO: handle error
		_to_net += a;
		enc += from_app.size();

		QMetaObject::invokeMethod(this, "resultsReady", Qt::QueuedConnection);
	}

	virtual bool waitForResultsReady(int msecs)
	{
		// TODO
		Q_UNUSED(msecs);
		return true;
	}

	virtual Result result() const
	{
		// TODO
		if(authed)
			return Success;
		else
			return Continue;
	}

	virtual QStringList mechlist() const
	{
		// TODO
		return QStringList();
	}

	virtual QString mech() const
	{
		// TODO
		return "GSSAPI";
	}

	virtual bool haveClientInit() const
	{
		// TODO
		return true;
	}

	virtual QByteArray stepData() const
	{
		// TODO
		return _to_net;
	}

	virtual QByteArray to_net()
	{
		// TODO
		QByteArray a = _to_net;
		_to_net.clear();
		enc = 0;
		return a;
	}

	virtual int encoded() const
	{
		// TODO
		return enc;
	}

	virtual QByteArray to_app()
	{
		// TODO
		return _to_app;
	}

	virtual int ssf() const
	{
		// TODO
		return 56;
	}

	virtual SASL::AuthCondition authCondition() const
	{
		// TODO
		return SASL::AuthFail;
	}

	virtual SASL::Params clientParams() const
	{
		// TODO
		return SASL::Params();
	}

	virtual void setClientParams(const QString *user, const QString *authzid, const SecureArray *pass, const QString *realm)
	{
		// TODO
		Q_UNUSED(user);
		Q_UNUSED(authzid);
		Q_UNUSED(pass);
		Q_UNUSED(realm);
	}

	virtual QStringList realmlist() const
	{
		// TODO
		return QStringList();
	}

	virtual QString username() const
	{
		// TODO
		return QString();
	}

	virtual QString authzid() const
	{
		// TODO
		return QString();
	}
};

#endif // !defined(FORWARD_ONLY)

class MetaSasl : public SASLContext
{
	Q_OBJECT

public:
	SASLContext *s;

	QString opt_service, opt_host;
	bool have_opt_local, have_opt_remote;
	HostPort opt_local, opt_remote;
	QString opt_ext_id;
	int opt_ext_ssf;
	SASL::AuthFlags opt_flags;
	int opt_minssf, opt_maxssf;

	bool have_opt_user, have_opt_authzid, have_opt_pass, have_opt_realm;
	QString opt_user, opt_authzid, opt_realm;
	SecureArray opt_pass;

	class SaslProvider
	{
	public:
		SASLContext *sasl;
		bool ready;
		QStringList mechlist;

		SaslProvider() :
			sasl(0),
			ready(false)
		{
		}
	};

	QList<SaslProvider> saslProviders;
	bool serverInit_active;
	Result serverInit_result;
	QStringList serverInit_mechlist;

	MetaSasl(Provider *p) :
		SASLContext(p),
		serverInit_active(false)
	{
		s = 0;

		have_opt_user = false;
		have_opt_authzid = false;
		have_opt_pass = false;
		have_opt_realm = false;
	}

	~MetaSasl()
	{
		delete s;
	}

	virtual Provider::Context *clone() const
	{
		return 0;
	}

	virtual void reset()
	{
		delete s;
		s = 0;
	}

	virtual void setup(const QString &service, const QString &host, const HostPort *local, const HostPort *remote, const QString &ext_id, int ext_ssf)
	{
		opt_service = service;
		opt_host = host;
		have_opt_local = false;
		have_opt_remote = false;
		if(local)
		{
			have_opt_local = true;
			opt_local = *local;
		}
		if(remote)
		{
			have_opt_remote = true;
			opt_remote = *remote;
		}
		opt_ext_id = ext_id;
		opt_ext_ssf = ext_ssf;
	}

	virtual void setConstraints(SASL::AuthFlags f, int minSSF, int maxSSF)
	{
		opt_flags = f;
		opt_minssf = minSSF;
		opt_maxssf = maxSSF;
	}

	virtual void startClient(const QStringList &mechlist, bool allowClientSendFirst)
	{
#ifndef FORWARD_ONLY
		if(mechlist.contains("GSSAPI") && wingss_available())
		{
			s = new SaslWinGss(provider());
		}
		else
		{
#endif
			// collect providers supporting sasl, in priority order.
			//   (note: providers() is in priority order already)
			ProviderList list;
			foreach(Provider *p, providers())
			{
				QString name = p->name();

				// skip ourself
				if(name == PROVIDER_NAME)
					continue;

				if(p->features().contains("sasl"))
				{
					// FIXME: improve qca so this isn't needed
					SASL tmp_object_to_cause_plugin_init(0, name);

					// add to the list
					list += p;
				}
			}

			// use the first
			s = static_cast<SASLContext *>(list.first()->createContext("sasl"));
#ifndef FORWARD_ONLY
		}
#endif

		if(!s)
		{
			// TODO: report error
			return;
		}

		const HostPort *pLocal = 0;
		const HostPort *pRemote = 0;
		if(have_opt_local)
			pLocal = &opt_local;
		if(have_opt_remote)
			pRemote = &opt_remote;
		s->setup(opt_service, opt_host, pLocal, pRemote, opt_ext_id, opt_ext_ssf);
		s->setConstraints(opt_flags, opt_minssf, opt_maxssf);

		const QString *pUser = 0;
		const QString *pAuthzid = 0;
		const SecureArray *pPass = 0;
		const QString *pRealm = 0;
		if(have_opt_user)
			pUser = &opt_user;
		if(have_opt_authzid)
			pAuthzid = &opt_authzid;
		if(have_opt_pass)
			pPass = &opt_pass;
		if(have_opt_realm)
			pRealm = &opt_realm;
		s->setClientParams(pUser, pAuthzid, pPass, pRealm);
		connect(s, SIGNAL(resultsReady()), SLOT(s_resultsReady()));

		printf("client using [%s] with %d mechs\n", qPrintable(s->provider()->name()), mechlist.count());
		s->startClient(mechlist, allowClientSendFirst);
	}

	virtual void startServer(const QString &realm, bool disableServerSendLast)
	{
		// collect mechs of all providers, by starting all of them
		serverInit_active = true;

		ProviderList list;
		foreach(Provider *p, providers())
		{
			QString name = p->name();

			// skip ourself
			if(name == PROVIDER_NAME)
				continue;

			if(p->features().contains("sasl"))
			{
				// FIXME: improve qca so this isn't needed
				SASL tmp_object_to_cause_plugin_init(0, name);

				// add to the list
				list += p;
			}
		}

		foreach(Provider *p, list)
		{
			SaslProvider sp;

			sp.sasl = static_cast<SASLContext *>(p->createContext("sasl"));

			const HostPort *pLocal = 0;
			const HostPort *pRemote = 0;
			if(have_opt_local)
				pLocal = &opt_local;
			if(have_opt_remote)
				pRemote = &opt_remote;
			sp.sasl->setup(opt_service, opt_host, pLocal, pRemote, opt_ext_id, opt_ext_ssf);
			sp.sasl->setConstraints(opt_flags, opt_minssf, opt_maxssf);
			connect(sp.sasl, SIGNAL(resultsReady()), SLOT(serverInit_resultsReady()));

			saslProviders += sp;

			sp.sasl->startServer(realm, disableServerSendLast);
		}
	}

	virtual void serverFirstStep(const QString &mech, const QByteArray *clientInit)
	{
		// TODO: set 's' based on chosen mech
		SASLContext *sasl = saslProviders[0].sasl;
		saslProviders.clear();
		serverInit_active = false;
		sasl->disconnect(this);
		s = sasl;

		connect(s, SIGNAL(resultsReady()), SLOT(s_resultsReady()));
		s->serverFirstStep(mech, clientInit);
	}

	virtual void nextStep(const QByteArray &from_net)
	{
		s->nextStep(from_net);
	}

	virtual void tryAgain()
	{
		s->tryAgain();
	}

	virtual void update(const QByteArray &from_net, const QByteArray &from_app)
	{
		s->update(from_net, from_app);
	}

	virtual bool waitForResultsReady(int msecs)
	{
		return s->waitForResultsReady(msecs);
	}

	virtual Result result() const
	{
		if(serverInit_active)
			return serverInit_result;
		else
			return s->result();
	}

	virtual QStringList mechlist() const
	{
		return serverInit_mechlist;
	}

	virtual QString mech() const
	{
		if(s)
			return s->mech();
		else
			return QString();
	}

	virtual bool haveClientInit() const
	{
		return s->haveClientInit();
	}

	virtual QByteArray stepData() const
	{
		return s->stepData();
	}

	virtual QByteArray to_net()
	{
		return s->to_net();
	}

	virtual int encoded() const
	{
		return s->encoded();
	}

	virtual QByteArray to_app()
	{
		return s->to_app();
	}

	virtual int ssf() const
	{
		return s->ssf();
	}

	virtual SASL::AuthCondition authCondition() const
	{
		return s->authCondition();
	}

	virtual SASL::Params clientParams() const
	{
		return s->clientParams();
	}

	virtual void setClientParams(const QString *user, const QString *authzid, const SecureArray *pass, const QString *realm)
	{
		if(!s)
		{
			if(user)
			{
				have_opt_user = true;
				opt_user = *user;
			}
			if(authzid)
			{
				have_opt_authzid = true;
				opt_authzid = *authzid;
			}
			if(pass)
			{
				have_opt_pass = true;
				opt_pass = *pass;
			}
			if(realm)
			{
				have_opt_realm = true;
				opt_realm = *realm;
			}
		}
		else
		{
			s->setClientParams(user, authzid, pass, realm);
		}
	}

	virtual QStringList realmlist() const
	{
		return s->realmlist();
	}

	virtual QString username() const
	{
		return s->username();
	}

	virtual QString authzid() const
	{
		return s->authzid();
	}

private slots:
	void s_resultsReady()
	{
		emit resultsReady();
	}

	void serverInit_resultsReady()
	{
		SASLContext *sasl = (SASLContext *)sender();

		int at = -1;
		for(int n = 0; n < saslProviders.count(); ++n)
		{
			if(saslProviders[n].sasl == sasl)
			{
				at = n;
				break;
			}
		}
		if(at == -1)
			return;

		if(sasl->result() == Success)
		{
			saslProviders[at].ready = true;
			saslProviders[at].mechlist = sasl->mechlist();

			bool allReady = true;
			for(int n = 0; n < saslProviders.count(); ++n)
			{
				if(!saslProviders[n].ready)
				{
					allReady = false;
					break;
				}
			}

			if(allReady)
			{
				// indicate success
				serverInit_result = Success;
				serverInit_mechlist = combine_mechlists();

				emit resultsReady();
			}
		}
		else
		{
			// TODO: ?
			delete sasl;
			saslProviders.removeAt(at);
		}
	}

private:
	QStringList combine_mechlists()
	{
		// TODO
		return saslProviders[0].mechlist;
	}
};

class wingssProvider : public Provider
{
public:
	mutable QMutex m;
	mutable bool forced_priority;

	wingssProvider() :
		forced_priority(false)
	{
	}

	virtual void init()
	{
#ifndef FORWARD_ONLY
		sspi_load(); // TODO: handle error
#endif
	}

	~wingssProvider()
	{
		sspi_unload();
	}

	virtual int qcaVersion() const
	{
		return QCA_VERSION;
	}

	virtual QString name() const
	{
		return PROVIDER_NAME;
	}

	virtual QStringList features() const
	{
		// due to context manipulation, this plugin is only designed
		//   for qca 2.0 at this time, and not a possible 2.1, etc.
		if((qcaVersion() & 0xffff00) > 0x020000)
			return QStringList();

		m.lock();
		// FIXME: we need to prioritize this plugin to be higher
		//   than other plugins by default.  unfortunately there's
		//   no clean way to do this.  we can't change our priority
		//   until we are slotted into the qca provider system.  the
		//   constructor, qcaVersion, and name functions are all
		//   guaranteed to be called, but unfortunately they are
		//   only guaranteed to be called before the slotting.  the
		//   features function is essentially guaranteed to be called
		//   after the slotting though, since QCA::isSupported()
		//   trips it, and any proper QCA app will call isSupported.
		if(!forced_priority)
		{
			forced_priority = true;
			setProviderPriority(PROVIDER_NAME, 0);
		}
		m.unlock();

		QStringList list;
		list += "sasl";
		return list;
	}

	virtual Context *createContext(const QString &type)
	{
		if(type == "sasl")
			return new MetaSasl(this);
		else
			return 0;
	}
};

}

using namespace wingssQCAPlugin;

//----------------------------------------------------------------------------
// wingssPlugin
//----------------------------------------------------------------------------

class wingssPlugin : public QObject, public QCAPlugin
{
	Q_OBJECT
	Q_INTERFACES(QCAPlugin)

public:
	virtual Provider *createProvider() { return new wingssProvider; }
};

#include "qca-wingss.moc"

Q_EXPORT_PLUGIN2(qca_wingss, wingssPlugin)
