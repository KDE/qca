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
#include <QTimer>

#ifndef FORWARD_ONLY
#include <windows.h>
#define SECURITY_WIN32
#include <Security.h>
#endif

using namespace QCA;

#define PROVIDER_NAME "qca-wingss"

#if !defined(FORWARD_ONLY)

// some defs possibly missing from MinGW

#ifndef SEC_E_MESSAGE_ALTERED
#define SEC_E_MESSAGE_ALTERED       0x8009030F
#endif

#ifndef SEC_E_CONTEXT_EXPIRED
#define SEC_E_CONTEXT_EXPIRED       0x80090317
#endif

#ifndef SEC_E_CRYPTO_SYSTEM_INVALID
#define SEC_E_CRYPTO_SYSTEM_INVALID 0x80090337
#endif

#ifndef SEC_E_OUT_OF_SEQUENCE
#define SEC_E_OUT_OF_SEQUENCE       0x80090310
#endif

#ifndef SEC_E_BUFFER_TOO_SMALL
#define SEC_E_BUFFER_TOO_SMALL      0x80090321
#endif

#ifndef SECURITY_ENTRYPOINTW
#define SECURITY_ENTRYPOINTW        TEXT("InitSecurityInterfaceW")
#endif

#ifndef SECURITY_ENTRYPOINT_ANSIA
#define SECURITY_ENTRYPOINT_ANSIA   "InitSecurityInterfaceA"
#endif

#ifndef SECPKG_FLAG_GSS_COMPATIBLE
#define SECPKG_FLAG_GSS_COMPATIBLE  0x00001000
#endif

#ifndef SECQOP_WRAP_NO_ENCRYPT
#define SECQOP_WRAP_NO_ENCRYPT      0x80000001
#endif

#ifndef ISC_RET_MUTUAL_AUTH
#define ISC_RET_MUTUAL_AUTH         0x00000002
#endif

#ifndef ISC_RET_SEQUENCE_DETECT
#define ISC_RET_SEQUENCE_DETECT     0x00000008
#endif

#ifndef ISC_RET_CONFIDENTIALITY
#define ISC_RET_CONFIDENTIALITY     0x00000010
#endif

#ifndef ISC_RET_INTEGRITY
#define ISC_RET_INTEGRITY           0x00010000
#endif

#ifdef Q_CC_MINGW

// for some reason, the MinGW definition of the W table has A functions in
//   it, so we define a fixed version to use instead...

typedef struct _FIXED_SECURITY_FUNCTION_TABLEW {
	unsigned long dwVersion;
	ENUMERATE_SECURITY_PACKAGES_FN_W EnumerateSecurityPackagesW;
	QUERY_CREDENTIALS_ATTRIBUTES_FN_W QueryCredentialsAttributesW;
	ACQUIRE_CREDENTIALS_HANDLE_FN_W AcquireCredentialsHandleW;
	FREE_CREDENTIALS_HANDLE_FN FreeCredentialsHandle;
	void SEC_FAR* Reserved2;
	INITIALIZE_SECURITY_CONTEXT_FN_W InitializeSecurityContextW;
	ACCEPT_SECURITY_CONTEXT_FN AcceptSecurityContext;
	COMPLETE_AUTH_TOKEN_FN CompleteAuthToken;
	DELETE_SECURITY_CONTEXT_FN DeleteSecurityContext;
	APPLY_CONTROL_TOKEN_FN_W ApplyControlTokenW;
	QUERY_CONTEXT_ATTRIBUTES_FN_W QueryContextAttributesW;
	IMPERSONATE_SECURITY_CONTEXT_FN ImpersonateSecurityContext;
	REVERT_SECURITY_CONTEXT_FN RevertSecurityContext;
	MAKE_SIGNATURE_FN MakeSignature;
	VERIFY_SIGNATURE_FN VerifySignature;
	FREE_CONTEXT_BUFFER_FN FreeContextBuffer;
	QUERY_SECURITY_PACKAGE_INFO_FN_W QuerySecurityPackageInfoW;
	void SEC_FAR* Reserved3;
	void SEC_FAR* Reserved4;
	void SEC_FAR* Unknown1;
	void SEC_FAR* Unknown2;
	void SEC_FAR* Unknown3;
	void SEC_FAR* Unknown4;
	void SEC_FAR* Unknown5;
	ENCRYPT_MESSAGE_FN EncryptMessage;
	DECRYPT_MESSAGE_FN DecryptMessage;
} FixedSecurityFunctionTableW, *PFixedSecurityFunctionTableW;

typedef FixedSecurityFunctionTableW MySecurityFunctionTableW;
typedef PFixedSecurityFunctionTableW PMySecurityFunctionTableW;

#else

typedef SecurityFunctionTableW MySecurityFunctionTableW;
typedef PSecurityFunctionTableW PMySecurityFunctionTableW;

#endif

#ifdef UNICODE
# define MySecurityFunctionTable MySecurityFunctionTableW
# define PMySecurityFunctionTable PMySecurityFunctionTableW
#else
# define MySecurityFunctionTable MySecurityFunctionTableA
# define PMySecurityFunctionTable PMySecurityFunctionTableA
#endif

#endif // !defined(FORWARD_ONLY)

namespace wingssQCAPlugin {

//----------------------------------------------------------------------------
// SSPI helper API
//----------------------------------------------------------------------------

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

//----------------------------------------------------------------------------
// SSPI helper implementation
//----------------------------------------------------------------------------

Q_GLOBAL_STATIC(QMutex, sspi_mutex)
Q_GLOBAL_STATIC(QMutex, sspi_logger_mutex)

union SecurityFunctionTableUnion
{
	PMySecurityFunctionTableW W;
	PSecurityFunctionTableA A;
	void *ptr;
};

static QLibrary *sspi_lib = 0;
static SecurityFunctionTableUnion sspi;
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
	if(sspi_lib)
		return true;

	sspi_lib = new QLibrary("secur32");
	if(!sspi_lib->load())
	{
		delete sspi_lib;
		sspi_lib = 0;
		return false;
	}

	union
	{
		INIT_SECURITY_INTERFACE_W W;
		INIT_SECURITY_INTERFACE_A A;
		void *ptr;
	} pInitSecurityInterface;
	pInitSecurityInterface.ptr = 0;

	QString securityEntrypoint;
#if QT_VERSION >= 0x050000
	securityEntrypoint = QString::fromUtf16((const ushort *)SECURITY_ENTRYPOINTW);
	pInitSecurityInterface.W = (INIT_SECURITY_INTERFACE_W)(sspi_lib->resolve(securityEntrypoint.toLatin1().data()));
#else
	QT_WA(
		securityEntrypoint = QString::fromUtf16((const ushort *)SECURITY_ENTRYPOINTW);
		pInitSecurityInterface.W = (INIT_SECURITY_INTERFACE_W)(sspi_lib->resolve(securityEntrypoint.toLatin1().data()));
	,
		securityEntrypoint = QString::fromLatin1(SECURITY_ENTRYPOINT_ANSIA);
		pInitSecurityInterface.A = (INIT_SECURITY_INTERFACE_A)(sspi_lib->resolve(securityEntrypoint.toLatin1().data()));
	)
#endif
	if(!pInitSecurityInterface.ptr)
	{
		sspi_lib->unload();
		delete sspi_lib;
		sspi_lib = 0;
		return false;
	}

	union
	{
		PMySecurityFunctionTableW W;
		PSecurityFunctionTableA A;
		void *ptr;
	} funcs;
	funcs.ptr = 0;

#if QT_VERSION >= 0x050000
	funcs.W = (PMySecurityFunctionTableW)pInitSecurityInterface.W();
#else
	QT_WA(
		funcs.W = (PMySecurityFunctionTableW)pInitSecurityInterface.W();
	,
		funcs.A = pInitSecurityInterface.A();
	)
#endif

	sspi_log(QString("%1() = %2\n").arg(securityEntrypoint, ptr_toString(funcs.ptr)));
	if(!funcs.ptr)
	{
		sspi_lib->unload();
		delete sspi_lib;
		sspi_lib = 0;
		return false;
	}

#if QT_VERSION >= 0x050000
	sspi.W = funcs.W;
#else
	QT_WA(
		sspi.W = funcs.W;
	,
		sspi.A = funcs.A;
	)
#endif

	return true;
}

void sspi_unload()
{
	QMutexLocker locker(sspi_mutex());

	sspi_lib->unload();
	delete sspi_lib;
	sspi_lib = 0;
	sspi.ptr = 0;
}

static QList<SspiPackage> sspi_get_packagelist_direct()
{
	QList<SspiPackage> out;

#if QT_VERSION >= 0x050000
	ULONG cPackages;
	SecPkgInfoW *pPackageInfo;
	SECURITY_STATUS ret = sspi.W->EnumerateSecurityPackagesW(&cPackages, &pPackageInfo);
	sspi_log(QString("EnumerateSecurityPackages() = %1\n").arg(SECURITY_STATUS_toString(ret)));
	if(ret != SEC_E_OK)
		return out;

	for(int n = 0; n < (int)cPackages; ++n)
	{
		SecPkgInfoW *p = &pPackageInfo[n];
		SspiPackage i;
		i.name = QString::fromUtf16((const ushort *)p->Name);
		i.caps = p->fCapabilities;
		i.version = p->wVersion;
		i.rpcid = p->wRPCID;
		i.maxtok = p->cbMaxToken;
		i.comment = QString::fromUtf16((const ushort *)p->Comment);
		out += i;
	}

	ret = sspi.W->FreeContextBuffer(&pPackageInfo);
	sspi_log(QString("FreeContextBuffer() = %1\n").arg(SECURITY_STATUS_toString(ret)));
#else
	QT_WA(
		ULONG cPackages;
		SecPkgInfoW *pPackageInfo;
		SECURITY_STATUS ret = sspi.W->EnumerateSecurityPackagesW(&cPackages, &pPackageInfo);
		sspi_log(QString("EnumerateSecurityPackages() = %1\n").arg(SECURITY_STATUS_toString(ret)));
		if(ret != SEC_E_OK)
			return out;

		for(int n = 0; n < (int)cPackages; ++n)
		{
			SecPkgInfoW *p = &pPackageInfo[n];
			SspiPackage i;
			i.name = QString::fromUtf16((const ushort *)p->Name);
			i.caps = p->fCapabilities;
			i.version = p->wVersion;
			i.rpcid = p->wRPCID;
			i.maxtok = p->cbMaxToken;
			i.comment = QString::fromUtf16((const ushort *)p->Comment);
			out += i;
		}

		ret = sspi.W->FreeContextBuffer(&pPackageInfo);
		sspi_log(QString("FreeContextBuffer() = %1\n").arg(SECURITY_STATUS_toString(ret)));
	,
		ULONG cPackages;
		SecPkgInfoA *pPackageInfo;
		SECURITY_STATUS ret = sspi.A->EnumerateSecurityPackagesA(&cPackages, &pPackageInfo);
		sspi_log(QString("EnumerateSecurityPackages() = %1\n").arg(SECURITY_STATUS_toString(ret)));
		if(ret != SEC_E_OK)
			return out;

		for(int n = 0; n < (int)cPackages; ++n)
		{
			SecPkgInfoA *p = &pPackageInfo[n];
			SspiPackage i;
			i.name = QString::fromLocal8Bit(p->Name);
			i.caps = p->fCapabilities;
			i.version = p->wVersion;
			i.rpcid = p->wRPCID;
			i.maxtok = p->cbMaxToken;
			i.comment = QString::fromLocal8Bit(p->Comment);
			out += i;
		}

		ret = sspi.A->FreeContextBuffer(&pPackageInfo);
		sspi_log(QString("FreeContextBuffer() = %1\n").arg(SECURITY_STATUS_toString(ret)));
	)
#endif

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

template <typename T>
inline T cap_to_int(const T &t)
{
	if(sizeof(int) <= sizeof(T))
		return (int)((t > INT_MAX) ? INT_MAX : t);
	else
		return (int)t;
}

//----------------------------------------------------------------------------
// KerberosSession
//----------------------------------------------------------------------------
// this class thinly wraps SSPI to perform kerberos.
class KerberosSession
{
public:
	enum ReturnCode
	{
		Success,
		NeedMoreData, // for decrypt
		ErrorInvalidSystem,
		ErrorKerberosNotFound,
		ErrorAcquireCredentials,
		ErrorInitialize,
		ErrorQueryContext,
		ErrorEncrypt,
		ErrorDecrypt
	};

	SECURITY_STATUS lastErrorCode;

	quint32 maxtok;

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
	SecPkgContext_StreamSizes ctx_streamSizes;

	KerberosSession() :
		initialized(false),
		have_sizes(false)
	{
	}

	~KerberosSession()
	{
		if(initialized)
		{
			SECURITY_STATUS ret = sspi.W->DeleteSecurityContext(&ctx);
			sspi_log(QString("DeleteSecurityContext() = %1\n").arg(SECURITY_STATUS_toString(ret)));

			ret = sspi.W->FreeCredentialsHandle(&user_cred);
			sspi_log(QString("FreeCredentialsHandle() = %1\n").arg(SECURITY_STATUS_toString(ret)));
		}
	}

	ReturnCode init(const QString &_spn)
	{
		// kerberos only works on unicode-based systems.  we do this
		//   check so we can lazily use the W api from here on out.
#if QT_VERSION < 0x050000
		bool validSystem;
		QT_WA(
			validSystem = true;
		,
			validSystem = false;
		)
		if(!validSystem)
			return ErrorInvalidSystem;
#endif

		// ensure kerberos is available
		bool found = false;
		quint32 _maxtok = 0;
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
				_maxtok = p.maxtok;
			}

			QString gssstr = gss ? "yes" : "no";
			sspi_log(QString("  %1 (gss=%2, maxtok=%3)\n").arg(p.name, gssstr, QString::number(p.maxtok)));
		}

		if(!found)
			return ErrorKerberosNotFound;

		// get the logged-in user's credentials
		SECURITY_STATUS ret = sspi.W->AcquireCredentialsHandleW(
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
		{
			lastErrorCode = ret;
			return ErrorAcquireCredentials;
		}

		maxtok = _maxtok;
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

		ret = sspi.W->InitializeSecurityContextW(
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

				SECURITY_STATUS fret = sspi.W->FreeContextBuffer(outbuf.pvBuffer);
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

			lastErrorCode = ret;

			ret = sspi.W->FreeCredentialsHandle(&user_cred);
			sspi_log(QString("FreeCredentialsHandle() = %1\n").arg(SECURITY_STATUS_toString(ret)));

			return ErrorInitialize;
		}

		initialized = true;
		first_step = true;

		return Success;
	}

	ReturnCode step(const QByteArray &in, QByteArray *out, bool *authenticated)
	{
		if(authed)
		{
			out->clear();
			*authenticated = true;
			return Success;
		}

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

			SECURITY_STATUS ret = sspi.W->InitializeSecurityContextW(
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

					SECURITY_STATUS fret = sspi.W->FreeContextBuffer(outbuf.pvBuffer);
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

				lastErrorCode = ret;

				ret = sspi.W->DeleteSecurityContext(&ctx);
				sspi_log(QString("DeleteSecurityContext() = %1\n").arg(SECURITY_STATUS_toString(ret)));

				ret = sspi.W->FreeCredentialsHandle(&user_cred);
				sspi_log(QString("FreeCredentialsHandle() = %1\n").arg(SECURITY_STATUS_toString(ret)));

				initialized = false;
				return ErrorInitialize;
			}
		}

		*authenticated = authed;
		return Success;
	}

	// private
	bool ensure_sizes_cached()
	{
		if(!have_sizes)
		{
			SECURITY_STATUS ret = sspi.W->QueryContextAttributesW(&ctx, SECPKG_ATTR_SIZES, &ctx_sizes);
			sspi_log(QString("QueryContextAttributes(ctx, SECPKG_ATTR_SIZES, ...) = %1\n").arg(SECURITY_STATUS_toString(ret)));
			if(ret != SEC_E_OK)
			{
				lastErrorCode = ret;
				return false;
			}

			// for some reason, querying the stream sizes returns
			//   SEC_E_UNSUPPORTED_FUNCTION on my system, even
			//   though the docs say it should work and putty
			//   wingss also calls it.

			// all we really need is cbMaximumMessage, and since
			//   we can't query for it, we'll hard code some
			//   value.  according to putty wingss, the max size
			//   is essentially unbounded anyway, so this should
			//   be safe to do.
			ctx_streamSizes.cbMaximumMessage = 8192;

			//ret = sspi.W->QueryContextAttributesW(&ctx, SECPKG_ATTR_STREAM_SIZES, &ctx_streamSizes);
			//sspi_log(QString("QueryContextAttributes(ctx, SECPKG_ATTR_STREAM_SIZES, ...) = %1\n").arg(SECURITY_STATUS_toString(ret)));
			//if(ret != SEC_E_OK)
			//{
			//	lastErrorCode = ret;
			//	return ErrorQueryContext;
			//}

			have_sizes = true;
		}

		return true;
	}

	ReturnCode get_max_encrypt_size(int *max)
	{
		if(!ensure_sizes_cached())
			return ErrorQueryContext;

		*max = cap_to_int<unsigned long>(ctx_streamSizes.cbMaximumMessage);

		return Success;
	}

	ReturnCode encode(const QByteArray &in, QByteArray *out, bool encrypt)
	{
		if(!ensure_sizes_cached())
			return ErrorQueryContext;

		QByteArray tokenbuf(ctx_sizes.cbSecurityTrailer, 0);
		QByteArray padbuf(ctx_sizes.cbBlockSize, 0);

		// we assume here, like putty wingss, that the output size is
		//   less than or equal to the input size.  honestly I don't
		//   see how this is clear from the SSPI documentation, but
		//   the code seems to work so we'll go with it...
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

		SECURITY_STATUS ret = sspi.W->EncryptMessage(&ctx, encrypt ? 0 : SECQOP_WRAP_NO_ENCRYPT, &bufdesc, 0);
		sspi_log(QString("EncryptMessage() = %1\n").arg(SECURITY_STATUS_toString(ret)));
		if(ret != SEC_E_OK)
		{
			lastErrorCode = ret;
			return ErrorEncrypt;
		}

		QByteArray fullbuf;
		for(int i = 0; i < (int)bufdesc.cBuffers; ++i)
			fullbuf += QByteArray((const char *)bufdesc.pBuffers[i].pvBuffer, bufdesc.pBuffers[i].cbBuffer);

		*out = fullbuf;
		return Success;
	}

	ReturnCode decode(const QByteArray &in, QByteArray *out, bool *encrypted)
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
		SECURITY_STATUS ret = sspi.W->DecryptMessage(&ctx, &bufdesc, 0, &fQOP);
		sspi_log(QString("DecryptMessage() = %1\n").arg(SECURITY_STATUS_toString(ret)));
		if(ret == SEC_E_INCOMPLETE_MESSAGE)
		{
			return NeedMoreData;
		}
		else if(ret != SEC_E_OK)
		{
			lastErrorCode = ret;
			return ErrorDecrypt;
		}

		if(buf[0].pvBuffer)
		{
			out->resize(buf[0].cbBuffer);
			memcpy(out->data(), buf[0].pvBuffer, buf[0].cbBuffer);

			SECURITY_STATUS ret = sspi.W->FreeContextBuffer(buf[0].pvBuffer);
			sspi_log(QString("FreeContextBuffer() = %1\n").arg(SECURITY_STATUS_toString(ret)));
		}
		else
			out->clear();

		if(fQOP & SECQOP_WRAP_NO_ENCRYPT)
			*encrypted = false;
		else
			*encrypted = true;

		return Success;
	}
};

//----------------------------------------------------------------------------
// SaslGssapiSession
//----------------------------------------------------------------------------
// this class wraps KerberosSession to perform SASL GSSAPI.  it hides away
//   any SSPI details, and is thus very simple to use.
class SaslGssapiSession
{
private:
	int secflags;
	KerberosSession sess;
	int mode; // 0 = kerberos tokens, 1 = app packets
	bool authed;
	QByteArray inbuf;

	int max_enc_size; // most we can encrypt to them
	int max_dec_size; // most we are expected to decrypt from them

public:
	enum SecurityFlags
	{
		// only one of these should be set
		RequireAtLeastInt  = 0x0001,
		RequireConf        = 0x0002
	};

	enum ReturnCode
	{
		Success,
		ErrorInit,
		ErrorKerberosStep,
		ErrorAppTokenDecode,
		ErrorAppTokenIsEncrypted,
		ErrorAppTokenWrongSize,
		ErrorAppTokenInvalid,
		ErrorAppTokenEncode,
		ErrorLayerTooWeak,
		ErrorEncode,
		ErrorDecode,
		ErrorDecodeTooLarge,
		ErrorDecodeNotEncrypted
	};

	// set this before auth, if you want
	QString authzid;

	// read-only
	bool do_layer, do_conf;

	SaslGssapiSession()
	{
	}

	ReturnCode init(const QString &proto, const QString &fqdn, int _secflags)
	{
		secflags = _secflags;
		mode = 0; // kerberos tokens
		authed = false;

		do_layer = false;
		do_conf = false;

		if(sess.init(proto + '/' + fqdn) != KerberosSession::Success)
			return ErrorInit;

		return Success;
	}

	ReturnCode step(const QByteArray &in, QByteArray *out, bool *authenticated)
	{
		if(authed)
		{
			out->clear();
			*authenticated = true;
			return Success;
		}

		if(mode == 0) // kerberos tokens
		{
			bool kerb_authed;
			if(sess.step(in, out, &kerb_authed) != KerberosSession::Success)
				return ErrorKerberosStep;

			if(kerb_authed)
				mode = 1; // switch to app packets

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
			if(sess.decode(in, &decbuf, &encrypted) != KerberosSession::Success)
			{
				sspi_log("Error decoding application token\n");
				return ErrorAppTokenDecode;
			}

			// this packet is supposed to be not encrypted
			if(encrypted)
			{
				sspi_log("Error, application token is encrypted\n");
				return ErrorAppTokenIsEncrypted;
			}

			// packet must be exactly 4 bytes
			if(decbuf.size() != 4)
			{
				sspi_log("Error, application token is the wrong size\n");
				return ErrorAppTokenWrongSize;
			}

			QString str;
			str.sprintf("%02x%02x%02x%02x",
				(unsigned int)decbuf[0],
				(unsigned int)decbuf[1],
				(unsigned int)decbuf[2],
				(unsigned int)decbuf[3]);
			sspi_log(QString("Received application token: [%1]\n").arg(str));

			unsigned char layermask = decbuf[0];
			quint32 maxsize = 0;
			maxsize += (unsigned char)decbuf[1];
			maxsize <<= 8;
			maxsize += (unsigned char)decbuf[2];
			maxsize <<= 8;
			maxsize += (unsigned char)decbuf[3];

			// if 'None' is all that is supported, then maxsize
			//   must be zero
			if(layermask == 1 && maxsize > 0)
			{
				sspi_log("Error, supports no security layer but the max buffer size is not zero\n");
				return ErrorAppTokenInvalid;
			}

			// convert maxsize to a signed int, by capping it
			int _max_enc_size = cap_to_int<quint32>(maxsize);

			// parse out layermask
			bool saslLayerNone = false;
			bool saslLayerInt = false;
			bool saslLayerConf = false;
			QStringList saslLayerModes;
			if(layermask & 1)
			{
				saslLayerNone = true;
				saslLayerModes += "None";
			}
			if(layermask & 2)
			{
				saslLayerInt = true;
				saslLayerModes += "Int";
			}
			if(layermask & 4)
			{
				saslLayerConf = true;
				saslLayerModes += "Conf";
			}

			sspi_log(QString("Security layer modes supported: %1\n").arg(saslLayerModes.join(", ")));
			sspi_log(QString("Security layer max packet size: %1\n").arg(maxsize));

			// create outbound application token
			QByteArray obuf(4, 0); // initially 4 bytes

			// set one of use_conf or use_int, but not both
			bool use_conf = false;
			bool use_int = false;
			if(encryptionPossible && saslLayerConf)
				use_conf = true;
			else if(layerPossible && saslLayerInt)
				use_int = true;
			else if(!saslLayerNone)
			{
				sspi_log("Error, no compatible layer mode supported, not even 'None'\n");
				return ErrorLayerTooWeak;
			}

			if((secflags & RequireConf) && !use_conf)
			{
				sspi_log("Error, 'Conf' required but not supported\n");
				return ErrorLayerTooWeak;
			}

			if((secflags & RequireAtLeastInt) && !use_conf && !use_int)
			{
				sspi_log("Error, 'Conf' or 'Int' required but not supported\n");
				return ErrorLayerTooWeak;
			}

			if(use_conf)
			{
				sspi_log("Using 'Conf' layer\n");
				obuf[0] = 4;
			}
			else if(use_int)
			{
				sspi_log("Using 'Int' layer\n");
				obuf[0] = 2;
			}
			else
			{
				sspi_log("Using 'None' layer\n");
				obuf[0] = 1;
			}

			// as far as i can tell, there is no max decrypt size
			//   with sspi.  so we'll just pick some number.
			//   a small one is good, to prevent excessive input
			//   buffering.
			// in other parts of the code, it is assumed this
			//   value is less than INT_MAX
			int _max_dec_size = 8192; // same as cyrus

			// max size must be zero if no security layer is used
			if(!use_conf && !use_int)
				_max_dec_size = 0;

			obuf[1] = (unsigned char)((_max_dec_size >> 16) & 0xff);
			obuf[2] = (unsigned char)((_max_dec_size >> 8)  & 0xff);
			obuf[3] = (unsigned char)((_max_dec_size)       & 0xff);

			if(!authzid.isEmpty())
				obuf += authzid.toUtf8();

			str.clear();
			for(int n = 0; n < obuf.size(); ++n)
				str += QString().sprintf("%02x", (unsigned int)obuf[n]);
			sspi_log(QString("Sending application token: [%1]\n").arg(str));

			if(sess.encode(obuf, out, false) != KerberosSession::Success)
			{
				sspi_log("Error encoding application token\n");
				return ErrorAppTokenEncode;
			}

			if(use_conf || use_int)
				do_layer = true;
			if(use_conf)
				do_conf = true;

			max_enc_size = _max_enc_size;
			max_dec_size = _max_dec_size;

			*authenticated = true;
		}

		return Success;
	}

	ReturnCode encode(const QByteArray &in, QByteArray *out)
	{
		if(!do_layer)
		{
			*out = in;
			return Success;
		}

		int local_encrypt_max;
		if(sess.get_max_encrypt_size(&local_encrypt_max) != KerberosSession::Success)
			return ErrorEncode;

		// send no more per-packet than what our local system will
		//   encrypt AND no more than what the peer will accept.
		int chunk_max = qMin(local_encrypt_max, max_enc_size);
		if(chunk_max < 8)
		{
			sspi_log("Error, chunk_max is ridiculously small\n");
			return ErrorEncode;
		}

		QByteArray total_out;

		// break up into packets, if input exceeds max size
		int encoded = 0;
		while(encoded < in.size())
		{
			int left = in.size() - encoded;
			int chunk_size = qMin(left, chunk_max);
			QByteArray kerb_in = QByteArray::fromRawData(in.data() + encoded, chunk_size);
			QByteArray kerb_out;
			if(sess.encode(kerb_in, &kerb_out, do_conf) != KerberosSession::Success)
				return ErrorEncode;

			QByteArray sasl_out(kerb_out.size() + 4, 0);

			// SASL (not GSS!) uses a 4 byte length prefix
			quint32 len = kerb_out.size();
			sasl_out[0] = (unsigned char)((len >> 24) & 0xff);
			sasl_out[1] = (unsigned char)((len >> 16) & 0xff);
			sasl_out[2] = (unsigned char)((len >> 8)  & 0xff);
			sasl_out[3] = (unsigned char)((len)       & 0xff);

			memcpy(sasl_out.data() + 4, kerb_out.data(), kerb_out.size());

			encoded += kerb_in.size();
			total_out += sasl_out;
		}

		*out = total_out;
		return Success;
	}

	ReturnCode decode(const QByteArray &in, QByteArray *out)
	{
		if(!do_layer)
		{
			*out = in;
			return Success;
		}

		// buffer the input
		inbuf += in;

		QByteArray total_out;

		// the buffer might contain many packets.  decode as many
		//   as possible
		while(1)
		{
			if(inbuf.size() < 4)
			{
				// need more data
				break;
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

			// this capping is safe, because we throw error if the value
			//   is too large, and an acceptable value will always be
			//   lower than the maximum integer size.
			int len = cap_to_int<quint32>(ulen);
			if(len > max_dec_size)
			{
				// this means the peer ignored our max buffer size.
				//   very evil, or we're under attack.
				sspi_log("Error, decode size too large\n");
				return ErrorDecodeTooLarge;
			}

			if(inbuf.size() - 4 < len)
			{
				// need more data
				break;
			}

			// take the packet from the inbuf
			QByteArray kerb_in = inbuf.mid(4, len);
			memmove(inbuf.data(), inbuf.data() + len + 4, inbuf.size() - len - 4);
			inbuf.resize(inbuf.size() - len - 4);

			// count incomplete packets as errors, since they are sasl framed
			QByteArray kerb_out;
			bool encrypted;
			if(sess.decode(kerb_in, &kerb_out, &encrypted) != KerberosSession::Success)
				return ErrorDecode;

			if(do_conf && !encrypted)
			{
				sspi_log("Error, received unencrypted packet in 'Conf' mode\n");
				return ErrorDecodeNotEncrypted;
			}

			total_out += kerb_out;
		}

		*out = total_out;
		return Success;
	}
};

//----------------------------------------------------------------------------
// SaslWinGss
//----------------------------------------------------------------------------
class SaslWinGss : public SASLContext
{
	Q_OBJECT

public:
	SaslGssapiSession *sess;
	bool authed;
	Result _result;
	SASL::AuthCondition _authCondition;
	QByteArray _step_to_net;
	QByteArray _to_net, _to_app;
	int enc;
	SafeTimer resultsReadyTrigger;

	QString opt_service, opt_host, opt_ext_id;
	int opt_ext_ssf;
	int opt_flags;
	int opt_minssf, opt_maxssf;

	QString opt_authzid;

	SaslWinGss(Provider *p) :
		SASLContext(p),
		sess(0),
		resultsReadyTrigger(this)
	{
		connect(&resultsReadyTrigger, SIGNAL(timeout()), SIGNAL(resultsReady()));
		resultsReadyTrigger.setSingleShot(true);
	}

	Provider::Context *clone() const
	{
		return 0;
	}

	virtual void reset()
	{
		delete sess;
		sess = 0;
		authed = false;
		_step_to_net.clear();
		_to_net.clear();
		_to_app.clear();
		resultsReadyTrigger.stop();

		opt_service.clear();
		opt_host.clear();
		opt_ext_id.clear();
		opt_authzid.clear();
	}

	virtual void setup(const QString &service, const QString &host, const HostPort *local, const HostPort *remote, const QString &ext_id, int ext_ssf)
	{
		// unused by this provider
		Q_UNUSED(local);
		Q_UNUSED(remote);

		opt_service = service;
		opt_host = host;
		opt_ext_id = ext_id;
		opt_ext_ssf = ext_ssf;
	}

	virtual void setConstraints(SASL::AuthFlags f, int minSSF, int maxSSF)
	{
		opt_flags = (int)f;
		opt_minssf = minSSF;
		opt_maxssf = maxSSF;
	}

	virtual void startClient(const QStringList &mechlist, bool allowClientSendFirst)
	{
		// we only support GSSAPI
		if(!mechlist.contains("GSSAPI"))
		{
			_result = Error;
			_authCondition = SASL::NoMechanism;
			resultsReadyTrigger.start();
			return;
		}

		// GSSAPI (or this provider) doesn't meet these requirements
		if(opt_flags & SASL::RequireForwardSecrecy
			|| opt_flags & SASL::RequirePassCredentials
			|| !allowClientSendFirst)
		{
			_result = Error;
			_authCondition = SASL::NoMechanism;
			resultsReadyTrigger.start();
			return;
		}

		sess = new SaslGssapiSession;
		sess->authzid = opt_authzid;

		int secflags = 0;
		if(opt_minssf > 1)
			secflags |= SaslGssapiSession::RequireConf;
		else if(opt_minssf == 1)
			secflags |= SaslGssapiSession::RequireAtLeastInt;

		SaslGssapiSession::ReturnCode ret = sess->init(opt_service, opt_host, secflags);
		if(ret != SaslGssapiSession::Success)
		{
			_result = Error;
			_authCondition = SASL::AuthFail;
			resultsReadyTrigger.start();
			return;
		}

		ret = sess->step(QByteArray(), &_step_to_net, &authed);
		if(ret != SaslGssapiSession::Success)
		{
			_result = Error;
			_authCondition = SASL::AuthFail;
			resultsReadyTrigger.start();
			return;
		}

		if(authed)
			_result = Success;
		else
			_result = Continue;

		resultsReadyTrigger.start();
	}

	virtual void startServer(const QString &realm, bool disableServerSendLast)
	{
		// server mode unsupported at this time
		Q_UNUSED(realm);
		Q_UNUSED(disableServerSendLast);

		_result = Error;
		_authCondition = SASL::AuthFail;
		resultsReadyTrigger.start();
	}

	virtual void serverFirstStep(const QString &mech, const QByteArray *clientInit)
	{
		// server mode unsupported at this time
		Q_UNUSED(mech);
		Q_UNUSED(clientInit);
	}

	virtual void nextStep(const QByteArray &from_net)
	{
		SaslGssapiSession::ReturnCode ret = sess->step(from_net, &_step_to_net, &authed);
		if(ret != SaslGssapiSession::Success)
		{
			_result = Error;
			_authCondition = SASL::AuthFail;
			resultsReadyTrigger.start();
			return;
		}

		if(authed)
			_result = Success;
		else
			_result = Continue;

		resultsReadyTrigger.start();
	}

	virtual void tryAgain()
	{
		// we never ask for params, so this function should never be
		//   called
	}

	virtual void update(const QByteArray &from_net, const QByteArray &from_app)
	{
		SaslGssapiSession::ReturnCode ret;
		QByteArray a;

		if(!from_net.isEmpty())
		{
			ret = sess->decode(from_net, &a);
			if(ret != SaslGssapiSession::Success)
			{
				_result = Error;
				resultsReadyTrigger.start();
				return;
			}

			_to_app += a;
		}

		if(!from_app.isEmpty())
		{
			ret = sess->encode(from_app, &a);
			if(ret != SaslGssapiSession::Success)
			{
				_result = Error;
				resultsReadyTrigger.start();
				return;
			}

			_to_net += a;
			enc += from_app.size();
		}

		_result = Success;
		resultsReadyTrigger.start();
	}

	virtual bool waitForResultsReady(int msecs)
	{
		// all results are ready instantly
		Q_UNUSED(msecs);
		resultsReadyTrigger.stop();
		return true;
	}

	virtual Result result() const
	{
		return _result;
	}

	virtual QStringList mechlist() const
	{
		// server mode unsupported at this time
		return QStringList();
	}

	virtual QString mech() const
	{
		// only mech we support :)
		return "GSSAPI";
	}

	virtual bool haveClientInit() const
	{
		// GSSAPI always has a client init response
		return true;
	}

	virtual QByteArray stepData() const
	{
		return _step_to_net;
	}

	virtual QByteArray to_net()
	{
		QByteArray a = _to_net;
		_to_net.clear();
		enc = 0;
		return a;
	}

	virtual int encoded() const
	{
		return enc;
	}

	virtual QByteArray to_app()
	{
		QByteArray a = _to_app;
		_to_app.clear();
		return a;
	}

	virtual int ssf() const
	{
		if(!sess->do_layer)
			return 0;

		if(sess->do_conf)
		{
			// TODO: calculate this value somehow?  for now we'll
			//   just hard code it to 56, which is basically what
			//   cyrus does.
			return 56;
		}
		else
			return 1;
	}

	virtual SASL::AuthCondition authCondition() const
	{
		return _authCondition;
	}

	virtual SASL::Params clientParams() const
	{
		// we never ask for params
		return SASL::Params();
	}

	virtual void setClientParams(const QString *user, const QString *authzid, const SecureArray *pass, const QString *realm)
	{
		// unused by this provider
		Q_UNUSED(user);
		Q_UNUSED(pass);
		Q_UNUSED(realm);

		if(authzid)
		{
			opt_authzid = *authzid;
			if(sess)
				sess->authzid = opt_authzid;
		}
		else
		{
			opt_authzid.clear();
			if(sess)
				sess->authzid.clear();
		}
	}

	virtual QStringList realmlist() const
	{
		// unused by this provider
		return QStringList();
	}

	virtual QString username() const
	{
		// server mode unsupported at this time
		return QString();
	}

	virtual QString authzid() const
	{
		// server mode unsupported at this time
		return QString();
	}
};

#endif // !defined(FORWARD_ONLY)

//----------------------------------------------------------------------------
// MetaSasl
//----------------------------------------------------------------------------
#ifndef FORWARD_ONLY
class wingssProvider;
static bool wingssProvider_have_sspi(wingssProvider *provider);
#endif

class MetaSasl : public SASLContext
{
	Q_OBJECT

public:
	SASLContext *s;

	Result _result;
	SASL::AuthCondition _authCondition;
	SafeTimer resultsReadyTrigger;
	Synchronizer sync;
	bool waiting;

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
		resultsReadyTrigger(this),
		sync(this),
		waiting(false),
		serverInit_active(false)
	{
		s = 0;

		have_opt_user = false;
		have_opt_authzid = false;
		have_opt_pass = false;
		have_opt_realm = false;

		connect(&resultsReadyTrigger, SIGNAL(timeout()), SIGNAL(resultsReady()));
		resultsReadyTrigger.setSingleShot(true);
	}

	~MetaSasl()
	{
		delete s;
	}

	virtual Provider::Context *clone() const
	{
		return 0;
	}

	void clearSaslProviders()
	{
		foreach(const SaslProvider &sp, saslProviders)
			delete sp.sasl;

		saslProviders.clear();
	}

	virtual void reset()
	{
		delete s;
		s = 0;

		resultsReadyTrigger.stop();

		opt_service.clear();
		opt_host.clear();
		opt_ext_id.clear();
		opt_user.clear();
		opt_authzid.clear();
		opt_realm.clear();
		opt_pass.clear();

		have_opt_user = false;
		have_opt_authzid = false;
		have_opt_pass = false;
		have_opt_realm = false;

		clearSaslProviders();
		serverInit_active = false;
		serverInit_mechlist.clear();
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
		if(mechlist.contains("GSSAPI") && wingssProvider_have_sspi((wingssProvider *)provider()))
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

			if(!list.isEmpty())
			{
				// use the first
				s = static_cast<SASLContext *>(list.first()->createContext("sasl"));
			}
#ifndef FORWARD_ONLY
		}
#endif

		if(!s)
		{
			// no usable provider?  throw error
			_result = Error;
			_authCondition = SASL::NoMechanism;
			resultsReadyTrigger.start();
			return;
		}

		// proper parenting
		s->setParent(this);

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

		QString str = QString("MetaSasl: client using %1 with %2 mechs").arg(s->provider()->name(), QString::number(mechlist.count()));
		QCA_logTextMessage(str, Logger::Debug);
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

			// proper parenting
			sp.sasl->setParent(this);

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
		// choose a provider based on the mech
		int at = choose_provider(mech);

		// extract it and clean up the rest
		SASLContext *sasl = saslProviders[at].sasl;
		sasl->disconnect(this);
		saslProviders.removeAt(at);
		clearSaslProviders();
		serverInit_active = false;

		// use the chosen provider
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
		if(serverInit_active)
		{
			waiting = true;
			bool ret = sync.waitForCondition(msecs);
			waiting = false;
			return ret;
		}
		else if(s)
			return s->waitForResultsReady(msecs);
		else
			return true;
	}

	virtual Result result() const
	{
		if(serverInit_active)
			return serverInit_result;
		else if(s)
			return s->result();
		else
			return _result;
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
		if(s)
			return s->authCondition();
		else
			return _authCondition;
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

				if(waiting)
					sync.conditionMet();
				else
					emit resultsReady();
			}
		}
		else
		{
			delete sasl;
			saslProviders.removeAt(at);

			if(saslProviders.isEmpty())
			{
				// indicate error
				serverInit_result = Error;
				_authCondition = SASL::NoMechanism;

				if(waiting)
					sync.conditionMet();
				else
					emit resultsReady();
			}
		}
	}

private:
	QStringList combine_mechlists()
	{
		QStringList out;

		// FIXME: consider prioritizing certain mechs?
		foreach(const SaslProvider &sp, saslProviders)
		{
			foreach(const QString &mech, sp.mechlist)
			{
				if(!out.contains(mech))
					out += mech;
			}
		}

		return out;
	}

	int choose_provider(const QString &mech)
	{
		int at = -1;

		// find a provider for this mech
		for(int n = 0; n < saslProviders.count(); ++n)
		{
			const SaslProvider &sp = saslProviders[n];
			if(sp.mechlist.contains(mech))
			{
				at = n;
				break;
			}
		}

		// no provider offered this mech?  then just go with the
		//   first provider
		if(at == -1)
			at = 0;

		return at;
	}
};

class wingssProvider : public Provider
{
public:
	mutable QMutex m;
	mutable bool forced_priority;
	bool have_sspi;

	wingssProvider() :
		forced_priority(false),
		have_sspi(false)
	{
	}

	virtual void init()
	{
#ifndef FORWARD_ONLY
		sspi_set_logger(do_log);
		have_sspi = sspi_load();
#endif
	}

	~wingssProvider()
	{
#ifndef FORWARD_ONLY
		if(have_sspi)
			sspi_unload();
#endif
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

#ifndef FORWARD_ONLY
	static void do_log(const QString &str)
	{
		QCA_logTextMessage(str, Logger::Debug);
	}
#endif
};

#ifndef FORWARD_ONLY
bool wingssProvider_have_sspi(wingssProvider *provider)
{
	return provider->have_sspi;
}
#endif

}

using namespace wingssQCAPlugin;

//----------------------------------------------------------------------------
// wingssPlugin
//----------------------------------------------------------------------------

class wingssPlugin : public QObject, public QCAPlugin
{
	Q_OBJECT
#if QT_VERSION >= 0x050000
	Q_PLUGIN_METADATA(IID "com.affinix.qca.Plugin/1.0")
#endif
	Q_INTERFACES(QCAPlugin)

public:
	virtual Provider *createProvider() { return new wingssProvider; }
};

#include "qca-wingss.moc"

#if QT_VERSION < 0x050000
Q_EXPORT_PLUGIN2(qca_wingss, wingssPlugin)
#endif
