/*
 * Copyright (C) 2005  Justin Karneges <justin@affinix.com>
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

#include <QtCore>
#include <QtCrypto>

#ifdef Q_OS_WIN
# include "rsaref/win32.h"
# pragma pack(push, cryptoki, 1)
# include "rsaref/pkcs11.h"
# pragma pack(pop, cryptoki)
#endif

#ifdef Q_OS_UNIX
# include "rsaref/unix.h"
# include "rsaref/pkcs11.h"
#endif

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>

using namespace QCA;

namespace pkcs11QCAPlugin {

struct mech_name
{
	CK_MECHANISM_TYPE mech;
	const char *name;
};

static struct mech_name mech_table[] =
{
#include "mech_names.cpp"
};

/*struct tokenflag_name
{
	CK_FLAGS flag;
	const char *name;
};

static struct tokenflag_name tokenflag_table[] =
{
	{ CKF_RNG,                           "RNG" },
	{ CKF_WRITE_PROTECTED,               "WRITE_PROTECTED" },
	{ CKF_LOGIN_REQUIRED,                "LOGIN_REQUIRED" },
	{ CKF_USER_PIN_INITIALIZED,          "USER_PIN_INITIALIZED" },
	{ CKF_RESTORE_KEY_NOT_NEEDED,        "RESTORE_KEY_NOT_NEEDED" },
	{ CKF_CLOCK_ON_TOKEN,                "CLOCK_ON_TOKEN" },
	{ CKF_PROTECTED_AUTHENTICATION_PATH, "PROTECTED_AUTHENTICATION_PATH" },
	{ CKF_DUAL_CRYPTO_OPERATIONS,        "DUAL_CRYPTO_OPERATIONS" },
	{ CKF_TOKEN_INITIALIZED,             "TOKEN_INITIALIZED" },
	{ CKF_SECONDARY_AUTHENTICATION,      "SECONDARY_AUTHENTICATION" },
	{ CKF_USER_PIN_COUNT_LOW,            "USER_PIN_COUNT_LOW" },
	{ CKF_USER_PIN_FINAL_TRY,            "USER_PIN_FINAL_TRY" },
	{ CKF_USER_PIN_LOCKED,               "USER_PIN_LOCKED" },
	{ CKF_USER_PIN_TO_BE_CHANGED,        "USER_PIN_TO_BE_CHANGED" },
	{ CKF_SO_PIN_COUNT_LOW,              "SO_PIN_COUNT_LOW" },
	{ CKF_SO_PIN_FINAL_TRY,              "SO_PIN_FINAL_TRY" },
	{ CKF_SO_PIN_LOCKED,                 "SO_PIN_LOCKED" },
	{ CKF_SO_PIN_TO_BE_CHANGED,          "SO_PIN_TO_BE_CHANGED" },
	{ 0, 0 }
};*/

/*struct mechflag_name
{
	CK_FLAGS flag;
	const char *name;
};

static struct mechflag_name mechflag_table[] =
{
	{ CKF_HW,                "HW" },
	{ CKF_ENCRYPT,           "ENCRYPT" },
	{ CKF_DECRYPT,           "DECRYPT" },
	{ CKF_DIGEST,            "DIGEST" },
	{ CKF_SIGN,              "SIGN" },
	{ CKF_SIGN_RECOVER,      "SIGN_RECOVER" },
	{ CKF_VERIFY,            "VERIFY" },
	{ CKF_VERIFY_RECOVER,    "VERIFY_RECOVER" },
	{ CKF_GENERATE,          "GENERATE" },
	{ CKF_GENERATE_KEY_PAIR, "GENERATE_KEY_PAIR" },
	{ CKF_WRAP,              "WRAP" },
	{ CKF_UNWRAP,            "UNWRAP" },
	{ CKF_DERIVE,            "DERIVE" },
	{ 0, 0 }
};*/

static QString getString(CK_UTF8CHAR *string, size_t len)
{
	QByteArray cs((const char *)string, (int)len);
	return QString::fromUtf8(cs).trimmed();
}

/*static QString hexify(const QByteArray &buf)
{
	QString hex;
	for(int n = 0; n < buf.size(); ++n)
	{
		QString s;
		s.sprintf("%02x", (unsigned char)buf[n]);
		hex += s;
	}
	return hex;
}*/

class CTIModule
{
private:
	QString libname;
	QLibrary *lib;

	static CK_RV cb_createMutex(CK_VOID_PTR_PTR ppMutex)
	{
		*((QMutex **)ppMutex) = new QMutex;
		return CKR_OK;
	}

	static CK_RV cb_destroyMutex(CK_VOID_PTR pMutex)
	{
		delete ((QMutex *)pMutex);
		return CKR_OK;
	}

	static CK_RV cb_lockMutex(CK_VOID_PTR pMutex)
	{
		((QMutex *)pMutex)->lock();
		return CKR_OK;
	}

	static CK_RV cb_unlockMutex(CK_VOID_PTR pMutex)
	{
		((QMutex *)pMutex)->unlock();
		return CKR_OK;
	}

public:
	CK_FUNCTION_LIST_PTR p11;

	CTIModule()
	{
		lib = 0;
		p11 = 0;
	}

	~CTIModule()
	{
		unload();
	}

	bool load(const QString &fname)
	{
		libname = fname;
		lib = new QLibrary(libname);
		if(!lib->load())
		{
			delete lib;
			lib = 0;
			return false;
		}

		CK_RV (*C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR);
		C_GetFunctionList = (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR))lib->resolve("C_GetFunctionList");
		if(!C_GetFunctionList)
		{
			delete lib;
			lib = 0;
			return false;
		}

		CK_RV rv = C_GetFunctionList(&p11);
		if(rv != CKR_OK)
		{
			delete lib;
			lib = 0;
			return false;
		}

		printf("Initializing\n");
		CK_C_INITIALIZE_ARGS args;
		args.CreateMutex = cb_createMutex;
		args.DestroyMutex = cb_destroyMutex;
		args.LockMutex = cb_lockMutex;
		args.UnlockMutex = cb_unlockMutex;
		args.flags = CKF_OS_LOCKING_OK;
		args.pReserved = NULL_PTR;
		rv = p11->C_Initialize(&args);
		printf("Done\n");
		if(rv != CKR_OK)
		{
			delete lib;
			lib = 0;
			return false;
		}

		return true;
	}

	void unload()
	{
		if(lib)
		{
			printf("finalizing / unloading\n");
			p11->C_Finalize(NULL_PTR);
			delete lib;
			lib = 0;
			p11 = 0;
		}
	}

	static QString mechanismName(CK_MECHANISM_TYPE mech)
	{
		for(int n = 0; mech_table[n].name; ++n)
		{
			if(mech_table[n].mech == mech)
				return QString::fromLatin1(mech_table[n].name);
		}
		return QString("Unknown-%1").arg(mech, (int)8, (int)16, QChar('0'));
	}
};

class CTIWaitThread : public QThread
{
	Q_OBJECT
public:
	CK_FUNCTION_LIST_PTR p11;
	QEventLoop *loop;
	QMutex m;
	bool cancelled;

	struct SlotItem
	{
		CK_SLOT_ID id;
		bool haveToken;
	};
	QList<SlotItem> slotList;

	CTIWaitThread(const QList<SlotItem> &_slotList, QObject *parent = 0)
	:QThread(parent), slotList(_slotList)
	{
		cancelled = false;
	}

	~CTIWaitThread()
	{
		wait();
	}

	void cancel()
	{
		QMutexLocker ml(&m);
		cancelled = true;
		if(loop)
			QMetaObject::invokeMethod(loop, "quit", Qt::QueuedConnection);
	}

signals:
	void slotEvent(CK_SLOT_ID id, bool haveToken);

protected:
	virtual void run()
	{
		while(1)
		{
			CK_SLOT_ID slot;
			CK_RV rv = p11->C_WaitForSlotEvent(0, &slot, NULL_PTR);
			if(rv == CKR_FUNCTION_NOT_SUPPORTED)
			{
				// fall back on polling
				printf("C_WaitForSlotEvent not supported, falling back to polling\n");
				m.lock();
				loop = new QEventLoop;
				QTimer *t = new QTimer;
				connect(t, SIGNAL(timeout()), SLOT(t_timeout()));
				t->start(5000);
				m.unlock();
				loop->exec();
				m.lock();
				delete t;
				delete loop;
				loop = 0;
				m.unlock();
				break;
			}
			else if(rv != CKR_OK)
			{
				printf("C_WaitForSlotEvent returned: %08x\n", (unsigned int)rv);
				break;
			}

			printf("C_WaitForSlotEvent success\n");
			CK_SLOT_INFO info;
			rv = p11->C_GetSlotInfo(slot, &info);
			if(rv != CKR_OK)
				continue;
			bool found = false;
			for(int n = 0; n < slotList.count(); ++n)
			{
				if(slotList[n].id == slot)
				{
					found = true;
					break;
				}
			}
			if(!found)
			{
				printf("slot event from unknown slot?? [%lu]\n", slot);
				continue;
			}
			bool haveToken = info.flags & CKF_TOKEN_PRESENT;
			emit slotEvent(slot, haveToken);
		}
		printf("CTIWaitThread ending\n");
	}

private slots:
	void t_timeout()
	{
		m.lock();
		if(cancelled)
		{
			loop->quit();
			m.unlock();
			return;
		}
		m.unlock();

		printf("checking slot states\n");
		for(int n = 0; n < slotList.count(); ++n)
		{
			SlotItem &i = slotList[n];
			CK_SLOT_ID slot = i.id;
			CK_SLOT_INFO info;
			CK_RV rv = p11->C_GetSlotInfo(slot, &info);
			if(rv != CKR_OK)
				continue;
			bool haveToken = info.flags & CKF_TOKEN_PRESENT;
			if(haveToken == i.haveToken)
				continue; // no change in state
			i.haveToken = haveToken;
			emit slotEvent(slot, haveToken);
		}
	}
};

class CTIControl : public QObject
{
	Q_OBJECT
public:
	class ModuleInfo
	{
	public:
		QString ckVersion;
		QString manufacturer;
		QString libraryDescription;
		QString libraryVersion;
	};

	class MechInfo
	{
	public:
		CK_MECHANISM_TYPE type;
		int flags;

		MechInfo() : flags(0) {}
	};

	class TokenInfo
	{
	public:
		QString label;
		QString manufacturer;
		QString model;
		QString serialNumber;
		int flags;
		QList<MechInfo> mechInfoList;

		TokenInfo() : flags(0) {}
	};

	class SlotInfo
	{
	public:
		CK_SLOT_ID slotId;
		QString slotDescription;
		QString manufacturer;
		bool haveToken;
		bool isRemovable;
		bool isHardware;
		TokenInfo tokenInfo;
	};

	CTIModule module;
	CK_FUNCTION_LIST_PTR p11;
	bool have_init;
	CTIWaitThread *waitThread;

	// "public"
	ModuleInfo moduleInfo;
	QList<SlotInfo> slotInfoList;

	CTIControl(QObject *parent = 0) : QObject(parent)
	{
		have_init = false;
		waitThread = 0;
	}

	~CTIControl()
	{
		deinit();
	}

	bool init(const QString &fname)
	{
		if(!module.load(fname))
			return false;

		p11 = module.p11;

		CK_INFO info;
		CK_RV rv = p11->C_GetInfo(&info);
		if(rv == CKR_OK)
		{
			moduleInfo.ckVersion = QString("%1.%2").arg(info.cryptokiVersion.major).arg(info.cryptokiVersion.minor);
			moduleInfo.manufacturer = getString(info.manufacturerID, sizeof(info.manufacturerID));
			moduleInfo.libraryDescription = getString(info.libraryDescription, sizeof(info.libraryDescription));
			moduleInfo.libraryVersion = QString("%1.%2").arg(info.libraryVersion.major).arg(info.libraryVersion.minor);
		}

		CK_ULONG num;
		QVector<CK_SLOT_ID> slotList;
		rv = p11->C_GetSlotList(FALSE, NULL_PTR, &num);
		if(rv == CKR_OK)
		{
			slotList.resize(num);
			p11->C_GetSlotList(FALSE, slotList.data(), &num);
		}

		int n;
		for(n = 0; n < slotList.count(); ++n)
		{
			CK_SLOT_ID slot = slotList[n];
			CK_SLOT_INFO info;
			CK_RV rv = p11->C_GetSlotInfo(slot, &info);
			if(rv != CKR_OK)
				continue;

			SlotInfo i;
			i.slotId = slot;
			i.slotDescription = getString(info.slotDescription, sizeof(info.slotDescription));
			i.manufacturer = getString(info.manufacturerID, sizeof(info.manufacturerID));
			i.haveToken = info.flags & CKF_TOKEN_PRESENT;
			i.isRemovable = info.flags & CKF_REMOVABLE_DEVICE;
			i.isHardware = info.flags & CKF_HW_SLOT;
			slotInfoList += i;
		}

		QList<CTIWaitThread::SlotItem> sl;
		for(n = 0; n < slotInfoList.count(); ++n)
		{
			SlotInfo &i = slotInfoList[n];
			CTIWaitThread::SlotItem wi;
			wi.id = i.slotId;
			wi.haveToken = i.haveToken;
			sl += wi;
			if(i.haveToken)
				getTokenInfo(&i);
		}

		waitThread = new CTIWaitThread(sl, this);
		connect(waitThread, SIGNAL(slotEvent(CK_SLOT_ID, bool)), SLOT(slotEvent(CK_SLOT_ID, bool)));
		waitThread->p11 = module.p11;
		waitThread->start();

		have_init = true;
		return true;
	}

	void deinit()
	{
		if(have_init)
		{
			moduleInfo = ModuleInfo();
			slotInfoList.clear();
			waitThread->cancel(); // needed to stop polling mode
			module.unload(); // C_Finalize will stop wait mode
			delete waitThread;
			waitThread = 0;
		}
	}

signals:
	void slotChanged(int index);

private slots:
	void slotEvent(CK_SLOT_ID slot, bool haveToken)
	{
		for(int n = 0; n < slotInfoList.count(); ++n)
		{
			if(slotInfoList[n].slotId == slot)
			{
				processSlotEvent(n, &slotInfoList[n], haveToken);
				break;
			}
		}
	}

private:
	void processSlotEvent(int index, SlotInfo *_i, bool haveToken)
	{
		SlotInfo &i = *_i;

		if(haveToken)
		{
			printf("Slot Event [%lu]: token inserted\n", i.slotId);
			getTokenInfo(&i);
		}
		else
		{
			printf("Slot Event [%lu]: token removed\n", i.slotId);

			i.haveToken = false;
			i.tokenInfo = TokenInfo();
		}

		emit slotChanged(index);
	}

	void getTokenInfo(SlotInfo *_slotInfo)
	{
		SlotInfo &slotInfo = *_slotInfo;

		CK_SLOT_ID slot = slotInfo.slotId;
		CK_TOKEN_INFO info;
		printf("getting token info\n");
		CK_RV rv = p11->C_GetTokenInfo(slot, &info);
		if(rv != CKR_OK)
		{
			printf("error getting token info\n");
			return;
		}

		TokenInfo i;
		i.label = getString(info.label, sizeof(info.label));
		i.manufacturer = getString(info.manufacturerID, sizeof(info.manufacturerID));
		i.model = getString(info.model, sizeof(info.model));
		i.serialNumber = getString(info.serialNumber, sizeof(info.serialNumber));
		i.flags = info.flags;

		CK_ULONG num;
		QVector<CK_MECHANISM_TYPE> mechList;
		printf("getting token mechanism list\n");
		rv = p11->C_GetMechanismList(slot, NULL_PTR, &num);
		if(rv != CKR_OK)
		{
			printf("error getting token mechanism list\n");
			return;
		}
		mechList.resize(num);
		rv = p11->C_GetMechanismList(slot, mechList.data(), &num);
		if(rv != CKR_OK)
		{
			printf("error getting token mechanism list (error 2)\n");
			return;
		}
		for(int n = 0; n < mechList.count(); ++n)
		{
			CK_MECHANISM_TYPE type = mechList[n];
			bool found = false;
			for(int x = 0; x < i.mechInfoList.count(); ++x)
			{
				if(i.mechInfoList[x].type == type)
				{
					found = true;
					break;
				}
			}
			if(found) // already have it
				continue;

			CK_MECHANISM_INFO info;
			rv = p11->C_GetMechanismInfo(slot, type, &info);
			if(rv != CKR_OK)
			{
				printf("error getting mechanism list (error 3)\n");
				return;
			}
			MechInfo mi;
			mi.type = type;
			mi.flags = info.flags;
			i.mechInfoList += mi;
		}

		slotInfo.haveToken = true;
		slotInfo.tokenInfo = i;
	}
};

class CTISession
{
private:
	CTIModule *mod;
	bool have_session;
	bool have_login;

public:
	CK_FUNCTION_LIST_PTR p11;
	CK_SESSION_HANDLE handle;

	class Object
	{
	public:
		CK_OBJECT_HANDLE handle;
		CK_OBJECT_CLASS type;
		QByteArray id;
		QString label;
	};
	QList<Object> objectList;

	CTISession(CTIModule *_mod)
	{
		mod = _mod;
		p11 = mod->p11;
		have_session = false;
		have_login = false;
	}

	~CTISession()
	{
		close();
	}

	bool open(CK_SLOT_ID slot, CK_FLAGS _flags)
	{
		int flags = CKF_SERIAL_SESSION;
		flags |= _flags;
		CK_RV rv = p11->C_OpenSession(slot, flags, NULL, NULL, &handle);
		if(rv != CKR_OK)
			return false;
		have_session = true;
		return true;
	}

	void close()
	{
		if(have_session)
		{
			printf("closing session\n");
			p11->C_CloseSession(handle);
			have_session = false;
		}
	}

	bool login(CK_USER_TYPE type, const char *pin, int pin_len)
	{
		CK_RV rv = p11->C_Login(handle, type, (CK_UTF8CHAR *)pin, pin_len);
		if(rv != CKR_OK)
			return false;
		have_login = true;
		return true;
	}

	bool loginProtected(CK_USER_TYPE type)
	{
		CK_RV rv = p11->C_Login(handle, type, NULL_PTR, 0);
		if(rv != CKR_OK)
			return false;
		have_login = true;
		return true;
	}

	void logout()
	{
		p11->C_Logout(handle);
	}

	bool getObjects()
	{
		objectList.clear();

		CK_RV rv = p11->C_FindObjectsInit(handle, NULL_PTR, 0);
		if(rv != CKR_OK)
			return false;

		QVector<CK_OBJECT_HANDLE> objectHandles;
		while(1)
		{
			// read 128 objects at a time
			QVector<CK_OBJECT_HANDLE> tmp(128);
			CK_ULONG num;
			rv = p11->C_FindObjects(handle, tmp.data(), tmp.count(), &num);
			if(rv != CKR_OK)
				return false;
			bool done = ((int)num < tmp.size());
			tmp.resize(num);
			objectHandles += tmp;
			if(done)
				break;
		}

		rv = p11->C_FindObjectsFinal(handle);
		if(rv != CKR_OK)
			return false;

		// get some basic info about each object
		QList<Object> list;
		for(int n = 0; n < objectHandles.count(); ++n)
		{
			CK_OBJECT_HANDLE obj = objectHandles[n];

			CK_OBJECT_CLASS cls;
			CK_ATTRIBUTE attr[3] =
			{
				{ CKA_CLASS, &cls, sizeof(CK_OBJECT_CLASS) },
				{ CKA_ID, NULL_PTR, 0 },
				{ CKA_LABEL, NULL_PTR, 0 }
			};
			CK_RV rv = p11->C_GetAttributeValue(handle, obj, attr, 3);
			if(rv != CKR_OK)
				return false;

			// make buffers
			QByteArray buf_id(attr[1].ulValueLen, 0);
			QByteArray buf_label(attr[2].ulValueLen, 0);
			attr[1].pValue = buf_id.data();
			attr[2].pValue = buf_label.data();

			// optimize by skipping over attr[0] (we have it already)
			rv = p11->C_GetAttributeValue(handle, obj, &(attr[1]), 2);
			if(rv != CKR_OK)
				return false;

			Object i;
			i.handle = obj;
			i.type = cls;
			i.id = buf_id;
			i.label = QString::fromUtf8(buf_label);
			list += i;
		}

		objectList = list;
		return true;
	}

	bool sign_RSA_EMSA3_Raw(CK_OBJECT_HANDLE key, int type, const unsigned char *in, int in_len, unsigned char *out, int *out_len)
	{
		// using RSA_PKCS (very "raw" algorithm)
		// TODO: check if we have it first
		CK_MECHANISM mechanism;
		memset(&mechanism, 0, sizeof(mechanism));
		mechanism.mechanism = CKM_RSA_PKCS;

		CK_RV rv = p11->C_SignInit(handle, &mechanism, key);
		if(rv != CKR_OK)
		{
			printf("sign fail [%08x]\n", (unsigned int)rv);
			return false;
		}

		CK_ULONG sigsize;
		rv = p11->C_Sign(handle, (unsigned char*)in, in_len, out, &sigsize);
		if(rv != CKR_OK)
		{
			//p11->C_CloseSession(session);
			printf("sign fail [%08x]\n", (unsigned int)rv);
			return false;
			//goto error;
		}

		printf("done with signing\n");

		*out_len = sigsize;
		return true;
	}

	bool getBigIntegerData(CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_TYPE type, QByteArray *out)
	{
		CK_ATTRIBUTE attr;
		attr.type = type;
		attr.pValue = NULL_PTR;
		attr.ulValueLen = 0;
		CK_RV rv = p11->C_GetAttributeValue(handle, obj, &attr, 1);
		if(rv != CKR_OK)
			return false;

		// make buffer
		QByteArray buf(attr.ulValueLen, 0);
		attr.pValue = buf.data();

		rv = p11->C_GetAttributeValue(handle, obj, &attr, 1);
		if(rv != CKR_OK)
			return false;

		*out = buf;
		return true;
	}
};

CTIControl *con;

static QBigInteger bn2bi(BIGNUM *n)
{
	QSecureArray buf(BN_num_bytes(n) + 1);
	buf[0] = 0; // positive
	BN_bn2bin(n, (unsigned char *)buf.data() + 1);
	return QBigInteger(buf);
}

static QSecureArray bio2buf(BIO *b)
{
	QSecureArray buf;
	while(1) {
		QSecureArray block(1024);
		int ret = BIO_read(b, block.data(), block.size());
		if(ret <= 0)
			break;
		block.resize(ret);
		buf.append(block);
		if(ret != 1024)
			break;
	}
	BIO_free(b);
	return buf;
}

EVP_PKEY *qca_d2i_PKCS8PrivateKey(const QSecureArray &in, EVP_PKEY **x, pem_password_cb *cb, void *u)
{
	PKCS8_PRIV_KEY_INFO *p8inf;

	// first try unencrypted form
	BIO *bi = BIO_new(BIO_s_mem());
	BIO_write(bi, in.data(), in.size());
	p8inf = d2i_PKCS8_PRIV_KEY_INFO_bio(bi, NULL);
	BIO_free(bi);
	if(!p8inf)
	{
		X509_SIG *p8;

		// now try encrypted form
		bi = BIO_new(BIO_s_mem());
		BIO_write(bi, in.data(), in.size());
		p8 = d2i_PKCS8_bio(bi, NULL);
		BIO_free(bi);
		if(!p8)
			return NULL;

		// get passphrase
		char psbuf[PEM_BUFSIZE];
		int klen;
		if(cb)
			klen = cb(psbuf, PEM_BUFSIZE, 0, u);
		else
			klen = PEM_def_callback(psbuf, PEM_BUFSIZE, 0, u);
		if(klen <= 0)
		{
			PEMerr(PEM_F_D2I_PKCS8PRIVATEKEY_BIO, PEM_R_BAD_PASSWORD_READ);
			X509_SIG_free(p8);
			return NULL;
		}

		// decrypt it
		p8inf = PKCS8_decrypt(p8, psbuf, klen);
		X509_SIG_free(p8);
		if(!p8inf)
			return NULL;
	}

	EVP_PKEY *ret = EVP_PKCS82PKEY(p8inf);
	PKCS8_PRIV_KEY_INFO_free(p8inf);
	if(!ret)
		return NULL;
	if(x)
	{
		if(*x)
			EVP_PKEY_free(*x);
		*x = ret;
	}
	return ret;
}

static CTISession *global_session = 0;

//----------------------------------------------------------------------------
// EVPKey
//----------------------------------------------------------------------------

// note: this class squelches processing errors, since QCA doesn't care about them
class EVPKey
{
public:
	enum State { Idle, SignActive, SignError, VerifyActive, VerifyError };
	EVP_PKEY *pkey;
	EVP_MD_CTX mdctx;
	State state;

	EVPKey()
	{
		pkey = 0;
		state = Idle;
	}

	EVPKey(const EVPKey &from)
	{
		pkey = from.pkey;
		CRYPTO_add(&pkey->references, 1, CRYPTO_LOCK_EVP_PKEY);
		state = Idle;
	}

	~EVPKey()
	{
		reset();
	}

	void reset()
	{
		if(pkey)
			EVP_PKEY_free(pkey);
		pkey = 0;
	}

	void startSign(const EVP_MD *type)
	{
		if(!type)
		{
			state = SignError;
			return;
		}

		state = SignActive;
		EVP_MD_CTX_init(&mdctx);
		if(!EVP_SignInit_ex(&mdctx, type, NULL))
			state = SignError;
	}

	void startVerify(const EVP_MD *type)
	{
		if(!type)
		{
			state = VerifyError;
			return;
		}

		state = VerifyActive;
		EVP_MD_CTX_init(&mdctx);
		if(!EVP_VerifyInit_ex(&mdctx, type, NULL))
			state = VerifyError;
	}

	void update(const QSecureArray &in)
	{
		if(state == SignActive)
		{
			if(!EVP_SignUpdate(&mdctx, in.data(), (unsigned int)in.size()))
				state = SignError;
		}
		else if(state == VerifyActive)
		{
			if(!EVP_VerifyUpdate(&mdctx, in.data(), (unsigned int)in.size()))
				state = VerifyError;
		}
	}

	QSecureArray endSign()
	{
		if(state == SignActive)
		{
			QSecureArray out(EVP_PKEY_size(pkey));
			unsigned int len = out.size();
			if(!EVP_SignFinal(&mdctx, (unsigned char *)out.data(), &len, pkey))
			{
				state = SignError;
				return QSecureArray();
			}
			out.resize(len);
			state = Idle;
			return out;
		}
		else
			return QSecureArray();
	}

	bool endVerify(const QSecureArray &sig)
	{
		if(state == VerifyActive)
		{
			if(EVP_VerifyFinal(&mdctx, (unsigned char *)sig.data(), (unsigned int)sig.size(), pkey) != 1)
			{
				state = VerifyError;
				return false;
			}
			state = Idle;
			return true;
		}
		else
			return false;
	}
};

//----------------------------------------------------------------------------
// RSAKey
//----------------------------------------------------------------------------
class RSAKey : public RSAContext
{
	Q_OBJECT
public:
	//EVPKey evp;
	//RSAKeyMaker *keymaker;
	//bool wasBlocking;
	QSecureArray inbuf;
	bool sec;
	CK_OBJECT_HANDLE handle;

	QBigInteger big_n, big_e;

	RSAKey(Provider *p) : RSAContext(p)
	{
		//keymaker = 0;
		sec = false;
	}

	RSAKey(const RSAKey &from) : RSAContext(from.provider()) //, evp(from.evp)
	{
		//keymaker = 0;

		inbuf = from.inbuf;
		sec = from.sec;
		handle = from.handle;
		big_n = from.big_n;
		big_e = from.big_e;
	}

	~RSAKey()
	{
		//delete keymaker;
	}

	virtual Provider::Context *clone() const
	{
		return new RSAKey(*this);
	}

	virtual bool isNull() const
	{
		return false; //return (evp.pkey ? false: true);
	}

	virtual PKey::Type type() const
	{
		return PKey::RSA;
	}

	virtual bool isPrivate() const
	{
		return sec;
	}

	virtual bool canExport() const
	{
		return true;
	}

	virtual void convertToPublic()
	{
		/*if(!sec)
			return;

		// extract the public key into DER format
		int len = i2d_RSAPublicKey(evp.pkey->pkey.rsa, NULL);
		QSecureArray result(len);
		unsigned char *p = (unsigned char *)result.data();
		i2d_RSAPublicKey(evp.pkey->pkey.rsa, &p);
		p = (unsigned char *)result.data();

		// put the DER public key back into openssl
		evp.reset();
		RSA *rsa;
#ifdef OSSL_097
		rsa = d2i_RSAPublicKey(NULL, (const unsigned char **)&p, result.size());
#else
		rsa = d2i_RSAPublicKey(NULL, (unsigned char **)&p, result.size());
#endif
		evp.pkey = EVP_PKEY_new();
		EVP_PKEY_assign_RSA(evp.pkey, rsa);
		sec = false;*/
	}

	virtual int bits() const
	{
		//return 8*RSA_size(evp.pkey->pkey.rsa);
		return 0;
	}

	virtual int maximumEncryptSize(EncryptionAlgorithm alg) const
	{
		/*RSA *rsa = evp.pkey->pkey.rsa;
		if(alg == EME_PKCS1v15)
			return RSA_size(rsa) - 11 - 1;
		else // oaep
			return RSA_size(rsa) - 41 - 1;*/
		Q_UNUSED(alg);
		return 0;
	}

	virtual QSecureArray encrypt(const QSecureArray &in, EncryptionAlgorithm alg) const
	{
		/*RSA *rsa = evp.pkey->pkey.rsa;

		QSecureArray buf = in;
		int max = maximumEncryptSize(alg);
		if(buf.size() > max)
			buf.resize(max);
		QSecureArray result(RSA_size(rsa));

		int pad;
		if(alg == EME_PKCS1v15)
			pad = RSA_PKCS1_PADDING;
		else // oaep
			pad = RSA_PKCS1_OAEP_PADDING;

		int ret = RSA_public_encrypt(buf.size(), (unsigned char *)buf.data(), (unsigned char *)result.data(), rsa, pad);
		if(ret < 0)
			return QSecureArray();
		result.resize(ret);

		return result;*/
		return QSecureArray();
	}

	virtual bool decrypt(const QSecureArray &in, QSecureArray *out, EncryptionAlgorithm alg) const
	{
		/*RSA *rsa = evp.pkey->pkey.rsa;

		QSecureArray result(RSA_size(rsa));

		int pad;
		if(alg == EME_PKCS1v15)
			pad = RSA_PKCS1_PADDING;
		else // oaep
			pad = RSA_PKCS1_OAEP_PADDING;

		int ret = RSA_private_decrypt(in.size(), (unsigned char *)in.data(), (unsigned char *)result.data(), rsa, pad);
		if(ret < 0)
			return false;
		result.resize(ret);

		*out = result;
		return true;*/
		return false;
	}

	virtual void startSign(SignatureAlgorithm alg, SignatureFormat)
	{
		Q_UNUSED(alg);

		printf("pkcs11: about to rsa sign\n");

		/*const EVP_MD *md = 0;
		if(alg == EMSA3_SHA1)
			md = EVP_sha1();
		else if(alg == EMSA3_MD5)
			md = EVP_md5();
		else if(alg == EMSA3_MD2)
			md = EVP_md2();
		else if(alg == EMSA3_RIPEMD160)
			md = EVP_ripemd160();
		else if(alg == EMSA3_Raw)
		{
			// TODO
		}
		evp.startSign(md);*/
	}

	virtual void startVerify(SignatureAlgorithm alg, SignatureFormat)
	{
		Q_UNUSED(alg);

		/*const EVP_MD *md = 0;
		if(alg == EMSA3_SHA1)
			md = EVP_sha1();
		else if(alg == EMSA3_MD5)
			md = EVP_md5();
		else if(alg == EMSA3_MD2)
			md = EVP_md2();
		else if(alg == EMSA3_RIPEMD160)
			md = EVP_ripemd160();
		else if(alg == EMSA3_Raw)
		{
			// TODO
		}
		evp.startVerify(md);*/
	}

	virtual void update(const QSecureArray &in)
	{
		//evp.update(in);
		inbuf.append(in);
	}

	virtual QSecureArray endSign()
	{
		//return evp.endSign();
		const unsigned char *m = (const unsigned char *)inbuf.data();
		unsigned int m_len = inbuf.size();
		QSecureArray out(512);
		int out_len = out.size();
		bool ok = global_session->sign_RSA_EMSA3_Raw(handle, 0, m, m_len, (unsigned char *)out.data(), &out_len);
		if(ok)
			out.resize(out_len);
		else
			out.clear();
		return out;
	}

	virtual bool endVerify(const QSecureArray &sig)
	{
		//return evp.endVerify(sig);
		Q_UNUSED(sig);
		return false;
	}

	virtual void createPrivate(int bits, int exp, bool block)
	{
		Q_UNUSED(bits);
		Q_UNUSED(exp);
		Q_UNUSED(block);

		/*evp.reset();

		keymaker = new RSAKeyMaker(bits, exp);
		wasBlocking = block;
		if(block)
		{
			keymaker->run();
			km_finished();
		}
		else
		{
			connect(keymaker, SIGNAL(finished()), SLOT(km_finished()));
			keymaker->start();
		}*/
	}

	virtual void createPrivate(const QBigInteger &n, const QBigInteger &e, const QBigInteger &p, const QBigInteger &q, const QBigInteger &d)
	{
		Q_UNUSED(n);
		Q_UNUSED(e);
		Q_UNUSED(p);
		Q_UNUSED(q);
		Q_UNUSED(d);

		/*evp.reset();

		RSA *rsa = RSA_new();
		rsa->n = bi2bn(n);
		rsa->e = bi2bn(e);
		rsa->p = bi2bn(p);
		rsa->q = bi2bn(q);
		rsa->d = bi2bn(d);

		if(!rsa->n || !rsa->e || !rsa->p || !rsa->q || !rsa->d)
		{
			RSA_free(rsa);
			return;
		}

		evp.pkey = EVP_PKEY_new();
		EVP_PKEY_assign_RSA(evp.pkey, rsa);
		sec = true;*/
	}

	virtual void createPublic(const QBigInteger &n, const QBigInteger &e)
	{
		Q_UNUSED(n);
		Q_UNUSED(e);

		/*evp.reset();

		RSA *rsa = RSA_new();
		rsa->n = bi2bn(n);
		rsa->e = bi2bn(e);

		if(!rsa->n || !rsa->e)
		{
			RSA_free(rsa);
			return;
		}

		evp.pkey = EVP_PKEY_new();
		EVP_PKEY_assign_RSA(evp.pkey, rsa);
		sec = false;*/
	}

	virtual QBigInteger n() const
	{
		return big_n;
		//return bn2bi(evp.pkey->pkey.rsa->n);
	}

	virtual QBigInteger e() const
	{
		return big_e;
		//return bn2bi(evp.pkey->pkey.rsa->e);
	}

	virtual QBigInteger p() const
	{
		//return bn2bi(evp.pkey->pkey.rsa->p);
		return QBigInteger();
	}

	virtual QBigInteger q() const
	{
		//return bn2bi(evp.pkey->pkey.rsa->q);
		return QBigInteger();
	}

	virtual QBigInteger d() const
	{
		//return bn2bi(evp.pkey->pkey.rsa->d);
		return QBigInteger();
	}

/*private slots:
	void km_finished()
	{
		RSA *rsa = keymaker->takeResult();
		if(wasBlocking)
			delete keymaker;
		else
			keymaker->deleteLater();
		keymaker = 0;

		if(rsa)
		{
			evp.pkey = EVP_PKEY_new();
			EVP_PKEY_assign_RSA(evp.pkey, rsa);
			sec = true;
		}

		if(!wasBlocking)
			emit finished();
	}*/
};

//----------------------------------------------------------------------------
// MyPKeyContext
//----------------------------------------------------------------------------
class MyPKeyContext : public PKeyContext
{
public:
	PKeyBase *k;

	MyPKeyContext(Provider *p) : PKeyContext(p)
	{
		k = 0;
	}

	~MyPKeyContext()
	{
		delete k;
	}

	virtual Provider::Context *clone() const
	{
		MyPKeyContext *c = new MyPKeyContext(*this);
		c->k = (PKeyBase *)k->clone();
		return c;
	}

	virtual QList<PKey::Type> supportedTypes() const
	{
		QList<PKey::Type> list;
		list += PKey::RSA;
		//list += PKey::DSA;
		//list += PKey::DH;
		return list;
	}

	virtual QList<PKey::Type> supportedIOTypes() const
	{
		QList<PKey::Type> list;
		list += PKey::RSA;
		//list += PKey::DSA;
		return list;
	}

	virtual QList<PBEAlgorithm> supportedPBEAlgorithms() const
	{
		QList<PBEAlgorithm> list;
		//list += PBES2_DES_SHA1;
		//list += PBES2_TripleDES_SHA1;
		return list;
	}

	virtual PKeyBase *key()
	{
		return k;
	}

	virtual const PKeyBase *key() const
	{
		return k;
	}

	virtual void setKey(PKeyBase *key)
	{
		k = key;
	}

	virtual bool importKey(const PKeyBase *key)
	{
		Q_UNUSED(key);
		return false;
	}

	EVP_PKEY *get_pkey() const
	{
		//PKey::Type t = k->type();
		//if(t == PKey::RSA)
			//return static_cast<RSAKey *>(k)->evp.pkey;
		/*else if(t == PKey::DSA)
			return static_cast<DSAKey *>(k)->evp.pkey;
		else
			return static_cast<DHKey *>(k)->evp.pkey;*/
		return 0;
	}

	PKeyBase *pkeyToBase(EVP_PKEY *pkey, bool sec) const
	{
		PKeyBase *nk = 0;
		if(pkey->type == EVP_PKEY_RSA)
		{
			RSAKey *c = new RSAKey(provider());
			//c->evp.pkey = pkey;
			c->sec = sec;
			nk = c;
		}
		/*else if(pkey->type == EVP_PKEY_DSA)
		{
			DSAKey *c = new DSAKey(provider());
			c->evp.pkey = pkey;
			c->sec = sec;
			nk = c;
		}
		else if(pkey->type == EVP_PKEY_DH)
		{
			DHKey *c = new DHKey(provider());
			c->evp.pkey = pkey;
			c->sec = sec;
			nk = c;
		}*/
		else
		{
			EVP_PKEY_free(pkey);
		}
		return nk;
	}

	static int passphrase_cb(char *buf, int size, int rwflag, void *u)
	{
		Q_UNUSED(buf);
		Q_UNUSED(size);
		Q_UNUSED(rwflag);
		Q_UNUSED(u);
		return 0;
	}

	virtual QSecureArray publicToDER() const
	{
		EVP_PKEY *pkey = get_pkey();

		// OpenSSL does not have DH import/export support
		if(pkey->type == EVP_PKEY_DH)
			return QSecureArray();

		BIO *bo = BIO_new(BIO_s_mem());
		i2d_PUBKEY_bio(bo, pkey);
		QSecureArray buf = bio2buf(bo);
		return buf;
	}

	virtual QString publicToPEM() const
	{
		EVP_PKEY *pkey = get_pkey();

		// OpenSSL does not have DH import/export support
		if(pkey->type == EVP_PKEY_DH)
			return QString();

		BIO *bo = BIO_new(BIO_s_mem());
		PEM_write_bio_PUBKEY(bo, pkey);
		QSecureArray buf = bio2buf(bo);
		return QString::fromLatin1(buf.toByteArray());
	}

	virtual ConvertResult publicFromDER(const QSecureArray &in)
	{
		delete k;
		k = 0;

		BIO *bi = BIO_new(BIO_s_mem());
		BIO_write(bi, in.data(), in.size());
		EVP_PKEY *pkey = d2i_PUBKEY_bio(bi, NULL);
		BIO_free(bi);

		if(!pkey)
			return ErrorDecode;

		k = pkeyToBase(pkey, false);
		if(k)
			return ConvertGood;
		else
			return ErrorDecode;
	}

	virtual ConvertResult publicFromPEM(const QString &s)
	{
		delete k;
		k = 0;

		QByteArray in = s.toLatin1();
		BIO *bi = BIO_new(BIO_s_mem());
		BIO_write(bi, in.data(), in.size());
		EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bi, NULL, NULL, NULL);
		BIO_free(bi);

		if(!pkey)
			return ErrorDecode;

		k = pkeyToBase(pkey, false);
		if(k)
			return ConvertGood;
		else
			return ErrorDecode;
	}

	virtual QSecureArray privateToDER(const QSecureArray &passphrase, PBEAlgorithm pbe) const
	{
		//if(pbe == PBEDefault)
		//	pbe = PBES2_TripleDES_SHA1;

		const EVP_CIPHER *cipher = 0;
		if(pbe == PBES2_TripleDES_SHA1)
			cipher = EVP_des_ede3_cbc();
		else if(pbe == PBES2_DES_SHA1)
			cipher = EVP_des_cbc();

		if(!cipher)
			return QSecureArray();

		EVP_PKEY *pkey = get_pkey();

		// OpenSSL does not have DH import/export support
		if(pkey->type == EVP_PKEY_DH)
			return QSecureArray();

		BIO *bo = BIO_new(BIO_s_mem());
		if(!passphrase.isEmpty())
			i2d_PKCS8PrivateKey_bio(bo, pkey, cipher, NULL, 0, NULL, (void *)passphrase.data());
		else
			i2d_PKCS8PrivateKey_bio(bo, pkey, NULL, NULL, 0, NULL, NULL);
		QSecureArray buf = bio2buf(bo);
		return buf;
	}

	virtual QString privateToPEM(const QSecureArray &passphrase, PBEAlgorithm pbe) const
	{
		//if(pbe == PBEDefault)
		//	pbe = PBES2_TripleDES_SHA1;

		const EVP_CIPHER *cipher = 0;
		if(pbe == PBES2_TripleDES_SHA1)
			cipher = EVP_des_ede3_cbc();
		else if(pbe == PBES2_DES_SHA1)
			cipher = EVP_des_cbc();

		if(!cipher)
			return QString();

		EVP_PKEY *pkey = get_pkey();

		// OpenSSL does not have DH import/export support
		if(pkey->type == EVP_PKEY_DH)
			return QString();

		BIO *bo = BIO_new(BIO_s_mem());
		if(!passphrase.isEmpty())
			PEM_write_bio_PKCS8PrivateKey(bo, pkey, cipher, NULL, 0, NULL, (void *)passphrase.data());
		else
			PEM_write_bio_PKCS8PrivateKey(bo, pkey, NULL, NULL, 0, NULL, NULL);
		QSecureArray buf = bio2buf(bo);
		return QString::fromLatin1(buf.toByteArray());
	}

	virtual ConvertResult privateFromDER(const QSecureArray &in, const QSecureArray &passphrase)
	{
		delete k;
		k = 0;

		EVP_PKEY *pkey;
		if(!passphrase.isEmpty())
			pkey = qca_d2i_PKCS8PrivateKey(in, NULL, NULL, (void *)passphrase.data());
		else
			pkey = qca_d2i_PKCS8PrivateKey(in, NULL, &passphrase_cb, NULL);

		if(!pkey)
			return ErrorDecode;

		k = pkeyToBase(pkey, true);
		if(k)
			return ConvertGood;
		else
			return ErrorDecode;
	}

	virtual ConvertResult privateFromPEM(const QString &s, const QSecureArray &passphrase)
	{
		delete k;
		k = 0;

		QByteArray in = s.toLatin1();
		BIO *bi = BIO_new(BIO_s_mem());
		BIO_write(bi, in.data(), in.size());
		EVP_PKEY *pkey;
		if(!passphrase.isEmpty())
			pkey = PEM_read_bio_PrivateKey(bi, NULL, NULL, (void *)passphrase.data());
		else
			pkey = PEM_read_bio_PrivateKey(bi, NULL, &passphrase_cb, NULL);
		BIO_free(bi);

		if(!pkey)
			return ErrorDecode;

		k = pkeyToBase(pkey, true);
		if(k)
			return ConvertGood;
		else
			return ErrorDecode;
	}
};

class MyKeyStoreEntry : public KeyStoreEntryContext
{
public:
	KeyStoreEntry::Type item_type;
	KeyBundle _key;
	Certificate _cert;
	QString _name, _id;

	MyKeyStoreEntry(const Certificate &cert, const QString &name, const QString &id, Provider *p) : KeyStoreEntryContext(p)
	{
		_cert = cert;
		_name = name;
		_id = id;
		item_type = KeyStoreEntry::TypeCertificate;
	}

	MyKeyStoreEntry(const KeyBundle &key, const QString &name, const QString &id, Provider *p) : KeyStoreEntryContext(p)
	{
		_key = key;
		_name = name;
		_id = id;
		item_type = KeyStoreEntry::TypeKeyBundle;
	}

	MyKeyStoreEntry(const MyKeyStoreEntry &from) : KeyStoreEntryContext(from)
	{
	}

	~MyKeyStoreEntry()
	{
	}

	virtual Provider::Context *clone() const
	{
		return new MyKeyStoreEntry(*this);
	}

	virtual KeyStoreEntry::Type type() const
	{
		return item_type;
	}

	virtual QString name() const
	{
		// TODO
		return _name;
	}

	virtual QString id() const
	{
		// TODO
		return _id;
	}

	virtual KeyBundle keyBundle() const
	{
		return _key;
	}

	virtual Certificate certificate() const
	{
		return _cert;
	}
};

class MyKeyStoreList;

static MyKeyStoreList *keyStoreList = 0;

class MyKeyStoreList : public KeyStoreListContext
{
	Q_OBJECT
public:
	QString libname;
	QList<int> list;

	MyKeyStoreList(Provider *p) : KeyStoreListContext(p)
	{
		keyStoreList = this;
	}

	~MyKeyStoreList()
	{
		keyStoreList = 0;
	}

	virtual Provider::Context *clone() const
	{
		return 0;
	}

	virtual void start()
	{
		libname = qgetenv("QCA_PKCS11_LIB");

		if(libname.isEmpty())
		{
			QMetaObject::invokeMethod(this, "doReady", Qt::QueuedConnection);
			return;
		}

		con = new CTIControl;//(this);
		//connect(con, SIGNAL(slotChanged(int)), SLOT(slotChanged(int)));

		if(!con->init(libname))
		{
			printf("unable to load [%s]\n", qPrintable(libname));
			QMetaObject::invokeMethod(this, "doReady", Qt::QueuedConnection);
			return;
			//emit quit();
		}

		/*CTIControl::ModuleInfo moduleInfo = con->moduleInfo;
		QList<CTIControl::SlotInfo> slotInfoList = con->slotInfoList;

		printf("Cryptoki version: %s\n", qPrintable(moduleInfo.ckVersion));
		printf("Manufacturer:     %s\n", qPrintable(moduleInfo.manufacturer));
		printf("Library:          %s (ver %s)\n", qPrintable(moduleInfo.libraryDescription), qPrintable(moduleInfo.libraryVersion));

		printf("Slots: %d\n", slotInfoList.count());
		QList<int> tokens;
		for(int n = 0; n < slotInfoList.count(); ++n)
		{
			const CTIControl::SlotInfo &slotInfo = slotInfoList[n];
			printf("ID: %lu\n", slotInfo.slotId);
			printf("  Description:  %s\n", qPrintable(slotInfo.slotDescription));
			printf("  Manufacturer: %s\n", qPrintable(slotInfo.manufacturer));
			printf("  Hardware:     %s\n", slotInfo.isHardware ? "Yes" : "No");
			printf("  Removable:    %s\n", slotInfo.isRemovable ? "Yes" : "No");
			printf("  Token:        %s\n", slotInfo.haveToken ? "Yes" : "No");
			//if(slotInfo.haveToken)
			//{
			//	tokens += n;
			//	const CTIControl::TokenInfo &tokenInfo = slotInfo.tokenInfo;
			//	print_tokenInfo(tokenInfo);
			//}
		}*/

		// TODO
		for(int n = 0; n < con->slotInfoList.count(); ++n)
		{
			const CTIControl::SlotInfo &i = con->slotInfoList[n];
			if(i.haveToken)
			{
				list += n;
			}
		}

		QMetaObject::invokeMethod(this, "doReady", Qt::QueuedConnection);
	}

	virtual QList<int> keyStores() const
	{
		QList<int> out;
		for(int n = 0; n < list.count(); ++n)
			out.append(list[n]);
		return out;
	}

	virtual KeyStore::Type type(int id) const
	{
		Q_UNUSED(id);
		// TODO
		return KeyStore::SmartCard;
	}

	virtual QString storeId(int id) const
	{
		Q_UNUSED(id);
		// TODO
		return "qca-pkcs11"; // horrible
	}

	virtual QString name(int id) const
	{
		// TODO
		return con->slotInfoList[id].tokenInfo.label;
	}

	virtual QList<KeyStoreEntry::Type> entryTypes(int id) const
	{
		Q_UNUSED(id);
		// TODO
		QList<KeyStoreEntry::Type> list;
		list += KeyStoreEntry::TypeKeyBundle;
		list += KeyStoreEntry::TypeCertificate;
		return list;
	}

	virtual QList<KeyStoreEntryContext*> entryList(int id) const
	{
		// TODO
		Q_UNUSED(id);

		QList<KeyStoreEntryContext*> out;

		//printf("let's do some things with token at index %d\n", index);
		CTIControl::SlotInfo &i = con->slotInfoList[id];

		global_session = new CTISession(&con->module);
		CTISession &sess = *global_session;

		//printf("opening session\n");
		if(!sess.open(i.slotId, CKF_RW_SESSION))
		{
			printf("error opening session\n");
			return out;
		}

		emit keyStoreList->storeNeedPassphrase(0, 0, QString());

		//printf("getting object list (before login)\n");
		if(!sess.getObjects())
		{
			printf("error getting objects\n");
			return out;
		}

		// try to find keybundles
		for(int n = 0; n < sess.objectList.count(); ++n)
		{
			const CTISession::Object &i = sess.objectList[n];
			if(i.type == CKO_PRIVATE_KEY)
			{
				const CTISession::Object *obj_key = &i;
				QList<const CTISession::Object *> obj_certs;
				for(int n2 = 0; n2 < sess.objectList.count(); ++n2)
				{
					const CTISession::Object &i2 = sess.objectList[n2];
					if(i2.type == CKO_CERTIFICATE && i2.id == i.id)
						obj_certs += &i2;
				}

				if(!obj_certs.isEmpty())
				{
					QByteArray der_buf;
					sess.getBigIntegerData(obj_certs[0]->handle, CKA_VALUE, &der_buf);
					Certificate cert = Certificate::fromDER(der_buf);
					if(cert.isNull())
						continue;

					RSAKey *rsakey = new RSAKey(provider());
					rsakey->sec = true;
					rsakey->handle = obj_key->handle;

					QByteArray buf;
					sess.getBigIntegerData(rsakey->handle, CKA_MODULUS, &buf);
					rsakey->big_n.fromArray(buf);
					sess.getBigIntegerData(rsakey->handle, CKA_PUBLIC_EXPONENT, &buf);
					rsakey->big_e.fromArray(buf);

					MyPKeyContext *pkc = new MyPKeyContext(provider());
					pkc->setKey(rsakey);
					PrivateKey privkey;
					privkey.change(pkc);
					if(privkey.isNull())
						continue;

					KeyBundle key;
					key.setCertificateChainAndKey(cert, privkey);

					MyKeyStoreEntry *e = new MyKeyStoreEntry(key, obj_certs[0]->label, arrayToHex(obj_certs[0]->id), provider());
					out += e;
				}
			}
		}

		/*for(int n = 0; n < sess.objectList.count(); ++n)
		{
			const CTISession::Object &i = sess.objectList[n];
			QString type;
			if(i.type == CKO_PUBLIC_KEY)
				type = "PublicKey";
			else if(i.type == CKO_PRIVATE_KEY)
				type = "PrivateKey";
			else if(i.type == CKO_CERTIFICATE)
				type = "Certificate";
			else
				type = QString("Unknown-%1").arg(i.type, (int)8, (int)16, QChar('0'));
			//printf("  %s:\n", qPrintable(type));
			//printf("    label: %s\n", qPrintable(i.label));
			//printf("    id:    %s\n", qPrintable(hexify(i.id)));

			if(i.type != CKO_CERTIFICATE)
				continue;

			QByteArray der_buf;
			// hack hack
			sess.getBigIntegerData(i.handle, CKA_VALUE, &der_buf);

			// FIXME: this requires cert support elsewhere
			Certificate cert = Certificate::fromDER(der_buf);
			if(cert.isNull())
			{
				printf("cert is null?\n");
				continue;
			}
			MyKeyStoreEntry *e = new MyKeyStoreEntry(cert, i.label, arrayToHex(i.id), provider());
			out += e;
		}*/

		return out;
	}

	virtual void submitPassphrase(int id, const QSecureArray &passphrase)
	{
		Q_UNUSED(id);
		// TODO
		global_session->login(CKU_USER, passphrase.data(), passphrase.size());
	}

private slots:
	void doReady()
	{
		emit busyEnd();
	}
};

}

using namespace pkcs11QCAPlugin;

class pkcs11Provider : public QCA::Provider
{
public:
	pkcs11Provider()
	{
		con = 0;
	}

	~pkcs11Provider()
	{
		delete con;
	}

	virtual void init()
	{
	}

	virtual QString name() const
	{
		return "qca-pkcs11";
	}

	virtual QStringList features() const
	{
		QStringList list;
		list += "smartcard"; // indicator, not algorithm
		list += "pkey";
		list += "keystorelist";
		return list;
	}

	virtual Context *createContext(const QString &type)
	{
		if(type == "keystorelist")
			return new MyKeyStoreList(this);
		else
			return 0;
	}
};

class pkcs11Plugin : public QCAPlugin
{
	Q_OBJECT
	Q_INTERFACES(QCAPlugin)
public:
	virtual QCA::Provider *createProvider() { return new pkcs11Provider; }
};

#include "qca-pkcs11.moc"

Q_EXPORT_PLUGIN2(qca-pkcs11, pkcs11Plugin);
