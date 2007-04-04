/*
 * Copyright (C) 2004  Justin Karneges
 * Copyright (C) 2006-2007  Alon Bar-Lev <alon.barlev@gmail.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 *
 */

#include <QtCore>
#include <QtCrypto>

#include <pkcs11-helper-1.0/pkcs11h-token.h>
#include <pkcs11-helper-1.0/pkcs11h-certificate.h>
#include <openssl/x509.h>

using namespace QCA;

//----------------------------------------------------------------------------
// pkcs11Provider
//----------------------------------------------------------------------------
class pkcs11Provider : public QCA::Provider
{
private:
	static const int _CONFIG_MAX_PROVIDERS;

	bool _fLowLevelInitialized;
	bool _fSlotEventsActive;
	bool _fSlotEventsLowLevelActive;
	QStringList _providers;

public:
	pkcs11Provider ();
	~pkcs11Provider ();

public:
	virtual
	int
	version() const;

	virtual
	void
	init ();

	virtual
	QString
	name () const;

	virtual
	QStringList
	features () const;

	virtual
	Context *
	createContext (
		const QString &type
	);

	void
	startSlotEvents ();

	void
	stopSlotEvents ();

	virtual
	QVariantMap
	defaultConfig () const;

	virtual
	void
	configChanged (const QVariantMap &config);

protected:
	static
	void
	_logHook (
		void * const global_data,
		const unsigned flags,
		const char * const format,
		va_list args
	);

	static
	void
	_slotEventHook (
		void * const global_data
	);

	static
	PKCS11H_BOOL
	_tokenPromptHook (
		void * const global_data,
		void * const user_data,
		const pkcs11h_token_id_t token,
		const unsigned retry
	);

	static
	PKCS11H_BOOL
	_pinPromptHook (
		void * const global_data,
		void * const user_data,
		const pkcs11h_token_id_t token,
		const unsigned retry,
		char * const pin,
		const size_t pin_max
	);

	void
	logHook (
		const unsigned flags,
		const char * const format,
		va_list args
	);

	void
	slotEventHook ();

	PKCS11H_BOOL
	tokenPromptHook (
		const pkcs11h_token_id_t token
	);

	PKCS11H_BOOL
	pinPromptHook (
		const pkcs11h_token_id_t token,
		char * const pin,
		const size_t pin_max
	);
};

namespace pkcs11QCAPlugin {

class MyKeyStoreEntry;

//----------------------------------------------------------------------------
// MyKeyStoreList
//----------------------------------------------------------------------------
class MyKeyStoreList : public KeyStoreListContext
{
	Q_OBJECT

private:
	class KeyStoreItem {
	public:
		int id;
		pkcs11h_token_id_t token_id;

		KeyStoreItem () {
			id = 0;
			token_id = NULL;
		}

		~KeyStoreItem () {
			if (token_id != NULL) {
				pkcs11h_token_freeTokenId (token_id);
			}
		}
	};
	int _last_id;
	typedef QList<KeyStoreItem *> _stores_t;
	_stores_t _stores;
	QHash<int, KeyStoreItem *> _storesById;
	QMutex _mutexStores;
	bool _initialized;

public:
	MyKeyStoreList (Provider *p);

	~MyKeyStoreList ();

	virtual
	Provider::Context *
	clone () const;

public:
	virtual
	void
	start ();

	virtual
	void
	setUpdatesEnabled (bool enabled);

	virtual
	KeyStoreEntryContext *
	entry (
		int id,
		const QString &entryId
	);

	virtual
	KeyStoreEntryContext *
	entryPassive (
		const QString &storeId,
		const QString &entryId
	);

	virtual
	KeyStore::Type
	type (int id) const;

	virtual
	QString
	storeId (int id) const;

	virtual
	QString
	name (int id) const;

	virtual
	QList<KeyStoreEntry::Type>
	entryTypes (int id) const;

	virtual
	QList<int>
	keyStores ();

	virtual
	QList<KeyStoreEntryContext*>
	entryList (int id);

	bool
	tokenPrompt (
		const pkcs11h_token_id_t token_id
	);

	void
	pinPrompt (
		const pkcs11h_token_id_t token_id,
		QSecureArray &pin
	);

	void
	emit_updated ();

	void
	emit_diagnosticText (
		const QString &t
	);

private slots:
	void
	doReady ();

	void
	doUpdated ();

private:
	KeyStoreItem *
	registerTokenId (
		const pkcs11h_token_id_t token_id
	);

	void
	clearStores ();

	MyKeyStoreEntry *
	getKeyStoreEntryByCertificateId (
		const pkcs11h_certificate_id_t certificate_id,
		bool has_private,
		const QList<Certificate> &listIssuers
	) const;

	QString
	tokenId2storeId (
		const pkcs11h_token_id_t token_id
	) const;

	QString
	serializeCertificateId (
		const pkcs11h_certificate_id_t certificate_id,
		const CertificateChain &chain,
		const bool has_private
	) const;

	void
	deserializeCertificateId (
		const QString &from,
		pkcs11h_certificate_id_t * const p_certificate_id,
		bool * const has_private,
		QList<Certificate> *listIssuers
	) const;

	QString
	escapeString (
		const QString &from
	) const;

	QString
	unescapeString (
		const QString &from
	) const;
};

static MyKeyStoreList *s_keyStoreList = NULL;

//----------------------------------------------------------------------------
// PKCS11Exception
//----------------------------------------------------------------------------
class PKCS11Exception {

private:
	CK_RV rv;
	QString msg;

private:
	PKCS11Exception () {}

public:
	PKCS11Exception (CK_RV rv, const QString &msg) {
		this->rv = rv;
		this->msg = msg;
	}

	PKCS11Exception (const PKCS11Exception &other) {
		*this = other;
	}

	PKCS11Exception &
	operator = (const PKCS11Exception &other) {
		this->rv = other.rv;
		this->msg = other.msg;
		return *this;
	}

	CK_RV
	getRV () const {
		return rv;
	}

	QString
	getMessage () const {
		return msg + QString (" ") + pkcs11h_getMessage (rv);
	}
};

//----------------------------------------------------------------------------
// MyRSAKey
//----------------------------------------------------------------------------
class MyRSAKey : public RSAContext
{
	Q_OBJECT

private:
	bool _has_privateKeyRole;
	pkcs11h_certificate_id_t _pkcs11h_certificate_id;
	pkcs11h_certificate_t _pkcs11h_certificate;
	RSAPublicKey _pubkey;

	struct sign_data_s {
		SignatureAlgorithm alg;
		QCA::Hash *hash;
		QSecureArray raw;

		sign_data_s() {
			hash = NULL;
		}
	} sign_data;

public:
	MyRSAKey (
		Provider *p,
		pkcs11h_certificate_id_t pkcs11h_certificate_id,
		RSAPublicKey pubkey
	) : RSAContext (p) {
		_has_privateKeyRole = true;
		_pkcs11h_certificate_id = NULL;
		_pkcs11h_certificate = NULL;

		_pubkey = pubkey;
		clearSign ();

		setCertificateId (pkcs11h_certificate_id);
	}

	MyRSAKey (const MyRSAKey &from) : RSAContext (from.provider ()) {
		_has_privateKeyRole = from._has_privateKeyRole;
		_pkcs11h_certificate_id = NULL;
		_pkcs11h_certificate = NULL;
		_pubkey = from._pubkey;
		sign_data.hash = NULL;
		clearSign ();

		setCertificateId (from._pkcs11h_certificate_id);
	}

	~MyRSAKey () {
		clearSign ();
		freeResources ();

	}

	virtual
	Provider::Context *
	clone () const {
		return new MyRSAKey (*this);
	}

public:
	virtual
	bool
	isNull () const {
		return _pubkey.isNull ();
	}

	virtual
	PKey::Type
	type () const {
		return _pubkey.type ();
	}

	virtual
	bool
	isPrivate () const {
		return _has_privateKeyRole;
	}

	virtual
	bool
	canExport () const {
		return !_has_privateKeyRole;
	}

	virtual
	void
	convertToPublic () {
		if (_has_privateKeyRole) {
			if (_pkcs11h_certificate != NULL) {
				pkcs11h_certificate_freeCertificate (_pkcs11h_certificate);
				_pkcs11h_certificate = NULL;
			}
			_has_privateKeyRole = false;
		}
	}

	virtual
	int
	bits () const {
		return _pubkey.bitSize ();
	}

	virtual
	int
	maximumEncryptSize (
		EncryptionAlgorithm alg
	) const {
		return _pubkey.maximumEncryptSize (alg);
	}

	virtual
	QSecureArray
	encrypt (
		const QSecureArray &in,
		EncryptionAlgorithm alg
	) {
		return _pubkey.encrypt (in, alg);
	}

	virtual
	bool
	decrypt (
		const QSecureArray &in,
		QSecureArray *out,
		EncryptionAlgorithm alg
	) {
		bool session_locked = false;

		try {
			CK_MECHANISM_TYPE mech;
			CK_RV rv;
			size_t my_size;

			switch (alg) {
				case EME_PKCS1v15:
					mech = CKM_RSA_PKCS;
				break;
				case EME_PKCS1_OAEP:
					mech = CKM_RSA_PKCS_OAEP;
				break;
				default:
					throw PKCS11Exception (CKR_FUNCTION_NOT_SUPPORTED, "Invalid algorithm");
				break;
			}

			ensureCertificate ();

			if (
				(rv = pkcs11h_certificate_lockSession (
					_pkcs11h_certificate
				)) != CKR_OK
			) {
				throw PKCS11Exception (rv, "Cannot lock session");
			}
			session_locked = true;

			if (
				(rv = pkcs11h_certificate_decryptAny (
					_pkcs11h_certificate,
					mech,
					(const unsigned char *)in.constData (),
					in.size (),
					NULL,
					&my_size
				)) != CKR_OK
			) {
				throw PKCS11Exception (rv, "Decryption error");
			}

			out->resize (my_size);

			if (
				(rv = pkcs11h_certificate_decryptAny (
					_pkcs11h_certificate,
					mech,
					(const unsigned char *)in.constData (),
					in.size (),
					(unsigned char *)out->data (),
					&my_size
				)) != CKR_OK
			) {
				throw PKCS11Exception (rv, "Decryption error");
			}

			rv = out->resize (my_size);

			if (
				(rv = pkcs11h_certificate_releaseSession (
					_pkcs11h_certificate
				)) != CKR_OK
			) {
				throw PKCS11Exception (rv, "Cannot release session");
			}
			session_locked = false;

			return true;
		}
		catch (const PKCS11Exception &e) {
			if (session_locked) {
				pkcs11h_certificate_releaseSession (
					_pkcs11h_certificate
				);
				session_locked = false;
			}

			if (s_keyStoreList != NULL) {
				s_keyStoreList->emit_diagnosticText (
					QString ().sprintf (
						"PKCS#11: Cannot decrypt: %lu-'%s'.\n",
						e.getRV (),
						qPrintable (e.getMessage ())
					)
				);
			}

			return false;
		}
	}

	virtual
	void
	startSign (
		SignatureAlgorithm alg,
		SignatureFormat
	) {
		clearSign ();

		sign_data.alg = alg;

		switch (sign_data.alg) {
			case EMSA3_SHA1:
				sign_data.hash = new QCA::Hash ("sha1");
			break;
			case EMSA3_MD5:
				sign_data.hash = new QCA::Hash ("md5");
			break;
			case EMSA3_MD2:
				sign_data.hash = new QCA::Hash ("md2");
			break;
			case EMSA3_Raw:
			break;
			case SignatureUnknown:
			case EMSA1_SHA1:
			case EMSA3_RIPEMD160:
			default:
			break;
		}
	}

	virtual
	void
	startVerify (
		SignatureAlgorithm alg,
		SignatureFormat sf
	) {
		_pubkey.startVerify (alg, sf);
	}

	virtual
	void
	update (
		const QSecureArray &in
	) {
		if (_has_privateKeyRole) {
			if (sign_data.hash != NULL) {
				sign_data.hash->update (in);
			}
			else {
				sign_data.raw.append (in);
			}
		}
		else {
			_pubkey.update (in);
		}
	}

	virtual
	QSecureArray
	endSign () {
		QSecureArray result;
		unsigned char *enc_alloc = NULL;
		bool session_locked = false;

		try {
			int myrsa_size = 0;

			unsigned char *enc = NULL;
			int enc_len = 0;

			CK_RV rv;

			QSecureArray final;

			int type;

			if (sign_data.hash != NULL) {
				final = sign_data.hash->final ();
			}
			else {
				final = sign_data.raw;
			}

			switch (sign_data.alg) {
				case EMSA3_SHA1:
					type = NID_sha1;
				break;
				case EMSA3_MD5:
					type = NID_md5;
				break;
				case EMSA3_MD2:
					type = NID_md2;
				break;
				case EMSA3_Raw:
					type = NID_rsa;
				break;
				case SignatureUnknown:
				case EMSA1_SHA1:
				case EMSA3_RIPEMD160:
				default:
					throw PKCS11Exception (CKR_FUNCTION_NOT_SUPPORTED, "Invalid algorithm");
				break;
			}

			ensureCertificate ();

			// from some strange reason I got 2047... (for some)	<---- BUG?!?!?!
			myrsa_size=(_pubkey.bitSize () + 7) / 8;

			if (type == NID_md5_sha1 || type == NID_rsa) {
				enc = (unsigned char *)final.data ();
				enc_len = final.size ();
			}
			else {
				X509_SIG sig;
				ASN1_TYPE parameter;
				X509_ALGOR algor;
				ASN1_OCTET_STRING digest;

				if ((enc = (unsigned char *)malloc (myrsa_size+1)) == NULL) {
					throw PKCS11Exception (CKR_HOST_MEMORY, "Memory error");
				}

				enc_alloc = enc;
				sig.algor= &algor;

				if ((sig.algor->algorithm=OBJ_nid2obj (type)) == NULL) {
					throw PKCS11Exception (CKR_FUNCTION_FAILED, "Invalid algorithm");
				}

				if (sig.algor->algorithm->length == 0) {
					throw PKCS11Exception (CKR_KEY_SIZE_RANGE, "Key size error");
				}

				parameter.type = V_ASN1_NULL;
				parameter.value.ptr = NULL;

				sig.algor->parameter = &parameter;

				sig.digest = &digest;
				sig.digest->data = (unsigned char *)final.data ();
				sig.digest->length = final.size ();

				if ((enc_len=i2d_X509_SIG (&sig, NULL)) < 0) {
					throw PKCS11Exception (CKR_FUNCTION_FAILED, "Signature prepare failed");
				}

				unsigned char *p = enc;
				i2d_X509_SIG (&sig, &p);
			}

			if (enc_len > (myrsa_size-RSA_PKCS1_PADDING_SIZE)) {
				throw PKCS11Exception (CKR_KEY_SIZE_RANGE, "Padding too small");
			}

			size_t my_size;

			if (
				(rv = pkcs11h_certificate_lockSession (
					_pkcs11h_certificate
				)) != CKR_OK
			) {
				throw PKCS11Exception (rv, "Cannot lock session");
			}
			session_locked = true;

			if (
				(rv = pkcs11h_certificate_signAny (
					_pkcs11h_certificate,
					CKM_RSA_PKCS,
					enc,
					enc_len,
					NULL,
					&my_size
				)) != CKR_OK
			) {
				throw PKCS11Exception (rv, "Signature failed");
			}

			result.resize (my_size);

			if (
				(rv = pkcs11h_certificate_signAny (
					_pkcs11h_certificate,
					CKM_RSA_PKCS,
					enc,
					enc_len,
					(unsigned char *)result.data (),
					&my_size
				)) != CKR_OK
			) {
				throw PKCS11Exception (rv, "Signature failed");
			}

			result.resize (my_size);

			if (
				(rv = pkcs11h_certificate_releaseSession (
					_pkcs11h_certificate
				)) != CKR_OK
			) {
				throw PKCS11Exception (rv, "Cannot release session");
			}
			session_locked = false;

		}
		catch (const PKCS11Exception &e) {
			result.clear ();

			if (session_locked) {
				pkcs11h_certificate_releaseSession (
					_pkcs11h_certificate
				);
				session_locked = false;
			}

			if (s_keyStoreList != NULL) {
				s_keyStoreList->emit_diagnosticText (
					QString ().sprintf (
						"PKCS#11: Cannot sign: %lu-'%s'.\n",
						e.getRV (),
						qPrintable (e.getMessage ())
					)
				);
			}
		}

		if (enc_alloc != NULL) {
			free (enc_alloc);
		}

		clearSign ();

		return result;
	}

	virtual
	bool
	validSignature (
		const QSecureArray &sig
	) {
		return _pubkey.validSignature (sig);
	}

	virtual
	void
	createPrivate (
		int bits,
		int exp,
		bool block
	) {
		Q_UNUSED(bits);
		Q_UNUSED(exp);
		Q_UNUSED(block);
	}

	virtual
	void
	createPrivate (
		const QBigInteger &n,
		const QBigInteger &e,
		const QBigInteger &p,
		const QBigInteger &q,
		const QBigInteger &d
	) {
		Q_UNUSED(n);
		Q_UNUSED(e);
		Q_UNUSED(p);
		Q_UNUSED(q);
		Q_UNUSED(d);
	}

	virtual
	void
	createPublic (
		const QBigInteger &n,
		const QBigInteger &e
	) {
		Q_UNUSED(n);
		Q_UNUSED(e);
	}

	virtual
	QBigInteger
	n () const {
		return _pubkey.n ();
	}

	virtual
	QBigInteger
	e () const {
		return _pubkey.e ();
	}

	virtual
	QBigInteger
	p () const {
		return QBigInteger();
	}

	virtual
	QBigInteger
	q () const {
		return QBigInteger();
	}

	virtual
	QBigInteger
	d () const {
		return QBigInteger();
	}

public:
	PublicKey
	getPublicKey () const {
		return _pubkey;
	}

	bool
	ensureTokenAccess () {
		try {
			CK_RV rv;

			if (
				(rv = pkcs11h_token_ensureAccess (
					_pkcs11h_certificate_id->token_id,
					NULL,
					0
				)) != CKR_OK
			) {
				throw PKCS11Exception (rv, "Token access");
			}

			return true;
		}
		catch (const PKCS11Exception &) {
			return false;
		}
	}

private:
	void
	clearSign () {
		sign_data.raw.clear ();
		sign_data.alg = SignatureUnknown;
		delete sign_data.hash;
		sign_data.hash = NULL;
	}

	void
	freeResources () {
		if (_pkcs11h_certificate != NULL) {
			pkcs11h_certificate_freeCertificate (_pkcs11h_certificate);
			_pkcs11h_certificate = NULL;
		}

		if (_pkcs11h_certificate_id != NULL) {
			pkcs11h_certificate_freeCertificateId (_pkcs11h_certificate_id);
			_pkcs11h_certificate_id = NULL;
		}
	}

	void
	setCertificateId (
		pkcs11h_certificate_id_t pkcs11h_certificate_id
	) {
		CK_RV rv;

		freeResources ();

		if (
			(rv = pkcs11h_certificate_duplicateCertificateId (
				&_pkcs11h_certificate_id,
				pkcs11h_certificate_id
			)) != CKR_OK
		) {
			throw PKCS11Exception (rv, "Memory error");
		}
	}

	void
	ensureCertificate () {
		CK_RV rv;

		if (_pkcs11h_certificate == NULL) {
			if (
				(rv = pkcs11h_certificate_create (
					_pkcs11h_certificate_id,
					NULL,
					PKCS11H_PROMPT_MASK_ALLOW_ALL,
					PKCS11H_PIN_CACHE_INFINITE,
					&_pkcs11h_certificate
				)) != CKR_OK
			) {
				throw PKCS11Exception (rv, "Cannot create low-level certificate");
			}
		}
	}
};

//----------------------------------------------------------------------------
// MyPKeyContext
//----------------------------------------------------------------------------
class MyPKeyContext : public PKeyContext
{

private:
	PKeyBase *_k;

public:
	MyPKeyContext (Provider *p) : PKeyContext (p) {
		_k = NULL;
	}

	~MyPKeyContext () {
		delete _k;
	}

	virtual
	Provider::Context *
	clone () const {
		MyPKeyContext *c = new MyPKeyContext(*this);
		c->_k = (PKeyBase *)_k->clone();
		return c;
	}

public:
	virtual
	QList<PKey::Type>
	supportedTypes () const {
		QList<PKey::Type> list;
		list += PKey::RSA;
		return list;
	}

	virtual
	QList<PKey::Type>
	supportedIOTypes () const {
		QList<PKey::Type> list;
		list += PKey::RSA;
		return list;
	}

	virtual
	QList<PBEAlgorithm>
	supportedPBEAlgorithms () const {
		QList<PBEAlgorithm> list;
		return list;
	}

	virtual
	PKeyBase *
	key () {
		return _k;
	}

	virtual
	const PKeyBase *
	key () const {
		return _k;
	}

	virtual
	void
	setKey (PKeyBase *key) {
		delete _k;
		_k = key;
	}

	virtual
	bool
	importKey (
		const PKeyBase *key
	) {
		Q_UNUSED(key);
		return false;
	}

	static
	int
	passphrase_cb (
		char *buf,
		int size,
		int rwflag,
		void *u
	) {
		Q_UNUSED(buf);
		Q_UNUSED(size);
		Q_UNUSED(rwflag);
		Q_UNUSED(u);
		return 0;
	}

	virtual
	QSecureArray
	publicToDER () const {
		return static_cast<MyRSAKey *>(_k)->getPublicKey ().toDER ();
	}

	virtual
	QString
	publicToPEM () const {
		return static_cast<MyRSAKey *>(_k)->getPublicKey ().toPEM ();
	}

	virtual
	ConvertResult
	publicFromDER (
		const QSecureArray &in
	) {
		Q_UNUSED(in);
		return ErrorDecode;
	}

	virtual
	ConvertResult
	publicFromPEM (
		const QString &s
	) {
		Q_UNUSED(s);
		return ErrorDecode;
	}

	virtual
	QSecureArray
	privateToDER(
		const QSecureArray &passphrase,
		PBEAlgorithm pbe
	) const {
		Q_UNUSED(passphrase);
		Q_UNUSED(pbe);
		return QSecureArray ();
	}

	virtual
	QString
	privateToPEM (
		const QSecureArray &passphrase,
		PBEAlgorithm pbe
	) const {
		Q_UNUSED(passphrase);
		Q_UNUSED(pbe);
		return QString ();
	}

	virtual
	ConvertResult
	privateFromDER (
		const QSecureArray &in,
		const QSecureArray &passphrase
	) {
		Q_UNUSED(in);
		Q_UNUSED(passphrase);
		return ErrorDecode;
	}

	virtual
	ConvertResult
	privateFromPEM (
		const QString &s,
		const QSecureArray &passphrase
	) {
		Q_UNUSED(s);
		Q_UNUSED(passphrase);
		return ErrorDecode;
	}
};

//----------------------------------------------------------------------------
// MyKeyStoreEntry
//----------------------------------------------------------------------------
class MyKeyStoreEntry : public KeyStoreEntryContext
{
private:
	KeyStoreEntry::Type _item_type;
	KeyBundle _key;
	Certificate _cert;
	QString _storeId;
	QString _id;
	QString _storeName;
	QString _name;

public:
	MyKeyStoreEntry (
		const Certificate &cert,
		const QString &storeId,
		const QString &id,
		const QString &storeName,
		const QString &name,
		Provider *p
	) : KeyStoreEntryContext(p) {
		_item_type = KeyStoreEntry::TypeCertificate;
		_cert = cert;
		_storeId = storeId;
		_id = id;
		_storeName = storeName;
		_name = name;
	}

	MyKeyStoreEntry (
		const KeyBundle &key,
		const QString &storeId,
		const QString &id,
		const QString &storeName,
		const QString &name,
		Provider *p
	) : KeyStoreEntryContext(p) {
		_item_type = KeyStoreEntry::TypeKeyBundle;
		_key = key;
		_storeId = storeId,
		_id = id;
		_storeName = storeName;
		_name = name;
	}

	MyKeyStoreEntry (
		const MyKeyStoreEntry &from
	) : KeyStoreEntryContext(from) {
		_item_type = from._item_type;
		_key = from._key;
		_storeId = from._storeId;
		_id = from._id;
		_storeName = from._storeName;
		_name = from._name;
	}

	~MyKeyStoreEntry() {
	}

	virtual
	Provider::Context *
	clone () const {
		return new MyKeyStoreEntry(*this);
	}

public:
	virtual
	KeyStoreEntry::Type
	type () const {
		return _item_type;
	}

	virtual
	QString
	name () const {
		return _name;
	}

	virtual
	QString
	id () const {
		return _id;
	}

	virtual
	KeyBundle
	keyBundle () const {
		return _key;
	}

	virtual
	Certificate
	certificate () const {
		return _cert;
	}

	virtual
	QString
	storeId () const {
		return _storeId;
	}

	virtual
	QString
	storeName () const {
		return _storeName;
	}

	virtual
	bool
	ensureAccess () {
		return static_cast<MyRSAKey *>(static_cast<PKeyContext *>(_key.privateKey ().context ())->key ())->ensureTokenAccess ();
	}
};

//----------------------------------------------------------------------------
// pkcs11QCACrypto
//----------------------------------------------------------------------------
class pkcs11QCACrypto {

private:
	static
	int
	_pkcs11h_crypto_qca_initialize (
		void * const global_data
	) {
		Q_UNUSED(global_data);

		return 1;
	}

	static
	int
	_pkcs11h_crypto_qca_uninitialize (
		void * const global_data
	) {
		Q_UNUSED(global_data);

		return 1;
	}

	static
	int
	_pkcs11h_crypto_qca_certificate_get_expiration (
		void * const global_data,
		const unsigned char * const blob,
		const size_t blob_size,
		time_t * const expiration
	) {
		Q_UNUSED(global_data);

		Certificate cert = Certificate::fromDER (
			QByteArray (
				(char *)blob,
				blob_size
			)
		);

		*expiration = cert.notValidAfter ().toTime_t ();

		return 1;
	}

	static
	int
	_pkcs11h_crypto_qca_certificate_get_dn (
		void * const global_data,
		const unsigned char * const blob,
		const size_t blob_size,
		char * const dn,
		const size_t dn_max
	) {
		Q_UNUSED(global_data);

		Certificate cert = Certificate::fromDER (
			QByteArray (
				(char *)blob,
				blob_size
			)
		);
		CertificateInfoOrdered dnlist = cert.subjectInfoOrdered ();
		QString qdn;

		for (
			CertificateInfoOrdered::iterator i = dnlist.begin ();
			i != dnlist.end ();
			i++
		) {
			QString c;
			CertificateInfoPair e = (*i);

			switch (e.type ()) {
				case CommonName:
					c = "CN";
				break;
				case Email:
					c = "E";
				break;
				case Organization:
					c = "O";
				break;
				case OrganizationalUnit:
					c = "OU";
				break;
				case Locality:
					c = "L";
				break;
				case IncorporationLocality:
					c = "EVL";
				break;
				case State:
					c = "ST";
				break;
				case IncorporationState:
					c = "EVST";
				break;
				case Country:
					c = "C";
				break;
				case IncorporationCountry:
					c = "EVC";
				break;
				case URI:
					c = "URI";
				break;
				case DNS:
					c = "DNS";
				break;
				case IPAddress:
					c = "IP";
				break;
				case XMPP:
					c = "XMPP";
				break;
				default:
					c = "Unknown";
				break;
			}

			if (!qdn.isEmpty ()) {
				qdn += ", ";
			}
			qdn += c + '=' + e.value ();
		}

		if ((size_t)qdn.length () > dn_max-1) {
			return 0;
		}
		else {
			strcpy (dn, qPrintable (qdn));
			return 1;
		}
	}

	static
	int
	_pkcs11h_crypto_qca_certificate_is_issuer (
		void * const global_data,
		const unsigned char * const signer_blob,
		const size_t signer_blob_size,
		const unsigned char * const cert_blob,
		const size_t cert_blob_size
	) {
		Q_UNUSED(global_data);

		Certificate signer = Certificate::fromDER (
			QByteArray (
				(char *)signer_blob,
				signer_blob_size
			)
		);

		Certificate cert = Certificate::fromDER (
			QByteArray (
				(char *)cert_blob,
				cert_blob_size
			)
		);

		return signer.isIssuerOf (cert);
	}

public:
	static pkcs11h_engine_crypto_t crypto;
};

pkcs11h_engine_crypto_t pkcs11QCACrypto::crypto = {
	NULL,
	_pkcs11h_crypto_qca_initialize,
	_pkcs11h_crypto_qca_uninitialize,
	_pkcs11h_crypto_qca_certificate_get_expiration,
	_pkcs11h_crypto_qca_certificate_get_dn,
	_pkcs11h_crypto_qca_certificate_is_issuer
};

//----------------------------------------------------------------------------
// MyKeyStoreList
//----------------------------------------------------------------------------
MyKeyStoreList::MyKeyStoreList (Provider *p) : KeyStoreListContext(p) {
	_last_id = 0;
	_initialized = false;
}

MyKeyStoreList::~MyKeyStoreList () {
	s_keyStoreList = NULL;
	clearStores ();
}

QCA::Provider::Context *
MyKeyStoreList::clone () const {
	return NULL;
}

void
MyKeyStoreList::start () {
	QMetaObject::invokeMethod(this, "doReady", Qt::QueuedConnection);
}

void
MyKeyStoreList::setUpdatesEnabled (bool enabled) {
	try {
		pkcs11Provider *p = static_cast<pkcs11Provider *>(provider ());
		if (enabled) {
			p->startSlotEvents ();
		}
		else {
			p->stopSlotEvents ();
		}
	}
	catch (const PKCS11Exception &e) {
		s_keyStoreList->emit_diagnosticText (
			QString ().sprintf (
				"PKCS#11: Start event failed %lu-'%s'.\n",
				e.getRV (),
				qPrintable (e.getMessage ())
			)
		);
	}
}

KeyStoreEntryContext *
MyKeyStoreList::entry (
	int id,
	const QString &entryId
) {
	Q_UNUSED(id);
	Q_UNUSED(entryId);
	return NULL;
}

KeyStoreEntryContext *
MyKeyStoreList::entryPassive (
	const QString &storeId,
	const QString &entryId
) {
	KeyStoreEntryContext *entry = NULL;

	Q_UNUSED(storeId);

	try {
		QList<Certificate> listIssuers;
		pkcs11h_certificate_id_t certificate_id;
		bool has_private;

		deserializeCertificateId (entryId, &certificate_id, &has_private, &listIssuers);

		entry = getKeyStoreEntryByCertificateId (certificate_id, has_private, listIssuers);
	}
	catch (const PKCS11Exception &e) {
		s_keyStoreList->emit_diagnosticText (
			QString ().sprintf (
				"PKCS#11: Add key store entry %lu-'%s'.\n",
				e.getRV (),
				qPrintable (e.getMessage ())
			)
		);
	}

	return entry;
}

KeyStore::Type
MyKeyStoreList::type (int id) const {
	Q_UNUSED(id);
	return KeyStore::SmartCard;
}

QString
MyKeyStoreList::storeId (int id) const {
	QString ret;

	if (_storesById.contains (id)) {
		if (_storesById[id]->token_id != NULL) {
			ret = tokenId2storeId (_storesById[id]->token_id);
		}
	}

	return ret;
}

QString
MyKeyStoreList::name (int id) const {
	QString ret;

	if (_storesById.contains (id)) {
		if (_storesById[id]->token_id != NULL) {
			ret = _storesById[id]->token_id->label;
		}
	}

	return ret;
}

QList<KeyStoreEntry::Type>
MyKeyStoreList::entryTypes (int id) const {
	Q_UNUSED(id);
	QList<KeyStoreEntry::Type> list;
	list += KeyStoreEntry::TypeKeyBundle;
	list += KeyStoreEntry::TypeCertificate;
	return list;
}

QList<int>
MyKeyStoreList::keyStores () {
	pkcs11h_token_id_list_t tokens = NULL;
	QList<int> out;

	try {
		CK_RV rv;

		/*
		 * Get available tokens
		 */
		if (
			(rv = pkcs11h_token_enumTokenIds (
				PKCS11H_ENUM_METHOD_CACHE,
				&tokens
			)) != CKR_OK
		) {
			throw PKCS11Exception (rv, "Enumerating tokens");
		}

		/*
		 * Register all tokens, unmark
		 * them from remove list
		 */
		QList<int> to_remove = _storesById.keys ();
		for (
			pkcs11h_token_id_list_t entry = tokens;
			entry != NULL;
			entry = entry->next
		) {
			KeyStoreItem *item = registerTokenId (entry->token_id);
			out += item->id;
			to_remove.removeAll (item->id);
		}

		/*
		 * Remove all items
		 * that were not discovered
		 */
		{
			QMutexLocker l(&_mutexStores);

			for (
				QList<int>::iterator i = to_remove.begin ();
				i != to_remove.end ();
				i++
			) {
				KeyStoreItem *item = _storesById[*i];
				_storesById.remove (item->id);
				_stores.removeAll (item);
				delete item;
			}
		}
	}
	catch (const PKCS11Exception &e) {
		s_keyStoreList->emit_diagnosticText (
			QString ().sprintf (
				"PKCS#11: Cannot get key stores: %lu-'%s'.\n",
				e.getRV (),
				qPrintable (e.getMessage ())
			)
		);
	}

	if (tokens != NULL) {
		pkcs11h_token_freeTokenIdList (tokens);
	}

	return out;
}

QList<KeyStoreEntryContext*>
MyKeyStoreList::entryList (int id) {
	pkcs11h_certificate_id_list_t certs = NULL;
	QList<KeyStoreEntryContext*> out;

	try {
		CK_RV rv;

		if (_storesById.contains (id)) {
			KeyStoreItem *entry = _storesById[id];

			if (entry->token_id != NULL) {
				pkcs11h_certificate_id_list_t issuers = NULL;
				pkcs11h_certificate_id_list_t current = NULL;
				QList<Certificate> listIssuers;

				if (
					(rv = pkcs11h_certificate_enumTokenCertificateIds (
						entry->token_id,
						PKCS11H_ENUM_METHOD_CACHE,
						NULL,
						PKCS11H_PROMPT_MASK_ALLOW_ALL,
						&issuers,
						&certs
					)) != CKR_OK
				) {
					throw PKCS11Exception (rv, "Enumerate certificates");
				}

				for (current=issuers;current!=NULL;current=current->next) {
					listIssuers += Certificate::fromDER (
						QByteArray (
							(char *)current->certificate_id->certificate_blob,
							current->certificate_id->certificate_blob_size
						)
					);
				}

				for (current=issuers;current!=NULL;current=current->next) {
					try {
						out += getKeyStoreEntryByCertificateId (
							current->certificate_id,
							false,
							listIssuers
						);
					}
					catch (const PKCS11Exception &e) {
						s_keyStoreList->emit_diagnosticText (
							QString ().sprintf (
								"PKCS#11: Add key store entry %lu-'%s'.\n",
								e.getRV (),
								qPrintable (e.getMessage ())
							)
						);
					}
				}

				for (current=certs;current!=NULL;current=current->next) {
					try {
						out += getKeyStoreEntryByCertificateId (
							current->certificate_id,
							true,
							listIssuers
						);
					}
					catch (const PKCS11Exception &e) {
						s_keyStoreList->emit_diagnosticText (
							QString ().sprintf (
								"PKCS#11: Add key store entry %lu-'%s'.\n",
								e.getRV (),
								qPrintable (e.getMessage ())
							)
						);
					}
				}
			}

		}
	}
	catch (const PKCS11Exception &e) {
		s_keyStoreList->emit_diagnosticText (
			QString ().sprintf (
				"PKCS#11: Enumerating store failed %lu-'%s'.\n",
				e.getRV (),
				qPrintable (e.getMessage ())
			)
		);
	}

	if (certs != NULL) {
		pkcs11h_certificate_freeCertificateIdList (certs);
	}

	return out;
}

bool
MyKeyStoreList::tokenPrompt (
	const pkcs11h_token_id_t token_id
) {
	KeyStoreItem *entry = registerTokenId (token_id);

	TokenAsker asker;
	asker.ask (
		tokenId2storeId (entry->token_id),
		NULL
	);
	asker.waitForResponse ();
	return asker.accepted ();
}

void
MyKeyStoreList::pinPrompt (
	const pkcs11h_token_id_t token_id,
	QSecureArray &pin
) {
	KeyStoreItem *entry = registerTokenId (token_id);

	PasswordAsker asker;
	asker.ask (
		Event::StylePIN,
		tokenId2storeId (entry->token_id),
		QString(),
		NULL
	);
	asker.waitForResponse ();
	if (asker.accepted ()) {
		pin = asker.password();
	}
	else {
		pin = QSecureArray();
	}
}

void
MyKeyStoreList::emit_updated () {
	QMetaObject::invokeMethod(this, "doUpdated", Qt::QueuedConnection);
}

void
MyKeyStoreList::emit_diagnosticText (
	const QString &t
) {
	emit diagnosticText (t);
}

void
MyKeyStoreList::doReady () {
	emit busyEnd ();
}

void
MyKeyStoreList::doUpdated () {
	emit updated ();
}

MyKeyStoreList::KeyStoreItem *
MyKeyStoreList::registerTokenId (
	const pkcs11h_token_id_t token_id
) {
	QMutexLocker l(&_mutexStores);

	_stores_t::iterator i=_stores.begin ();

	while (
		i != _stores.end () &&
		!pkcs11h_token_sameTokenId (
			token_id,
			(*i)->token_id
		)
	) {
		i++;
	}

	KeyStoreItem *entry = NULL;

	if (i == _stores.end ()) {
		/*
		 * Deal with last_id overlap
		 */
		while (_storesById.find (++_last_id) != _storesById.end ());

		entry = new KeyStoreItem;
		entry->id = _last_id;
		pkcs11h_token_duplicateTokenId (&entry->token_id, token_id);

		_stores += entry;
		_storesById.insert (entry->id, entry);
	}
	else {
		entry = (*i);
	}

	return entry;
}

void
MyKeyStoreList::clearStores () {
	QMutexLocker l(&_mutexStores);

	_storesById.clear ();

	for (
		_stores_t::iterator i=_stores.begin ();
		i != _stores.end ();
		i++
	) {
		KeyStoreItem *entry = (*i);
		delete entry;
	}

	_stores.clear ();
}

MyKeyStoreEntry *
MyKeyStoreList::getKeyStoreEntryByCertificateId (
	const pkcs11h_certificate_id_t certificate_id,
	bool has_private,
	const QList<Certificate> &listIssuers
) const {
	MyKeyStoreEntry *entry = NULL;

	if (certificate_id == 0) {
		throw PKCS11Exception (CKR_ARGUMENTS_BAD, "Missing certificate object");
	}

	if (certificate_id->certificate_blob_size == 0) {
		throw PKCS11Exception (CKR_ARGUMENTS_BAD, "Missing certificate");
	}

	Certificate cert = Certificate::fromDER (
		QByteArray (
			(char *)certificate_id->certificate_blob,
			certificate_id->certificate_blob_size
		)
	);

	if (cert.isNull ()) {
		throw PKCS11Exception (CKR_ARGUMENTS_BAD, "Invalid certificate");
	}

	CertificateChain chain = CertificateChain (cert).complete (listIssuers);

	QString description = cert.commonName () + " by " + cert.issuerInfo ().value (CommonName, "Unknown");

	QString id = serializeCertificateId (
		certificate_id,
		chain,
		has_private
	);

	if (has_private) {
		MyRSAKey *rsakey = new MyRSAKey (
			provider(),
			certificate_id,
			cert.subjectPublicKey ().toRSA ()
		);

		MyPKeyContext *pkc = new MyPKeyContext (provider ());
		pkc->setKey (rsakey);
		PrivateKey privkey;
		privkey.change (pkc);
		KeyBundle key;
		key.setCertificateChainAndKey (
			chain,
			privkey
		);

		entry = new MyKeyStoreEntry (
			key,
			tokenId2storeId (certificate_id->token_id),
			id,
			certificate_id->token_id->label,
			description,
			provider ()
		);
	}
	else {
		entry = new MyKeyStoreEntry (
			cert,
			tokenId2storeId (certificate_id->token_id),
			id,
			certificate_id->token_id->label,
			description,
			provider()
		);
	}

	return entry;
}

QString
MyKeyStoreList::tokenId2storeId (
	const pkcs11h_token_id_t token_id
) const {
	QString qid = "Unknown";
	char *id = NULL;
	size_t len;

	if (
		pkcs11h_token_serializeTokenId (
			NULL,
			&len,
			token_id
		) == CKR_OK &&
		(id = (char *)malloc (len)) != NULL &&
		pkcs11h_token_serializeTokenId (
			id,
			&len,
			token_id
		) == CKR_OK
	) {
		qid = id;
	}

	if (id != NULL) {
		free (id);
		id = NULL;
	}

	return "qca-pkcs11/" + escapeString (qid);
}

QString
MyKeyStoreList::serializeCertificateId (
	const pkcs11h_certificate_id_t certificate_id,
	const CertificateChain &chain,
	const bool has_private
) const {
	QString serialized;
	QString qid = "Unknown";
	char *id = NULL;
	size_t len;

	if (
		pkcs11h_certificate_serializeCertificateId (
			NULL,
			&len,
			certificate_id
		) == CKR_OK &&
		(id = (char *)malloc (len)) != NULL &&
		pkcs11h_certificate_serializeCertificateId (
			id,
			&len,
			certificate_id
		) == CKR_OK
	) {
		qid = id;
	}

	if (id != NULL) {
		free (id);
		id = NULL;
	}

	serialized = QString ().sprintf (
		"qca-pkcs11/%s/%d",
		qPrintable(escapeString (qid)),
		has_private ? 1 : 0
	);

	for (
		CertificateChain::const_iterator i = chain.begin ();
		i != chain.end ();
		i++
	) {
		serialized += '/' + escapeString (Base64 ().arrayToString ((*i).toDER ()));
	}

	return serialized;
}

void
MyKeyStoreList::deserializeCertificateId (
	const QString &from,
	pkcs11h_certificate_id_t * const p_certificate_id,
	bool * const has_private,
	QList<Certificate> *listIssuers
) const {
	pkcs11h_certificate_id_t certificate_id = NULL;

	try {
		int n = 0;
		CK_RV rv;

		*p_certificate_id = NULL;
		*has_private = false;

		QStringList list = from.split ("/");

		if (list.size () < 3) {
			throw PKCS11Exception (CKR_FUNCTION_FAILED, "Invalid serialization");
		}

		if (list[n++] != "qca-pkcs11") {
			throw PKCS11Exception (CKR_FUNCTION_FAILED, "Invalid serialization");
		}

		if (
			(rv = pkcs11h_certificate_deserializeCertificateId (
				&certificate_id,
				qPrintable (list[n++])
			)) != CKR_OK
		) {
			throw PKCS11Exception (rv, "Invalid serialization");
		}

		*has_private = list[n++].toInt () != 0;

		QSecureArray arrayCertificate = Base64 ().stringToArray (unescapeString (list[n++]));

		if (
			(rv = pkcs11h_certificate_setCertificateIdCertificateBlob (
				certificate_id,
				(unsigned char *)arrayCertificate.data (),
				(size_t)arrayCertificate.size ()
			)) != CKR_OK
		) {
			throw PKCS11Exception (rv, "Invalid serialization");
		}

		while (n < list.size ()) {
			*listIssuers += Certificate::fromDER (
				Base64 ().stringToArray (unescapeString (list[n++]))
			);
		}

		*p_certificate_id = certificate_id;
		certificate_id = NULL;
	}
	catch (...) {
		if (certificate_id != NULL) {
			pkcs11h_certificate_freeCertificateId (certificate_id);
			certificate_id = NULL;
		}
	}
}

QString
MyKeyStoreList::escapeString (
	const QString &from
) const {
	QString to;

	for (int i=0;i<from.size ();i++) {
		QChar c = from[i];

		if (c == '/' || c == '\\') {
			to += QString ().sprintf ("\\x%02x", c.toLatin1 ());
		}
		else {
			to += c;
		}
	}

	return to;
}

QString
MyKeyStoreList::unescapeString (
	const QString &from
) const {
	QString to;

	for (int i=0;i<from.size ();i++) {
		QChar c = from[i];

		if (c == '\\') {
			to += QChar ((uchar)from.mid (i+2, 2).toInt (0, 16));
			i+=3;
		}
		else {
			to += c;
		}
	}

	return to;
}

}

using namespace pkcs11QCAPlugin;

const int pkcs11Provider::_CONFIG_MAX_PROVIDERS = 10;

//----------------------------------------------------------------------------
// pkcs11Provider
//----------------------------------------------------------------------------
pkcs11Provider::pkcs11Provider () {
	_fLowLevelInitialized = false;
	_fSlotEventsActive = false;
	_fSlotEventsLowLevelActive = false;
}

pkcs11Provider::~pkcs11Provider () {
	delete s_keyStoreList;
	s_keyStoreList = NULL;
	pkcs11h_terminate ();
}

int pkcs11Provider::version() const
{
	return QCA_VERSION;
}

void pkcs11Provider::init () {
	try {
		CK_RV rv;

		if ((rv = pkcs11h_engine_setCrypto (&pkcs11QCACrypto::crypto)) != CKR_OK) {
			throw PKCS11Exception (rv, "Cannot set crypto");
		}

		if ((rv = pkcs11h_initialize ()) != CKR_OK) {
			throw PKCS11Exception (rv, "Cannot initialize");
		}

		if (
			(rv = pkcs11h_setLogHook (
				_logHook,
				this
			)) != CKR_OK
		) {
			throw PKCS11Exception (rv, "Cannot set hook");
		}

		pkcs11h_setLogLevel (PKCS11H_LOG_QUITE);

		if (
			(rv = pkcs11h_setTokenPromptHook (
				_tokenPromptHook,
				this
			)) != CKR_OK
		) {
			throw PKCS11Exception (rv, "Cannot set hook");
		}

		if (
			(rv = pkcs11h_setPINPromptHook (
				_pinPromptHook,
				this
			)) != CKR_OK
		) {
			throw PKCS11Exception (rv, "Cannot set hook");
		}

		_fLowLevelInitialized = true;

//		setProviderConfig (name (), getProviderConfig (name ()));
	}
	catch (const PKCS11Exception &) {
/*CANNOT DO ANYTHING HERE
		emit_diagnosticText (
			QString ().sprintf (
				"PKCS#11: Cannot initialize: %lu-'%s'.\n",
				e.getRV (),
				qPrintable (e.getMessage ())
			)
		);
*/
	}
	catch (...) {
/*CANNOT DO ANYTHING HERE
		emit_diagnosticText ("PKCS#11: Unknown error during provider initialization.\n");
*/
	}
}

QString
pkcs11Provider::name () const {
	return "qca-pkcs11";
}

QStringList
pkcs11Provider::features() const {
	QStringList list;
	list += "smartcard"; // indicator, not algorithm
	list += "pkey";
	list += "keystorelist";
	return list;
}

QCA::Provider::Context
*pkcs11Provider::createContext (const QString &type) {
	if (_fLowLevelInitialized) {
		if(type == "keystorelist") {
			if (s_keyStoreList == NULL) {
				s_keyStoreList = new MyKeyStoreList (this);
				return s_keyStoreList;
			}
		}
	}
	return NULL;
}

void
pkcs11Provider::startSlotEvents () {
	CK_RV rv;

	if (_fLowLevelInitialized) {
		if (!_fSlotEventsLowLevelActive) {
			if (
				(rv = pkcs11h_setSlotEventHook (
					_slotEventHook,
					this
				)) != CKR_OK
			) {
				throw PKCS11Exception (rv, "Cannot start slot events");
			}

			_fSlotEventsLowLevelActive = true;
		}

		_fSlotEventsActive = true;
	}
}

void
pkcs11Provider::stopSlotEvents () {
	_fSlotEventsActive = false;
}

QVariantMap
pkcs11Provider::defaultConfig () const {
	QVariantMap mytemplate;

	mytemplate["formtype"] = "http://affinix.com/qca/forms/qca-pkcs11#1.0";
	mytemplate["allow_protected_authentication"] = true;
	mytemplate["pin_cache"] = PKCS11H_PIN_CACHE_INFINITE;
	mytemplate["log_level"] = PKCS11H_LOG_QUITE;
	for (int i=0;i<_CONFIG_MAX_PROVIDERS;i++) {
		mytemplate[QString ().sprintf ("provider_%02d_enabled", i)] = false;
		mytemplate[QString ().sprintf ("provider_%02d_name", i)] = "";
		mytemplate[QString ().sprintf ("provider_%02d_library", i)] = "";
		mytemplate[QString ().sprintf ("provider_%02d_allow_protected_authentication", i)] = true;
		mytemplate[QString ().sprintf ("provider_%02d_cert_private", i)] = false;
		mytemplate[QString ().sprintf ("provider_%02d_private_mask", i)] = PKCS11H_PRIVATEMODE_MASK_AUTO;
		mytemplate[QString ().sprintf ("provider_%02d_slotevent_method", i)] = "auto";
		mytemplate[QString ().sprintf ("provider_%02d_slotevent_timeout", i)] = 0;
	}

	return mytemplate;
}

void
pkcs11Provider::configChanged (const QVariantMap &config) {
	CK_RV rv = CKR_OK;

	if (!_fLowLevelInitialized) {
/*CANNOT DO ANYTHING HERE
		emit_diagnosticText ("PKCS#11: Not initialized.\n");
*/
		return;
	}

	pkcs11h_setLogLevel (config["log_level"].toInt ());
	pkcs11h_setProtectedAuthentication (
		config["allow_protected_authentication"].toBool () != false ? TRUE : FALSE //krazy:exclude=captruefalse
	);
	pkcs11h_setPINCachePeriod (config["pin_cache"].toInt ());

	/*
	 * Remove current providers
	 */
	for (
		QStringList::iterator pi = _providers.begin ();
		pi != _providers.end ();
		pi++
	) {
		pkcs11h_removeProvider (qPrintable (*pi));
	}
	_providers.clear ();

	/*
	 * Add new providers
	 */
	for (int i=0;i<_CONFIG_MAX_PROVIDERS;i++) {
		bool enabled = config[QString ().sprintf ("provider_%02d_enabled", i)].toBool ();
		QString provider = config[QString ().sprintf ("provider_%02d_library", i)].toString ();
		QString name = config[QString ().sprintf ("provider_%02d_name", i)].toString ();
		QString qslotevent = config[QString ().sprintf ("provider_%02d_slotevent_method", i)].toString ();
		unsigned slotevent = PKCS11H_SLOTEVENT_METHOD_AUTO;
		if (qslotevent == "trigger") {
			slotevent = PKCS11H_SLOTEVENT_METHOD_TRIGGER;
		}
		else if (qslotevent == "poll") {
			slotevent = PKCS11H_SLOTEVENT_METHOD_POLL;
		}

		if (name.isEmpty ()) {
			name = provider;
		}

		if (enabled && !provider.isEmpty()) {
			if (
				(rv = pkcs11h_addProvider (
					qPrintable (name),
					qPrintable (provider),
					config[
						QString ().sprintf ("provider_%02d_allow_protected_authentication", i)
					].toBool () != false ? TRUE : FALSE, //krazy:exclude=captruefalse
					(unsigned)config[
						QString ().sprintf ("provider_%02d_private_mask", i)
					].toInt (),
					slotevent,
					(unsigned)config[
						QString ().sprintf ("provider_%02d_slotevent_timeout", i)
					].toInt (),
					config[
						QString ().sprintf ("provider_%02d_cert_private", i)
					].toBool () != false ? TRUE : FALSE //krazy:exclude=captruefalse
				)) != CKR_OK
			) {
/*CANNOT DO ANYTHING HERE
				emit_diagnosticText (
					QString ().sprintf (
						"PKCS#11: Cannot log provider '%s'-'%s' %lu-'%s'.\n",
						qPrintable (name),
						qPrintable (provider),
						rv,
						pkcs11h_getMessage (rv)
					)
				);
*/
			}
			else {
				_providers += provider;
			}
		}
	}
}

void
pkcs11Provider::_logHook (
	void * const global_data,
	const unsigned flags,
	const char * const format,
	va_list args
) {
	pkcs11Provider *me = (pkcs11Provider *)global_data;
	me->logHook (flags, format, args);
}

void
pkcs11Provider::_slotEventHook (
	void * const global_data
) {
	pkcs11Provider *me = (pkcs11Provider *)global_data;
	me->slotEventHook ();
}

PKCS11H_BOOL
pkcs11Provider::_tokenPromptHook (
	void * const global_data,
	void * const user_data,
	const pkcs11h_token_id_t token,
	const unsigned retry
) {
	Q_UNUSED(user_data);
	Q_UNUSED(retry);

	pkcs11Provider *me = (pkcs11Provider *)global_data;
	return me->tokenPromptHook (token);
}

PKCS11H_BOOL
pkcs11Provider::_pinPromptHook (
	void * const global_data,
	void * const user_data,
	const pkcs11h_token_id_t token,
	const unsigned retry,
	char * const pin,
	const size_t pin_max
) {
	Q_UNUSED(user_data);
	Q_UNUSED(retry);

	pkcs11Provider *me = (pkcs11Provider *)global_data;
	return me->pinPromptHook (token, pin, pin_max);
}

void
pkcs11Provider::logHook (
	const unsigned flags,
	const char * const format,
	va_list args
) {
	Logger::Severity severity;

	switch (flags) {
		case PKCS11H_LOG_DEBUG2:
		case PKCS11H_LOG_DEBUG1:
			severity = Logger::Debug;
		break;
		case PKCS11H_LOG_INFO:
			severity = Logger::Information;
		break;
		case PKCS11H_LOG_WARN:
			severity = Logger::Warning;
		break;
		case PKCS11H_LOG_ERROR:
			severity = Logger::Error;
		break;
		default:
			severity = Logger::Debug;
		break;
	}


//@BEGIN-WORKAROUND
// Qt vsprintf cannot can NULL for %s as vsprintf does.
//	logger ()->logTextMessage (QString ().vsprintf (format, args), severity);
	char buffer[1024];
	vsnprintf (buffer, sizeof (buffer)-1, format, args);
	buffer[sizeof (buffer)-1] = '\x0';
// logger has problem during shutdown
// @bhards
//	logger ()->logTextMessage (QString ().fromUtf8 (buffer), severity);
//@END-WORKAROUND
}

void
pkcs11Provider::slotEventHook () {
	/*
	 * This is called from a separate
	 * thread.
	 */
	if (s_keyStoreList != NULL && _fSlotEventsActive) {
		s_keyStoreList->emit_updated ();
	}
}

PKCS11H_BOOL
pkcs11Provider::tokenPromptHook (
	const pkcs11h_token_id_t token
) {
	if (s_keyStoreList != NULL) {
		return s_keyStoreList->tokenPrompt (token) ? TRUE : FALSE; //krazy:exclude=captruefalse
	}

	return FALSE; //krazy:exclude=captruefalse
}

PKCS11H_BOOL
pkcs11Provider::pinPromptHook (
	const pkcs11h_token_id_t token,
	char * const pin,
	const size_t pin_max
) {
	QSecureArray qpin;
	if (s_keyStoreList != NULL) {

		s_keyStoreList->pinPrompt (token, qpin);

		if (!qpin.isEmpty ()) {
			if ((size_t)qpin.size () < pin_max-1) {
				memmove (pin, qpin.constData (), qpin.size ());
				pin[qpin.size ()] = '\0';
				return TRUE; //krazy:exclude=captruefalse
			}
		}
	}
	return FALSE; //krazy:exclude=captruefalse
}

class pkcs11Plugin : public QCAPlugin
{
	Q_OBJECT
	Q_INTERFACES(QCAPlugin)

public:
	virtual QCA::Provider *createProvider() { return new pkcs11Provider; }
};

#include "qca-pkcs11.moc"

Q_EXPORT_PLUGIN2(qca_pkcs11, pkcs11Plugin)
