/*
 * Copyright (C) 2004  Justin Karneges
 * Copyright (C) 2006  Alon Bar-Lev <alon.barlev@gmail.com>
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

/*
 * The routines in this file deal with providing private key cryptography
 * using RSA Security Inc. PKCS #11 Cryptographic Token Interface (Cryptoki).
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
	bool _fLowLevelInitialized;
	int _log_level;
	bool _fSlotEventsActive;
	bool _fSlotEventsLowLevelActive;

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
	QString
	credit () const;
	
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

protected:
	static
	void
	_logHook (
		void * const global_data,
		const unsigned flags,
		const char * const szFormat,
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
		char * const szPIN,
		const size_t nMaxPIN
	);
	
	void
	logHook (
		const unsigned flags,
		const char * const szFormat,
		va_list args
	);

	void
	slotEventHook ();

	PKCS11H_BOOL
	cardPromptHook (
		const pkcs11h_token_id_t token
	);
	
	PKCS11H_BOOL
	pinPromptHook (
		const pkcs11h_token_id_t token,
		char * const szPIN,
		const size_t nMaxPIN
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
		bool fPrivate,
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
		const bool fPrivate
	) const;

	void
	deserializeCertificateId (
		const QString &from,
		pkcs11h_certificate_id_t * const p_certificate_id,
		bool * const fPrivate,
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
	bool _fPrivateKeyRole;
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
		_fPrivateKeyRole = true;
		_pkcs11h_certificate_id = NULL;
		_pkcs11h_certificate = NULL;
		
		_pubkey = pubkey;
		clearSign ();

		setCertificateId (pkcs11h_certificate_id);
	}

	MyRSAKey (const MyRSAKey &from) : RSAContext (from.provider ()) {
		_fPrivateKeyRole = from._fPrivateKeyRole;
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
		return _fPrivateKeyRole;
	}

	virtual
	bool
	canExport () const {
		return !_fPrivateKeyRole;
	}

	virtual
	void
	convertToPublic () {
		if (_fPrivateKeyRole) {
			if (_pkcs11h_certificate != NULL) {
				pkcs11h_certificate_freeCertificate (_pkcs11h_certificate);
				_pkcs11h_certificate = NULL;
			}
			_fPrivateKeyRole = false;
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
				(rv = pkcs11h_certificate_decrypt (
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
				(rv = pkcs11h_certificate_decrypt (
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

			return true;
		}
		catch (const PKCS11Exception &e) {
			if (s_keyStoreList != NULL) {
				s_keyStoreList->emit_diagnosticText (
					QString ().sprintf (
						"PKCS#11: Cannot decrypt: %ld-'%s'.\n",
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
		if (_fPrivateKeyRole) {
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
		}
		catch (const PKCS11Exception &e) {
			result.clear ();

			if (s_keyStoreList != NULL) {
				s_keyStoreList->emit_diagnosticText (
					QString ().sprintf (
						"PKCS#11: Cannot sign: %ld-'%s'.\n",
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

	CK_RV rv = CKR_OK;

	try {
		QString strProvider = qgetenv ("QCA_PKCS11_LIB");

		if (!strProvider.isEmpty()) {
			if (
				(rv = pkcs11h_addProvider (
					qPrintable (strProvider),
					qPrintable (strProvider),
					FALSE,
					PKCS11H_SLOTEVENT_METHOD_AUTO,
					PKCS11H_SLOTEVENT_METHOD_AUTO,
					0,
					FALSE
				)) != CKR_OK
			) {
				throw PKCS11Exception (rv, "Adding provider " + strProvider);
			}
		}
	}
	catch (const PKCS11Exception &e) {
		s_keyStoreList->emit_diagnosticText (
			QString ().sprintf (
				"PKCS#11: Start failed %ld-'%s'.\n",
				e.getRV (),
				qPrintable (e.getMessage ())
			)
		);
	}

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
				"PKCS#11: Start event failed %ld-'%s'.\n",
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
	Q_UNUSED(storeId);

	try {
		QList<Certificate> listIssuers;
		pkcs11h_certificate_id_t certificate_id;
		bool fPrivate;
		
		deserializeCertificateId (entryId, &certificate_id, &fPrivate, &listIssuers);
			
		return getKeyStoreEntryByCertificateId (certificate_id, fPrivate, listIssuers);
	}
	catch (const PKCS11Exception &e) {
		s_keyStoreList->emit_diagnosticText (
			QString ().sprintf (
				"PKCS#11: Add key store entry %ld-'%s'.\n",
				e.getRV (),
				qPrintable (e.getMessage ())
			)
		);

		return NULL;
	}
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
				"PKCS#11: Cannot get key stores: %ld-'%s'.\n",
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
								"PKCS#11: Add key store entry %ld-'%s'.\n",
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
								"PKCS#11: Add key store entry %ld-'%s'.\n",
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
				"PKCS#11: Enumerating store failed %ld-'%s'.\n",
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

void
MyKeyStoreList::pinPrompt (
	const pkcs11h_token_id_t token_id,
	QSecureArray &pin
) {
	KeyStoreItem *entry = NULL;

	{
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

		if (i != _stores.end ()) {
			entry = (*i);
		}
	}

	if (entry == NULL) {
		entry = registerTokenId (token_id);
	}

	PasswordAsker asker;
	asker.ask (
		Event::StylePIN,
		tokenId2storeId (entry->token_id),
		QString(),
		0
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
	bool fPrivate,
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

	QString strDescription = cert.commonName () + " by " + cert.issuerInfo ().value (CommonName, "Unknown");

	QString id = serializeCertificateId (
		certificate_id,
		chain,
		fPrivate
	);

	if (fPrivate) {
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
			strDescription,
			provider ()
		);
	}
	else {
		entry = new MyKeyStoreEntry (
			cert,
			tokenId2storeId (certificate_id->token_id),
			id,
			certificate_id->token_id->label,
			strDescription,
			provider()
		);
	}

	return entry;
}

QString
MyKeyStoreList::tokenId2storeId (
	const pkcs11h_token_id_t token_id
) const {
	QCA::Hash hash1 ("md2");
	hash1.update (token_id->manufacturerID, strlen (token_id->manufacturerID));
	hash1.update (token_id->model, strlen (token_id->model));
	hash1.update (token_id->serialNumber, strlen (token_id->serialNumber));

	return "qca-pkcs11/" + escapeString (Base64 ().arrayToString (hash1.final ()));
}

QString
MyKeyStoreList::serializeCertificateId (
	const pkcs11h_certificate_id_t certificate_id,
	const CertificateChain &chain,
	const bool fPrivate
) const {
	QString strSerialized;
	
	strSerialized += QString ().sprintf (
		"qca-pkcs11/%s/%s/%s/%s/%s/%d",
		qPrintable (escapeString (certificate_id->token_id->manufacturerID)),
		qPrintable (escapeString (certificate_id->token_id->model)),
		qPrintable (escapeString (certificate_id->token_id->serialNumber)),
		qPrintable (escapeString (certificate_id->token_id->label)),
		qPrintable (escapeString (Base64 ().arrayToString (
			(QByteArray (
				(const char *)certificate_id->attrCKA_ID,
				(int)certificate_id->attrCKA_ID_size
			)
		)))),
		fPrivate ? 1 : 0
	);
	
	for (
		CertificateChain::const_iterator i = chain.begin ();
		i != chain.end ();
		i++
	) {
		strSerialized += "/" + escapeString (Base64 ().arrayToString ((*i).toDER ()));
	}

	return strSerialized;
}

void
MyKeyStoreList::deserializeCertificateId (
	const QString &from,
	pkcs11h_certificate_id_t * const p_certificate_id,
	bool * const fPrivate,
	QList<Certificate> *listIssuers
) const {
	*p_certificate_id = NULL;
	*fPrivate = false;
	int n = 0;

	CK_RV rv;

	QStringList list = from.split ("/");

	if (list.size () < 8) {
		throw PKCS11Exception (CKR_FUNCTION_FAILED, "Invalid serialization");
	}

	if (list[n++] != "qca-pkcs11") {
		throw PKCS11Exception (CKR_FUNCTION_FAILED, "Invalid serialization");
	}

	pkcs11h_token_id_s token_id_s;
	pkcs11h_certificate_id_s certificate_id_s;

	memset (&token_id_s, 0, sizeof (token_id_s));
	memset (&certificate_id_s, 0, sizeof (certificate_id_s));

	certificate_id_s.token_id = &token_id_s;

	strncpy (
		token_id_s.manufacturerID,
		qPrintable (unescapeString (list[n++])),
		sizeof (token_id_s.manufacturerID)
	);
	token_id_s.manufacturerID[sizeof (token_id_s.manufacturerID)-1] = '\0';
	strncpy (
		token_id_s.model,
		qPrintable (unescapeString (list[n++])),
		sizeof (token_id_s.model)
	);
	token_id_s.model[sizeof (token_id_s.model)-1] = '\0';
	strncpy (
		token_id_s.serialNumber,
		qPrintable (unescapeString (list[n++])),
		sizeof (token_id_s.serialNumber)
	);
	token_id_s.serialNumber[sizeof (token_id_s.serialNumber)-1] = '\0';
	strncpy (
		token_id_s.label,
		qPrintable (unescapeString (list[n++])),
		sizeof (token_id_s.label)
	);
	token_id_s.label[sizeof (token_id_s.label)-1] = '\0';

	QSecureArray arrayCKA_ID = Base64 ().stringToArray (unescapeString (list[n++]));
	certificate_id_s.attrCKA_ID = (unsigned char *)arrayCKA_ID.data ();
	certificate_id_s.attrCKA_ID_size = (size_t)arrayCKA_ID.size ();

	*fPrivate = list[n++].toInt () != 0;

	QSecureArray arrayCertificate = Base64 ().stringToArray (unescapeString (list[n++]));
	certificate_id_s.certificate_blob = (unsigned char *)arrayCertificate.data ();
	certificate_id_s.certificate_blob_size = (size_t)arrayCertificate.size ();

	if (
		(rv = pkcs11h_certificate_duplicateCertificateId (
			p_certificate_id,
			&certificate_id_s
		)) != CKR_OK
	) {
		throw PKCS11Exception (rv, "Memory error");
	}

	while (n < list.size ()) {
		*listIssuers += Certificate::fromDER (
			Base64 ().stringToArray (unescapeString (list[n++]))
		);
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

//----------------------------------------------------------------------------
// pkcs11Provider
//----------------------------------------------------------------------------
pkcs11Provider::pkcs11Provider () {
	_fLowLevelInitialized = false;
	_log_level = PKCS11H_LOG_QUITE;
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
		QString strLogLevel = qgetenv ("QCA_PKCS11_LOGLEVEL");
		CK_RV rv;

		if (!strLogLevel.isEmpty ()) {
			_log_level = strLogLevel.toInt ();
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

		pkcs11h_setLogLevel (_log_level);

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
		
		if (rv == CKR_OK) {
			_fLowLevelInitialized = true;
		}
	}
	catch (const PKCS11Exception &) {
/*CANNOT DO ANYTHING HERE
		emit_diagnosticText (
			QString ().sprintf (
				"PKCS#11: Cannot initialize: %ld-'%s'.\n",
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
		throw;
	}
}

QString
pkcs11Provider::name () const {
	return "qca-pkcs11";
}

QString
pkcs11Provider::credit () const {
	return "RSA Security Inc. PKCS #11 Cryptographic Token Interface (Cryptoki).";
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

void
pkcs11Provider::_logHook (
	void * const global_data,
	const unsigned flags,
	const char * const szFormat,
	va_list args
) {
	pkcs11Provider *me = (pkcs11Provider *)global_data;
	me->logHook (flags, szFormat, args);
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
	return me->cardPromptHook (token);
}

PKCS11H_BOOL
pkcs11Provider::_pinPromptHook (
	void * const global_data,
	void * const user_data,
	const pkcs11h_token_id_t token,
	const unsigned retry,
	char * const szPIN,
	const size_t nMaxPIN
) {
	Q_UNUSED(user_data);
	Q_UNUSED(retry);

	pkcs11Provider *me = (pkcs11Provider *)global_data;
	return me->pinPromptHook (token, szPIN, nMaxPIN);
}

void
pkcs11Provider::logHook (
	const unsigned flags,
	const char * const szFormat,
	va_list args
) {
	Q_UNUSED(flags);

	vprintf (szFormat, args);
	printf ("\n");
}

void
pkcs11Provider::slotEventHook () {
	/*
	 * This is called from a seperate
	 * thread.
	 */
	if (s_keyStoreList != NULL && _fSlotEventsActive) {
		s_keyStoreList->emit_updated ();
	}
}

PKCS11H_BOOL
pkcs11Provider::cardPromptHook (
	const pkcs11h_token_id_t token
) {
	printf ("PKCS#11: Token prompt '%s'\n", token->label);
	return FALSE;
}

PKCS11H_BOOL
pkcs11Provider::pinPromptHook (
	const pkcs11h_token_id_t token,
	char * const szPIN,
	const size_t nMaxPIN
) {
	QSecureArray pin;
	if (s_keyStoreList != NULL) {
		
		s_keyStoreList->pinPrompt (token, pin);

		if (!pin.isEmpty ()) {
			if ((size_t)pin.size () < nMaxPIN-1) {
				memmove (szPIN, pin.constData (), pin.size ());
				szPIN[pin.size ()] = '\0';
				return TRUE;
			}
		}
	}
	return FALSE;
}

class pkcs11Plugin : public QCAPlugin
{
	Q_OBJECT
	Q_INTERFACES(QCAPlugin)

public:
	virtual QCA::Provider *createProvider() { return new pkcs11Provider; }
};

#include "qca-pkcs11.moc"

Q_EXPORT_PLUGIN2(qca-pkcs11, pkcs11Plugin)
