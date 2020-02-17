/*
 * Copyright (C) 2004  Justin Karneges  <justin@affinix.com>
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

#include <QtCrypto>
#include <qcaprovider.h>
#include <qplatformdefs.h>

#include <QHash>
#include <QMutexLocker>
#include <QtPlugin>

#include <pkcs11-helper-1.0/pkcs11h-token.h>
#include <pkcs11-helper-1.0/pkcs11h-certificate.h>

using namespace QCA;

// qPrintable is ASCII only!!!
#define myPrintable(s) (s).toUtf8 ().constData ()

static
inline
QString
certificateHash (
	const Certificate &cert
) {
	if (cert.isNull ()) {
		return QString();
	}
	else {
		return Hash (QStringLiteral("sha1")).hashToString (cert.toDER ());
	}
}

//----------------------------------------------------------------------------
// pkcs11Provider
//----------------------------------------------------------------------------
class pkcs11Provider : public Provider
{
private:
	static const int _CONFIG_MAX_PROVIDERS;

	bool _lowLevelInitialized;
	bool _slotEventsActive;
	bool _slotEventsLowLevelActive;
	QStringList _providers;

public:
	bool _allowLoadRootCA;

public:
	pkcs11Provider ();
	~pkcs11Provider () override;

public:
	int
	qcaVersion() const override;

	void
	init () override;

	void
	deinit () override;

	QString
	name () const override;

	QStringList
	features () const override;

	Context *
	createContext (
		const QString &type
	) override;

	void
	startSlotEvents ();

	void
	stopSlotEvents ();

	QVariantMap
	defaultConfig () const override;

	void
	configChanged (const QVariantMap &config) override;

protected:
	static
	void
	__logHook (
		void * const global_data,
		const unsigned flags,
		const char * const format,
		va_list args
	);

	static
	void
	__slotEventHook (
		void * const global_data
	);

	static
	PKCS11H_BOOL
	__tokenPromptHook (
		void * const global_data,
		void * const user_data,
		const pkcs11h_token_id_t token,
		const unsigned retry
	);

	static
	PKCS11H_BOOL
	__pinPromptHook (
		void * const global_data,
		void * const user_data,
		const pkcs11h_token_id_t token,
		const unsigned retry,
		char * const pin,
		const size_t pin_max
	);

	void
	_logHook (
		const unsigned flags,
		const char * const format,
		va_list args
	);

	void
	_slotEventHook ();

	PKCS11H_BOOL
	_tokenPromptHook (
		void * const user_data,
		const pkcs11h_token_id_t token
	);

	PKCS11H_BOOL
	_pinPromptHook (
		void * const user_data,
		const pkcs11h_token_id_t token,
		char * const pin,
		const size_t pin_max
	);
};

namespace pkcs11QCAPlugin {

class pkcs11KeyStoreEntryContext;

//----------------------------------------------------------------------------
// pkcs11KeyStoreListContext
//----------------------------------------------------------------------------
class pkcs11KeyStoreListContext : public KeyStoreListContext
{
	Q_OBJECT

private:
	struct pkcs11KeyStoreItem {

	protected:
		int _id;
		pkcs11h_token_id_t _token_id;
		QList<Certificate> _certs;

	public:
		pkcs11KeyStoreItem (
			const int id,
			const pkcs11h_token_id_t token_id
		) {
			_id = id;;
			pkcs11h_token_duplicateTokenId (&_token_id, token_id);
		}

		~pkcs11KeyStoreItem () {
			if (_token_id != nullptr) {
				pkcs11h_token_freeTokenId (_token_id);
			}
		}

		pkcs11KeyStoreItem(const pkcs11KeyStoreItem &) = delete;
		pkcs11KeyStoreItem &operator=(const pkcs11KeyStoreItem &) = delete;

		inline int id () const {
			return _id;
		}

		inline pkcs11h_token_id_t tokenId () const {
			return _token_id;
		}

		void
		registerCertificates (
			const QList<Certificate> &certs
		) {
			foreach (Certificate i, certs) {
				if (std::find (_certs.begin (), _certs.end (), i) == _certs.end ()) {
					_certs += i;
				}
			}
		}

		QMap<QString, QString>
		friendlyNames () {
			const QStringList names = makeFriendlyNames (_certs);
			QMap<QString, QString> friendlyNames;

			for (int i=0;i<names.size ();i++) {
				friendlyNames.insert (certificateHash (_certs[i]), names[i]);
			}

			return friendlyNames;
		}
	};
	int _last_id;
	typedef QList<pkcs11KeyStoreItem *> _stores_t;
	_stores_t _stores;
	QHash<int, pkcs11KeyStoreItem *> _storesById;
	QMutex _mutexStores;
	bool _initialized;

public:
	pkcs11KeyStoreListContext (Provider *p);

	~pkcs11KeyStoreListContext () override;

	Provider::Context *
	clone () const override;

public:
	void
	start () override;

	void
	setUpdatesEnabled (bool enabled) override;

	KeyStoreEntryContext *
	entry (
		int id,
		const QString &entryId
	) override;

	KeyStoreEntryContext *
	entryPassive (
		const QString &serialized
	) override;

	KeyStore::Type
	type (int id) const override;

	QString
	storeId (int id) const override;

	QString
	name (int id) const override;

	QList<KeyStoreEntry::Type>
	entryTypes (int id) const override;

	QList<int>
	keyStores () override;

	QList<KeyStoreEntryContext *>
	entryList (int id) override;

	bool
	_tokenPrompt (
		void * const user_data,
		const pkcs11h_token_id_t token_id
	);

	bool
	_pinPrompt (
		void * const user_data,
		const pkcs11h_token_id_t token_id,
		SecureArray &pin
	);

	void
	_emit_diagnosticText (
		const QString &t
	);

private Q_SLOTS:
	void
	doReady ();

	void
	doUpdated ();

private:
	pkcs11KeyStoreItem *
	_registerTokenId (
		const pkcs11h_token_id_t token_id
	);

	void
	_clearStores ();

	pkcs11KeyStoreEntryContext *
	_keyStoreEntryByCertificateId (
		const pkcs11h_certificate_id_t certificate_id,
		const bool has_private,
		const CertificateChain &chain,
		const QString &description
	) const;

	QString
	_tokenId2storeId (
		const pkcs11h_token_id_t token_id
	) const;

	QString
	_serializeCertificate (
		const pkcs11h_certificate_id_t certificate_id,
		const CertificateChain &chain,
		const bool has_private
	) const;

	void
	_deserializeCertificate (
		const QString &from,
		pkcs11h_certificate_id_t * const p_certificate_id,
		bool * const p_has_private,
		CertificateChain &chain
	) const;

	QString
	_escapeString (
		const QString &from
	) const;

	QString
	_unescapeString (
		const QString &from
	) const;
};

static pkcs11KeyStoreListContext *s_keyStoreList = nullptr;

//----------------------------------------------------------------------------
// pkcs11Exception
//----------------------------------------------------------------------------
class pkcs11Exception {

private:
	CK_RV _rv;
	QString _msg;

private:
	pkcs11Exception () {}

public:
	pkcs11Exception (const CK_RV rv, const QString &msg) {
		_rv = rv;
		_msg = msg;
	}

	CK_RV
	rv () const {
		return _rv;
	}

	QString
	message () const {
		return _msg + QStringLiteral(" ") + QString::fromLatin1(pkcs11h_getMessage (_rv));
	}
};

//----------------------------------------------------------------------------
// pkcs11RSAContext
//----------------------------------------------------------------------------
class pkcs11RSAContext : public RSAContext
{
	Q_OBJECT

private:
	bool _has_privateKeyRole;
	pkcs11h_certificate_id_t _pkcs11h_certificate_id;
	pkcs11h_certificate_t _pkcs11h_certificate;
	RSAPublicKey _pubkey;
	QString _serialized;

	struct _sign_data_s {
		SignatureAlgorithm alg;
		Hash *hash;
		QByteArray raw;

		_sign_data_s() {
			hash = nullptr;
		}
	} _sign_data;

public:
	pkcs11RSAContext (
		Provider *p,
		const pkcs11h_certificate_id_t pkcs11h_certificate_id,
		const QString  &serialized,
		const RSAPublicKey &pubkey
	) : RSAContext (p) {
		CK_RV rv;

		QCA_logTextMessage (
			QStringLiteral("pkcs11RSAContext::pkcs11RSAContext1 - entry"),
			Logger::Debug
		);

		_has_privateKeyRole = true;
		_pkcs11h_certificate_id = nullptr;
		_pkcs11h_certificate = nullptr;
		_pubkey = pubkey;
		_serialized = serialized;
		_clearSign ();

		if (
			(rv = pkcs11h_certificate_duplicateCertificateId (
				&_pkcs11h_certificate_id,
				pkcs11h_certificate_id
			)) != CKR_OK
		) {
			throw pkcs11Exception (rv, QStringLiteral("Memory error"));
		}

		QCA_logTextMessage (
			QStringLiteral("pkcs11RSAContext::pkcs11RSAContext1 - return"),
			Logger::Debug
		);
	}

	pkcs11RSAContext (const pkcs11RSAContext &from) : RSAContext (from.provider ()) {
		CK_RV rv;

		QCA_logTextMessage (
			QStringLiteral("pkcs11RSAContext::pkcs11RSAContextC - entry"),
			Logger::Debug
		);

		_has_privateKeyRole = from._has_privateKeyRole;
		_pkcs11h_certificate_id = nullptr;
		_pkcs11h_certificate = nullptr;
		_pubkey = from._pubkey;
		_serialized = from._serialized;
		_sign_data.hash = nullptr;
		_clearSign ();

		if (
			(rv = pkcs11h_certificate_duplicateCertificateId (
				&_pkcs11h_certificate_id,
				from._pkcs11h_certificate_id
			)) != CKR_OK
		) {
			throw pkcs11Exception (rv, QStringLiteral("Memory error"));
		}

		QCA_logTextMessage (
			QStringLiteral("pkcs11RSAContext::pkcs11RSAContextC - return"),
			Logger::Debug
		);
	}

	~pkcs11RSAContext () override {
		QCA_logTextMessage (
			QStringLiteral("pkcs11RSAContext::~pkcs11RSAContext - entry"),
			Logger::Debug
		);

		_clearSign ();

		if (_pkcs11h_certificate != nullptr) {
			pkcs11h_certificate_freeCertificate (_pkcs11h_certificate);
			_pkcs11h_certificate = nullptr;
		}

		if (_pkcs11h_certificate_id != nullptr) {
			pkcs11h_certificate_freeCertificateId (_pkcs11h_certificate_id);
			_pkcs11h_certificate_id = nullptr;
		}

		QCA_logTextMessage (
			QStringLiteral("pkcs11RSAContext::~pkcs11RSAContext - return"),
			Logger::Debug
		);
	}

	Provider::Context *
	clone () const override {
		return new pkcs11RSAContext (*this);
	}

public:
	bool
	isNull () const override {
		return _pubkey.isNull ();
	}

	PKey::Type
	type () const override {
		return _pubkey.type ();
	}

	bool
	isPrivate () const override {
		return _has_privateKeyRole;
	}

	bool
	canExport () const override {
		return !_has_privateKeyRole;
	}

	void
	convertToPublic () override {
		QCA_logTextMessage (
			QStringLiteral("pkcs11RSAContext::convertToPublic - entry"),
			Logger::Debug
		);

		if (_has_privateKeyRole) {
			if (_pkcs11h_certificate != nullptr) {
				pkcs11h_certificate_freeCertificate (_pkcs11h_certificate);
				_pkcs11h_certificate = nullptr;
			}
			_has_privateKeyRole = false;
		}

		QCA_logTextMessage (
			QStringLiteral("pkcs11RSAContext::convertToPublic - return"),
			Logger::Debug
		);
	}

	int
	bits () const override {
		return _pubkey.bitSize ();
	}

	int
	maximumEncryptSize (
		EncryptionAlgorithm alg
	) const override {
		return _pubkey.maximumEncryptSize (alg);
	}

	SecureArray
	encrypt (
		const SecureArray &in,
		EncryptionAlgorithm alg
	) override {
		return _pubkey.encrypt (in, alg);
	}

	bool
	decrypt (
		const SecureArray &in,
		SecureArray *out,
		EncryptionAlgorithm alg
	) override {
		bool session_locked = false;
		bool ret = false;

		QCA_logTextMessage (
			QString::asprintf (
				"pkcs11RSAContext::decrypt - decrypt in.size()=%d, alg=%d",
				in.size (),
				(int)alg
			),
			Logger::Debug
		);

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
					throw pkcs11Exception (CKR_FUNCTION_NOT_SUPPORTED, QStringLiteral("Invalid algorithm"));
				break;
			}

			_ensureCertificate ();

			if (
				(rv = pkcs11h_certificate_lockSession (
					_pkcs11h_certificate
				)) != CKR_OK
			) {
				throw pkcs11Exception (rv, QStringLiteral("Cannot lock session"));
			}
			session_locked = true;

			if (
				(rv = pkcs11h_certificate_decryptAny (
					_pkcs11h_certificate,
					mech,
					(const unsigned char *)in.constData (),
					in.size (),
					nullptr,
					&my_size
				)) != CKR_OK
			) {
				throw pkcs11Exception (rv, QStringLiteral("Decryption error"));
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
				throw pkcs11Exception (rv, QStringLiteral("Decryption error"));
			}

			rv = out->resize (my_size);

			if (
				(rv = pkcs11h_certificate_releaseSession (
					_pkcs11h_certificate
				)) != CKR_OK
			) {
				throw pkcs11Exception (rv, QStringLiteral("Cannot release session"));
			}
			session_locked = false;

			ret = true;
		}
		catch (const pkcs11Exception &e) {
			if (session_locked) {
				pkcs11h_certificate_releaseSession (
					_pkcs11h_certificate
				);
				session_locked = false;
			}

			if (s_keyStoreList != nullptr) {
				s_keyStoreList->_emit_diagnosticText (
					QString::asprintf (
						"PKCS#11: Cannot decrypt: %lu-'%s'.\n",
						e.rv (),
						myPrintable (e.message ())
					)
				);
			}
		}

		QCA_logTextMessage (
			QString::asprintf (
				"pkcs11RSAContext::decrypt - decrypt out->size()=%d",
				out->size ()
			),
			Logger::Debug
		);

		return ret;
	}

	void
	startSign (
		SignatureAlgorithm alg,
		SignatureFormat
	) override {
		_clearSign ();

		_sign_data.alg = alg;

		switch (_sign_data.alg) {
			case EMSA3_SHA1:
				_sign_data.hash = new Hash(QStringLiteral("sha1"));
			break;
			case EMSA3_MD5:
				_sign_data.hash = new Hash(QStringLiteral("md5"));
			break;
			case EMSA3_MD2:
				_sign_data.hash = new Hash(QStringLiteral("md2"));
			break;
			case EMSA3_Raw:
			break;
			case SignatureUnknown:
			case EMSA1_SHA1:
			case EMSA3_RIPEMD160:
			default:
				QCA_logTextMessage (
					QString::asprintf (
						"PKCS#11: Invalid hash algorithm %d",
						_sign_data.alg
					),
					Logger::Warning
				);
			break;
		}
	}

	void
	startVerify (
		SignatureAlgorithm alg,
		SignatureFormat sf
	) override {
		_pubkey.startVerify (alg, sf);
	}

	void
	update (
		const MemoryRegion &in
	) override {
		if (_has_privateKeyRole) {
			if (_sign_data.hash != nullptr) {
				_sign_data.hash->update (in);
			}
			else {
				_sign_data.raw.append (in.toByteArray ());
			}
		}
		else {
			_pubkey.update (in);
		}
	}

	QByteArray
	endSign () override {
		QByteArray result;
		bool session_locked = false;

		QCA_logTextMessage (
			QStringLiteral("pkcs11RSAContext::endSign - entry"),
			Logger::Debug
		);

		try {
			QByteArray final;
			CK_RV rv;

			// from some strange reason I got 2047... (for some)	<---- BUG?!?!?!
			int myrsa_size=(_pubkey.bitSize () + 7) / 8;

			if (_sign_data.hash != nullptr) {
				final = emsa3Encode (
					_sign_data.hash->type (),
					_sign_data.hash->final ().toByteArray (),
					myrsa_size
				);
			}
			else {
				final = _sign_data.raw;
			}

			if (final.size () == 0) {
				throw pkcs11Exception (CKR_FUNCTION_FAILED, QStringLiteral("Cannot encode signature"));
			}

			_ensureCertificate ();

			size_t my_size;

			if (
				(rv = pkcs11h_certificate_lockSession (
					_pkcs11h_certificate
				)) != CKR_OK
			) {
				throw pkcs11Exception (rv, QStringLiteral("Cannot lock session"));
			}
			session_locked = true;

			if (
				(rv = pkcs11h_certificate_signAny (
					_pkcs11h_certificate,
					CKM_RSA_PKCS,
					(const unsigned char *)final.constData (),
					(size_t)final.size (),
					nullptr,
					&my_size
				)) != CKR_OK
			) {
				throw pkcs11Exception (rv, QStringLiteral("Signature failed"));
			}

			result.resize (my_size);

			if (
				(rv = pkcs11h_certificate_signAny (
					_pkcs11h_certificate,
					CKM_RSA_PKCS,
					(const unsigned char *)final.constData (),
					(size_t)final.size (),
					(unsigned char *)result.data (),
					&my_size
				)) != CKR_OK
			) {
				throw pkcs11Exception (rv, QStringLiteral("Signature failed"));
			}

			result.resize (my_size);

			if (
				(rv = pkcs11h_certificate_releaseSession (
					_pkcs11h_certificate
				)) != CKR_OK
			) {
				throw pkcs11Exception (rv, QStringLiteral("Cannot release session"));
			}
			session_locked = false;

		}
		catch (const pkcs11Exception &e) {
			result.clear ();

			if (session_locked) {
				pkcs11h_certificate_releaseSession (
					_pkcs11h_certificate
				);
				session_locked = false;
			}

			if (s_keyStoreList != nullptr) {
				s_keyStoreList->_emit_diagnosticText (
					QString::asprintf (
						"PKCS#11: Cannot sign: %lu-'%s'.\n",
						e.rv (),
						myPrintable (e.message ())
					)
				);
			}
		}

		_clearSign ();

		QCA_logTextMessage (
			QString::asprintf (
				"pkcs11RSAContext::endSign - return result.size ()=%d",
				result.size ()
			),
			Logger::Debug
		);

		return result;
	}

	virtual
	bool
	validSignature (
		const QByteArray &sig
	) {
		return _pubkey.validSignature (sig);
	}

	void
	createPrivate (
		int bits,
		int exp,
		bool block
	) override {
		Q_UNUSED(bits);
		Q_UNUSED(exp);
		Q_UNUSED(block);
	}

	void
	createPrivate (
		const BigInteger &n,
		const BigInteger &e,
		const BigInteger &p,
		const BigInteger &q,
		const BigInteger &d
	) override {
		Q_UNUSED(n);
		Q_UNUSED(e);
		Q_UNUSED(p);
		Q_UNUSED(q);
		Q_UNUSED(d);
	}

	void
	createPublic (
		const BigInteger &n,
		const BigInteger &e
	) override {
		Q_UNUSED(n);
		Q_UNUSED(e);
	}

	BigInteger
	n () const override {
		return _pubkey.n ();
	}

	BigInteger
	e () const override {
		return _pubkey.e ();
	}

	BigInteger
	p () const override {
		return BigInteger();
	}

	BigInteger
	q () const override {
		return BigInteger();
	}

	BigInteger
	d () const override {
		return BigInteger();
	}

public:
	PublicKey
	_publicKey () const {
		return _pubkey;
	}

	bool
	_isTokenAvailable() const {
		bool ret;

		QCA_logTextMessage (
			QStringLiteral("pkcs11RSAContext::_ensureTokenAvailable - entry"),
			Logger::Debug
		);

		ret = pkcs11h_token_ensureAccess (
			_pkcs11h_certificate_id->token_id,
			nullptr,
			0
		) == CKR_OK;

		QCA_logTextMessage (
			QString::asprintf (
				"pkcs11RSAContext::_ensureTokenAvailable - return ret=%d",
				ret ? 1 : 0
			),
			Logger::Debug
		);

		return ret;
	}

	bool
	_ensureTokenAccess () {
		bool ret;

		QCA_logTextMessage (
			QStringLiteral("pkcs11RSAContext::_ensureTokenAccess - entry"),
			Logger::Debug
		);

		ret = pkcs11h_token_ensureAccess (
			_pkcs11h_certificate_id->token_id,
			nullptr,
			PKCS11H_PROMPT_MASK_ALLOW_ALL
		) == CKR_OK;

		QCA_logTextMessage (
			QString::asprintf (
				"pkcs11RSAContext::_ensureTokenAccess - return ret=%d",
				ret ? 1 : 0
			),
			Logger::Debug
		);

		return ret;
	}

private:
	void
	_clearSign () {
		_sign_data.raw.clear ();
		_sign_data.alg = SignatureUnknown;
		delete _sign_data.hash;
		_sign_data.hash = nullptr;
	}

	void
	_ensureCertificate () {
		CK_RV rv;

		QCA_logTextMessage (
			QStringLiteral("pkcs11RSAContext::_ensureCertificate - entry"),
			Logger::Debug
		);

		if (_pkcs11h_certificate == nullptr) {
			if (
				(rv = pkcs11h_certificate_create (
					_pkcs11h_certificate_id,
					&_serialized,
					PKCS11H_PROMPT_MASK_ALLOW_ALL,
					PKCS11H_PIN_CACHE_INFINITE,
					&_pkcs11h_certificate
				)) != CKR_OK
			) {
				throw pkcs11Exception (rv, QStringLiteral("Cannot create low-level certificate"));
			}
		}

		QCA_logTextMessage (
			QStringLiteral("pkcs11RSAContext::_ensureCertificate - return"),
			Logger::Debug
		);
	}
};

//----------------------------------------------------------------------------
// pkcs11PKeyContext
//----------------------------------------------------------------------------
class pkcs11PKeyContext : public PKeyContext
{
    Q_OBJECT

private:
	PKeyBase *_k;

public:
	pkcs11PKeyContext (Provider *p) : PKeyContext (p) {
		_k = nullptr;
	}

	~pkcs11PKeyContext () override {
		delete _k;
		_k = nullptr;
	}

	Provider::Context *
	clone () const override {
		pkcs11PKeyContext *c = new pkcs11PKeyContext (*this);
		c->_k = (PKeyBase *)_k->clone();
		return c;
	}

public:
	QList<PKey::Type>
	supportedTypes () const override {
		QList<PKey::Type> list;
		list += PKey::RSA;
		return list;
	}

	QList<PKey::Type>
	supportedIOTypes () const override {
		QList<PKey::Type> list;
		list += PKey::RSA;
		return list;
	}

	QList<PBEAlgorithm>
	supportedPBEAlgorithms () const override {
		QList<PBEAlgorithm> list;
		return list;
	}

	PKeyBase *
	key () override {
		return _k;
	}

	const PKeyBase *
	key () const override {
		return _k;
	}

	void
	setKey (PKeyBase *key) override {
		delete _k;
		_k = key;
	}

	bool
	importKey (
		const PKeyBase *key
	) override {
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

	QByteArray
	publicToDER () const override {
		return static_cast<pkcs11RSAContext *>(_k)->_publicKey ().toDER ();
	}

	QString
	publicToPEM () const override {
		return static_cast<pkcs11RSAContext *>(_k)->_publicKey ().toPEM ();
	}

	ConvertResult
	publicFromDER (
		const QByteArray &in
	) override {
		Q_UNUSED(in);
		return ErrorDecode;
	}

	ConvertResult
	publicFromPEM (
		const QString &s
	) override {
		Q_UNUSED(s);
		return ErrorDecode;
	}

	SecureArray
	privateToDER(
		const SecureArray &passphrase,
		PBEAlgorithm pbe
	) const override {
		Q_UNUSED(passphrase);
		Q_UNUSED(pbe);
		return SecureArray ();
	}

	QString
	privateToPEM (
		const SecureArray &passphrase,
		PBEAlgorithm pbe
	) const override {
		Q_UNUSED(passphrase);
		Q_UNUSED(pbe);
		return QString ();
	}

	ConvertResult
	privateFromDER (
		const SecureArray &in,
		const SecureArray &passphrase
	) override {
		Q_UNUSED(in);
		Q_UNUSED(passphrase);
		return ErrorDecode;
	}

	ConvertResult
	privateFromPEM (
		const QString &s,
		const SecureArray &passphrase
	) override {
		Q_UNUSED(s);
		Q_UNUSED(passphrase);
		return ErrorDecode;
	}
};

//----------------------------------------------------------------------------
// pkcs11KeyStoreEntryContext
//----------------------------------------------------------------------------
class pkcs11KeyStoreEntryContext : public KeyStoreEntryContext
{
    Q_OBJECT
private:
	KeyStoreEntry::Type _item_type;
	KeyBundle _key;
	Certificate _cert;
	QString _storeId;
	QString _id;
	QString _serialized;
	QString _storeName;
	QString _name;

public:
	pkcs11KeyStoreEntryContext (
		const Certificate &cert,
		const QString &storeId,
		const QString &serialized,
		const QString &storeName,
		const QString &name,
		Provider *p
	) : KeyStoreEntryContext(p) {
		_item_type = KeyStoreEntry::TypeCertificate;
		_cert = cert;
		_storeId = storeId;
		_id = certificateHash (_cert);
		_serialized = serialized;
		_storeName = storeName;
		_name = name;
	}

	pkcs11KeyStoreEntryContext (
		const KeyBundle &key,
		const QString &storeId,
		const QString &serialized,
		const QString &storeName,
		const QString &name,
		Provider *p
	) : KeyStoreEntryContext(p) {
		_item_type = KeyStoreEntry::TypeKeyBundle;
		_key = key;
		_storeId = storeId,
		_id = certificateHash (key.certificateChain ().primary ());
		_serialized = serialized;
		_storeName = storeName;
		_name = name;
	}

	pkcs11KeyStoreEntryContext (
		const pkcs11KeyStoreEntryContext &from
	) : KeyStoreEntryContext(from) {
		_item_type = from._item_type;
		_key = from._key;
		_storeId = from._storeId;
		_id = from._id;
		_serialized = from._serialized;
		_storeName = from._storeName;
		_name = from._name;
	}

	Provider::Context *
	clone () const override {
		return new pkcs11KeyStoreEntryContext (*this);
	}

public:
	KeyStoreEntry::Type
	type () const override {
		return _item_type;
	}

	QString
	name () const override {
		return _name;
	}

	QString
	id () const override {
		return _id;
	}

	KeyBundle
	keyBundle () const override {
		return _key;
	}

	Certificate
	certificate () const override {
		return _cert;
	}

	QString
	storeId () const override {
		return _storeId;
	}

	QString
	storeName () const override {
		return _storeName;
	}

	bool
	isAvailable() const override {
		return static_cast<pkcs11RSAContext *>(static_cast<PKeyContext *>(_key.privateKey ().context ())->key ())->_isTokenAvailable ();
	}

	bool
	ensureAccess () override {
		return static_cast<pkcs11RSAContext *>(static_cast<PKeyContext *>(_key.privateKey ().context ())->key ())->_ensureTokenAccess ();
	}

	QString
	serialize () const override {
		return _serialized;
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

		return TRUE; //krazy:exclude=captruefalse
	}

	static
	int
	_pkcs11h_crypto_qca_uninitialize (
		void * const global_data
	) {
		Q_UNUSED(global_data);

		return TRUE; //krazy:exclude=captruefalse
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

		return TRUE; //krazy:exclude=captruefalse
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
		QString qdn = cert.subjectInfoOrdered ().toString ();

		if ((size_t)qdn.length () > dn_max-1) {
			return FALSE; //krazy:exclude=captruefalse
		}
		else {
			qstrcpy (dn, myPrintable (qdn));
			return TRUE; //krazy:exclude=captruefalse
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
	nullptr,
	_pkcs11h_crypto_qca_initialize,
	_pkcs11h_crypto_qca_uninitialize,
	_pkcs11h_crypto_qca_certificate_get_expiration,
	_pkcs11h_crypto_qca_certificate_get_dn,
	_pkcs11h_crypto_qca_certificate_is_issuer
};

//----------------------------------------------------------------------------
// pkcs11KeyStoreListContext
//----------------------------------------------------------------------------
pkcs11KeyStoreListContext::pkcs11KeyStoreListContext (Provider *p) : KeyStoreListContext(p) {
	QCA_logTextMessage (
		QString::asprintf (
			"pkcs11KeyStoreListContext::pkcs11KeyStoreListContext - entry Provider=%p",
			(void *)p
		),
		Logger::Debug
	);

	_last_id = 0;
	_initialized = false;

	QCA_logTextMessage (
		QStringLiteral("pkcs11KeyStoreListContext::pkcs11KeyStoreListContext - return"),
		Logger::Debug
	);
}

pkcs11KeyStoreListContext::~pkcs11KeyStoreListContext () {
	QCA_logTextMessage (
		QStringLiteral("pkcs11KeyStoreListContext::~pkcs11KeyStoreListContext - entry"),
		Logger::Debug
	);

	s_keyStoreList = nullptr;
	_clearStores ();

	QCA_logTextMessage (
		QStringLiteral("pkcs11KeyStoreListContext::~pkcs11KeyStoreListContext - return"),
		Logger::Debug
	);
}

Provider::Context *
pkcs11KeyStoreListContext::clone () const {
	QCA_logTextMessage (
		QStringLiteral("pkcs11KeyStoreListContext::clone - entry/return"),
		Logger::Debug
	);
	return nullptr;
}

void
pkcs11KeyStoreListContext::start () {
	QCA_logTextMessage (
		QStringLiteral("pkcs11KeyStoreListContext::start - entry"),
		Logger::Debug
	);

	QMetaObject::invokeMethod(this, "doReady", Qt::QueuedConnection);

	QCA_logTextMessage (
		QStringLiteral("pkcs11KeyStoreListContext::start - return"),
		Logger::Debug
	);
}

void
pkcs11KeyStoreListContext::setUpdatesEnabled (bool enabled) {
	QCA_logTextMessage (
		QString::asprintf (
			"pkcs11KeyStoreListContext::setUpdatesEnabled - entry enabled=%d",
			enabled ? 1 : 0
		),
		Logger::Debug
	);

	try {
		pkcs11Provider *p = static_cast<pkcs11Provider *>(provider ());
		if (enabled) {
			p->startSlotEvents ();
		}
		else {
			p->stopSlotEvents ();
		}
	}
	catch (const pkcs11Exception &e) {
		s_keyStoreList->_emit_diagnosticText (
			QString::asprintf (
				"PKCS#11: Start event failed %lu-'%s'.\n",
				e.rv (),
				myPrintable (e.message ())
			)
		);
	}

	QCA_logTextMessage (
		QStringLiteral("pkcs11KeyStoreListContext::setUpdatesEnabled - return"),
		Logger::Debug
	);
}

KeyStoreEntryContext *
pkcs11KeyStoreListContext::entry (
	int id,
	const QString &entryId
) {
	QCA_logTextMessage (
		QString::asprintf (
			"pkcs11KeyStoreListContext::entry - entry/return id=%d entryId='%s'",
			id,
			myPrintable (entryId)
		),
		Logger::Debug
	);

	Q_UNUSED(id);
	Q_UNUSED(entryId);
	return nullptr;
}

KeyStoreEntryContext *
pkcs11KeyStoreListContext::entryPassive (
	const QString &serialized
) {
	KeyStoreEntryContext *entry = nullptr;
	pkcs11h_certificate_id_t certificate_id = nullptr;

	QCA_logTextMessage (
		QString::asprintf (
			"pkcs11KeyStoreListContext::entryPassive - entry serialized='%s'",
			myPrintable (serialized)
		),
		Logger::Debug
	);

	try {
		if (serialized.startsWith (QLatin1String("qca-pkcs11/"))) {
			CertificateChain chain;
			bool has_private;

			_deserializeCertificate (serialized, &certificate_id, &has_private, chain);
			pkcs11KeyStoreItem *sentry = _registerTokenId (certificate_id->token_id);
			sentry->registerCertificates (chain);
			QMap<QString, QString> friendlyNames = sentry->friendlyNames ();

			entry = _keyStoreEntryByCertificateId (
				certificate_id,
				has_private,
				chain,
				friendlyNames[certificateHash (chain.primary ())]
			);
		}
	}
	catch (const pkcs11Exception &e) {
		s_keyStoreList->_emit_diagnosticText (
			QString::asprintf (
				"PKCS#11: Add key store entry %lu-'%s'.\n",
				e.rv (),
				myPrintable (e.message ())
			)
		);
	}

	if (certificate_id != nullptr) {
		pkcs11h_certificate_freeCertificateId (certificate_id);
		certificate_id = nullptr;
	}

	QCA_logTextMessage (
		QString::asprintf (
			"pkcs11KeyStoreListContext::entryPassive - return entry=%p",
			(void *)entry
		),
		Logger::Debug
	);

	return entry;
}

KeyStore::Type
pkcs11KeyStoreListContext::type (int id) const {

	Q_UNUSED(id);

	QCA_logTextMessage (
		QString::asprintf (
			"pkcs11KeyStoreListContext::type - entry/return id=%d",
			id
		),
		Logger::Debug
	);

	return KeyStore::SmartCard;
}

QString
pkcs11KeyStoreListContext::storeId (int id) const {
	QString ret;

	QCA_logTextMessage (
		QString::asprintf (
			"pkcs11KeyStoreListContext::storeId - entry id=%d",
			id
		),
		Logger::Debug
	);

	if (_storesById.contains (id)) {
		ret = _tokenId2storeId (_storesById[id]->tokenId ());
	}

	QCA_logTextMessage (
		QString::asprintf (
			"pkcs11KeyStoreListContext::storeId - return ret=%s",
			myPrintable (ret)
		),
		Logger::Debug
	);

	return ret;
}

QString
pkcs11KeyStoreListContext::name (int id) const {
	QString ret;

	QCA_logTextMessage (
		QString::asprintf (
			"pkcs11KeyStoreListContext::name - entry id=%d",
			id
		),
		Logger::Debug
	);

	if (_storesById.contains (id)) {
		ret = QString::fromLatin1(_storesById[id]->tokenId ()->label);
	}

	QCA_logTextMessage (
		QString::asprintf (
			"pkcs11KeyStoreListContext::name - return ret=%s",
			myPrintable (ret)
		),
		Logger::Debug
	);

	return ret;
}

QList<KeyStoreEntry::Type>
pkcs11KeyStoreListContext::entryTypes (int id) const {

	Q_UNUSED(id);

	QCA_logTextMessage (
		QString::asprintf (
			"pkcs11KeyStoreListContext::entryTypes - entry/return id=%d",
			id
		),
		Logger::Debug
	);

	QList<KeyStoreEntry::Type> list;
	list += KeyStoreEntry::TypeKeyBundle;
	list += KeyStoreEntry::TypeCertificate;
	return list;
}

QList<int>
pkcs11KeyStoreListContext::keyStores () {
	pkcs11h_token_id_list_t tokens = nullptr;
	QList<int> out;

	QCA_logTextMessage (
		QStringLiteral("pkcs11KeyStoreListContext::keyStores - entry"),
		Logger::Debug
	);

	try {
		CK_RV rv;

		/*
		 * Get available tokens
		 */
		if (
			(rv = pkcs11h_token_enumTokenIds (
				PKCS11H_ENUM_METHOD_CACHE_EXIST,
				&tokens
			)) != CKR_OK
		) {
			throw pkcs11Exception (rv, QStringLiteral("Enumerating tokens"));
		}

		/*
		 * Register all tokens, unmark
		 * them from remove list
		 */
		QList<int> to_remove = _storesById.keys ();
		for (
			pkcs11h_token_id_list_t entry = tokens;
			entry != nullptr;
			entry = entry->next
		) {
			pkcs11KeyStoreItem *item = _registerTokenId (entry->token_id);
			out += item->id ();
			to_remove.removeAll (item->id ());
		}

		/*
		 * Remove all items
		 * that were not discovered
		 */
		{
			QMutexLocker l(&_mutexStores);

			foreach (int i, to_remove) {
				pkcs11KeyStoreItem *item = _storesById[i];

				_storesById.remove (item->id ());
				_stores.removeAll (item);

				delete item;
				item = nullptr;
			}
		}
	}
	catch (const pkcs11Exception &e) {
		s_keyStoreList->_emit_diagnosticText (
			QString::asprintf (
				"PKCS#11: Cannot get key stores: %lu-'%s'.\n",
				e.rv (),
				myPrintable (e.message ())
			)
		);
	}

	if (tokens != nullptr) {
		pkcs11h_token_freeTokenIdList (tokens);
	}

	QCA_logTextMessage (
		QString::asprintf (
			"pkcs11KeyStoreListContext::keyStores - return out.size()=%d",
			out.size ()
		),
		Logger::Debug
	);

	return out;
}

QList<KeyStoreEntryContext*>
pkcs11KeyStoreListContext::entryList (int id) {
	pkcs11h_certificate_id_list_t certs = nullptr;
	QList<KeyStoreEntryContext*> out;

	QCA_logTextMessage (
		QString::asprintf (
			"pkcs11KeyStoreListContext::entryList - entry id=%d",
			id
		),
		Logger::Debug
	);

	try {
		CK_RV rv;

		if (_storesById.contains (id)) {
			pkcs11KeyStoreItem *entry = _storesById[id];

			pkcs11h_certificate_id_list_t issuers = nullptr;
			pkcs11h_certificate_id_list_t current = nullptr;
			QList<Certificate> listCerts;
			QList<Certificate> listIssuers;
			int i = 0;

			if (
				(rv = pkcs11h_certificate_enumTokenCertificateIds (
					entry->tokenId (),
					PKCS11H_ENUM_METHOD_CACHE,
					nullptr,
					PKCS11H_PROMPT_MASK_ALLOW_ALL,
					&issuers,
					&certs
				)) != CKR_OK
			) {
				throw pkcs11Exception (rv, QStringLiteral("Enumerate certificates"));
			}

			for (
				current=certs;
				current!=nullptr;
				current=current->next
			) {
				if (current->certificate_id->certificate_blob_size > 0) {
					listCerts += Certificate::fromDER (
						QByteArray (
							(char *)current->certificate_id->certificate_blob,
							current->certificate_id->certificate_blob_size
						)
					);
				}
			}

			for (
				current=issuers;
				current!=nullptr;
				current=current->next
			) {
				if (current->certificate_id->certificate_blob_size > 0) {
					listIssuers += Certificate::fromDER (
						QByteArray (
							(char *)current->certificate_id->certificate_blob,
							current->certificate_id->certificate_blob_size
						)
					);
				}
			}

			entry->registerCertificates (listIssuers + listCerts);
			QMap<QString, QString> friendlyNames = entry->friendlyNames ();

			QList<Certificate> listIssuersForComplete;
			if (dynamic_cast<pkcs11Provider *> (provider ())->_allowLoadRootCA) {
				listIssuersForComplete = listIssuers;
			}
			else {
				foreach (Certificate c, listIssuers) {
					if (!c.isSelfSigned ()) {
						listIssuersForComplete += c;
					}
				}
			}

			for (
				i=0, current=issuers;
				current!=nullptr;
				i++, current=current->next
			) {
				try {
					if (listIssuers[i].isNull ()) {
						throw pkcs11Exception (CKR_ARGUMENTS_BAD, QStringLiteral("Invalid certificate"));
					}

					if (
						listIssuers[i].isSelfSigned () &&
						dynamic_cast<pkcs11Provider *> (provider ())->_allowLoadRootCA
					) {
						CertificateChain chain = CertificateChain (listIssuers[i]).complete (listIssuersForComplete);
						out += _keyStoreEntryByCertificateId (
							current->certificate_id,
							false,
							chain,
							friendlyNames[certificateHash (chain.primary ())]
						);
					}
				}
				catch (const pkcs11Exception &e) {
					s_keyStoreList->_emit_diagnosticText (
						QString::asprintf (
							"PKCS#11: Add key store entry %lu-'%s'.\n",
							e.rv (),
							myPrintable (e.message ())
						)
					);
				}
			}

			for (
				i=0, current=certs;
				current!=nullptr;
				i++, current=current->next
			) {
				try {
					if (listCerts[i].isNull ()) {
						throw pkcs11Exception (CKR_ARGUMENTS_BAD, QStringLiteral("Invalid certificate"));
					}

					CertificateChain chain = CertificateChain (listCerts[i]).complete (listIssuersForComplete);
					out += _keyStoreEntryByCertificateId (
						current->certificate_id,
						true,
						chain,
						friendlyNames[certificateHash (chain.primary ())]
					);
				}
				catch (const pkcs11Exception &e) {
					s_keyStoreList->_emit_diagnosticText (
						QString::asprintf (
							"PKCS#11: Add key store entry %lu-'%s'.\n",
							e.rv (),
							myPrintable (e.message ())
						)
					);
				}
			}
		}
	}
	catch (const pkcs11Exception &e) {
		s_keyStoreList->_emit_diagnosticText (
			QString::asprintf (
				"PKCS#11: Enumerating store failed %lu-'%s'.\n",
				e.rv (),
				myPrintable (e.message ())
			)
		);
	}

	if (certs != nullptr) {
		pkcs11h_certificate_freeCertificateIdList (certs);
	}

	QCA_logTextMessage (
		QString::asprintf (
			"pkcs11KeyStoreListContext::entryList - return out.size()=%d",
			out.size ()
		),
		Logger::Debug
	);

	return out;
}

bool
pkcs11KeyStoreListContext::_tokenPrompt (
	void * const user_data,
	const pkcs11h_token_id_t token_id
) {
	KeyStoreEntry entry;
	KeyStoreEntryContext *context = nullptr;
	QString storeId, storeName;
	bool ret = false;

	QCA_logTextMessage (
		QString::asprintf (
			"pkcs11KeyStoreListContext::_tokenPrompt - entry user_data=%p, token_id=%p",
			user_data,
			(void *)token_id
		),
		Logger::Debug
	);

	if (user_data != nullptr) {
		QString *serialized = (QString *)user_data;
		context = entryPassive (*serialized);
		storeId = context->storeId ();
		storeName = context->storeName ();
		entry.change (context);
	}
	else {
		_registerTokenId (token_id);
		storeId = _tokenId2storeId (token_id);
		storeName = QString::fromLatin1(token_id->label);
	}

	TokenAsker asker;
	asker.ask (
		KeyStoreInfo (KeyStore::SmartCard, storeId, storeName),
		entry,
		context
	);
	asker.waitForResponse ();
	if (asker.accepted ()) {
		ret = true;
	}

	QCA_logTextMessage (
		QString::asprintf (
			"pkcs11KeyStoreListContext::_tokenPrompt - return ret=%d",
			ret ? 1 : 0
		),
		Logger::Debug
	);

	return ret;
}

bool
pkcs11KeyStoreListContext::_pinPrompt (
	void * const user_data,
	const pkcs11h_token_id_t token_id,
	SecureArray &pin
) {
	KeyStoreEntry entry;
	KeyStoreEntryContext *context = nullptr;
	QString storeId, storeName;
	bool ret = false;

	QCA_logTextMessage (
		QString::asprintf (
			"pkcs11KeyStoreListContext::_pinPrompt - entry user_data=%p, token_id=%p",
			user_data,
			(void *)token_id
		),
		Logger::Debug
	);

	pin = SecureArray();

	if (user_data != nullptr) {
		QString *serialized = (QString *)user_data;
		context = entryPassive (*serialized);
		storeId = context->storeId ();
		storeName = context->storeName ();
		entry.change (context);
	}
	else {
		_registerTokenId (token_id);
		storeId = _tokenId2storeId (token_id);
		storeName = QString::fromLatin1(token_id->label);
	}

	PasswordAsker asker;
	asker.ask (
		Event::StylePIN,
		KeyStoreInfo (KeyStore::SmartCard, storeId, storeName),
		entry,
		context
	);
	asker.waitForResponse ();
	if (asker.accepted ()) {
		ret = true;
		pin = asker.password ();
	}

	QCA_logTextMessage (
		QString::asprintf (
			"pkcs11KeyStoreListContext::_pinPrompt - return ret=%d",
			ret ? 1 : 0
		),
		Logger::Debug
	);

	return ret;
}

void
pkcs11KeyStoreListContext::_emit_diagnosticText (
	const QString &t
) {
	QCA_logTextMessage (
		QString::asprintf (
			"pkcs11KeyStoreListContext::_emit_diagnosticText - entry t='%s'",
			myPrintable (t)
		),
		Logger::Debug
	);

	QCA_logTextMessage (t, Logger::Warning);

	emit diagnosticText (t);

	QCA_logTextMessage (
		QStringLiteral("pkcs11KeyStoreListContext::_emit_diagnosticText - return"),
		Logger::Debug
	);
}

void
pkcs11KeyStoreListContext::doReady () {
	QCA_logTextMessage (
		QStringLiteral("pkcs11KeyStoreListContext::doReady - entry"),
		Logger::Debug
	);

	emit busyEnd ();

	QCA_logTextMessage (
		QStringLiteral("pkcs11KeyStoreListContext::doReady - return"),
		Logger::Debug
	);
}

void
pkcs11KeyStoreListContext::doUpdated () {
	QCA_logTextMessage (
		QStringLiteral("pkcs11KeyStoreListContext::doUpdated - entry"),
		Logger::Debug
	);

	emit updated ();

	QCA_logTextMessage (
		QStringLiteral("pkcs11KeyStoreListContext::doUpdated - return"),
		Logger::Debug
	);
}

pkcs11KeyStoreListContext::pkcs11KeyStoreItem *
pkcs11KeyStoreListContext::_registerTokenId (
	const pkcs11h_token_id_t token_id
) {
	QCA_logTextMessage (
		QString::asprintf (
			"pkcs11KeyStoreListContext::_registerTokenId - entry token_id=%p",
			(void *)token_id
		),
		Logger::Debug
	);

	QMutexLocker l(&_mutexStores);

	_stores_t::iterator i=_stores.begin ();

	while (
		i != _stores.end () &&
		!pkcs11h_token_sameTokenId (
			token_id,
			(*i)->tokenId ()
		)
	) {
		i++;
	}

	pkcs11KeyStoreItem *entry = nullptr;

	if (i == _stores.end ()) {
		/*
		 * Deal with last_id overlap
		 */
		while (_storesById.find (++_last_id) != _storesById.end ());

		entry = new pkcs11KeyStoreItem (_last_id, token_id);

		_stores += entry;
		_storesById.insert (entry->id (), entry);
	}
	else {
		entry = (*i);
	}

	QCA_logTextMessage (
		QString::asprintf (
			"pkcs11KeyStoreListContext::_registerTokenId - return entry=%p",
			(void *)token_id
		),
		Logger::Debug
	);

	return entry;
}

void
pkcs11KeyStoreListContext::_clearStores () {
	QCA_logTextMessage (
		QStringLiteral("pkcs11KeyStoreListContext::_clearStores - entry"),
		Logger::Debug
	);

	QMutexLocker l(&_mutexStores);

	_storesById.clear ();
	foreach (pkcs11KeyStoreItem *i, _stores) {
		delete i;
	}

	_stores.clear ();

	QCA_logTextMessage (
		QStringLiteral("pkcs11KeyStoreListContext::_clearStores - return"),
		Logger::Debug
	);
}

pkcs11KeyStoreEntryContext *
pkcs11KeyStoreListContext::_keyStoreEntryByCertificateId (
	const pkcs11h_certificate_id_t certificate_id,
	const bool has_private,
	const CertificateChain &chain,
	const QString &_description
) const {
	pkcs11KeyStoreEntryContext *entry = nullptr;

	QCA_logTextMessage (
		QString::asprintf (
			"pkcs11KeyStoreListContext::_keyStoreEntryByCertificateId - entry certificate_id=%p, has_private=%d, chain.size()=%d",
			(void *)certificate_id,
			has_private ? 1 : 0,
			chain.size ()
		),
		Logger::Debug
	);

	if (certificate_id == nullptr) {
		throw pkcs11Exception (CKR_ARGUMENTS_BAD, QStringLiteral("Missing certificate object"));
	}

	QString serialized = _serializeCertificate (
		certificate_id,
		chain,
		has_private
	);

	QString description = _description;
	const Certificate &cert = chain.primary ();
	if (description.isEmpty ()) {
		description = cert.subjectInfoOrdered ().toString () + QStringLiteral(" by ") + cert.issuerInfo ().value (CommonName, QStringLiteral("Unknown"));
	}

	if (has_private) {
		pkcs11RSAContext *rsakey = new pkcs11RSAContext (
			provider(),
			certificate_id,
			serialized,
			cert.subjectPublicKey ().toRSA ()
		);

		pkcs11PKeyContext *pkc = new pkcs11PKeyContext (provider ());
		pkc->setKey (rsakey);
		PrivateKey privkey;
		privkey.change (pkc);
		KeyBundle key;
		key.setCertificateChainAndKey (
			chain,
			privkey
		);

		entry = new pkcs11KeyStoreEntryContext (
			key,
			_tokenId2storeId (certificate_id->token_id),
			serialized,
			QString::fromLatin1(certificate_id->token_id->label),
			description,
			provider ()
		);
	}
	else {
		entry = new pkcs11KeyStoreEntryContext (
			cert,
			_tokenId2storeId (certificate_id->token_id),
			serialized,
			QString::fromLatin1(certificate_id->token_id->label),
			description,
			provider()
		);
	}

	QCA_logTextMessage (
		QString::asprintf (
			"pkcs11KeyStoreListContext::_keyStoreEntryByCertificateId - return entry=%p",
			(void *)entry
		),
		Logger::Debug
	);

	return entry;
}

QString
pkcs11KeyStoreListContext::_tokenId2storeId (
	const pkcs11h_token_id_t token_id
) const {
	QString storeId;
	size_t len;

	QCA_logTextMessage (
		QString::asprintf (
			"pkcs11KeyStoreListContext::_tokenId2storeId - entry token_id=%p",
			(void *)token_id
		),
		Logger::Debug
	);

	if (
		pkcs11h_token_serializeTokenId (
			nullptr,
			&len,
			token_id
		) != CKR_OK
	) {
		throw pkcs11Exception (CKR_FUNCTION_FAILED, QStringLiteral("Cannot serialize token id"));
	}

	QByteArray buf;
	buf.resize ((int)len);

	if (
		pkcs11h_token_serializeTokenId (
			buf.data (),
			&len,
			token_id
		) != CKR_OK
	) {
		throw pkcs11Exception (CKR_FUNCTION_FAILED, QStringLiteral("Cannot serialize token id"));
	}

	buf.resize ((int)len);

	storeId = QStringLiteral("qca-pkcs11/") + _escapeString (QString::fromUtf8 (buf));

	QCA_logTextMessage (
		QString::asprintf (
			"pkcs11KeyStoreListContext::_tokenId2storeId - return storeId='%s'",
			myPrintable (storeId)
		),
		Logger::Debug
	);

	return storeId;
}

QString
pkcs11KeyStoreListContext::_serializeCertificate (
	const pkcs11h_certificate_id_t certificate_id,
	const CertificateChain &chain,
	const bool has_private
) const {
	QString serialized;
	size_t len;

	QCA_logTextMessage (
		QString::asprintf (
			"pkcs11KeyStoreListContext::_serializeCertificate - entry certificate_id=%p, xx, has_private=%d",
			(void *)certificate_id,
			has_private ? 1 : 0
		),
		Logger::Debug
	);

	if (
		pkcs11h_certificate_serializeCertificateId (
			nullptr,
			&len,
			certificate_id
		) != CKR_OK
	) {
		throw pkcs11Exception (CKR_FUNCTION_FAILED, QStringLiteral("Cannot serialize certificate id"));
	}

	QByteArray buf;
	buf.resize ((int)len);

	if (
		pkcs11h_certificate_serializeCertificateId (
			buf.data (),
			&len,
			certificate_id
		) != CKR_OK
	) {
		throw pkcs11Exception (CKR_FUNCTION_FAILED, QStringLiteral("Cannot serialize certificate id"));
	}

	buf.resize ((int)len);

	serialized = QString::asprintf (
		"qca-pkcs11/0/%s/%d/",
		myPrintable(_escapeString (QString::fromUtf8 (buf))),
		has_private ? 1 : 0
	);

	QStringList list;
	foreach (Certificate i, chain) {
		list += _escapeString (Base64 ().arrayToString (i.toDER ()));
	}

	serialized.append (list.join (QStringLiteral("/")));

	QCA_logTextMessage (
		QString::asprintf (
			"pkcs11KeyStoreListContext::_serializeCertificate - return serialized='%s'",
			myPrintable (serialized)
		),
		Logger::Debug
	);

	return serialized;
}

void
pkcs11KeyStoreListContext::_deserializeCertificate (
	const QString &from,
	pkcs11h_certificate_id_t * const p_certificate_id,
	bool * const p_has_private,
	CertificateChain &chain
) const {
	pkcs11h_certificate_id_t certificate_id = nullptr;
	chain.clear ();

	QCA_logTextMessage (
		QString::asprintf (
			"pkcs11KeyStoreListContext::_deserializeCertificate - entry from='%s', p_certificate_id=%p, p_has_private=%p",
			myPrintable (from),
			(void *)p_certificate_id,
			(void *)p_has_private
		),
		Logger::Debug
	);

	try {
		int n = 0;
		CK_RV rv;

		*p_certificate_id = nullptr;
		*p_has_private = false;

		const QStringList list = from.split (QStringLiteral("/"));

		if (list.size () < 5) {
			throw pkcs11Exception (CKR_FUNCTION_FAILED, QStringLiteral("Invalid serialization"));
		}

		if (list[n++] != QLatin1String("qca-pkcs11")) {
			throw pkcs11Exception (CKR_FUNCTION_FAILED, QStringLiteral("Invalid serialization"));
		}

		if (list[n++].toInt () != 0) {
			throw pkcs11Exception (CKR_FUNCTION_FAILED, QStringLiteral("Invalid serialization version"));
		}

		if (
			(rv = pkcs11h_certificate_deserializeCertificateId (
				&certificate_id,
				myPrintable (_unescapeString (list[n++]))
			)) != CKR_OK
		) {
			throw pkcs11Exception (rv, QStringLiteral("Invalid serialization"));
		}

		*p_has_private = list[n++].toInt () != 0;

		const QByteArray endCertificateBytes = Base64 ().stringToArray (_unescapeString (list[n++])).toByteArray ();
		Certificate endCertificate = Certificate::fromDER (endCertificateBytes);

		if (endCertificate.isNull ()) {
			throw pkcs11Exception (rv, QStringLiteral("Invalid certificate"));
		}

		if (
			(rv = pkcs11h_certificate_setCertificateIdCertificateBlob (
				certificate_id,
				(const unsigned char *)endCertificateBytes.data (),
				(size_t)endCertificateBytes.size ()
			)) != CKR_OK
		) {
			throw pkcs11Exception (rv, QStringLiteral("Invalid serialization"));
		}

		chain = endCertificate;
		while (n < list.size ()) {
			Certificate cert = Certificate::fromDER (
				Base64 ().stringToArray (_unescapeString (list[n++])).toByteArray ()
			);
			if (cert.isNull ()) {
				throw pkcs11Exception (rv, QStringLiteral("Invalid certificate"));
			}
			chain += cert;
		}

		*p_certificate_id = certificate_id;
		certificate_id = nullptr;
	}
	catch (...) {
		if (certificate_id != nullptr) {
			pkcs11h_certificate_freeCertificateId (certificate_id);
			certificate_id = nullptr;
		}
		throw;
	}

	QCA_logTextMessage (
		QString::asprintf (
			"pkcs11KeyStoreListContext::_deserializeCertificate - return *p_certificate_id=%p, chain.size()=%d",
			(void *)*p_certificate_id,
			chain.size ()
		),
		Logger::Debug
	);
}

QString
pkcs11KeyStoreListContext::_escapeString (
	const QString &from
) const {
	QString to;

	foreach (QChar c, from) {
		if (c == QLatin1Char('/') || c == QLatin1Char('\\')) {
			to += QString::asprintf ("\\x%04x", c.unicode ());
		}
		else {
			to += c;
		}
	}

	return to;
}

QString
pkcs11KeyStoreListContext::_unescapeString (
	const QString &from
) const {
	QString to;

	for (int i=0;i<from.size ();i++) {
		QChar c = from[i];

		if (c == QLatin1Char('\\')) {
			to += QChar ((ushort)from.midRef (i+2, 4).toInt (nullptr, 16));
			i+=5;
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

	QCA_logTextMessage (
		QStringLiteral("pkcs11Provider::pkcs11Provider - entry"),
		Logger::Debug
	);

	_lowLevelInitialized = false;
	_slotEventsActive = false;
	_slotEventsLowLevelActive = false;
	_allowLoadRootCA = false;

	QCA_logTextMessage (
		QStringLiteral("pkcs11Provider::pkcs11Provider - return"),
		Logger::Debug
	);
}

pkcs11Provider::~pkcs11Provider () {
	QCA_logTextMessage (
		QStringLiteral("pkcs11Provider::~pkcs11Provider - entry/return"),
		Logger::Debug
	);
}

int pkcs11Provider::qcaVersion() const
{
	QCA_logTextMessage (
		QStringLiteral("pkcs11Provider::qcaVersion - entry/return"),
		Logger::Debug
	);

	return QCA_VERSION;
}

void pkcs11Provider::init () {
	QCA_logTextMessage (
		QStringLiteral("pkcs11Provider::init - entry"),
		Logger::Debug
	);

	try {
		CK_RV rv;

		if ((rv = pkcs11h_engine_setCrypto (&pkcs11QCACrypto::crypto)) != CKR_OK) {
			throw pkcs11Exception (rv, QStringLiteral("Cannot set crypto"));
		}

		if ((rv = pkcs11h_initialize ()) != CKR_OK) {
			throw pkcs11Exception (rv, QStringLiteral("Cannot initialize"));
		}

		if (
			(rv = pkcs11h_setLogHook (
				__logHook,
				this
			)) != CKR_OK
		) {
			throw pkcs11Exception (rv, QStringLiteral("Cannot set hook"));
		}

		pkcs11h_setLogLevel (0);

		if (
			(rv = pkcs11h_setTokenPromptHook (
				__tokenPromptHook,
				this
			)) != CKR_OK
		) {
			throw pkcs11Exception (rv, QStringLiteral("Cannot set hook"));
		}

		if (
			(rv = pkcs11h_setPINPromptHook (
				__pinPromptHook,
				this
			)) != CKR_OK
		) {
			throw pkcs11Exception (rv, QStringLiteral("Cannot set hook"));
		}

		_lowLevelInitialized = true;
	}
	catch (const pkcs11Exception &e) {
		QCA_logTextMessage (e.message (), Logger::Error);
		appendPluginDiagnosticText (
			QString::asprintf (
				"An error %s during initialization of qca-pkcs11 plugin\n",
				myPrintable (e.message ())
			)
		);
	}
	catch (...) {
		QCA_logTextMessage (QStringLiteral("PKCS#11: Unknown error during provider initialization"), Logger::Error);
		appendPluginDiagnosticText (QStringLiteral("Unknown error during initialization of qca-pkcs11 plugin\n"));
	}

	QCA_logTextMessage (
		QStringLiteral("pkcs11Provider::init - return"),
		Logger::Debug
	);
}

void pkcs11Provider::deinit () {
	QCA_logTextMessage (
		QStringLiteral("pkcs11Provider::deinit - entry"),
		Logger::Debug
	);

	delete s_keyStoreList;
	s_keyStoreList = nullptr;

	pkcs11h_terminate ();

	QCA_logTextMessage (
		QStringLiteral("pkcs11Provider::deinit - return"),
		Logger::Debug
	);
}

QString
pkcs11Provider::name () const {
	QCA_logTextMessage (
		QStringLiteral("pkcs11Provider::name - entry/return"),
		Logger::Debug
	);

	return QStringLiteral("qca-pkcs11");
}

QStringList
pkcs11Provider::features() const {
	QCA_logTextMessage (
		QStringLiteral("pkcs11Provider::features - entry/return"),
		Logger::Debug
	);

	QStringList list;
	list += QStringLiteral("smartcard"); // indicator, not algorithm
	list += QStringLiteral("pkey");
	list += QStringLiteral("keystorelist");
	return list;
}

Provider::Context *
pkcs11Provider::createContext (const QString &type) {

	Provider::Context *context = nullptr;

	QCA_logTextMessage (
		QString::asprintf (
			"pkcs11Provider::createContext - entry type='%s'",
			myPrintable (type)
		),
		Logger::Debug
	);

	if (_lowLevelInitialized) {
		if (type == QLatin1String("keystorelist")) {
			if (s_keyStoreList == nullptr) {
				s_keyStoreList = new pkcs11KeyStoreListContext (this);
			}
			context = s_keyStoreList;
		}
	}

	QCA_logTextMessage (
		QString::asprintf (
			"pkcs11Provider::createContext - return context=%p",
			(void *)context
		),
		Logger::Debug
	);

	return context;
}

void
pkcs11Provider::startSlotEvents () {
	CK_RV rv;

	QCA_logTextMessage (
		QStringLiteral("pkcs11Provider::startSlotEvents - entry"),
		Logger::Debug
	);

	if (_lowLevelInitialized) {
		if (!_slotEventsLowLevelActive) {
			if (
				(rv = pkcs11h_setSlotEventHook (
					__slotEventHook,
					this
				)) != CKR_OK
			) {
				throw pkcs11Exception (rv, QStringLiteral("Cannot start slot events"));
			}

			_slotEventsLowLevelActive = true;
		}

		_slotEventsActive = true;
	}

	QCA_logTextMessage (
		QStringLiteral("pkcs11Provider::startSlotEvents - return"),
		Logger::Debug
	);
}

void
pkcs11Provider::stopSlotEvents () {
	QCA_logTextMessage (
		QStringLiteral("pkcs11Provider::stopSlotEvents - entry/return"),
		Logger::Debug
	);

	_slotEventsActive = false;
}

QVariantMap
pkcs11Provider::defaultConfig () const {
	QVariantMap mytemplate;

	QCA_logTextMessage (
		QStringLiteral("pkcs11Provider::defaultConfig - entry/return"),
		Logger::Debug
	);

	mytemplate[QStringLiteral("formtype")] = QStringLiteral("http://affinix.com/qca/forms/qca-pkcs11#1.0");
	mytemplate[QStringLiteral("allow_load_rootca")] = false;
	mytemplate[QStringLiteral("allow_protected_authentication")] = true;
	mytemplate[QStringLiteral("pin_cache")] = PKCS11H_PIN_CACHE_INFINITE;
	mytemplate[QStringLiteral("log_level")] = 0;
	for (int i=0;i<_CONFIG_MAX_PROVIDERS;i++) {
		mytemplate[QString::asprintf ("provider_%02d_enabled", i)] = false;
		mytemplate[QString::asprintf ("provider_%02d_name", i)] = QLatin1String("");
		mytemplate[QString::asprintf ("provider_%02d_library", i)] = QLatin1String("");
		mytemplate[QString::asprintf ("provider_%02d_allow_protected_authentication", i)] = true;
		mytemplate[QString::asprintf ("provider_%02d_cert_private", i)] = false;
		mytemplate[QString::asprintf ("provider_%02d_private_mask", i)] = PKCS11H_PRIVATEMODE_MASK_AUTO;
		mytemplate[QString::asprintf ("provider_%02d_slotevent_method", i)] = QStringLiteral("auto");
		mytemplate[QString::asprintf ("provider_%02d_slotevent_timeout", i)] = 0;
	}

	return mytemplate;
}

void
pkcs11Provider::configChanged (const QVariantMap &config) {
	CK_RV rv = CKR_OK;

	QCA_logTextMessage (
		QStringLiteral("pkcs11Provider::configChanged - entry"),
		Logger::Debug
	);

	if (!_lowLevelInitialized) {
		QCA_logTextMessage (QStringLiteral("PKCS#11: Not initialized"), Logger::Error);
		return;
	}

	_allowLoadRootCA = config[QStringLiteral("allow_load_rootca")].toBool ();

	pkcs11h_setLogLevel (config[QStringLiteral("log_level")].toInt ());
	pkcs11h_setProtectedAuthentication (
		config[QStringLiteral("allow_protected_authentication")].toBool () != false ? TRUE : FALSE //krazy:exclude=captruefalse
	);
	pkcs11h_setPINCachePeriod (config[QStringLiteral("pin_cache")].toInt ());

	/*
	 * Remove current providers
	 */
	foreach (QString i, _providers) {
		pkcs11h_removeProvider (myPrintable (i));
	}
	_providers.clear ();

	/*
	 * Add new providers
	 */
	for (int i=0;i<_CONFIG_MAX_PROVIDERS;i++) {
		bool enabled = config[QString::asprintf ("provider_%02d_enabled", i)].toBool ();
		QString provider = config[QString::asprintf ("provider_%02d_library", i)].toString ();
		QString name = config[QString::asprintf ("provider_%02d_name", i)].toString ();
		QString qslotevent = config[QString::asprintf ("provider_%02d_slotevent_method", i)].toString ();
		unsigned slotevent = PKCS11H_SLOTEVENT_METHOD_AUTO;
		if (qslotevent == QLatin1String("trigger")) {
			slotevent = PKCS11H_SLOTEVENT_METHOD_TRIGGER;
		}
		else if (qslotevent == QLatin1String("poll")) {
			slotevent = PKCS11H_SLOTEVENT_METHOD_POLL;
		}

		if (name.isEmpty ()) {
			name = provider;
		}

		if (enabled && !provider.isEmpty()) {

			QCA_logTextMessage (
				QString::asprintf (
					"Loading PKCS#11 provider '%s' (%s)",
					myPrintable (name),
					myPrintable (provider)
				),
				Logger::Information
			);

			if (
				(rv = pkcs11h_addProvider (
					myPrintable (name),
					myPrintable (provider),
					config[
						QString::asprintf ("provider_%02d_allow_protected_authentication", i)
					].toBool () != false ? TRUE : FALSE, //krazy:exclude=captruefalse
					(unsigned)config[
						QString::asprintf ("provider_%02d_private_mask", i)
					].toInt (),
					slotevent,
					(unsigned)config[
						QString::asprintf ("provider_%02d_slotevent_timeout", i)
					].toInt (),
					config[
						QString::asprintf ("provider_%02d_cert_private", i)
					].toBool () != false ? TRUE : FALSE //krazy:exclude=captruefalse
				)) != CKR_OK
			) {
				QCA_logTextMessage (
					QString::asprintf (
						"PKCS#11: Cannot log provider '%s'-'%s' %lu-'%s'.\n",
						myPrintable (name),
						myPrintable (provider),
						rv,
						pkcs11h_getMessage (rv)
					),
					Logger::Error
				);
				appendPluginDiagnosticText (
					QString::asprintf (
						"Cannot load PKCS#11 provider '%s'\n",
						myPrintable (name)
					)
				);
			}
			else {
				_providers += provider;
			}
		}
	}

	QCA_logTextMessage (
		QStringLiteral("pkcs11Provider::configChanged - return"),
		Logger::Debug
	);
}

void
pkcs11Provider::__logHook (
	void * const global_data,
	const unsigned flags,
	const char * const format,
	va_list args
) {
	pkcs11Provider *me = (pkcs11Provider *)global_data;
	me->_logHook (flags, format, args);
}

void
pkcs11Provider::__slotEventHook (
	void * const global_data
) {
	pkcs11Provider *me = (pkcs11Provider *)global_data;
	me->_slotEventHook ();
}

PKCS11H_BOOL
pkcs11Provider::__tokenPromptHook (
	void * const global_data,
	void * const user_data,
	const pkcs11h_token_id_t token,
	const unsigned retry
) {
	Q_UNUSED(retry);

	pkcs11Provider *me = (pkcs11Provider *)global_data;
	return me->_tokenPromptHook (user_data, token);
}

PKCS11H_BOOL
pkcs11Provider::__pinPromptHook (
	void * const global_data,
	void * const user_data,
	const pkcs11h_token_id_t token,
	const unsigned retry,
	char * const pin,
	const size_t pin_max
) {
	Q_UNUSED(retry);

	pkcs11Provider *me = (pkcs11Provider *)global_data;
	return me->_pinPromptHook (user_data, token, pin, pin_max);
}

void
pkcs11Provider::_logHook (
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
//	QCA_logTextMessage (QString ().vsprintf (format, args), severity);
	char buffer[2048];
	qvsnprintf (buffer, sizeof (buffer)-1, format, args);
	buffer[sizeof (buffer)-1] = '\x0';
	QCA_logTextMessage (QString::fromLatin1(buffer), severity);
//@END-WORKAROUND
}

void
pkcs11Provider::_slotEventHook () {
	/*
	 * This is called from a separate
	 * thread.
	 */
	if (s_keyStoreList != nullptr && _slotEventsActive) {
		QMetaObject::invokeMethod(s_keyStoreList, "doUpdated", Qt::QueuedConnection);
	}
}

PKCS11H_BOOL
pkcs11Provider::_tokenPromptHook (
	void * const user_data,
	const pkcs11h_token_id_t token
) {
	if (s_keyStoreList != nullptr) {
		return s_keyStoreList->_tokenPrompt (user_data, token) ? TRUE : FALSE; //krazy:exclude=captruefalse
	}

	return FALSE; //krazy:exclude=captruefalse
}

PKCS11H_BOOL
pkcs11Provider::_pinPromptHook (
	void * const user_data,
	const pkcs11h_token_id_t token,
	char * const pin,
	const size_t pin_max
) {
	PKCS11H_BOOL ret = FALSE; //krazy:exclude=captruefalse

	if (s_keyStoreList != nullptr) {
		SecureArray qpin;

		if (s_keyStoreList->_pinPrompt (user_data, token, qpin)) {
			if ((size_t)qpin.size () < pin_max-1) {
				memmove (pin, qpin.constData (), qpin.size ());
				pin[qpin.size ()] = '\0';
				ret = TRUE; //krazy:exclude=captruefalse
			}
		}
	}

	return ret; //krazy:exclude=captruefalse
}

class pkcs11Plugin : public QObject, public QCAPlugin
{
	Q_OBJECT
	Q_PLUGIN_METADATA(IID "com.affinix.qca.Plugin/1.0")
	Q_INTERFACES(QCAPlugin)

public:
	Provider *createProvider() override { return new pkcs11Provider; }
};

#include "qca-pkcs11.moc"
