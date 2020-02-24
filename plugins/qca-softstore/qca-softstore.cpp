/*
 * Copyright (C) 2007  Alon Bar-Lev <alon.barlev@gmail.com>
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
#include <QtPlugin>
#include <QHash>
#include <QFile>

using namespace QCA;

// qPrintable is ASCII only!!!
#define myPrintable(s) (s).toUtf8 ().constData ()

namespace softstoreQCAPlugin {

class softstoreKeyStoreListContext;
static softstoreKeyStoreListContext *s_keyStoreList = nullptr;

enum KeyType {
	keyTypeInvalid,
	keyTypePKCS12,
	keyTypePKCS8Inline,
	keyTypePKCS8FilePEM,
	keyTypePKCS8FileDER
};

enum PublicType {
	publicTypeInvalid,
	publicTypeX509Chain
};

struct SoftStoreEntry {
	QString name;
	CertificateChain chain;
	KeyType keyReferenceType;
	QString keyReference;
	bool noPassphrase;
	int unlockTimeout;
};

class softstorePKeyBase : public PKeyBase
{
	Q_OBJECT

private:
	bool _has_privateKeyRole;
	SoftStoreEntry _entry;
	QString _serialized;
	PrivateKey _privkey;
	PrivateKey _privkeySign;
	PublicKey _pubkey;
	QDateTime dueTime;

public:
	static inline QString typeToString (PKey::Type t) {
		switch (t) {
			case PKey::RSA:
				return QStringLiteral("rsa");
			case PKey::DSA:
				return QStringLiteral("dsa");
			case PKey::DH:
				return QStringLiteral("dh");
			default:
				return QLatin1String("");
		}
	}

	softstorePKeyBase (
		const SoftStoreEntry &entry,
		const QString &serialized,
		Provider *p
	) : PKeyBase (p, QStringLiteral("rsa")/*typeToString (entry.chain.primary ().subjectPublicKey ().type ())*/) {
		QCA_logTextMessage (
			QStringLiteral("softstorePKeyBase::softstorePKeyBase1 - entry"),
			Logger::Debug
		);

		_has_privateKeyRole = true;
		_entry = entry;
		_serialized = serialized;
		_pubkey = _entry.chain.primary ().subjectPublicKey ();

		QCA_logTextMessage (
			QStringLiteral("softstorePKeyBase::softstorePKeyBase1 - return"),
			Logger::Debug
		);
	}

	softstorePKeyBase (const softstorePKeyBase &from) : PKeyBase (from.provider (), QStringLiteral("rsa")/*typeToString (from._pubkey.type ())*/) {
		QCA_logTextMessage (
			QStringLiteral("softstorePKeyBase::softstorePKeyBaseC - entry"),
			Logger::Debug
		);

		_has_privateKeyRole = from._has_privateKeyRole;
		_entry = from._entry;
		_serialized = from._serialized;
		_pubkey = from._pubkey;
		_privkey = from._privkey;

		QCA_logTextMessage (
			QStringLiteral("softstorePKeyBase::softstorePKeyBaseC - return"),
			Logger::Debug
		);
	}

	~softstorePKeyBase () override {
		QCA_logTextMessage (
			QStringLiteral("softstorePKeyBase::~softstorePKeyBase - entry"),
			Logger::Debug
		);

		QCA_logTextMessage (
			QStringLiteral("softstorePKeyBase::~softstorePKeyBase - return"),
			Logger::Debug
		);
	}

	Provider::Context *
	clone () const override {
		return new softstorePKeyBase (*this);
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
			QStringLiteral("softstorePKeyBase::convertToPublic - entry"),
			Logger::Debug
		);

		if (_has_privateKeyRole) {
			_has_privateKeyRole = false;
		}

		QCA_logTextMessage (
			QStringLiteral("softstorePKeyBase::convertToPublic - return"),
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
		if (_ensureAccess ()) {
			return _privkey.decrypt (in, out, alg);
		}
		else {
			return false;
		}
	}

	void
	startSign (
		SignatureAlgorithm alg,
		SignatureFormat format
	) override {
		if (_ensureAccess ()) {
			/*
			 * We must use one object thought
			 * signing, so it won't expire by
			 * it-self or during passphrase.
			 */
			_privkeySign = _privkey;
			_privkeySign.startSign (alg, format);
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
			_privkeySign.update (in);
		}
		else {
			_pubkey.update (in);
		}
	}

	QByteArray
	endSign () override {
		const QByteArray r = _privkeySign.signature ();
		_privkeySign = PrivateKey ();
		return r;
	}

	virtual
	bool
	validSignature (
		const QByteArray &sig
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
		const BigInteger &n,
		const BigInteger &e,
		const BigInteger &p,
		const BigInteger &q,
		const BigInteger &d
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
		const BigInteger &n,
		const BigInteger &e
	) {
		Q_UNUSED(n);
		Q_UNUSED(e);
	}

public:
	PublicKey
	_publicKey () const {
		return _pubkey;
	}

	bool
	_ensureAccess () {
		bool ret = false;

		QCA_logTextMessage (
			QStringLiteral("softstorePKeyBase::_ensureAccess - entry"),
			Logger::Debug
		);

		if (_entry.unlockTimeout != -1) {
			if (dueTime >= QDateTime::currentDateTime ()) {
				QCA_logTextMessage (
					QStringLiteral("softstorePKeyBase::_ensureAccess - dueTime reached, clearing"),
					Logger::Debug
				);
				_privkey = PrivateKey ();
			}
		}

		if (!_privkey.isNull ()) {
			ret = true;
		}
		else {
			KeyStoreEntry entry;
			KeyStoreEntryContext *context = nullptr;
			QString storeId, storeName;
			ConvertResult cresult;

			QCA_logTextMessage (
				QStringLiteral("softstorePKeyBase::_ensureAccess - no current key, creating"),
				Logger::Debug
			);

			// too lazy to create scope
			context = reinterpret_cast<KeyStoreListContext *> (s_keyStoreList)->entryPassive (_serialized);
			if (context != nullptr) {
				storeId = context->storeId ();
				storeName = context->storeName ();
				entry.change (context);
			}

			while (!ret) {

				SecureArray passphrase;

				switch (_entry.keyReferenceType) {
					case keyTypeInvalid:
					case keyTypePKCS8Inline:
					break;
					case keyTypePKCS12:
					case keyTypePKCS8FilePEM:
					case keyTypePKCS8FileDER:
						{
							QFile file (_entry.keyReference);
							while (!file.open (QIODevice::ReadOnly)) {
								TokenAsker asker;
								asker.ask (
									KeyStoreInfo (KeyStore::SmartCard, storeId, storeName),
									entry,
									context
								);
								asker.waitForResponse ();
								if (!asker.accepted ()) {
									goto cleanup1;
								}
							}
						}
					break;
				}

				if (!_entry.noPassphrase) {
					PasswordAsker asker;
					asker.ask (
						Event::StylePassphrase,
						KeyStoreInfo (KeyStore::User, storeId, storeName),
						entry,
						context
					);
					asker.waitForResponse ();
					passphrase = asker.password ();
					if (!asker.accepted ()) {
						goto cleanup1;
					}
				}

				switch (_entry.keyReferenceType) {
					case keyTypeInvalid:
					break;
					case keyTypePKCS12:
						{
							KeyBundle bundle = KeyBundle::fromFile (
								_entry.keyReference,
								passphrase,
								&cresult
							);
							if (cresult == ConvertGood) {
								_privkey = bundle.privateKey ();
								ret = true;
							}
						}
					break;
					case keyTypePKCS8Inline:
						{
							PrivateKey k = PrivateKey::fromDER (
								Base64 ().stringToArray (_entry.keyReference),
								passphrase,
								&cresult
							);
							if (cresult == ConvertGood) {
								_privkey = k;
								ret = true;
							}
						}
					break;
					case keyTypePKCS8FilePEM:
						{
							PrivateKey k = PrivateKey::fromPEMFile (
								_entry.keyReference,
								passphrase,
								&cresult
							);
							if (cresult == ConvertGood) {
								_privkey = k;
								ret = true;
							}
						}
					break;
					case keyTypePKCS8FileDER:
						{
							QFile file (_entry.keyReference);
							if (file.open (QIODevice::ReadOnly)) {
								const QByteArray contents = file.readAll ();

								PrivateKey k = PrivateKey::fromDER (
									contents,
									passphrase,
									&cresult
								);
								if (cresult == ConvertGood) {
									_privkey = k;
									ret = true;
								}
							}
						}
					break;
				}
			}

			if (_entry.unlockTimeout != -1) {
				dueTime = QDateTime::currentDateTime ().addSecs (_entry.unlockTimeout);
			}

		cleanup1:
			;

		}

		QCA_logTextMessage (
			QString::asprintf (
				"softstorePKeyBase::_ensureAccess - return ret=%d",
				ret ? 1 : 0
			),
			Logger::Debug
		);

		return ret;
	}
};

class softstorePKeyContext : public PKeyContext
{
    Q_OBJECT

private:
	PKeyBase *_k;

public:
	softstorePKeyContext (Provider *p) : PKeyContext (p) {
		_k = nullptr;
	}

	~softstorePKeyContext () override {
		delete _k;
		_k = nullptr;
	}

	Provider::Context *
	clone () const override {
		softstorePKeyContext *c = new softstorePKeyContext (*this);
		c->_k = (PKeyBase *)_k->clone();
		return c;
	}

public:
	QList<PKey::Type>
	supportedTypes () const override {
		QList<PKey::Type> list;
		list += static_cast<softstorePKeyBase *>(_k)->_publicKey ().type ();
		return list;
	}

	QList<PKey::Type>
	supportedIOTypes () const override {
		QList<PKey::Type> list;
		list += static_cast<softstorePKeyBase *>(_k)->_publicKey ().type ();
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
		return static_cast<softstorePKeyBase *>(_k)->_publicKey ().toDER ();
	}

	QString
	publicToPEM () const override {
		return static_cast<softstorePKeyBase *>(_k)->_publicKey ().toPEM ();
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

class softstoreKeyStoreEntryContext : public KeyStoreEntryContext
{
    Q_OBJECT
private:
	KeyStoreEntry::Type _item_type;
	KeyBundle _key;
	SoftStoreEntry _entry;
	QString _serialized;

public:
	softstoreKeyStoreEntryContext (
		const KeyBundle &key,
		const SoftStoreEntry &entry,
		const QString &serialized,
		Provider *p
	) : KeyStoreEntryContext(p) {
		_item_type = KeyStoreEntry::TypeKeyBundle;
		_key = key;
		_entry = entry;
		_serialized = serialized;
	}

	softstoreKeyStoreEntryContext (
		const softstoreKeyStoreEntryContext &from
	) : KeyStoreEntryContext(from) {
		_item_type = from._item_type;
		_key = from._key;
		_entry = from._entry;
		_serialized = from._serialized;
	}

	Provider::Context *
	clone () const override {
		return new softstoreKeyStoreEntryContext (*this);
	}

public:
	KeyStoreEntry::Type
	type () const override {
		return KeyStoreEntry::TypeKeyBundle;
	}

	QString
	name () const override {
		return _entry.name;
	}

	QString
	id () const override {
		return _entry.name;
	}

	KeyBundle
	keyBundle () const override {
		return _key;
	}

	Certificate
	certificate () const override {
		return _entry.chain.primary ();
	}

	QString
	storeId () const override {
		return QString::asprintf ("%s/%s", "qca-softstore", myPrintable (_entry.name));
	}

	QString
	storeName () const override {
		return _entry.name;
	}

	bool
	ensureAccess () override {
		return static_cast<softstorePKeyBase *>(static_cast<PKeyContext *>(_key.privateKey ().context ())->key ())->_ensureAccess ();
	}

	QString
	serialize () const override {
		return _serialized;
	}
};

class softstoreKeyStoreListContext : public KeyStoreListContext
{
	Q_OBJECT

private:
	int _last_id;
	QList<SoftStoreEntry> _entries;

public:
	softstoreKeyStoreListContext (Provider *p) : KeyStoreListContext (p) {
		QCA_logTextMessage (
			QString::asprintf (
				"softstoreKeyStoreListContext::softstoreKeyStoreListContext - entry Provider=%p",
				(void *)p
			),
			Logger::Debug
		);

		_last_id = 0;

		QCA_logTextMessage (
			QStringLiteral("softstoreKeyStoreListContext::softstoreKeyStoreListContext - return"),
			Logger::Debug
		);
	}

	~softstoreKeyStoreListContext () override {
		QCA_logTextMessage (
			QStringLiteral("softstoreKeyStoreListContext::~softstoreKeyStoreListContext - entry"),
			Logger::Debug
		);

		s_keyStoreList = nullptr;

		QCA_logTextMessage (
			QStringLiteral("softstoreKeyStoreListContext::~softstoreKeyStoreListContext - return"),
			Logger::Debug
		);
	}

	Provider::Context *
	clone () const override {
		QCA_logTextMessage (
			QStringLiteral("softstoreKeyStoreListContext::clone - entry/return"),
			Logger::Debug
		);
		return nullptr;
	}

public:
	void
	start () override {
		QCA_logTextMessage (
			QStringLiteral("softstoreKeyStoreListContext::start - entry"),
			Logger::Debug
		);

		QMetaObject::invokeMethod(this, "doReady", Qt::QueuedConnection);

		QCA_logTextMessage (
			QStringLiteral("softstoreKeyStoreListContext::start - return"),
			Logger::Debug
		);
	}

	void
	setUpdatesEnabled (bool enabled) override {
		QCA_logTextMessage (
			QString::asprintf (
				"softstoreKeyStoreListContext::setUpdatesEnabled - entry/return enabled=%d",
				enabled ? 1 : 0
			),
			Logger::Debug
		);
	}

	KeyStoreEntryContext *
	entry (
		int id,
		const QString &entryId
	) override {
		QCA_logTextMessage (
			QString::asprintf (
				"softstoreKeyStoreListContext::entry - entry/return id=%d entryId='%s'",
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
	entryPassive (
		const QString &serialized
	) override {
		KeyStoreEntryContext *entry = nullptr;

		QCA_logTextMessage (
			QString::asprintf (
				"softstoreKeyStoreListContext::entryPassive - entry serialized='%s'",
				myPrintable (serialized)
			),
			Logger::Debug
		);

		if (serialized.startsWith (QLatin1String("qca-softstore/"))) {
			SoftStoreEntry sentry;

			if (_deserializeSoftStoreEntry (serialized, sentry)) {
				entry = _keyStoreEntryBySoftStoreEntry (sentry);
			}
		}

		QCA_logTextMessage (
			QString::asprintf (
				"softstoreKeyStoreListContext::entryPassive - return entry=%p",
				(void *)entry
			),
			Logger::Debug
		);

		return entry;
	}

	KeyStore::Type
	type (int id) const override {
		Q_UNUSED(id);

		QCA_logTextMessage (
			QString::asprintf (
				"softstoreKeyStoreListContext::type - entry/return id=%d",
				id
			),
			Logger::Debug
		);

		return KeyStore::User;
	}

	QString
	storeId (int id) const override {
		QString ret;

		QCA_logTextMessage (
			QString::asprintf (
				"softstoreKeyStoreListContext::storeId - entry id=%d",
				id
			),
			Logger::Debug
		);

		ret = QStringLiteral("qca-softstore");

		QCA_logTextMessage (
			QString::asprintf (
				"softstoreKeyStoreListContext::storeId - return ret=%s",
				myPrintable (ret)
			),
			Logger::Debug
		);

		return ret;
	}

	QString
	name (int id) const override {
		QString ret;

		QCA_logTextMessage (
			QString::asprintf (
				"softstoreKeyStoreListContext::name - entry id=%d",
				id
			),
			Logger::Debug
		);

		ret = QStringLiteral("User Software Store");

		QCA_logTextMessage (
			QString::asprintf (
				"softstoreKeyStoreListContext::name - return ret=%s",
				myPrintable (ret)
			),
			Logger::Debug
		);

		return ret;
	}

	QList<KeyStoreEntry::Type>
	entryTypes (int id) const override {
		Q_UNUSED(id);

		QCA_logTextMessage (
			QString::asprintf (
				"softstoreKeyStoreListContext::entryTypes - entry/return id=%d",
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
	keyStores () override {
		QList<int> list;

		QCA_logTextMessage (
			QStringLiteral("softstoreKeyStoreListContext::keyStores - entry"),
			Logger::Debug
		);

		list += _last_id;

		QCA_logTextMessage (
			QString::asprintf (
				"softstoreKeyStoreListContext::keyStores - return out.size()=%d",
				list.size ()
			),
			Logger::Debug
		);

		return list;
	}

	QList<KeyStoreEntryContext *>
	entryList (int id) override {
		QList<KeyStoreEntryContext*> list;

		QCA_logTextMessage (
			QString::asprintf (
				"softstoreKeyStoreListContext::entryList - entry id=%d",
				id
			),
			Logger::Debug
		);

		foreach (const SoftStoreEntry &e, _entries) {
			list += _keyStoreEntryBySoftStoreEntry (e);
		}

		QCA_logTextMessage (
			QString::asprintf (
				"softstoreKeyStoreListContext::entryList - return out.size()=%d",
				list.size ()
			),
			Logger::Debug
		);

		return list;
	}

	void
	_emit_diagnosticText (
		const QString &t
	) {
		QCA_logTextMessage (
			QString::asprintf (
				"softstoreKeyStoreListContext::_emit_diagnosticText - entry t='%s'",
				myPrintable (t)
			),
			Logger::Debug
		);

		QCA_logTextMessage (t, Logger::Warning);

		emit diagnosticText (t);

		QCA_logTextMessage (
			QStringLiteral("softstoreKeyStoreListContext::_emit_diagnosticText - return"),
			Logger::Debug
		);
	}

private Q_SLOTS:
	void
	doReady () {
		QCA_logTextMessage (
			QStringLiteral("softstoreKeyStoreListContext::doReady - entry"),
			Logger::Debug
		);

		emit busyEnd ();

		QCA_logTextMessage (
			QStringLiteral("softstoreKeyStoreListContext::doReady - return"),
			Logger::Debug
		);
	}

	void
	doUpdated () {
		QCA_logTextMessage (
			QStringLiteral("softstoreKeyStoreListContext::doUpdated - entry"),
			Logger::Debug
		);

		emit updated ();

		QCA_logTextMessage (
			QStringLiteral("softstoreKeyStoreListContext::doUpdated - return"),
			Logger::Debug
		);
	}

public:
	void
	_updateConfig (const QVariantMap &config, const int maxEntries) {
		QCA_logTextMessage (
			QStringLiteral("softstoreKeyStoreListContext::_updateConfig - entry"),
			Logger::Debug
		);

		QMap<QString, KeyType> keyTypeMap;
		keyTypeMap[QStringLiteral("pkcs12")] = keyTypePKCS12;
		keyTypeMap[QStringLiteral("pkcs8")] = keyTypePKCS8Inline;
		keyTypeMap[QStringLiteral("pkcs8-file-pem")] = keyTypePKCS8FilePEM;
		keyTypeMap[QStringLiteral("pkcs8-file-der")] = keyTypePKCS8FileDER;

		QMap<QString, PublicType> publicTypeMap;
		publicTypeMap[QStringLiteral("x509chain")] = publicTypeX509Chain;

		_last_id++;
		_entries.clear ();

		for (int i=0;i<maxEntries;i++) {
			if (config[QString::asprintf ("entry_%02d_enabled", i)].toBool ()) {
				ConvertResult cresult;
				SoftStoreEntry entry;
				PublicType publicType = publicTypeInvalid;

				entry.name = config[QString::asprintf ("entry_%02d_name", i)].toString ();
				const QString stringReferenceType  = config[QString::asprintf ("entry_%02d_private_type", i)].toString ();
				const QString stringPublicType  = config[QString::asprintf ("entry_%02d_public_type", i)].toString ();
				entry.noPassphrase = config[QString::asprintf ("entry_%02d_no_passphrase", i)].toBool ();
				entry.unlockTimeout = config[QString::asprintf ("entry_%02d_unlock_timeout", i)].toInt ();

				if (publicTypeMap.contains (stringPublicType)) {
					publicType = publicTypeMap[stringPublicType];
				}
				else {
					_emit_diagnosticText (
						QString::asprintf (
							"Software Store: Bad public key type of '%s' entry.\n",
							myPrintable (entry.name)
						)
					);
					goto cleanup1;
				}

				if (keyTypeMap.contains (stringReferenceType)) {
					entry.keyReferenceType = keyTypeMap[stringReferenceType];
				}
				else {
					_emit_diagnosticText (
						QString::asprintf (
							"Software Store: Bad private key type of '%s' entry.\n",
							myPrintable (entry.name)
						)
					);
					goto cleanup1;
				}

				entry.keyReference = config[QString::asprintf ("entry_%02d_private", i)].toString ();

				switch (publicType) {
					case publicTypeInvalid:
						goto cleanup1;
					break;
					case publicTypeX509Chain:
						const QStringList base64certs = config[QString::asprintf ("entry_%02d_public", i)].toString ().split (QStringLiteral("!"));

						foreach (const QString &s, base64certs) {
							entry.chain += Certificate::fromDER (
								Base64 ().stringToArray (s).toByteArray (),
								&cresult
							);
						}

						if (cresult != ConvertGood) {
							_emit_diagnosticText (
								QString::asprintf (
									"Software Store: Cannot load certificate of '%s' entry.\n",
									myPrintable (entry.name)
								)
							);
							goto cleanup1;
						}
					break;
				}

				_entries += entry;

			cleanup1:
				; //nothing to do for this entry.
			}
		}

		QMetaObject::invokeMethod(s_keyStoreList, "doUpdated", Qt::QueuedConnection);

		QCA_logTextMessage (
			QStringLiteral("softstoreKeyStoreListContext::_updateConfig - return"),
			Logger::Debug
		);
	}

private:
	QString
	_serializeSoftStoreEntry (
		const SoftStoreEntry &entry
	) const {
		QString serialized;

		QCA_logTextMessage (
			QString::asprintf (
				"softstoreKeyStoreListContext::_serializeSoftStoreEntry - entry name=%s",
				myPrintable (entry.name)
			),
			Logger::Debug
		);

		serialized = QString::asprintf (
			"qca-softstore/0/%s/%d/%s/%d/%d/x509chain/",
			myPrintable (_escapeString (entry.name)),
			entry.keyReferenceType,
			myPrintable (_escapeString (entry.keyReference)),
			entry.noPassphrase ? 1 : 0,
			entry.unlockTimeout
		);

		QStringList list;
		foreach (const Certificate &i, entry.chain) {
			list += _escapeString (Base64 ().arrayToString (i.toDER ()));
		}

		serialized.append (list.join (QStringLiteral("/")));

		QCA_logTextMessage (
			QString::asprintf (
				"softstoreKeyStoreListContext::_serializeSoftStoreEntry - return serialized='%s'",
				myPrintable (serialized)
			),
			Logger::Debug
		);

		return serialized;
	}

	bool
	_deserializeSoftStoreEntry (
		const QString &serialized,
		SoftStoreEntry &entry
	) const {
		bool ret = false;

		QCA_logTextMessage (
			QString::asprintf (
				"softstoreKeyStoreListContext::_deserializeSoftStoreEntry - entry from='%s'",
				myPrintable (serialized)
			),
			Logger::Debug
		);

		entry = SoftStoreEntry ();

		const QStringList list = serialized.split (QStringLiteral("/"));
		int n=0;

		if (list.size () < 8) {
			goto cleanup;
		}

		if (list[n++] != QLatin1String("qca-softstore")) {
			goto cleanup;
		}

		if (list[n++].toInt () != 0) {
			goto cleanup;
		}

		entry.name = _unescapeString (list[n++]);
		entry.keyReferenceType = (KeyType)list[n++].toInt ();
		entry.keyReference = _unescapeString (list[n++]);
		entry.noPassphrase = list[n++].toInt () != 0;
		entry.unlockTimeout = list[n++].toInt ();
		n++;	// skip public key for now.

		while (n < list.size ()) {
			Certificate cert = Certificate::fromDER (
				Base64 ().stringToArray (_unescapeString (list[n++])).toByteArray ()
			);
			if (cert.isNull ()) {
				goto cleanup;
			}
			entry.chain += cert;
		}

		ret = true;

	cleanup:

		QCA_logTextMessage (
			QString::asprintf (
				"softstoreKeyStoreListContext::_deserializeSoftStoreEntry - return ret=%d chain.size()=%d",
				ret ? 1 : 0,
				entry.chain.size ()
			),
			Logger::Debug
		);

		return ret;
	}

	softstoreKeyStoreEntryContext *
	_keyStoreEntryBySoftStoreEntry (
		const SoftStoreEntry &sentry
	) const {
		softstoreKeyStoreEntryContext *entry = nullptr;

		QCA_logTextMessage (
			QString::asprintf (
				"softstoreKeyStoreListContext::_keyStoreEntryBySoftStoreEntry - entry name=%s",
				myPrintable (sentry.name)
			),
			Logger::Debug
		);

		QString serialized = _serializeSoftStoreEntry (sentry);
		
		softstorePKeyBase *pkey = new softstorePKeyBase (
			sentry,
			serialized,
			provider()
		);

		softstorePKeyContext *pkc = new softstorePKeyContext (provider ());
		pkc->setKey (pkey);
		PrivateKey privkey;
		privkey.change (pkc);
		KeyBundle key;
		key.setCertificateChainAndKey (
			sentry.chain,
			privkey
		);

		entry = new softstoreKeyStoreEntryContext (
			key,
			sentry,
			serialized,
			provider ()
		);

		QCA_logTextMessage (
			QString::asprintf (
				"softstoreKeyStoreListContext::_keyStoreEntryBySoftStoreEntry - return entry=%p",
				(void *)entry
			),
			Logger::Debug
		);

		return entry;
	}

	QString
	_escapeString (
		const QString &from
	) const {
		QString to;

		foreach (const QChar &c, from) {
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
	_unescapeString (
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
};

}

using namespace softstoreQCAPlugin;

class softstoreProvider : public Provider
{
private:
	static const int _CONFIG_MAX_ENTRIES;

	QVariantMap _config;

public:
	softstoreProvider () {
	}

	~softstoreProvider () override {
	}

public:
	int
	qcaVersion() const override {
		return QCA_VERSION;
	}

	void
	init () override {
	}

	QString
	name () const override {
		return QStringLiteral("qca-softstore");
	}

	QStringList
	features () const override {
		QCA_logTextMessage (
			QStringLiteral("softstoreProvider::features - entry/return"),
			Logger::Debug
		);

		QStringList list;
		list += QStringLiteral("pkey");
		list += QStringLiteral("keystorelist");
		return list;
	}

	Context *
	createContext (
		const QString &type
	) override {
		Provider::Context *context = nullptr;

		QCA_logTextMessage (
			QString::asprintf (
				"softstoreProvider::createContext - entry type='%s'",
				myPrintable (type)
			),
			Logger::Debug
		);

		if (type == QLatin1String("keystorelist")) {
			if (s_keyStoreList == nullptr) {
				s_keyStoreList = new softstoreKeyStoreListContext (this);
				s_keyStoreList->_updateConfig (_config, _CONFIG_MAX_ENTRIES);
			}
			context = s_keyStoreList;
		}

		QCA_logTextMessage (
			QString::asprintf (
				"softstoreProvider::createContext - return context=%p",
				(void *)context
			),
			Logger::Debug
		);

		return context;
	}

	QVariantMap
	defaultConfig () const override {
		QVariantMap mytemplate;

		QCA_logTextMessage (
			QStringLiteral("softstoreProvider::defaultConfig - entry/return"),
			Logger::Debug
		);

		mytemplate[QStringLiteral("formtype")] = QStringLiteral("http://affinix.com/qca/forms/qca-softstore#1.0");
		for (int i=0;i<_CONFIG_MAX_ENTRIES;i++) {
			mytemplate[QString::asprintf ("entry_%02d_enabled", i)] = false;
			mytemplate[QString::asprintf ("entry_%02d_name", i)] = QLatin1String("");
			mytemplate[QString::asprintf ("entry_%02d_public_type", i)] = QLatin1String("");
			mytemplate[QString::asprintf ("entry_%02d_private_type", i)] = QLatin1String("");
			mytemplate[QString::asprintf ("entry_%02d_public", i)] = QLatin1String("");
			mytemplate[QString::asprintf ("entry_%02d_private", i)] = QLatin1String("");
			mytemplate[QString::asprintf ("entry_%02d_unlock_timeout", i)] = -1;
			mytemplate[QString::asprintf ("entry_%02d_no_passphrase", i)] = false;
		}

		return mytemplate;
	}

	void
	configChanged (const QVariantMap &config) override {

		QCA_logTextMessage (
			QStringLiteral("softstoreProvider::configChanged - entry"),
			Logger::Debug
		);

		_config = config;

		if (s_keyStoreList != nullptr) {
			s_keyStoreList->_updateConfig (_config, _CONFIG_MAX_ENTRIES);
		}

		QCA_logTextMessage (
			QStringLiteral("softstoreProvider::configChanged - return"),
			Logger::Debug
		);
	}
};

const int softstoreProvider::_CONFIG_MAX_ENTRIES = 50;

class softstorePlugin : public QObject, public QCAPlugin
{
	Q_OBJECT
	Q_PLUGIN_METADATA(IID "com.affinix.qca.Plugin/1.0")
	Q_INTERFACES(QCAPlugin)

public:
	Provider *createProvider() override { return new softstoreProvider; }
};

#include "qca-softstore.moc"
