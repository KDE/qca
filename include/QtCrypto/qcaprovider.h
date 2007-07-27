/*
 * qcaprovider.h - QCA Plugin API
 * Copyright (C) 2003-2007  Justin Karneges <justin@affinix.com>
 * Copyright (C) 2004,2005  Brad Hards <bradh@frogmouth.net>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 *
 */

/**
   \file qcaprovider.h

   Header file for provider implementation classes (e.g. plugins)

   \note You should not use this header directly from an
   application. You should just use <tt> \#include \<QtCrypto>
   </tt> instead.
*/

#ifndef QCAPROVIDER_H
#define QCAPROVIDER_H

#include "qca_core.h"
#include "qca_basic.h"
#include "qca_publickey.h"
#include "qca_cert.h"
#include "qca_keystore.h"
#include "qca_securelayer.h"
#include "qca_securemessage.h"

#include <limits>

/**
   Provider plugin base class

   QCA loads cryptographic provider plugins with QPluginLoader.  The QObject
   obtained when loading the plugin must implement the QCAPlugin interface.
   This is done by inheriting QCAPlugin, and including
   Q_INTERFACES(QCAPlugin) in your class declaration.

   For example:
\code
class MyPlugin : public QObject, public QCAPlugin
{
	Q_OBJECT
	Q_INTERFACES(QCAPlugin)
public:
	virtual Provider *createProvider() { ... }
};
\endcode

   There is only one function to reimplement, called createProvider().  This
   function should return a newly allocated Provider instance.
*/
class QCA_EXPORT QCAPlugin
{
public:
	/**
	   Destructs the object
	*/
	virtual ~QCAPlugin() {}

	/**
	   Returns a newly allocated Provider instance.
	*/
	virtual QCA::Provider *createProvider() = 0;
};

Q_DECLARE_INTERFACE(QCAPlugin, "com.affinix.qca.Plugin/1.0")

namespace QCA {

/**
   Random provider
*/
class QCA_EXPORT RandomContext : public BasicContext
{
	Q_OBJECT
public:
	/**
	   Standard constructor
	*/
	RandomContext(Provider *p) : BasicContext(p, "random") {}

	/**
	   Return an array of random bytes

	   \param size the number of random bytes to return
	*/
	virtual SecureArray nextBytes(int size) = 0;
};

/**
   Hash provider
*/
class QCA_EXPORT HashContext : public BasicContext
{
	Q_OBJECT
public:
	/**
	   Standard constructor
	*/
	HashContext(Provider *p, const QString &type) : BasicContext(p, type) {}

	/**
	   Reset the object to its initial state
	*/
	virtual void clear() = 0;

	/**
	   Process a chunk of data

	   \param a the input data to process
	*/
	virtual void update(const MemoryRegion &a) = 0;

	/**
	   Return the computed hash
	*/
	virtual MemoryRegion final() = 0;
};

/**
   Cipher provider
*/
class QCA_EXPORT CipherContext : public BasicContext
{
	Q_OBJECT
public:
	/**
	   Standard constructor
	*/
	CipherContext(Provider *p, const QString &type) : BasicContext(p, type) {}

	/**
	   Set up the object for encrypt/decrypt
	*/
	virtual void setup(Direction dir, const SymmetricKey &key, const InitializationVector &iv) = 0;

	/**
	   Returns the KeyLength for this cipher
	*/
	virtual KeyLength keyLength() const = 0;

	/**
	   Returns the block size for this cipher
	*/
	virtual int blockSize() const = 0;

	/**
	   Process a chunk of data.  Returns true if successful.

	   \param in the input data to process
	   \param out pointer to an array that should store the result
	*/
	virtual bool update(const SecureArray &in, SecureArray *out) = 0;

	/**
	   Finish the cipher processing.  Returns true if successful.

	   \param out pointer to an array that should store the result
	*/
	virtual bool final(SecureArray *out) = 0;
};

/**
   Message authentication code provider
*/
class QCA_EXPORT MACContext : public BasicContext
{
	Q_OBJECT
public:
	/**
	   Standard constructor
	*/
	MACContext(Provider *p, const QString &type) : BasicContext(p, type) {}

	/**
	   Set up the object for hashing
	*/
	virtual void setup(const SymmetricKey &key) = 0;

	/**
	   Returns the KeyLength for this MAC algorithm
	*/
	virtual KeyLength keyLength() const = 0;

	/**
	   Process a chunk of data

	   \param in the input data to process
	*/
	virtual void update(const MemoryRegion &in) = 0;

	/**
	   Compute the result after processing all data

	   \param out pointer to an array that should store the result
	*/
	virtual void final(MemoryRegion *out) = 0;

protected:
	/**
	   Returns a KeyLength that supports any length
	*/
	KeyLength anyKeyLength() const
	{
		// this is used instead of a default implementation to make sure that
		// provider authors think about it, at least a bit.
		// See Meyers, Effective C++, Effective C++ (2nd Ed), Item 36
		return KeyLength( 0, INT_MAX, 1 );
	}
};

/**
   Key derivation function provider
*/
class QCA_EXPORT KDFContext : public BasicContext
{
	Q_OBJECT
public:
	/**
	   Standard constructor
	*/
	KDFContext(Provider *p, const QString &type) : BasicContext(p, type) {}

	/**
	   Create a key and return it
	*/
	virtual SymmetricKey makeKey(const SecureArray &secret, const InitializationVector &salt, unsigned int keyLength, unsigned int iterationCount) = 0;
};

/**
   Discrete logarithm provider
*/
class QCA_EXPORT DLGroupContext : public Provider::Context
{
	Q_OBJECT
public:
	/**
	   Standard constructor
	*/
	DLGroupContext(Provider *p) : Provider::Context(p, "dlgroup") {}

	/**
	   The DLGroupSets supported by this object
	*/
	virtual QList<DLGroupSet> supportedGroupSets() const = 0;

	/**
	   Returns true if there is a result to obtain
	*/
	virtual bool isNull() const = 0;

	/**
	   Attempt to create P, Q, and G values from the specified group set

	   If \a block is true, then this function blocks until completion.
	   Otherwise, this function returns immediately and finished() is
	   emitted when the operation completes.

	   If an error occurs during generation, then the operation will
	   complete and isNull() will return true.
	*/
	virtual void fetchGroup(DLGroupSet set, bool block) = 0;

	/**
	   Obtain the result of the operation.  Ensure isNull() returns false
	   before calling this function.
	*/
	virtual void getResult(BigInteger *p, BigInteger *q, BigInteger *g) const = 0;

Q_SIGNALS:
	/**
	   Emitted when the fetchGroup() operation completes in non-blocking
	   mode.
	*/
	void finished();
};

/**
   Public key implementation provider base
*/
class QCA_EXPORT PKeyBase : public BasicContext
{
	Q_OBJECT
public:
	/**
	   Standard constructor
	*/
	PKeyBase(Provider *p, const QString &type);

	/**
	   Returns true if this object is not valid.  This is the default
	   state, and the object may also become this state if a conversion
	   or generation function fails.
	*/
	virtual bool isNull() const = 0;

	/**
	   Returns the type of public key
	*/
	virtual PKey::Type type() const = 0;

	/**
	   Returns true if this is a private key, otherwise false
	*/
	virtual bool isPrivate() const = 0;

	/**
	   Returns true if the components of this key are accessible and
	   whether it can be serialized into an output format.  Private keys
	   from a smart card device will often not be exportable.
	*/
	virtual bool canExport() const = 0;

	/**
	   If the key is a private key, this function will convert it into a
	   public key (all private key data includes the public data as well,
	   which is why this is possible).  If the key is already a public
	   key, then this function has no effect.
	*/
	virtual void convertToPublic() = 0;

	/**
	   Returns the number of bits in the key
	*/
	virtual int bits() const = 0;

	/**
	   Returns the maximum number of bytes that can be encrypted by this
	   key
	*/
	virtual int maximumEncryptSize(EncryptionAlgorithm alg) const;

	/**
	   Encrypt data

	   \param in the input data to encrypt
	   \param alg the encryption algorithm to use
	*/
	virtual SecureArray encrypt(const SecureArray &in, EncryptionAlgorithm alg);

	/**
	   Decrypt data

	   \param in the input data to decrypt
	   \param out pointer to an array to store the plaintext result
	   \param alg the encryption algorithm used to generate the input
	   data
	*/
	virtual bool decrypt(const SecureArray &in, SecureArray *out, EncryptionAlgorithm alg);

	/**
	   Begin a signing operation

	   \param alg the signature algorithm to use
	   \param format the signature format to use
	*/
	virtual void startSign(SignatureAlgorithm alg, SignatureFormat format);

	/**
	   Begin a verify operation

	   \param alg the signature algorithm used by the input signature
	   \param format the signature format used by the input signature
	*/
	virtual void startVerify(SignatureAlgorithm alg, SignatureFormat format);

	/**
	   Process the plaintext input data for either signing or verifying,
	   whichever operation is active.

	   \param in the input data to process
	*/
	virtual void update(const MemoryRegion &in);

	/**
	   Complete a signing operation, and return the signature value

	   If there is an error signing, an empty array is returned.
	*/
	virtual QByteArray endSign();

	/**
	   Complete a verify operation, and return true if successful

	   If there is an error verifying, this function returns false.

	   \param sig the signature to verify with the input data
	*/
	virtual bool endVerify(const QByteArray &sig);

	/**
	   Compute a symmetric key based on this private key and some other
	   public key

	   Essentially for Diffie-Hellman only.
	*/
	virtual SymmetricKey deriveKey(const PKeyBase &theirs);

Q_SIGNALS:
	/**
	   Emitted when an asynchronous operation completes on this key.
	   Such operations will be documented that they emit this signal.
	*/
	void finished();
};

/**
   RSA provider
*/
class QCA_EXPORT RSAContext : public PKeyBase
{
	Q_OBJECT
public:
	/**
	   Standard constructor
	*/
	RSAContext(Provider *p) : PKeyBase(p, "rsa") {}

	/**
	   Generate an RSA private key

	   If \a block is true, then this function blocks until completion.
	   Otherwise, this function returns immediately and finished() is
	   emitted when the operation completes.

	   If an error occurs during generation, then the operation will
	   complete and isNull() will return true.

	   \param bits the length of the key to generate, in bits
	   \param exp the exponent to use for generation
	   \param block whether to use blocking mode
	*/
	virtual void createPrivate(int bits, int exp, bool block) = 0;

	/**
	   Create an RSA private key based on the five components
	*/
	virtual void createPrivate(const BigInteger &n, const BigInteger &e, const BigInteger &p, const BigInteger &q, const BigInteger &d) = 0;

	/**
	   Create an RSA public key based on the two public components
	*/
	virtual void createPublic(const BigInteger &n, const BigInteger &e) = 0;

	/**
	   Returns the public N component of this RSA key
	*/
	virtual BigInteger n() const = 0;

	/**
	   Returns the public E component of this RSA key
	*/
	virtual BigInteger e() const = 0;

	/**
	   Returns the private P component of this RSA key
	*/
	virtual BigInteger p() const = 0;

	/**
	   Returns the private Q component of this RSA key
	*/
	virtual BigInteger q() const = 0;

	/**
	   Returns the private D component of this RSA key
	*/
	virtual BigInteger d() const = 0;
};

/**
   DSA provider
*/
class QCA_EXPORT DSAContext : public PKeyBase
{
	Q_OBJECT
public:
	/**
	   Standard constructor
	*/
	DSAContext(Provider *p) : PKeyBase(p, "dsa") {}

	/**
	   Generate a DSA private key

	   If \a block is true, then this function blocks until completion.
	   Otherwise, this function returns immediately and finished() is
	   emitted when the operation completes.

	   If an error occurs during generation, then the operation will
	   complete and isNull() will return true.

	   \param domain the domain values to use for generation
	   \param block whether to use blocking mode
	*/
	virtual void createPrivate(const DLGroup &domain, bool block) = 0;

	/**
	   Create a DSA private key based on its numeric components
	*/
	virtual void createPrivate(const DLGroup &domain, const BigInteger &y, const BigInteger &x) = 0;

	/**
	   Create a DSA public key based on its numeric components
	*/
	virtual void createPublic(const DLGroup &domain, const BigInteger &y) = 0;

	/**
	   Returns the public domain component of this DSA key
	*/
	virtual DLGroup domain() const = 0;

	/**
	   Returns the public Y component of this DSA key
	*/
	virtual BigInteger y() const = 0;

	/**
	   Returns the private X component of this DSA key
	*/
	virtual BigInteger x() const = 0;
};

/**
   Diffie-Hellman provider
*/
class QCA_EXPORT DHContext : public PKeyBase
{
	Q_OBJECT
public:
	/**
	   Standard constructor
	*/
	DHContext(Provider *p) : PKeyBase(p, "dh") {}

	/**
	   Generate a Diffie-Hellman private key

	   If \a block is true, then this function blocks until completion.
	   Otherwise, this function returns immediately and finished() is
	   emitted when the operation completes.

	   If an error occurs during generation, then the operation will
	   complete and isNull() will return true.

	   \param domain the domain values to use for generation
	   \param block whether to use blocking mode
	*/
	virtual void createPrivate(const DLGroup &domain, bool block) = 0;

	/**
	   Create a Diffie-Hellman private key based on its numeric
	   components
	*/
	virtual void createPrivate(const DLGroup &domain, const BigInteger &y, const BigInteger &x) = 0;

	/**
	   Create a Diffie-Hellman public key based on its numeric
	   components
	*/
	virtual void createPublic(const DLGroup &domain, const BigInteger &y) = 0;

	/**
	   Returns the public domain component of this Diffie-Hellman key
	*/
	virtual DLGroup domain() const = 0;

	/**
	   Returns the public Y component of this Diffie-Hellman key
	*/
	virtual BigInteger y() const = 0;

	/**
	   Returns the private X component of this Diffie-Hellman key
	*/
	virtual BigInteger x() const = 0;
};

/**
   Public key container provider

   This object "holds" a public key object.  By default it contains no key
   (key() returns 0), but you can put a key into it with setKey(), or you
   can call an import function such as publicFromDER().
*/
class QCA_EXPORT PKeyContext : public BasicContext
{
	Q_OBJECT
public:
	/**
	   Standard constructor
	*/
	PKeyContext(Provider *p) : BasicContext(p, "pkey") {}

	/**
	   Returns a list of supported public key types
	*/
	virtual QList<PKey::Type> supportedTypes() const = 0;

	/**
	   Returns a list of public key types that can be serialized and
	   deserialized into DER and PEM format
	*/
	virtual QList<PKey::Type> supportedIOTypes() const = 0;

	/**
	   Returns a list of password-based encryption algorithms that are
	   supported for private key serialization and deserialization
	*/
	virtual QList<PBEAlgorithm> supportedPBEAlgorithms() const = 0;

	/**
	   Returns the key held by this object, or 0 if there is no key
	*/
	virtual PKeyBase *key() = 0;

	/**
	   Returns the key held by this object, or 0 if there is no key
	*/
	virtual const PKeyBase *key() const = 0;

	/**
	   Sets the key for this object.  If this object already had a key,
	   then the old one is destructed.  This object takes ownership of
	   the key.
	*/
	virtual void setKey(PKeyBase *key) = 0;

	/**
	   Attempt to import a key from another provider.  Returns true if
	   successful, otherwise false.

	   Generally this function is used if the specified key's provider
	   does not support serialization, but your provider does.  The call
	   to this function would then be followed by an export function,
	   such as publicToDER().
	*/
	virtual bool importKey(const PKeyBase *key) = 0;

	/**
	   Convert a public key to DER format, and return the value
	*/
	virtual QByteArray publicToDER() const;

	/**
	   Convert a public key to PEM format, and return the value
	*/
	virtual QString publicToPEM() const;

	/**
	   Read DER-formatted input and convert it into a public key

	   Returns QCA::ConvertGood if successful, otherwise some error
	   value.

	   \param a the input data
	*/
	virtual ConvertResult publicFromDER(const QByteArray &a);

	/**
	   Read PEM-formatted input and convert it into a public key

	   Returns QCA::ConvertGood if successful, otherwise some error
	   value.

	   \param s the input data
	*/
	virtual ConvertResult publicFromPEM(const QString &s);

	/**
	   Convert a private key to DER format, and return the value

	   \param passphrase the passphrase to encode the result with, or an
	   empty array if no encryption is desired
	   \param pbe the encryption algorithm to use, if applicable
	*/
	virtual SecureArray privateToDER(const SecureArray &passphrase, PBEAlgorithm pbe) const;

	/**
	   Convert a private key to PEM format, and return the value

	   \param passphrase the passphrase to encode the result with, or an
	   empty array if no encryption is desired
	   \param pbe the encryption algorithm to use, if applicable
	*/
	virtual QString privateToPEM(const SecureArray &passphrase, PBEAlgorithm pbe) const;

	/**
	   Read DER-formatted input and convert it into a private key

	   Returns QCA::ConvertGood if successful, otherwise some error
	   value.

	   \param a the input data
	   \param passphrase the passphrase needed to decrypt, if applicable
	*/
	virtual ConvertResult privateFromDER(const SecureArray &a, const SecureArray &passphrase);

	/**
	   Read PEM-formatted input and convert it into a private key

	   Returns QCA::ConvertGood if successful, otherwise some error
	   value.

	   \param s the input data
	   \param passphrase the passphrase needed to decrypt, if applicable
	*/
	virtual ConvertResult privateFromPEM(const QString &s, const SecureArray &passphrase);
};

/**
   X.509 certificate and certificate request provider base
*/
class QCA_EXPORT CertBase : public BasicContext
{
	Q_OBJECT
public:
	/**
	   Standard constructor
	*/
	CertBase(Provider *p, const QString &type) : BasicContext(p, type) {}

	// import / export
	virtual QByteArray toDER() const = 0;
	virtual QString toPEM() const = 0;
	virtual ConvertResult fromDER(const QByteArray &a) = 0;
	virtual ConvertResult fromPEM(const QString &s) = 0;
};

class QCA_EXPORT CertContextProps
{
public:
	int version;                     // cert only
	QDateTime start, end;            // cert only
	CertificateInfoOrdered subject;
	CertificateInfoOrdered issuer;   // cert only
	Constraints constraints;
	QStringList policies;
	QStringList crlLocations;        // cert only
	QStringList issuerLocations;     // cert only
	QStringList ocspLocations;       // cert only
	BigInteger serial;               // cert only
	bool isCA;
	bool isSelfSigned;               // cert only
	int pathLimit;
	QByteArray sig;
	SignatureAlgorithm sigalgo;
	QByteArray subjectId, issuerId;  // cert only
	QString challenge;               // csr only
	CertificateRequestFormat format; // csr only
};

class QCA_EXPORT CRLContextProps
{
public:
	CertificateInfoOrdered issuer;
	int number;
	QDateTime thisUpdate, nextUpdate;
	QList<CRLEntry> revoked;
	QByteArray sig;
	SignatureAlgorithm sigalgo;
	QByteArray issuerId;
};

class CRLContext;

/**
   X.509 certificate provider
*/
class QCA_EXPORT CertContext : public CertBase
{
	Q_OBJECT
public:
	/**
	   Standard constructor
	*/
	CertContext(Provider *p) : CertBase(p, "cert") {}

	virtual bool createSelfSigned(const CertificateOptions &opts, const PKeyContext &priv) = 0;
	virtual const CertContextProps *props() const = 0;
	virtual bool compare(const CertContext *other) const = 0;
	virtual PKeyContext *subjectPublicKey() const = 0; // caller must delete
	virtual bool isIssuerOf(const CertContext *other) const = 0;

	// ownership of items IS NOT passed
	virtual Validity validate(const QList<CertContext*> &trusted, const QList<CertContext*> &untrusted, const QList<CRLContext*> &crls, UsageMode u, ValidateFlags vf) const = 0;
	virtual Validity validate_chain(const QList<CertContext*> &chain, const QList<CertContext*> &trusted, const QList<CRLContext*> &crls, UsageMode u, ValidateFlags vf) const = 0;
};

/**
   X.509 certificate request provider
*/
class QCA_EXPORT CSRContext : public CertBase
{
	Q_OBJECT
public:
	/**
	   Standard constructor
	*/
	CSRContext(Provider *p) : CertBase(p, "csr") {}

	virtual bool canUseFormat(CertificateRequestFormat f) const = 0;
	virtual bool createRequest(const CertificateOptions &opts, const PKeyContext &priv) = 0;
	virtual const CertContextProps *props() const = 0;
	virtual bool compare(const CSRContext *other) const = 0;
	virtual PKeyContext *subjectPublicKey() const = 0; // caller must delete
	virtual QString toSPKAC() const = 0;
	virtual ConvertResult fromSPKAC(const QString &s) = 0;
};

/**
   X.509 certificate revocation list provider
*/
class QCA_EXPORT CRLContext : public CertBase
{
	Q_OBJECT
public:
	/**
	   Standard constructor
	*/
	CRLContext(Provider *p) : CertBase(p, "crl") {}

	virtual const CRLContextProps *props() const = 0;
	virtual bool compare(const CRLContext *other) const = 0;
};

/**
   X.509 certificate collection provider
*/
class QCA_EXPORT CertCollectionContext : public BasicContext
{
	Q_OBJECT
public:
	/**
	   Standard constructor
	*/
	CertCollectionContext(Provider *p) : BasicContext(p, "certcollection") {}

	// ownership of items IS NOT passed
	virtual QByteArray toPKCS7(const QList<CertContext*> &certs, const QList<CRLContext*> &crls) const = 0;

	// ownership of items IS passed
	virtual ConvertResult fromPKCS7(const QByteArray &a, QList<CertContext*> *certs, QList<CRLContext*> *crls) const = 0;
};

/**
   X.509 certificate authority provider
*/
class QCA_EXPORT CAContext : public BasicContext
{
	Q_OBJECT
public:
	/**
	   Standard constructor
	*/
	CAContext(Provider *p) : BasicContext(p, "ca") {}

	virtual void setup(const CertContext &cert, const PKeyContext &priv) = 0;

	// caller must delete all return values here
	virtual CertContext *certificate() const = 0;
	virtual CertContext *signRequest(const CSRContext &req, const QDateTime &notValidAfter) const = 0;
	virtual CertContext *createCertificate(const PKeyContext &pub, const CertificateOptions &opts) const = 0;
	virtual CRLContext *createCRL(const QDateTime &nextUpdate) const = 0;
	virtual CRLContext *updateCRL(const CRLContext &crl, const QList<CRLEntry> &entries, const QDateTime &nextUpdate) const = 0;
};

/**
   PKCS#12 provider
*/
class QCA_EXPORT PKCS12Context : public BasicContext
{
	Q_OBJECT
public:
	/**
	   Standard constructor
	*/
	PKCS12Context(Provider *p) : BasicContext(p, "pkcs12") {}

	virtual QByteArray toPKCS12(const QString &name, const QList<const CertContext*> &chain, const PKeyContext &priv, const SecureArray &passphrase) const = 0;

	// caller must delete
	virtual ConvertResult fromPKCS12(const QByteArray &in, const SecureArray &passphrase, QString *name, QList<CertContext*> *chain, PKeyContext **priv) const = 0;
};

class QCA_EXPORT PGPKeyContextProps
{
public:
	QString keyId;
	QStringList userIds;
	bool isSecret;
	QDateTime creationDate, expirationDate;
	QString fingerprint; // all lowercase, no spaces
	bool inKeyring;
	bool isTrusted;
};

/**
   OpenPGP key provider
*/
class QCA_EXPORT PGPKeyContext : public BasicContext
{
	Q_OBJECT
public:
	/**
	   Standard constructor
	*/
	PGPKeyContext(Provider *p) : BasicContext(p, "pgpkey") {}

	virtual const PGPKeyContextProps *props() const = 0;

	virtual QByteArray toBinary() const = 0;
	virtual QString toAscii() const = 0;
	virtual ConvertResult fromBinary(const QByteArray &a) = 0;
	virtual ConvertResult fromAscii(const QString &s) = 0;
};

/**
   KeyStoreEntry provider
*/
class QCA_EXPORT KeyStoreEntryContext : public BasicContext
{
	Q_OBJECT
public:
	/**
	   Standard constructor
	*/
	KeyStoreEntryContext(Provider *p) : BasicContext(p, "keystoreentry") {}

	virtual KeyStoreEntry::Type type() const = 0;
	virtual QString id() const = 0;
	virtual QString name() const = 0;
	virtual QString storeId() const = 0;
	virtual QString storeName() const = 0;
	virtual bool isAvailable() const;
	virtual QString serialize() const = 0;

	virtual KeyBundle keyBundle() const;
	virtual Certificate certificate() const;
	virtual CRL crl() const;
	virtual PGPKey pgpSecretKey() const;
	virtual PGPKey pgpPublicKey() const;

	virtual bool ensureAccess();
};

/**
   KeyStore provider
*/
class QCA_EXPORT KeyStoreListContext : public Provider::Context
{
	Q_OBJECT
public:
	/**
	   Standard constructor
	*/
	KeyStoreListContext(Provider *p) : Provider::Context(p, "keystorelist") {}

	virtual void start();

	// enable/disable update events
	virtual void setUpdatesEnabled(bool enabled);

	// returns a list of integer context ids (for keystores)
	virtual QList<int> keyStores() = 0;

	// null/empty return values mean the context id is gone

	virtual KeyStore::Type type(int id) const = 0;
	virtual QString storeId(int id) const = 0;
	virtual QString name(int id) const = 0;
	virtual bool isReadOnly(int id) const;

	virtual QList<KeyStoreEntry::Type> entryTypes(int id) const = 0;

	// caller must delete any returned KeyStoreEntryContexts

	virtual QList<KeyStoreEntryContext*> entryList(int id) = 0;

	// return 0 if no such entry
	virtual KeyStoreEntryContext *entry(int id, const QString &entryId);

	// thread-safe
	// return 0 if the provider doesn't handle or understand the string
	virtual KeyStoreEntryContext *entryPassive(const QString &serialized);

	virtual QString writeEntry(int id, const KeyBundle &kb);
	virtual QString writeEntry(int id, const Certificate &cert);
	virtual QString writeEntry(int id, const CRL &crl);
	virtual QString writeEntry(int id, const PGPKey &key);
	virtual bool removeEntry(int id, const QString &entryId);

Q_SIGNALS:
	// note: busyStart is assumed after calling start(), no need to emit
	void busyStart();
	void busyEnd();

	void updated();
	void diagnosticText(const QString &str);
	void storeUpdated(int id);
};

/**
   TLS "session" provider
*/
class QCA_EXPORT TLSSessionContext : public BasicContext
{
	Q_OBJECT
public:
	/**
	   Standard constructor
	*/
	TLSSessionContext(Provider *p) : BasicContext(p, "tlssession") {}
};

/**
   TLS provider
*/
class QCA_EXPORT TLSContext : public Provider::Context
{
	Q_OBJECT
public:
	class SessionInfo
	{
	public:
		bool isCompressed;
		TLS::Version version;
		QString cipherSuite;
		int cipherBits, cipherMaxBits;
		TLSSessionContext *id;
	};

	enum Result
	{
		Success,
		Error,
		Continue
	};

	/**
	   Standard constructor
	*/
	TLSContext(Provider *p, const QString &type) : Provider::Context(p, type) {}

	virtual void reset() = 0;

	virtual QStringList supportedCipherSuites(const TLS::Version &version) const = 0;
	virtual bool canCompress() const = 0;
	virtual bool canSetHostName() const = 0;
	virtual int maxSSF() const = 0;

	virtual void setConstraints(int minSSF, int maxSSF) = 0;
	virtual void setConstraints(const QStringList &cipherSuiteList) = 0;
	virtual void setup(bool serverMode, const QString &hostName, bool compress) = 0;
	virtual void setTrustedCertificates(const CertificateCollection &trusted) = 0;
	virtual void setIssuerList(const QList<CertificateInfoOrdered> &issuerList) = 0;
	virtual void setCertificate(const CertificateChain &cert, const PrivateKey &key) = 0;
	virtual void setSessionId(const TLSSessionContext &id) = 0;

	virtual void shutdown() = 0; // flag for shutdown, call update next
	virtual void setMTU(int size); // for dtls

	// start() results:
	//   result (Success or Error)
	virtual void start() = 0;

	// update() results:
	//   during handshake:
	//     result
	//     to_net
	//   during shutdown:
	//     result
	//     to_net
	//   else
	//     result (Success or Error)
	//     to_net
	//     encoded
	//     to_app
	//     eof
	// note: for dtls, this function only operates with single
	//       packets.  perform the operation repeatedly to send/recv
	//       multiple packets.
	virtual void update(const QByteArray &from_net, const QByteArray &from_app) = 0;

	virtual void waitForResultsReady(int msecs) = 0; // -1 means wait forever

	// results
	virtual Result result() const = 0;
	virtual QByteArray to_net() = 0;
	virtual int encoded() const = 0;
	virtual QByteArray to_app() = 0;
	virtual bool eof() const = 0;

	// call after handshake continue, but before success
	virtual bool clientHelloReceived() const = 0;
	virtual bool serverHelloReceived() const = 0;
	virtual QString hostName() const = 0;
	virtual bool certificateRequested() const = 0;
	virtual QList<CertificateInfoOrdered> issuerList() const = 0;

	// call after successful handshake
	virtual Validity peerCertificateValidity() const = 0;
	virtual CertificateChain peerCertificateChain() const = 0;
	virtual SessionInfo sessionInfo() const = 0;

	// call after shutdown
	virtual QByteArray unprocessed() = 0;

Q_SIGNALS:
	void resultsReady();
	void dtlsTimeout(); // call update, even with empty args
};

/**
   SASL provider
*/
class QCA_EXPORT SASLContext : public Provider::Context
{
	Q_OBJECT
public:
	class HostPort
	{
	public:
		QString addr;
		quint16 port;
	};

	enum Result
	{
		Success,
		Error,
		Params,
		AuthCheck,
		Continue
	};

	/**
	   Standard constructor
	*/
	SASLContext(Provider *p) : Provider::Context(p, "sasl") {}

	virtual void reset() = 0;

	virtual void setConstraints(SASL::AuthFlags f, int minSSF, int maxSSF) = 0;
	virtual void setup(const QString &service, const QString &host, const HostPort *local, const HostPort *remote, const QString &ext_id, int ext_ssf) = 0;

	// startClient() results:
	//   result
	//   mech
	//   haveClientInit
	//   stepData
	virtual void startClient(const QStringList &mechlist, bool allowClientSendFirst) = 0;

	// startServer() results:
	//   result (Success or Error)
	//   mechlist
	virtual void startServer(const QString &realm, bool disableServerSendLast) = 0;

	// serverFirstStep() results:
	//   result
	//   stepData
	virtual void serverFirstStep(const QString &mech, const QByteArray *clientInit) = 0;

	// nextStep() results:
	//   result
	//   stepData
	virtual void nextStep(const QByteArray &from_net) = 0;

	// tryAgain() results:
	//   result
	//   stepData
	virtual void tryAgain() = 0;

	// update() results:
	//   result (Success or Error)
	//   to_net
	//   encoded
	//   to_app
	virtual void update(const QByteArray &from_net, const QByteArray &from_app) = 0;

	virtual void waitForResultsReady(int msecs) = 0; // -1 means wait forever

	// results
	virtual Result result() const = 0;
	virtual QStringList mechlist() const = 0;
	virtual QString mech() const = 0;
	virtual bool haveClientInit() const = 0;
	virtual QByteArray stepData() const = 0;
	virtual QByteArray to_net() = 0;
	virtual int encoded() const = 0;
	virtual QByteArray to_app() = 0;

	// call after auth success
	virtual int ssf() const = 0;

	// call after auth fail
	virtual SASL::AuthCondition authCondition() const = 0;

	// call after Params
	virtual SASL::Params clientParams() const = 0;
	virtual void setClientParams(const QString *user, const QString *authzid, const SecureArray *pass, const QString *realm) = 0;

	// call after Params and SASL::Params::canSendRealm == true
	virtual QStringList realmlist() const = 0;

	// call after AuthCheck
	virtual QString username() const = 0;
	virtual QString authzid() const = 0;

Q_SIGNALS:
	void resultsReady();
};

/**
   SecureMessage provider
*/
class QCA_EXPORT MessageContext : public Provider::Context
{
	Q_OBJECT
public:
	enum Operation
	{
		Encrypt,
		Decrypt,
		Sign,
		Verify,
		SignAndEncrypt
	};

	/**
	   Standard constructor
	*/
	MessageContext(Provider *p, const QString &type) : Provider::Context(p, type) {}

	virtual bool canSignMultiple() const = 0;

	virtual SecureMessage::Type type() const = 0;

	virtual void reset() = 0;
	virtual void setupEncrypt(const SecureMessageKeyList &keys) = 0;
	virtual void setupSign(const SecureMessageKeyList &keys, SecureMessage::SignMode m, bool bundleSigner, bool smime) = 0;
	virtual void setupVerify(const QByteArray &detachedSig) = 0;

	virtual void start(SecureMessage::Format f, Operation op) = 0;
	virtual void update(const QByteArray &in) = 0;
	virtual QByteArray read() = 0;
	virtual int written() = 0;
	virtual void end() = 0;

	virtual bool finished() const = 0;
	virtual void waitForFinished(int msecs) = 0; // -1 means wait forever

	virtual bool success() const = 0;
	virtual SecureMessage::Error errorCode() const = 0;
	virtual QByteArray signature() const = 0;
	virtual QString hashName() const = 0;
	virtual SecureMessageSignatureList signers() const = 0;
	virtual QString diagnosticText() const;

Q_SIGNALS:
	void updated();
};

/**
   SecureMessageSystem provider
*/
class QCA_EXPORT SMSContext : public BasicContext
{
	Q_OBJECT
public:
	/**
	   Standard constructor
	*/
	SMSContext(Provider *p, const QString &type) : BasicContext(p, type) {}

	virtual void setTrustedCertificates(const CertificateCollection &trusted);
	virtual void setUntrustedCertificates(const CertificateCollection &untrusted);
	virtual void setPrivateKeys(const QList<SecureMessageKey> &keys);
	virtual MessageContext *createMessage() = 0;
};

}

#endif
