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

	   Returns an empty array on error.
	*/
	virtual QByteArray publicToDER() const;

	/**
	   Convert a public key to PEM format, and return the value

	   Returns an empty string on error.
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

	   Returns an empty array on error.

	   \param passphrase the passphrase to encode the result with, or an
	   empty array if no encryption is desired
	   \param pbe the encryption algorithm to use, if applicable
	*/
	virtual SecureArray privateToDER(const SecureArray &passphrase, PBEAlgorithm pbe) const;

	/**
	   Convert a private key to PEM format, and return the value

	   Returns an empty string on error.

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

	/**
	   Convert this object to DER format, and return the value

	   Returns an empty array on error.
	*/
	virtual QByteArray toDER() const = 0;

	/**
	   Convert this object to PEM format, and return the value

	   Returns an empty string on error.
	*/
	virtual QString toPEM() const = 0;

	/**
	   Read DER-formatted input and convert it into this object

	   Returns QCA::ConvertGood if successful, otherwise some error
	   value.

	   \param a the input data
	*/
	virtual ConvertResult fromDER(const QByteArray &a) = 0;

	/**
	   Read PEM-formatted input and convert it into this object

	   Returns QCA::ConvertGood if successful, otherwise some error
	   value.

	   \param s the input data
	*/
	virtual ConvertResult fromPEM(const QString &s) = 0;
};

/**
   X.509 certificate or certificate request properties

   Some fields are only for certificates or only for certificate requests,
   and these fields are noted.
*/
class QCA_EXPORT CertContextProps
{
public:
	/**
	   The X.509 certificate version, usually 3

	   This field is for certificates only.
	*/
	int version;

	/**
	   The time the certificate becomes valid (often the time of create)

	   This field is for certificates only.
	*/
	QDateTime start;

	/**
	   The time the certificate expires

	   This field is for certificates only.
	*/
	QDateTime end;

	/**
	   The subject information
	*/
	CertificateInfoOrdered subject;

	/**
	   The issuer information

	   This field is for certificates only.
	*/
	CertificateInfoOrdered issuer;

	/**
	   The constraints
	*/
	Constraints constraints;

	/**
	   The policies
	*/
	QStringList policies;

	/**
	   A list of URIs for CRLs

	   This field is for certificates only.
	*/
	QStringList crlLocations;

	/**
	   A list of URIs for issuer certificates

	   This field is for certificates only.
	*/
	QStringList issuerLocations;

	/**
	   A list of URIs for OCSP services

	   This field is for certificates only.
	*/
	QStringList ocspLocations;

	/**
	   The certificate serial number

	   This field is for certificates only.
	*/
	BigInteger serial;

	/**
	   True if the certificate is a CA or the certificate request is
	   requesting to be a CA, otherwise false
	*/
	bool isCA;

	/**
	   True if the certificate is self-signed

	   This field is for certificates only.
	*/
	bool isSelfSigned;

	/**
	   The path limit
	*/
	int pathLimit;

	/**
	   The signature data
	*/
	QByteArray sig;

	/**
	   The signature algorithm used to create the signature
	*/
	SignatureAlgorithm sigalgo;

	/**
	   The subject id

	   This field is for certificates only.
	*/
	QByteArray subjectId;

	/**
	   The issuer id

	   This field is for certificates only.
	*/
	QByteArray issuerId;

	/**
	   The SPKAC challenge value

	   This field is for certificate requests only.
	*/
	QString challenge;

	/**
	   The format used for the certificate request

	   This field is for certificate requests only.
	*/
	CertificateRequestFormat format;
};

/**
   X.509 certificate revocation list properties

   For efficiency and simplicity, the members are directly accessed.
*/
class QCA_EXPORT CRLContextProps
{
public:
	/**
	   The issuer information of the CRL
	*/
	CertificateInfoOrdered issuer;

	/**
	   The CRL number, which increases at each update
	*/
	int number;

	/**
	   The time this CRL was created
	*/
	QDateTime thisUpdate;

	/**
	   The time this CRL expires, and the next CRL should be fetched
	*/
	QDateTime nextUpdate;

	/**
	   The revoked entries
	*/
	QList<CRLEntry> revoked;

	/**
	   The signature data of the CRL
	*/
	QByteArray sig;

	/**
	   The signature algorithm used by the issuer to sign the CRL
	*/
	SignatureAlgorithm sigalgo;

	/**
	   The issuer id
	*/
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

	/**
	   Create a self-signed certificate based on the given options and
	   private key.  Returns true if successful, otherwise false.

	   If successful, this object becomes the self-signed certificate.
	   If unsuccessful, this object is considered to be in an
	   uninitialized state.
	*/
	virtual bool createSelfSigned(const CertificateOptions &opts, const PKeyContext &priv) = 0;

	/**
	   Returns a pointer to the properties of this certificate
	*/
	virtual const CertContextProps *props() const = 0;

	/**
	   Returns true if this certificate is equal to another certificate,
	   otherwise false

	   \param other the certificate to compare with
	*/
	virtual bool compare(const CertContext *other) const = 0;

	/**
	   Returns a copy of this certificate's public key.  The caller is
	   responsible for deleting it.
	*/
	virtual PKeyContext *subjectPublicKey() const = 0;

	/**
	   Returns true if this certificate is an issuer of another
	   certificate, otherwise false

	   \param other the issued certificate to check
	*/
	virtual bool isIssuerOf(const CertContext *other) const = 0;

	/**
	   Validate this certificate

	   This function is blocking.

	   \param trusted list of trusted certificates
	   \param untrusted list of untrusted certificates (can be empty)
	   \param crls list of CRLs (can be empty)
	   \param u the desired usage for this certificate
	   \param vf validation options
	*/
	virtual Validity validate(const QList<CertContext*> &trusted, const QList<CertContext*> &untrusted, const QList<CRLContext*> &crls, UsageMode u, ValidateFlags vf) const = 0;

	/**
	   Validate a certificate chain.  This function makes no use of the
	   certificate represented by this object, and it can be used even
	   if this object is in an uninitialized state.

	   This function is blocking.

	   \param chain list of certificates in the chain, starting with the
	   user certificate.  It is not necessary for the chain to contain
	   the final root certificate.
	   \param trusted list of trusted certificates
	   \param crls list of CRLs (can be empty)
	   \param u the desired usage for the user certificate in the chain
	   \param vf validation options
	*/
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

	/**
	   Returns true if the provider of this object supports the specified
	   format, otherwise false
	*/
	virtual bool canUseFormat(CertificateRequestFormat f) const = 0;

	/**
	   Create a certificate request based on the given options and
	   private key.  Returns true if successful, otherwise false.

	   If successful, this object becomes the certificate request.
	   If unsuccessful, this object is considered to be in an
	   uninitialized state.
	*/
	virtual bool createRequest(const CertificateOptions &opts, const PKeyContext &priv) = 0;

	/**
	   Returns a pointer to the properties of this certificate request
	*/
	virtual const CertContextProps *props() const = 0;

	/**
	   Returns true if this certificate request is equal to another
	   certificate request, otherwise false

	   \param other the certificate request to compare with
	*/
	virtual bool compare(const CSRContext *other) const = 0;

	/**
	   Returns a copy of this certificate request's public key.  The
	   caller is responsible for deleting it.
	*/
	virtual PKeyContext *subjectPublicKey() const = 0;

	/**
	   Convert this certificate request to Netscape SPKAC format, and
	   return the value

	   Returns an empty string on error.
	*/
	virtual QString toSPKAC() const = 0;

	/**
	   Read Netscape SPKAC input and convert it into a certificate
	   request

	   Returns QCA::ConvertGood if successful, otherwise some error
	   value.

	   \param s the input data
	*/
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

	/**
	   Returns a pointer to the properties of this CRL
	*/
	virtual const CRLContextProps *props() const = 0;

	/**
	   Returns true if this CRL is equal to another CRL, otherwise false

	   \param other the CRL to compare with
	*/
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

	/**
	   Create PKCS#7 DER output based on the input certificates and CRLs

	   Returns an empty array on error.
	*/
	virtual QByteArray toPKCS7(const QList<CertContext*> &certs, const QList<CRLContext*> &crls) const = 0;

	/**
	   Read PKCS#7 DER input and convert it into a list of certificates
	   and CRLs

	   The caller is responsible for deleting the returned items.

	   Returns QCA::ConvertGood if successful, otherwise some error
	   value.

	   \param a the input data
	   \param certs the destination list for the certificates
	   \param crls the destination list for the CRLs
	*/
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

	/**
	   Prepare the object for usage

	   This must be called before any CA operations are performed.

	   \param cert the certificate of the CA
	   \param priv the private key of the CA
	*/
	virtual void setup(const CertContext &cert, const PKeyContext &priv) = 0;

	/**
	   Returns a copy of the CA's certificate.  The caller is responsible
	   for deleting it.
	*/
	virtual CertContext *certificate() const = 0;

	/**
	   Issue a certificate based on a certificate request, and return
	   the certificate.  The caller is responsible for deleting it.

	   \param req the certificate request
	   \param notValidAfter the expiration date
	*/
	virtual CertContext *signRequest(const CSRContext &req, const QDateTime &notValidAfter) const = 0;

	/**
	   Issue a certificate based on a public key and options, and return
	   the certificate.  The caller is responsible for deleting it.

	   \param pub the public key of the certificate
	   \param opts the options to use for generation
	*/
	virtual CertContext *createCertificate(const PKeyContext &pub, const CertificateOptions &opts) const = 0;

	/**
	   Create a new CRL and return it.  The caller is responsible for
	   deleting it.

	   The CRL has no entries in it.

	   \param nextUpdate the expiration date of the CRL
	*/
	virtual CRLContext *createCRL(const QDateTime &nextUpdate) const = 0;

	/**
	   Update an existing CRL, by examining an old one and creating a new
	   one based on it.  The new CRL is returned, and the caller is
	   responsible for deleting it.

	   \param crl an existing CRL issued by this CA
	   \param entries the list of revoked entries
	   \param nextUpdate the expiration date of the new CRL
	*/
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

	/**
	   Create PKCS#12 DER output based on a set of input items

	   Returns an empty array on error.

	   \param name the friendly name of the data
	   \param chain the certificate chain to store
	   \param priv the private key to store
	   \param passphrase the passphrase to encrypt the PKCS#12 data with
	*/
	virtual QByteArray toPKCS12(const QString &name, const QList<const CertContext*> &chain, const PKeyContext &priv, const SecureArray &passphrase) const = 0;

	/**
	   Read PKCS#12 DER input and convert it into a set of output items

	   The caller is responsible for deleting the returned items.

	   Returns QCA::ConvertGood if successful, otherwise some error
	   value.

	   \param in the input data
	   \param passphrase the passphrase needed to decrypt the input data
	   \param name the destination string for the friendly name
	   \param chain the destination list for the certificate chain
	   \param priv address of a pointer to accept the private key
	*/
	virtual ConvertResult fromPKCS12(const QByteArray &in, const SecureArray &passphrase, QString *name, QList<CertContext*> *chain, PKeyContext **priv) const = 0;
};

/**
   OpenPGP key properties

   For efficiency and simplicity, the members are directly accessed.
*/
class QCA_EXPORT PGPKeyContextProps
{
public:
	/**
	   The key id
	*/
	QString keyId;

	/**
	   List of user id strings for the key, the first one being the
	   primary user id
	*/
	QStringList userIds;

	/**
	   True if this key is a secret key, otherwise false
	*/
	bool isSecret;

	/**
	   The time the key was created
	*/
	QDateTime creationDate;

	/**
	   The time the key expires
	*/
	QDateTime expirationDate;

	/**
	   The hex fingerprint of the key

	   The format is all lowercase with no spaces.
	*/
	QString fingerprint;

	/**
	   True if this key is in a keyring (and thus usable), otherwise
	   false
	*/
	bool inKeyring;

	/**
	   True if this key is trusted (e.g. signed by the keyring owner or
	   via some web-of-trust), otherwise false
	*/
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

	/**
	   Returns a pointer to the properties of this key
	*/
	virtual const PGPKeyContextProps *props() const = 0;

	/**
	   Convert the key to binary format, and return the value
	*/
	virtual QByteArray toBinary() const = 0;

	/**
	   Convert the key to ascii-armored format, and return the value
	*/
	virtual QString toAscii() const = 0;

	/**
	   Read binary input and convert it into a key

	   Returns QCA::ConvertGood if successful, otherwise some error
	   value.

	   \param a the input data
	*/
	virtual ConvertResult fromBinary(const QByteArray &a) = 0;

	/**
	   Read ascii-armored input and convert it into a key

	   Returns QCA::ConvertGood if successful, otherwise some error
	   value.

	   \param s the input data
	*/
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

	/**
	   Returns the entry type
	*/
	virtual KeyStoreEntry::Type type() const = 0;

	/**
	   Returns the entry id

	   This id must be unique among all other entries in the same store.
	*/
	virtual QString id() const = 0;

	/**
	   Returns the name of this entry
	*/
	virtual QString name() const = 0;

	/**
	   Returns the id of the store that contains this entry
	*/
	virtual QString storeId() const = 0;

	/**
	   Returns the name of the store that contains this entry
	*/
	virtual QString storeName() const = 0;

	/**
	   Returns true if the private key of this entry is present for use
	*/
	virtual bool isAvailable() const;

	/**
	   Serialize the information about this entry

	   This allows the entry object to be restored later, even if the
	   store that contains it is not present.

	   \sa KeyStoreListContext::entryPassive()
	*/
	virtual QString serialize() const = 0;

	/**
	   If this entry is of type KeyStoreEntry::TypeKeyBundle, this
	   function returns the KeyBundle of the entry
	*/
	virtual KeyBundle keyBundle() const;

	/**
	   If this entry is of type KeyStoreEntry::TypeCertificate, this
	   function returns the Certificate of the entry
	*/
	virtual Certificate certificate() const;

	/**
	   If this entry is of type KeyStoreEntry::TypeCRL, this function
	   returns the CRL of the entry
	*/
	virtual CRL crl() const;

	/**
	   If this entry is of type KeyStoreEntry::TypePGPSecretKey, this
	   function returns the secret PGPKey of the entry
	*/
	virtual PGPKey pgpSecretKey() const;

	/**
	   If this entry is of type KeyStoreEntry::TypePGPPublicKey or
	   KeyStoreEntry::TypePGPSecretKey, this function returns the public
	   PGPKey of the entry
	*/
	virtual PGPKey pgpPublicKey() const;

	/**
	   Attempt to ensure the private key of this entry is usable and
	   accessible, potentially prompting the user and/or performing a
	   login to a token device.  Returns true if the entry is now
	   accessible, or false if the entry cannot be made accessible.

	   This function is blocking.
	*/
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
		int cipherBits;
		int cipherMaxBits;
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

	/**
	   Set the trusted certificates and for this secure message system,
	   to be used for validation

	   The collection may also contain CRLs.

	   This function is only valid for CMS.
	*/
	virtual void setTrustedCertificates(const CertificateCollection &trusted);

	/**
	   Set the untrusted certificates and CRLs for this secure message
	   system, to be used for validation

	   This function is only valid for CMS.
	*/
	virtual void setUntrustedCertificates(const CertificateCollection &untrusted);

	/**
	   Set the private keys for this secure message system, to be used
	   for decryption

	   This function is only valid for CMS.
	*/
	virtual void setPrivateKeys(const QList<SecureMessageKey> &keys);

	/**
	   Create a new message object for this system.  The caller is
	   responsible for deleting it.
	*/
	virtual MessageContext *createMessage() = 0;
};

}

#endif
