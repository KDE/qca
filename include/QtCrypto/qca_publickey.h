/*
 * qca_publickey.h - Qt Cryptographic Architecture
 * Copyright (C) 2003-2005  Justin Karneges <justin@affinix.com>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef QCA_PUBLICKEY_H
#define QCA_PUBLICKEY_H

#include <QObject>
#include "qca_core.h"

namespace QCA
{
	class PublicKey;
	class PrivateKey;
	class KeyGenerator;
	class RSAPublicKey;
	class RSAPrivateKey;
	class DSAPublicKey;
	class DSAPrivateKey;
	class DHPublicKey;
	class DHPrivateKey;

	/**
	   Encryption algorithms
	*/
	enum EncryptionAlgorithm
	{
		EME_PKCS1v15,  ///< Block type 2 (PKCS1, Version 1.5)
		EME_PKCS1_OAEP ///< Optimal asymmetric encryption padding (PKCS1, Version 2.0)
	};

	/**
	   Signature algorithm variants
	*/
	enum SignatureAlgorithm
	{
		SignatureUnknown, ///< Unknown signing algorithm
		EMSA1_SHA1,  ///< SHA1, with EMSA1 (IEEE1363-2000) encoding (this is the usual DSA algorithm - FIPS186)
		EMSA3_SHA1,  ///< SHA1, with EMSA3 (ie PKCS1 Version 1.5) encoding
		EMSA3_MD5,   ///< MD5, with EMSA3 (ie PKCS1 Version 1.5) encoding (this is the usual RSA algorithm)
		EMSA3_MD2,   ///< MD2, with EMSA3 (ie PKCS1 Version 1.5) encoding
		EMSA3_RIPEMD160 ///< RIPEMD160, with EMSA3 (ie PKCS1 Version 1.5) encoding
	};

	/**
	   Signature formats (DSA only)
	*/
	enum SignatureFormat
	{
		DefaultFormat, ///< For DSA, this is the same as IEEE_1363
		IEEE_1363,     ///< 40-byte format from IEEE 1363 (Botan/.NET)
		DERSequence    ///< Signature wrapped in DER formatting (OpenSSL/Java)
	};

	/**
	   Password-based encryption
	*/
	enum PBEAlgorithm
	{
		PBEDefault,           ///< Use modern default (same as PBES2_TripleDES_SHA1)
		PBES2_DES_SHA1,       ///< PKCS#5 v2.0 DES/CBC,SHA1
		PBES2_TripleDES_SHA1, ///< PKCS#5 v2.0 TripleDES/CBC,SHA1
		PBES2_AES128_SHA1,    ///< PKCS#5 v2.0 AES-128/CBC,SHA1
		PBES2_AES192_SHA1,    ///< PKCS#5 v2.0 AES-192/CBC,SHA1
		PBES2_AES256_SHA1     ///< PKCS#5 v2.0 AES-256/CBC,SHA1
	};

	/**
	   Return value from a format conversion

	   Note that if you are checking for any result other than ConvertGood,
	   then you may be introducing a provider specific dependency.
	*/
	enum ConvertResult
	{
		ConvertGood,      ///< Conversion succeeded, results should be valid
		ErrorDecode,      ///< General failure in the decode stage
		ErrorPassphrase,  ///< Failure because of incorrect pass phrase
		ErrorFile         ///< Failure because of incorrect file
	};

	/**
	   Well known discrete logarithm group sets
	*/
	enum DLGroupSet
	{
		DSA_512,
		DSA_768,
		DSA_1024,
		IETF_768,
		IETF_1024,
		IETF_1536,
		IETF_2048,
		IETF_3072,
		IETF_4096
	};

	/**
	   A discrete logarithm group
	*/
	class DLGroup
	{
	public:
		DLGroup();

		/**
		   Construct a discrete logarithm group from raw parameters

		   \param p
		   \param q
		   \param g
		*/
		DLGroup(const QBigInteger &p, const QBigInteger &q, const QBigInteger &g);

		/**
		   Construct a discrete logarithm group from raw parameters

		   \param p
		   \param g
		*/
		DLGroup(const QBigInteger &p, const QBigInteger &g);

		/**
		   Standard copy constructor
		*/
		DLGroup(const DLGroup &from);
		~DLGroup();
		DLGroup & operator=(const DLGroup &from);

		/**
		   Provide a list of the supported group sets

		   \param provider the provider to report which group sets are available. If not
		   specified, all providers will be checked
		*/
		static QList<DLGroupSet> supportedGroupSets(const QString &provider = QString());

		/**
		   Test if the group is empty
		*/
		bool isNull() const;

		/**
		   Provide the p component of the group
		*/
		QBigInteger p() const;

		/**
		   Provide the q component of the group
		*/
		QBigInteger q() const;

		/**
		   Provide the g component of the group
		*/
		QBigInteger g() const;

	private:
		class Private;
		Private *d;
	};

	/**
	   General superclass for public (PublicKey) and private (PrivateKey) keys
	   used with asymmetric encryption techniques.
	*/
	class QCA_EXPORT PKey : public Algorithm
	{
	public:
		/**
		   Types of public key cryptography keys supported by QCA
		*/
		enum Type { 
			RSA, ///< RSA key
			DSA, ///< DSA key
			DH   ///< Diffie Hellman key
		};

		PKey();
		PKey(const PKey &from);
		~PKey();

		PKey & operator=(const PKey &from);

		static QList<Type> supportedTypes(const QString &provider = QString());
		static QList<Type> supportedIOTypes(const QString &provider = QString());

		/**
		   Test if the key is null (empty)

		   \return true if the key is null
		*/
		bool isNull() const;

		/**
		   Report the Type of key (eg RSA, DSA or Diffie Hellman)
		   
		   \sa isRSA, isDSA and isDH for boolean tests.
		*/
		Type type() const;

		/**
		   Report the number of bits in the key
		*/
		int bitSize() const;

		/**
		   Test if the key is an RSA key
		*/
		bool isRSA() const;

		/**
		   Test if the key is a DSA key
		*/
		bool isDSA() const;

		/**
		   Test if the key is a Diffie Hellman key
		*/
		bool isDH() const;

		/**
		   Test if the key is a public key
		*/
		bool isPublic() const;	

		/**
		   Test if the key is a private key
		*/
		bool isPrivate() const;

		/**
		   Test if the key data can be exported.  If the key resides on a smart
		   card or other such device, this will likely return false.
		*/
		bool canExport() const;

		/**
		   Test if the key can be used for key agreement
		*/
		bool canKeyAgree() const;

		PublicKey toPublicKey() const;
		PrivateKey toPrivateKey() const;

		bool operator==(const PKey &a) const;
		bool operator!=(const PKey &a) const;

	protected:
		PKey(const QString &type, const QString &provider);
		void set(const PKey &k);

		RSAPublicKey toRSAPublicKey() const;
		RSAPrivateKey toRSAPrivateKey() const;
		DSAPublicKey toDSAPublicKey() const;
		DSAPrivateKey toDSAPrivateKey() const;
		DHPublicKey toDHPublicKey() const;
		DHPrivateKey toDHPrivateKey() const;

	private:
		void assignToPublic(PKey *dest) const;
		void assignToPrivate(PKey *dest) const;

		class Private;
		Private *d;
	};

	/**
	   Generic public key
	*/
	class QCA_EXPORT PublicKey : public PKey
	{
	public:
		PublicKey();
		PublicKey(const PrivateKey &k);
		PublicKey(const QString &fileName);

		/**
		   Convenience method to convert this key to an RSAPublicKey

		   Note that if the key is not an RSA key (eg it is DSA or DH),
		   then this will produce a null key.
		*/
		RSAPublicKey toRSA() const;

		/**
		   Convenience method to convert this key to a DSAPublicKey

		   Note that if the key is not an DSA key (eg it is RSA or DH),
		   then this will produce a null key.
		*/
		DSAPublicKey toDSA() const;

		/**
		   Convenience method to convert this key to a DHPublicKey

		   Note that if the key is not an RSA key (eg it is DSA or RSA),
		   then this will produce a null key.
		*/
		DHPublicKey toDH() const;

		/**
		   Test if this key can be used for encryption

		   \return true if the key can be used for encryption
		*/
		bool canEncrypt() const;

		/**
		   Test if the key can be used for verifying signatures

		   \return true of the key can be used for verification
		*/
		bool canVerify() const;

		// encrypt / verify
		int maximumEncryptSize(EncryptionAlgorithm alg) const;
		QSecureArray encrypt(const QSecureArray &a, EncryptionAlgorithm alg) const;
		void startVerify(SignatureAlgorithm alg, SignatureFormat format = DefaultFormat);
		void update(const QSecureArray &a);
		bool validSignature(const QSecureArray &sig);
		bool verifyMessage(const QSecureArray &a, const QSecureArray &sig, SignatureAlgorithm alg, SignatureFormat format = DefaultFormat);


		/**
		   Export the key in Distinguished Encoding Rules (DER) format
		*/
		QSecureArray toDER() const;

		/**
		   Export the key in Privacy Enhanced Mail (PEM) format

		   \sa toPEMFile provides a convenient way to save the PEM encoded key to a file
		   \sa fromPEM provides an inverse of toPEM, converting the PEM encoded key back to a PublicKey
		*/
		QString toPEM() const;

		/**
		   Export the key in Privacy Enhanced Mail (PEM) to a file

		   \param fileName the name (and path, if necessary) of the file to save the
		   PEM encoded key to.

		   \sa toPEM for a version that exports to a QString, which may be useful if you
		   need to do more sophisticated handling
		   \sa fromPEMFile provides an inverse of toPEMFile, reading a PEM encoded key from a file
		*/
		bool toPEMFile(const QString &fileName) const;

		/**
		   Import a key in Distinguished Encoding Rules (DER) format

		   This function takes a binary array, which is assumed to contain a public key
		   in DER encoding, and returns the key. Unless you don't care whether the import
		   succeeded, you should test the result, as shown below.

		   \code
		   QCA::ConvertResult conversionResult;
		   QCA::PublicKey publicKey = QCA::PublicKey::fromDER(keyArray, &conversionResult);
		   if (! QCA::ConvertGood == conversionResult) {
		       std::cout << "Public key read failed" << std::endl;
		   }
		   \endcode


		   \param a the array containing a DER encoded key
		   \param result pointer to a variable, which returns whether the conversion succeeded (ConvertGood) or not
		   \param provider the name of the provider to use for the import.
		*/
		static PublicKey fromDER(const QSecureArray &a, ConvertResult *result = 0, const QString &provider = QString());

		/**
		   Import a key in Privacy Enhanced Mail (PEM) format

		   This function takes a string, which is assumed to contain a public key
		   in PEM encoding, and returns that key. Unless you don't care whether the import
		   succeeded, you should test the result, as shown below.

		   \code
		   QCA::ConvertResult conversionResult;
		   QCA::PublicKey publicKey = QCA::PublicKey::fromPEM(keyAsString, &conversionResult);
		   if (! QCA::ConvertGood == conversionResult) {
		       std::cout << "Public key read failed" << std::endl;
		   }
		   \endcode

		   \param s the string containing a PEM encoded key
		   \param result pointer to a variable, which returns whether the conversion succeeded (ConvertGood) or not
		   \param provider the name of the provider to use for the import.

		   \sa toPEM, which provides an inverse of fromPEM()
		   \sa fromPEMFile, which provides an import direct from a file.
		*/
		static PublicKey fromPEM(const QString &s, ConvertResult *result = 0, const QString &provider = QString());

		/**
		   Import a key in Privacy Enhanced Mail (PEM) format from a file

		   This function takes the name of a file, which is assumed to contain a public key
		   in PEM encoding, and returns that key. Unless you don't care whether the import
		   succeeded, you should test the result, as shown below.

		   \code
		   QCA::ConvertResult conversionResult;
		   QCA::PublicKey publicKey = QCA::PublicKey::fromPEMFile(fileName, &conversionResult);
		   if (! QCA::ConvertGood == conversionResult) {
		       std::cout << "Public key read failed" << std::endl;
		   }
		   \endcode

		   \param fileName a string containing the name of the file
		   \param result pointer to a variable, which returns whether the conversion succeeded (ConvertGood) or not
		   \param provider the name of the provider to use for the import.

		   \sa toPEMFile, which provides an inverse of fromPEMFile()
		   \sa fromPEM, which provides an import from a string
		*/
		static PublicKey fromPEMFile(const QString &fileName, ConvertResult *result = 0, const QString &provider = QString());

	protected:
		PublicKey(const QString &type, const QString &provider);
	};

	/**
	   Generic private key
	*/
	class QCA_EXPORT PrivateKey : public PKey
	{
	public:
		PrivateKey();
		PrivateKey(const QString &fileName, const QSecureArray &passphrase = QSecureArray());

		/**
		   Interpret / convert the key to an RSA key
		*/
		RSAPrivateKey toRSA() const;
		
		/**
		   Interpret / convert the key to a DSA key
		*/
		DSAPrivateKey toDSA() const;

		/**
		   Interpret / convert the key to a Diffie-Hellman key
		*/
		DHPrivateKey toDH() const;

		/**
		   Test if this key can be used for decryption

		   \return true if the key can be used for decryption
		*/
		bool canDecrypt() const;

		/**
		   Test if this key can be used for signing

		   \return true if the key can be used to make a signature
		*/
		bool canSign() const;

		// decrypt / sign / key agreement
		bool decrypt(const QSecureArray &in, QSecureArray *out, EncryptionAlgorithm alg) const;
		void startSign(SignatureAlgorithm alg, SignatureFormat format = DefaultFormat);
		void update(const QSecureArray &a);
		QSecureArray signature();
		QSecureArray signMessage(const QSecureArray &a, SignatureAlgorithm alg, SignatureFormat = DefaultFormat);
		SymmetricKey deriveKey(const PublicKey &theirs) const;

		// import / export
		static QList<PBEAlgorithm> supportedPBEAlgorithms(const QString &provider = QString());
		QSecureArray toDER(const QSecureArray &passphrase = QSecureArray(), PBEAlgorithm pbe = PBEDefault) const;
		QString toPEM(const QSecureArray &passphrase = QSecureArray(), PBEAlgorithm pbe = PBEDefault) const;
		bool toPEMFile(const QString &fileName, const QSecureArray &passphrase = QSecureArray(), PBEAlgorithm pbe = PBEDefault) const;
		static PrivateKey fromDER(const QSecureArray &a, const QSecureArray &passphrase = QSecureArray(), ConvertResult *result = 0, const QString &provider = QString());
		static PrivateKey fromPEM(const QString &s, const QSecureArray &passphrase = QSecureArray(), ConvertResult *result = 0, const QString &provider = QString());
		static PrivateKey fromPEMFile(const QString &fileName, const QSecureArray &passphrase = QSecureArray(), ConvertResult *result = 0, const QString &provider = QString());

	protected:
		PrivateKey(const QString &type, const QString &provider);
	};

	/**
	   Class for generating asymmetric key pairs

	   This class is used for generating asymmetric keys (public/private key pairs)
	*/
	class QCA_EXPORT KeyGenerator : public QObject
	{
		Q_OBJECT
	public:
		KeyGenerator(QObject *parent = 0);
		~KeyGenerator();

		bool blocking() const;
		void setBlocking(bool b);
		bool isBusy() const;

		/**
		   Generate an RSA key of the specified length

		   This method creates both the public key and corresponding private key. You
		   almost certainly want to extract the public key part out - see PKey::toPublicKey
		   for an easy way.

		   Key length is a tricky judgement - using less than 2048 is probably being
		   too liberal for long term use. Don't use less than 1024 without serious
		   analysis.
		   
		   \param bits the length of key that is required
		   \param exp the exponent - typically 3, 17 or 65537
		   \param provider the name of the provider to use
		*/
		PrivateKey createRSA(int bits, int exp = 65537, const QString &provider = QString());

		PrivateKey createDSA(const DLGroup &domain, const QString &provider = QString());
		PrivateKey createDH(const DLGroup &domain, const QString &provider = QString());
		PrivateKey key() const;

		DLGroup createDLGroup(QCA::DLGroupSet set, const QString &provider = QString());
		DLGroup dlGroup() const;

	signals:
		void finished();

	public:
		class Private;
	private:
		friend class Private;
		Private *d;
	};

	/**
	   RSA Public Key
	*/
	class QCA_EXPORT RSAPublicKey : public PublicKey
	{
	public:
		RSAPublicKey();
		RSAPublicKey(const QBigInteger &n, const QBigInteger &e, const QString &provider = QString());
		RSAPublicKey(const RSAPrivateKey &k);

		/**
		   The public key value

		   This value is the actual public key value (the product of p and q, the random prime numbers
		   used to generate the RSA key), also known as the public modulus.
		*/
		QBigInteger n() const;

		/**
		   The public key exponent

		   This value is the exponent chosen in the original key generator step
		*/
		QBigInteger e() const;
	};

	/**
	   RSA Private Key
	*/
	class QCA_EXPORT RSAPrivateKey : public PrivateKey
	{
	public:
		RSAPrivateKey();
		RSAPrivateKey(const QBigInteger &n, const QBigInteger &e, const QBigInteger &p, const QBigInteger &q, const QBigInteger &d, const QString &provider = QString());

		QBigInteger n() const;
		QBigInteger e() const;
		QBigInteger p() const;
		QBigInteger q() const;
		QBigInteger d() const;
	};

	/**
	   Digital Signature Algorithm Public Key
	*/
	class QCA_EXPORT DSAPublicKey : public PublicKey
	{
	public:
		DSAPublicKey();
		DSAPublicKey(const DLGroup &domain, const QBigInteger &y, const QString &provider = QString());
		DSAPublicKey(const DSAPrivateKey &k);

		DLGroup domain() const;
		QBigInteger y() const;
	};

	/**
	   Digital Signature Algorithm Private Key
	*/
	class QCA_EXPORT DSAPrivateKey : public PrivateKey
	{
	public:
		DSAPrivateKey();
		DSAPrivateKey(const DLGroup &domain, const QBigInteger &y, const QBigInteger &x, const QString &provider = QString());

		DLGroup domain() const;
		QBigInteger y() const;
		QBigInteger x() const;
	};

	/**
	   Diffie-Hellman Public Key
	*/
	class QCA_EXPORT DHPublicKey : public PublicKey
	{
	public:
		DHPublicKey();
		DHPublicKey(const DLGroup &domain, const QBigInteger &y, const QString &provider = QString());
		DHPublicKey(const DHPrivateKey &k);

		DLGroup domain() const;
		QBigInteger y() const;
	};

	/**
	   Diffie-Hellman Private Key
	*/
	class QCA_EXPORT DHPrivateKey : public PrivateKey
	{
	public:
		DHPrivateKey();
		DHPrivateKey(const DLGroup &domain, const QBigInteger &y, const QBigInteger &x, const QString &provider = QString());

		DLGroup domain() const;
		QBigInteger y() const;
		QBigInteger x() const;
	};
}

#endif
