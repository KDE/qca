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

#include <qobject.h>
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

	enum DL_Group
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
	   Encryption algorithms
	*/
	enum EncryptionAlgorithm
	{
		EME_PKCS1v15,  ///< Block type 2 (PKCD1, Version 1.5)
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

	class QCA_EXPORT PKey : public Algorithm
	{
	public:
		enum Type { RSA, DSA, DH };

		PKey();
		PKey(const PKey &from);
		~PKey();

		PKey & operator=(const PKey &from);

		static QValueList<Type> supportedTypes(const QString &provider = QString());

		bool isNull() const;
		Type type() const;

		bool isRSA() const;
		bool isDSA() const;
		bool isDH() const;

		bool isPublic() const;
		bool isPrivate() const;

		bool canKeyAgree() const;

		PublicKey toPublicKey() const;
		PrivateKey toPrivateKey() const;

		friend class KeyGenerator;

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
		class Private;
		Private *d;
	};

	class QCA_EXPORT PublicKey : public PKey
	{
	public:
		PublicKey();
		PublicKey(const PrivateKey &k);

		RSAPublicKey toRSA() const;
		DSAPublicKey toDSA() const;
		DHPublicKey toDH() const;

		bool canEncrypt() const;
		bool canVerify() const;

		// encrypt / verify
		int maximumEncryptSize(EncryptionAlgorithm alg) const;
		QSecureArray encrypt(EncryptionAlgorithm alg, const QSecureArray &a);
		void startVerify(SignatureAlgorithm alg);
		void update(const QSecureArray &a);
		bool validSignature(const QSecureArray &sig);
		bool verifyMessage(SignatureAlgorithm alg, const QSecureArray &a, const QSecureArray &sig);

		// import / export
		QSecureArray toDER() const;
		QString toPEM() const;
		static PublicKey fromDER(const QSecureArray &a, const QString &provider = QString());
		static PublicKey fromPEM(const QString &s, const QString &provider = QString());

	protected:
		PublicKey(const QString &type, const QString &provider);

	private:
		friend class PrivateKey;
		friend class Certificate;
	};

	class QCA_EXPORT PrivateKey : public PKey
	{
	public:
		PrivateKey();

		RSAPrivateKey toRSA() const;
		DSAPrivateKey toDSA() const;
		DHPrivateKey toDH() const;

		bool canDecrypt() const;
		bool canSign() const;

		// decrypt / sign / key agreement
		bool decrypt(EncryptionAlgorithm alg, const QSecureArray &in, QSecureArray *out);
		void startSign(SignatureAlgorithm alg);
		void update(const QSecureArray &);
		QSecureArray signature();
		QSecureArray signMessage(SignatureAlgorithm alg, const QSecureArray &a);
		SymmetricKey deriveKey(const PublicKey &theirs);

		// import / export
		static bool canUsePBEAlgorithm(PBEAlgorithm algo, const QString &provider = QString());
		QSecureArray toDER(const QSecureArray &passphrase = QSecureArray(), PBEAlgorithm pbe = PBEDefault) const;
		QString toPEM(const QSecureArray &passphrase = QSecureArray(), PBEAlgorithm pbe = PBEDefault) const;
		static PrivateKey fromDER(const QSecureArray &a, const QSecureArray &passphrase = QSecureArray(), const QString &provider = QString());
		static PrivateKey fromPEM(const QString &s, const QSecureArray &passphrase = QSecureArray(), const QString &provider = QString());

	protected:
		PrivateKey(const QString &type, const QString &provider);

	private:
		friend class TLS;
	};

	class QCA_EXPORT KeyGenerator : public QObject
	{
		Q_OBJECT
	public:
		KeyGenerator(QObject *parent = 0, const char *name = 0);
		~KeyGenerator();

		bool blocking() const;
		void setBlocking(bool b);
		bool isBusy() const;

		void generateRSA(int bits, int exp = 65537, const QString &provider = QString());
		void generateDSA(DL_Group group, const QString &provider = QString());
		void generateDH(DL_Group group, const QString &provider = QString());
		PrivateKey result() const;

	signals:
		void finished();

	private:
		void done();

		class Private;
		Private *d;
	};

	class QCA_EXPORT RSAPublicKey : public PublicKey
	{
	public:
		RSAPublicKey();
		RSAPublicKey(const QBigInteger &n, const QBigInteger &e, const QString &provider = QString());
		RSAPublicKey(const RSAPrivateKey &k);

		QBigInteger n() const;
		QBigInteger e() const;
	};

	class QCA_EXPORT RSAPrivateKey : public PrivateKey
	{
	public:
		RSAPrivateKey();
		RSAPrivateKey(const QBigInteger &p, const QBigInteger &q, const QBigInteger &d, const QBigInteger &n, const QBigInteger &e, const QString &provider = QString());

		QBigInteger p() const;
		QBigInteger q() const;
		QBigInteger d() const;
		QBigInteger n() const;
		QBigInteger e() const;
	};

	class QCA_EXPORT DSAPublicKey : public PublicKey
	{
	public:
		DSAPublicKey();
		DSAPublicKey(DL_Group group, const QBigInteger &y, const QString &provider = QString());
		DSAPublicKey(const DSAPrivateKey &k);

		DL_Group domain() const;
		QBigInteger y() const;
	};

	class QCA_EXPORT DSAPrivateKey : public PrivateKey
	{
	public:
		DSAPrivateKey();
		DSAPrivateKey(DL_Group group, const QBigInteger &x, const QBigInteger &y, const QString &provider = QString());

		DL_Group domain() const;
		QBigInteger x() const;
		QBigInteger y() const;
	};

	class QCA_EXPORT DHPublicKey : public PublicKey
	{
	public:
		DHPublicKey();
		DHPublicKey(DL_Group group, const QBigInteger &y, const QString &provider = QString());
		DHPublicKey(const DHPrivateKey &k);

		DL_Group domain() const;
		QBigInteger y() const;
	};

	class QCA_EXPORT DHPrivateKey : public PrivateKey
	{
	public:
		DHPrivateKey();
		DHPrivateKey(DL_Group group, const QBigInteger &x, const QBigInteger &y, const QString &provider = QString());

		DL_Group domain() const;
		QBigInteger x() const;
		QBigInteger y() const;
	};
}

#endif
