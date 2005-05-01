/*
 * qca_cert.h - Qt Cryptographic Architecture
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

#ifndef QCA_CERT_H
#define QCA_CERT_H

#include <QMap>
#include <QDateTime>
#include "qca_core.h"
#include "qca_publickey.h"

namespace QCA
{
	class CertificateCollection;

	/**
	   Certificate Request Format
	*/
	enum CertificateRequestFormat
	{
		PKCS10, ///< standard PKCS#10 format
		SPKAC   ///< Signed Public Key and Challenge (Netscape) format
	};

	/**
	   Certificate information types
	*/
	enum CertificateInfoType
	{
		CommonName,
		Email,
		Organization,
		OrganizationalUnit,
		Locality,
		State,
		Country,
		URI,
		DNS,
		IPAddress,
		XMPP
	};

	/**
	   Certificate constraints
	*/
	enum ConstraintType
	{
		// basic
		DigitalSignature,
		NonRepudiation,
		KeyEncipherment,
		DataEncipherment,
		KeyAgreement,
		KeyCertificateSign,
		CRLSign,
		EncipherOnly,
		DecipherOnly,

		// extended
		ServerAuth,
		ClientAuth,
		CodeSigning,
		EmailProtection,
		IPSecEndSystem,
		IPSecTunnel,
		IPSecUser,
		TimeStamping,
		OCSPSigning
	};

	/**
	   Specify the intended usage of a certificate
	*/
	enum UsageMode
	{
		UsageAny             = 0x00, ///< Any application, or unspecified
		UsageTLSServer       = 0x01, ///< server side of a TLS or SSL connection
		UsageTLSClient       = 0x02, ///< client side of a TLS or SSL connection
		UsageCodeSigning     = 0x04, ///< code signing certificate
		UsageEmailProtection = 0x08, ///< email (S/MIME) certificate
		UsageTimeStamping    = 0x10, ///< time stamping certificate
		UsageCRLSigning      = 0x20  ///< certificate revocation list signing certificate
	};

	/**
	   The validity (or otherwise) of a certificate
	*/
	enum Validity
	{
		ValidityGood,            ///< The certificate is valid
		ErrorRejected,           ///< The root CA rejected the certificate purpose
		ErrorUntrusted,          ///< The certificate is not trusted
		ErrorSignatureFailed,    ///< The signature does not match
		ErrorInvalidCA,          ///< The Certificate Authority is invalid
		ErrorInvalidPurpose,     ///< The purpose does not match the intended usage
		ErrorSelfSigned,         ///< The certificate is self-signed, and is not found in the list of trusted certificates
		ErrorRevoked,            ///< The certificate has been revoked
		ErrorPathLengthExceeded, ///< The path length from the root CA to this certificate is too long
		ErrorExpired,            ///< The certificate has expired
		ErrorExpiredCA,          ///< The Certificate Authority has expired
		ErrorValidityUnknown     ///< Validity is unknown
	};

	/**
	   Certificate properties type
	*/
	typedef QMultiMap<CertificateInfoType, QString> CertificateInfo;

	/**
	   %Certificate constraints type
	*/
	typedef QList<ConstraintType> Constraints;

	/**
	   %Certificate options

	   \note In SPKAC mode, all options are ignored except for challenge
	*/
	class QCA_EXPORT CertificateOptions
	{
	public:
		CertificateOptions(CertificateRequestFormat = PKCS10);
		CertificateOptions(const CertificateOptions &from);
		~CertificateOptions();
		CertificateOptions & operator=(const CertificateOptions &from);

		CertificateRequestFormat format() const;
		void setFormat(CertificateRequestFormat f);

		bool isValid() const;

		QString challenge() const;        // request
		CertificateInfo info() const;     // request or create
		Constraints constraints() const;  // request or create
		QStringList policies() const;     // request or create
		bool isCA() const;                // request or create
		int pathLimit() const;            // request or create
		QBigInteger serialNumber() const; // create
		QDateTime notValidBefore() const; // create
		QDateTime notValidAfter() const;  // create

		void setChallenge(const QString &s);
		void setInfo(const CertificateInfo &info);
		void setConstraints(const Constraints &constraints);
		void setPolicies(const QStringList &policies);
		void setAsCA(int pathLimit = 8); // value from Botan
		void setSerialNumber(const QBigInteger &i);
		void setValidityPeriod(const QDateTime &start, const QDateTime &end);

	private:
		class Private;
		Private *d;
	};

	/**
	   Public Key (X.509) certificate

	   This class contains one X.509 certificate
	*/
	class QCA_EXPORT Certificate : public Algorithm
	{
	public:
		/**
		   Create an empty Certificate
		*/
		Certificate();

		/**
		   Create a Certificate from a PEM encoded file

		   \param fileName the name (and path, if required)
		   of the file that contains the PEM encoded certificate
		*/
		Certificate(const QString &fileName);

		/**
		   Create a Certificate with specified options and a specified private key

		   \param opts the options to use
		   \param key the private key for this certificate
		   \param provider the provider to use to create this key, if a particular provider is required
		*/
		Certificate(const CertificateOptions &opts, const PrivateKey &key, const QString &provider = QString());

		/**
		   Test if the certificate is empty (null)
		   \return true if the certificate is null
		*/
		bool isNull() const;

		/**
		   The earliest date that the certificate is valid
		*/
		QDateTime notValidBefore() const;

		/**
		   The latest date that the certificate is valid
		*/
		QDateTime notValidAfter() const;

		/**
		   Properties of the subject of the certificate
		*/
		CertificateInfo subjectInfo() const;

		/**
		   Properties of the issuer of the certificate
		*/
		CertificateInfo issuerInfo() const;

		/**
		   The constraints that apply to this certificate
		*/
		Constraints constraints() const;
		QStringList policies() const;

		QString commonName() const;
		QBigInteger serialNumber() const;
		PublicKey subjectPublicKey() const;

		/**
		   Test if the Certificate is valid as a Certificate Authority

		   \return true if the Certificate is valid as a Certificate Authority
		*/
		bool isCA() const;

		/**
		   Test if the Certificate is self-signed

		   \return true if the certificate is self-signed
		*/
		bool isSelfSigned() const;
		int pathLimit() const;

		QSecureArray signature() const;
		SignatureAlgorithm signatureAlgorithm() const;

		QByteArray subjectKeyId() const;
		QByteArray issuerKeyId() const;
		Validity validate(const CertificateCollection &trusted, const CertificateCollection &untrusted, UsageMode u = UsageAny) const;

		/**
		   Export the Certificate into a DER format
		*/
		QSecureArray toDER() const;

		/**
		   Export the Certificate into a PEM format
		*/
		QString toPEM() const;

		/**
		   Export the Certificate into PEM format in a file

		   \param fileName the name of the file to use
		*/
		bool toPEMFile(const QString &fileName) const;

		/**
		   Import the certificate from DER

		   \param a the array containing the certificate in DER format
		   \param result a pointer to a ConvertResult, which if not-null will be set to the conversion status
		   \param provider the provider to use, if a specific provider is required

		   \return the Certificate corresponding to the certificate in the provided array
		*/
		static Certificate fromDER(const QSecureArray &a, ConvertResult *result = 0, const QString &provider = QString());

		/**
		   Import the certificate from PEM format

		   \param s the string containing the certificate in PEM format
		   \param result a pointer to a ConvertResult, which if not-null will be set to the conversion status
		   \param provider the provider to use, if a specific provider is required

		   \return the Certificate corresponding to the certificate in the provided string
		*/
		static Certificate fromPEM(const QString &s, ConvertResult *result = 0, const QString &provider = QString());

		/**
		   Import the certificate from a file

		   \param fileName the name (and path, if required) of the file containing the certificate in PEM format
		   \param result a pointer to a ConvertResult, which if not-null will be set to the conversion status
		   \param provider the provider to use, if a specific provider is required

		   \return the Certificate corresponding to the certificate in the provided string
		*/
		static Certificate fromPEMFile(const QString &fileName, ConvertResult *result = 0, const QString &provider = QString());

		bool matchesHostname(const QString &host) const;

		/**
		   Test for equality of two certificates
		   
		   \return true if the two certificates are the same
		*/
		bool operator==(const Certificate &a) const;

		/**
		   Test for inequality of two certificates
		   
		   \return true if the two certificates are not the same
		*/
		bool operator!=(const Certificate &a) const;
	};

	class QCA_EXPORT CertificateChain : public QList<Certificate>
	{
	public:
		CertificateChain();
		CertificateChain(const Certificate &primary);

		const Certificate & primary() const;
	};

	/**
	   Certificate Request
	*/
	class QCA_EXPORT CertificateRequest : public Algorithm
	{
	public:
		CertificateRequest();
		CertificateRequest(const QString &fileName);
		CertificateRequest(const CertificateOptions &opts, const PrivateKey &key, const QString &provider = QString());

		bool isNull() const;

		static bool canUseFormat(CertificateRequestFormat f, const QString &provider = QString());

		CertificateRequestFormat format() const;

		CertificateInfo subjectInfo() const; // PKCS#10 only
		Constraints constraints() const;     // PKCS#10 only
		QStringList policies() const;        // PKCS#10 only

		PublicKey subjectPublicKey() const;
		bool isCA() const;                   // PKCS#10 only
		int pathLimit() const;               // PKCS#10 only
		QString challenge() const;

		QSecureArray signature() const;
		SignatureAlgorithm signatureAlgorithm() const;

		// import / export - PKCS#10 only
		QSecureArray toDER() const;
		QString toPEM() const;
		bool toPEMFile(const QString &fileName) const;
		static CertificateRequest fromDER(const QSecureArray &a, ConvertResult *result = 0, const QString &provider = QString());
		static CertificateRequest fromPEM(const QString &s, ConvertResult *result = 0, const QString &provider = QString());
		static CertificateRequest fromPEMFile(const QString &fileName, ConvertResult *result = 0, const QString &provider = QString());

		// import / export - SPKAC only
		QString toString() const;
		static CertificateRequest fromString(const QString &s, ConvertResult *result = 0, const QString &provider = QString());
	};

	/**
	   Part of a CRL representing a single certificate
	*/
	class QCA_EXPORT CRLEntry
	{
	public:
		enum Reason
		{
			Unspecified,
			KeyCompromise,
			CACompromise,
			AffiliationChanged,
			Superceded,
			CessationOfOperation,
			CertificateHold,
			RemoveFromCRL,
			PrivilegeWithdrawn,
			AACompromise
		};
		CRLEntry();
		CRLEntry(const Certificate &c, Reason r = Unspecified);

		QBigInteger serialNumber() const;
		QDateTime time() const;
		Reason reason() const;

	private:
		QBigInteger _serial;
		QDateTime _time;
		Reason _reason;
	};

	/**
	   Certificate Revocation List
	*/
	class QCA_EXPORT CRL : public Algorithm
	{
	public:
		CRL();

		bool isNull() const;

		CertificateInfo issuerInfo() const;

		int number() const;
		QDateTime thisUpdate() const;
		QDateTime nextUpdate() const;

		QList<CRLEntry> revoked() const;

		QSecureArray signature() const;
		SignatureAlgorithm signatureAlgorithm() const;

		QByteArray issuerKeyId() const;

		/**
		   Export the Certificate Revocation List (CRL) in DER format

		   \return an array containing the CRL in DER format
		*/
		QSecureArray toDER() const;

		/**
		   Export the Certificate Revocation List (CRL) in PEM format

		   \return a string containing the CRL in PEM format
		*/
		QString toPEM() const;

		/**
		   Import a DER encoded Certificate Revocation List (CRL)

		   \param a the array containing the CRL in DER format
		   \param result a pointer to a ConvertResult, which if not-null will be set to the conversion status
		   \param provider the provider to use, if a specific provider is required

		   \return the CRL corresponding to the contents of the array
		*/
		static CRL fromDER(const QSecureArray &a, ConvertResult *result = 0, const QString &provider = QString());

		/**
		   Import a PEM encoded %Certificate Revocation List (CRL)

		   \param s the string containing the CRL in PEM format
		   \param result a pointer to a ConvertResult, which if not-null will be set to the conversion status
		   \param provider the provider to use, if a specific provider is required

		   \return the CRL corresponding to the contents of the string
		*/
		static CRL fromPEM(const QString &s, ConvertResult *result = 0, const QString &provider = QString());
	};

	/**
	   Bundle of Certificates and CRLs
	*/
	class CertificateCollection
	{
	public:
		CertificateCollection();
		CertificateCollection(const CertificateCollection &from);
		~CertificateCollection();
		CertificateCollection & operator=(const CertificateCollection &from);

		void addCertificate(const Certificate &cert);
		void addCRL(const CRL &crl);

		/**
		   The Certificates in this collection
		*/
		QList<Certificate> certificates() const;

		/**
		   The CRLs in this collection
		*/
		QList<CRL> crls() const;

		void append(const CertificateCollection &other);
		CertificateCollection operator+(const CertificateCollection &other) const;
		CertificateCollection & operator+=(const CertificateCollection &other);

		// import / export
		static bool canUsePKCS7(const QString &provider = QString());
		bool toFlatTextFile(const QString &fileName);
		bool toPKCS7File(const QString &fileName, const QString &provider = QString());
		static CertificateCollection fromFlatTextFile(const QString &fileName, ConvertResult *result = 0, const QString &provider = QString());
		static CertificateCollection fromPKCS7File(const QString &fileName, ConvertResult *result = 0, const QString &provider = QString());

	private:
		class Private;
		QSharedDataPointer<Private> d;
	};

	class QCA_EXPORT CertificateAuthority : public Algorithm
	{
	public:
		CertificateAuthority(const Certificate &cert, const PrivateKey &key, const QString &provider);

		Certificate certificate() const;

		Certificate signRequest(const CertificateRequest &req, const QDateTime &notValidAfter) const;
		Certificate createCertificate(const PublicKey &key, const CertificateOptions &opts) const;
		CRL createCRL(const QDateTime &nextUpdate) const;
		CRL updateCRL(const CRL &crl, const QList<CRLEntry> &entries, const QDateTime &nextUpdate) const;
	};

	// holds a certificate chain and an associated private key
	class QCA_EXPORT KeyBundle
	{
	public:
		KeyBundle();
		KeyBundle(const QString &fileName, const QSecureArray &passphrase);
		KeyBundle(const KeyBundle &from);
		~KeyBundle();
		KeyBundle & operator=(const KeyBundle &from);

		bool isNull() const;

		QString name() const;
		CertificateChain certificateChain() const;
		PrivateKey privateKey() const;
		void setName(const QString &s);
		void setCertificateChainAndKey(const CertificateChain &c, const PrivateKey &key);

		// import / export
		QByteArray toArray(const QSecureArray &passphrase, const QString &provider = QString()) const;
		bool toFile(const QString &fileName, const QSecureArray &passphrase, const QString &provider = QString()) const;
		static KeyBundle fromArray(const QByteArray &a, const QSecureArray &passphrase, ConvertResult *result = 0, const QString &provider = QString());
		static KeyBundle fromFile(const QString &fileName, const QSecureArray &passphrase, ConvertResult *result = 0, const QString &provider = QString());

	private:
		class Private;
		QSharedDataPointer<Private> d;
	};

	// PGPKey can either reference an item in a real PGP keyring or can
	// be made by calling a "from" function.  Note that with the latter
	// method, the key is of no use besides being informational.  The
	// key must be in a keyring (inKeyring() == true) to actually do
	// crypto with it.
	class QCA_EXPORT PGPKey : public Algorithm
	{
	public:
		PGPKey();
		PGPKey(const QString &fileName);
		PGPKey(const PGPKey &from);
		~PGPKey();
		PGPKey & operator=(const PGPKey &from);

		bool isNull() const;

		QString keyId() const;
		QString primaryUserId() const;
		QStringList userIds() const;

		bool havePrivate() const;
		QDateTime creationDate() const;
		QDateTime expirationDate() const;
		QString fingerprint() const;

		bool inKeyring() const;
		bool isTrusted() const;

		// import / export
		QSecureArray toArray() const;
		QString toString() const;
		bool toFile(const QString &fileName) const;
		static PGPKey fromArray(const QSecureArray &a, ConvertResult *result = 0, const QString &provider = QString());
		static PGPKey fromString(const QString &s, ConvertResult *result = 0, const QString &provider = QString());
		static PGPKey fromFile(const QString &fileName, ConvertResult *result = 0, const QString &provider = QString());
	};
}

#endif
