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
	/**
	   Certificate Request Format
	*/
	enum CertificateRequestFormat
	{
		PKCS10, ///< standard PKCS#10 format
		SPKAC   ///< Signed Public Key and Challenge (Netscape) format
	};

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
		IPsecEndSystem,
		IPsecTunnel,
		IPsecUser,
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

	typedef QMap<CertificateInfoType, QString> CertificateInfo;
	typedef QList<ConstraintType> Constraints;

	// note: in SPKAC mode, all options are ignored except for challenge
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
		void setAsCA(int pathLimit);
		void setSerialNumber(const QBigInteger &i);
		void setValidityPeriod(const QDateTime &start, const QDateTime &end);

	private:
		class Private;
		Private *d;
	};

	class QCA_EXPORT Certificate : public Algorithm
	{
	public:
		Certificate();
		Certificate(const QString &fileName);
		Certificate(const CertificateOptions &opts, const PrivateKey &key, const QString &provider = QString());

		bool isNull() const;

		QDateTime notValidBefore() const;
		QDateTime notValidAfter() const;

		CertificateInfo subjectInfo() const;
		CertificateInfo issuerInfo() const;
		Constraints constraints() const;
		QStringList policies() const;

		QString commonName() const;
		QBigInteger serialNumber() const;
		PublicKey subjectPublicKey() const;
		bool isCA() const;
		bool isSelfSigned() const;
		int pathLimit() const;

		SignatureAlgorithm signatureAlgorithm() const;

		// import / export
		QSecureArray toDER() const;
		QString toPEM() const;
		bool toPEMFile(const QString &fileName) const;
		static Certificate fromDER(const QSecureArray &a, ConvertResult *result = 0, const QString &provider = QString());
		static Certificate fromPEM(const QString &s, ConvertResult *result = 0, const QString &provider = QString());
		static Certificate fromPEMFile(const QString &fileName, ConvertResult *result = 0, const QString &provider = QString());

		bool matchesHostname(const QString &host) const;

		bool operator==(const Certificate &a) const;
		bool operator!=(const Certificate &a) const;
	};

	class QCA_EXPORT CertificateChain : public QList<Certificate>
	{
	public:
		CertificateChain();
		CertificateChain(const Certificate &primary);

		const Certificate & primary() const;
	};

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

		SignatureAlgorithm signatureAlgorithm() const;

		// import / export
		QSecureArray toDER() const;
		QString toPEM() const;
		static CRL fromDER(const QSecureArray &a, ConvertResult *result = 0, const QString &provider = QString());
		static CRL fromPEM(const QString &s, ConvertResult *result = 0, const QString &provider = QString());
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

	class QCA_EXPORT Store : public Algorithm
	{
	public:
		Store(const QString &provider = QString());

		void addCertificate(const Certificate &cert, bool trusted = false);
		void addCRL(const CRL &crl);
		Validity validate(const Certificate &cert, UsageMode u = UsageAny) const;

		QList<Certificate> certificates() const;
		QList<CRL> crls() const;

		// import / export
		static bool canUsePKCS7(const QString &provider = QString());
		QByteArray toPKCS7() const;
		QString toFlatText() const;
		bool fromPKCS7(const QByteArray &a);
		bool fromFlatText(const QString &s);

		void append(const Store &a);
		Store operator+(const Store &a) const;
		Store & operator+=(const Store &a);
	};

	class QCA_EXPORT PersonalBundle : public Algorithm
	{
	public:
		PersonalBundle(const QString &provider = QString());

		bool isNull() const;

		CertificateChain certificateChain() const;
		PrivateKey privateKey() const;
		void setCertificateChainAndKey(const CertificateChain &c, const PrivateKey &key);

		// import / export
		QSecureArray toArray(const QString &name, const QSecureArray &passphrase) const;
		static PersonalBundle fromArray(const QSecureArray &a, const QSecureArray &passphrase, const QString &provider = QString());
	};
}

#endif
