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

#include <qmap.h>
#include "qca_core.h"
#include "qca_publickey.h"

class QDateTime;

namespace QCA
{
	/**
	   Certificate Request Format
	*/
	enum CertificateRequestFormat
	{
		CSR_PKCS10, ///< standard PKCS#10 format
		CSR_SPKAC   ///< Signed Public Key and Challenge (Netscape) format
	};

	enum CertInfoType
	{
		Info_Name,
		Info_Email,
		Info_Organization,
		Info_OrganizationalUnit,
		Info_Locality,
		Info_State,
		Info_Country,
		Info_URI,
		Info_DNS,
		Info_XMPP
	};

	enum CertConstraintType
	{
		// basic
		Constraint_DigitalSignature,
		Constraint_NonRepudiation,
		Constraint_KeyEncipherment,
		Constraint_DataEncipherment,
		Constraint_KeyAgreement,
		Constraint_KeyCertificateSign,
		Constraint_CRLSign,
		Constraint_EncipherOnly,
		Constraint_DecipherOnly,

		// extended
		Constraint_ServerAuth,
		Constraint_ClientAuth,
		Constraint_CodeSigning,
		Constraint_EmailProtection,
		Constraint_IPsecEndSystem,
		Constraint_IPsecTunnel,
		Constraint_IPsecUser,
		Constraint_TimeStamping,
		Constraint_OCSPSigning
	};

	/**
	   Specify the intended usage of a certificate
	*/
	enum CertUsage
	{
		Usage_Any             = 0x00, ///< Any application, or unspecified
		Usage_TLSServer       = 0x01, ///< server side of a TLS or SSL connection
		Usage_TLSClient       = 0x02, ///< client side of a TLS or SSL connection
		Usage_CodeSigning     = 0x04, ///< code signing certificate
		Usage_EmailProtection = 0x08, ///< email (S/MIME) certificate
		Usage_TimeStamping    = 0x10, ///< time stamping certificate
		Usage_CRLSigning      = 0x20  ///< certificate revocation list signing certificate
	};

	/**
	   The validity (or otherwise) of a certificate
	*/
	enum CertValidity
	{
		Valid,              ///< The certificate is valid
		Rejected,           ///< The root CA rejected the certificate purpose
		Untrusted,          ///< The certificate is not trusted
		SignatureFailed,    ///< The signature does not match
		InvalidCA,          ///< The Certificate Authority is invalid
		InvalidPurpose,     ///< The purpose does not match the intended usage
		SelfSigned,         ///< The certificate is self-signed, and is not
		                    ///< found in the list of trusted certificates
		Revoked,            ///< The certificate has been revoked
		PathLengthExceeded, ///< The path length from the root CA to this certificate is too long
		Expired,            ///< The certificate has expired
		Unknown             ///< Validity is unknown
	};

	typedef QMap<CertInfoType, QString> CertInfo;
	typedef QValueList<CertConstraintType> CertConstraints;

	// note: in SPKAC mode, all options are ignored except for challenge
	class QCA_EXPORT CertificateOptions
	{
	public:
		CertificateOptions(CertificateRequestFormat = CSR_PKCS10);
		CertificateOptions(const CertificateOptions &from);
		~CertificateOptions();
		CertificateOptions & operator=(const CertificateOptions &from);

		CertificateRequestFormat format() const;
		void setFormat(CertificateRequestFormat f);

		bool isValid() const;

		QString challenge() const;           // request
		CertInfo info() const;               // request or create
		CertConstraints constraints() const; // request or create
		QStringList policies() const;        // request or create
		bool isCA() const;                   // request or create
		int pathLimit() const;               // request or create
		QBigInteger serialNumber() const;    // create
		QDateTime notValidBefore() const;    // create
		QDateTime notValidAfter() const;     // create

		void setChallenge(const QString &s);
		void setInfo(const CertInfo &info);
		void setConstraints(const CertConstraints &constraints);
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
		Certificate(const CertificateOptions &opts, const PrivateKey &key, const QString &provider = QString());

		bool isNull() const;

		QDateTime notValidBefore() const;
		QDateTime notValidAfter() const;

		CertInfo subjectInfo() const;
		CertInfo issuerInfo() const;
		CertConstraints constraints() const;
		QStringList policies() const;

		QString commonName() const;
		QBigInteger serialNumber() const;
		PublicKey subjectPublicKey() const;
		bool isCA() const;
		bool isSelfSigned() const;
		int pathLimit() const;

		SignAlgo signatureAlgorithm() const;

		// import / export
		QSecureArray toDER() const;
		QString toPEM() const;
		static Certificate fromDER(const QSecureArray &a, const QString &provider = QString());
		static Certificate fromPEM(const QString &s, const QString &provider = QString());

		bool matchesHostname(const QString &host) const;

		bool operator==(const Certificate &a) const;
		bool operator!=(const Certificate &a) const;

	private:
		friend class Store;
		friend class TLS;
	};

	class QCA_EXPORT CertificateChain : public QValueList<Certificate>
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
		CertificateRequest(const CertificateOptions &opts, const PrivateKey &key, const QString &provider = QString());

		bool isNull() const;

		static bool canUseFormat(CertificateRequestFormat f, const QString &provider = QString());

		CertificateRequestFormat format() const;

		CertInfo subjectInfo() const;        // PKCS#10 only
		CertConstraints constraints() const; // PKCS#10 only
		QStringList policies() const;        // PKCS#10 only

		PublicKey subjectPublicKey() const;
		bool isCA() const;                   // PKCS#10 only
		int pathLimit() const;               // PKCS#10 only
		QString challenge() const;

		SignAlgo signatureAlgorithm() const;

		// import / export - PKCS#10 only
		QSecureArray toDER() const;
		QString toPEM() const;
		static CertificateRequest fromDER(const QSecureArray &a, const QString &provider = QString());
		static CertificateRequest fromPEM(const QString &s, const QString &provider = QString());

		// import / export - SPKAC only
		QString toString() const;
		static CertificateRequest fromString(const QString &s, const QString &provider = QString());
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
	};

	class QCA_EXPORT CRL : public Algorithm
	{
	public:
		CRL();

		bool isNull() const;

		CertInfo issuerInfo() const;

		int number() const;
		QDateTime thisUpdate() const;
		QDateTime nextUpdate() const;

		QValueList<CRLEntry> revoked() const;

		SignAlgo signatureAlgorithm() const;

		// import / export
		QSecureArray toDER() const;
		QString toPEM() const;
		static CRL fromDER(const QSecureArray &a, const QString &provider = QString());
		static CRL fromPEM(const QString &s, const QString &provider = QString());

	private:
		friend class Store;
	};

	class QCA_EXPORT CertificateAuthority : public Algorithm
	{
	public:
		CertificateAuthority(const Certificate &cert, const PrivateKey &key, const QString &provider);

		Certificate certificate() const;

		Certificate signRequest(const CertificateRequest &req, const QDateTime &notValidAfter) const;
		Certificate createCertificate(const PublicKey &key, const CertificateOptions &opts) const;
		CRL createCRL(const QDateTime &nextUpdate) const;
		CRL updateCRL(const CRL &crl, const QValueList<CRLEntry> &entries, const QDateTime &nextUpdate) const;
	};

	class QCA_EXPORT Store : public Algorithm
	{
	public:
		Store(const QString &provider = QString());

		void addCertificate(const Certificate &cert, bool trusted = false);
		void addCRL(const CRL &crl);
		CertValidity validate(const Certificate &cert, CertUsage u = Usage_Any) const;

		QValueList<Certificate> certificates() const;
		QValueList<CRL> crls() const;

		// import / export
		static bool canUsePKCS7(const QString &provider = QString());
		QByteArray toPKCS7() const;
		QString toFlatText() const;
		bool fromPKCS7(const QByteArray &a);
		bool fromFlatText(const QString &s);

		void append(const Store &a);
		Store operator+(const Store &a) const;
		Store & operator+=(const Store &a);

	private:
		friend class TLS;
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
