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

class QDateTime;

namespace QCA
{
	class PublicKey;
	class PrivateKey;

	class QCA_EXPORT CertificateOptions
	{
	public:
		CertificateOptions();

		bool isValid() const;

		QString commonName() const;
		QString country() const;
		QString organization() const;
		QString organizationalUnit() const;
		QString locality() const;
		QString state() const;
		QBigInteger serialNumber() const;
		QString email() const;
		QString uri() const;
		QString dns() const;
		QString challenge() const;
		QDateTime notValidBefore() const;
		QDateTime notValidAfter() const;
		bool isCA() const;
		int pathLimit() const;

		void setCommonName(const QString &s);
		void setCountry(const QString &s);
		void setOrganization(const QString &s);
		void setOrganizationalUnit(const QString &s);
		void setLocality(const QString &s);
		void setState(const QString &s);
		void setSerialNumber(const QBigInteger &i);
		void setEmail(const QString &s);
		void setURI(const QString &s);
		void setDNS(const QString &s);
		void setChallenge(const QString &s);
		void setValidityPeriod(const QDateTime &start, const QDateTime &end);
		void setAsCA(int pathLimit);
	};

	class QCA_EXPORT Certificate : public Algorithm
	{
	public:
		typedef QMap<QString, QString> Info;

		Certificate();
		Certificate(const CertificateOptions &opts, const PrivateKey &key, const QString &provider = QString());

		bool isNull() const;

		QDateTime notValidBefore() const;
		QDateTime notValidAfter() const;

		Info subjectInfo() const;
		Info issuerInfo() const;

		QString commonName() const;
		QBigInteger serialNumber() const;
		PublicKey subjectPublicKey() const;
		bool isCA() const;
		bool isSelfSigned() const;

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

		PublicKey subjectPublicKey() const;
		bool isCA() const;
		int pathLimit() const;
		QString challenge() const;

		SignAlgo signatureAlgorithm() const;

		// import / export
		QSecureArray toDER() const;
		QString toPEM() const;
		static CertificateRequest fromDER(const QSecureArray &a, const QString &provider = QString());
		static CertificateRequest fromPEM(const QString &s, const QString &provider = QString());
	};

	class QCA_EXPORT CRLEntry
	{
	public:
		enum Reason { Unspecified };
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
		CRL createCRL(const QDateTime &nextUpdate) const;
		CRL updateCRL(const CRL &crl, const QValueList<CRLEntry> &entries, const QDateTime &nextUpdate) const;
	};

	class QCA_EXPORT Store : public Algorithm
	{
	public:
		Store(const QString &provider = QString());

		void addCertificate(const Certificate &cert, bool trusted = false);
		void addCRL(const CRL &crl);
		CertValidity validate(const Certificate &cert, CertUsage u = Any) const;

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
