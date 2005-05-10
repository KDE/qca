/*
 * qca_securemessage.h - Qt Cryptographic Architecture
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

#ifndef QCA_SECUREMESSAGE_H
#define QCA_SECUREMESSAGE_H

#include <QObject>
#include "qca_core.h"
#include "qca_publickey.h"
#include "qca_cert.h"

class QDateTime;

namespace QCA
{
	class SecureMessageSystem;

	class SecureMessageKey
	{
	public:
		enum Type
		{
			None,
			PGP,
			X509
		};
		SecureMessageKey();
		SecureMessageKey(const SecureMessageKey &from);
		~SecureMessageKey();
		SecureMessageKey & operator=(const SecureMessageKey &from);

		Type type() const;

		// pgp
		PGPKey pgpPublicKey() const;
		PGPKey pgpSecretKey() const;
		void setPGPPublicKey(const PGPKey &pub);
		void setPGPSecretKey(const PGPKey &sec);

		// x509
		CertificateChain x509CertificateChain() const;
		PrivateKey x509PrivateKey() const;
		void setX509CertificateChain(const CertificateChain &c);
		void setX509PrivateKey(const PrivateKey &k);

		// generic
		bool havePrivate() const;
		QString name() const;  // pgp = primary user id, x509 = common name

	private:
		class Private;
		QSharedDataPointer<Private> d;
	};
	typedef QList<SecureMessageKey> SecureMessageKeyList;

	class SecureMessageSignature
	{
	public:
		enum IdentityResult
		{
			Valid,            // indentity is verified, matches signature
			InvalidSignature, // valid key provided, but signature failed
			InvalidKey,       // invalid key provided
			NoKey             // identity unknown
		};

		SecureMessageSignature();
		SecureMessageSignature(IdentityResult r, Validity v, const SecureMessageKey &key, const QDateTime &ts);
		SecureMessageSignature(const SecureMessageSignature &from);
		~SecureMessageSignature();
		SecureMessageSignature & operator=(const SecureMessageSignature &from);

		IdentityResult identityResult() const;
		Validity keyValidity() const;
		SecureMessageKey key() const;
		QDateTime timestamp() const;

	private:
		class Private;
		QSharedDataPointer<Private> d;
	};
	typedef QList<SecureMessageSignature> SecureMessageSignatureList;

	class SecureMessage : public QObject, public Algorithm
	{
		Q_OBJECT
	public:
		enum Type
		{
			OpenPGP,
			CMS
		};

		enum SignMode
		{
			Message,
			Clearsign,
			Detached
		};

		/**
		   Formats for secure messages
		*/
		enum Format
		{
			Binary, ///< DER/binary
			Ascii   ///< PEM/ascii-armored
		};

		/**
		   Errors for secure messages
		*/
		enum Error
		{
			ErrorPassphrase,     ///< passphrase was either wrong or not provided
			ErrorFormat,         ///< input format was bad
			ErrorSignerExpired,  ///< signing key is expired
			ErrorSignerInvalid,  ///< signing key is invalid in some way
			ErrorEncryptExpired, ///< encrypting key is expired
			ErrorEncryptInvalid, ///< encrypting key is invalid in some way
			ErrorUnknown         ///< other error
		};

		SecureMessage(SecureMessageSystem *system);
		~SecureMessage();

		Type type() const;
		bool canSignMultiple() const;     // CMS feature
		bool canClearsign() const;        // PGP feature
		bool canSignAndEncrypt() const;   // PGP feature

		void reset();

		void setEnableBundleSigner(bool b);    // CMS: bundle X.509 certificate chain (default true)
		void setEnableSMIMEAttributes(bool b); // CMS: include S/MIME attributes (default true)
		void setFormat(Format f);              // (default Binary)
		void setRecipient(const SecureMessageKey &key);
		void setRecipients(const SecureMessageKeyList &keys);
		void setSigner(const SecureMessageKey &key);
		void setSigners(const SecureMessageKeyList &keys);

		void startEncrypt();
		void startDecrypt(); // if decrypted result is signed (PGP only), it will be verified
		void startSign(SignMode m = Message);
		void startVerify(const QSecureArray &detachedSig = QSecureArray());
		void startSignAndEncrypt();
		void update(const QSecureArray &in);
		QSecureArray read();
		int bytesAvailable() const;
		void end();
		bool waitForFinished(int msecs = 30000);

		bool success() const;
		Error errorCode() const;

		// sign
		QSecureArray signature() const;
		QString hashName() const;

		// verify
		bool wasSigned() const; // PGP: true if decrypted message was signed
		bool verifySuccess() const;
		SecureMessageSignature signer() const;
		SecureMessageSignatureList signers() const;

		QString diagnosticText() const;

	signals:
		void readyRead();
		void finished();

	private:
		class Private;
		friend class Private;
		Private *d;
	};

	class SecureMessageSystem : public QObject, public Algorithm
	{
		Q_OBJECT
	public:
		~SecureMessageSystem();

	protected:
		SecureMessageSystem(QObject *parent, const QString &type, const QString &provider);
	};

	class OpenPGP : public SecureMessageSystem
	{
		Q_OBJECT
	public:
		OpenPGP(QObject *parent = 0, const QString &provider = QString());
		~OpenPGP();
	};

	class CMS : public SecureMessageSystem
	{
		Q_OBJECT
	public:
		CMS(QObject *parent = 0, const QString &provider = QString());
		~CMS();

		void setTrustedCertificates(const CertificateCollection &trusted);
		void setPrivateKeys(const QList<PrivateKey> &keys);
	};
}

#endif
