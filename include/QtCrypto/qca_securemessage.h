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

	/**
	   \class SecureMessageKey qca_securemessage.h QtCrypto

	   Key for SecureMessage system
	*/
	class QCA_EXPORT SecureMessageKey
	{
	public:
		/**
		   The key type
		*/
		enum Type
		{
			None, ///< no key
			PGP,  ///< Pretty Good Privacy key
			X509  ///< X.509 CMS key
		};

		/**
		   Construct an empty key
		*/
		SecureMessageKey();

		/**
		   Standard copy constructor

		   \param from the source key
		*/
		SecureMessageKey(const SecureMessageKey &from);

		~SecureMessageKey();

		/**
		   Standard assignment operator

		   \param from the source key
		*/
		SecureMessageKey & operator=(const SecureMessageKey &from);

		/**
		   Returns true for null object
		*/
		bool isNull() const;

		/**
		   The key type
		*/
		Type type() const;

		// pgp
		/**
		   Public key part of a PGP key
		*/
		PGPKey pgpPublicKey() const;

		/**
		   Private key part of a PGP key
		*/
		PGPKey pgpSecretKey() const;

		/**
		   Set the public key part of a PGP key

		   \param pub the PGP public key
		*/
		void setPGPPublicKey(const PGPKey &pub);

		/**
		   Set the private key part of a PGP key

		   \param sec the PGP secretkey
		*/
		void setPGPSecretKey(const PGPKey &sec);

		// x509
		/**
		   The X.509 certificate chain (public part) for this key
		*/
		CertificateChain x509CertificateChain() const;

		/**
		   The X.509 private key part of this key
		*/
		PrivateKey x509PrivateKey() const;

		/**
		   Set the public key part of this X.509 key.
		*/
		void setX509CertificateChain(const CertificateChain &c);

		/**
		   Set the private key part of this X.509 key.
		*/
		void setX509PrivateKey(const PrivateKey &k);

		// generic
		/**
		   Test if this key contains a private key part
		*/
		bool havePrivate() const;

		/**
		   The name associated with this key

		   For a PGP key, this is the primary user ID

		   For an X.509 key, this is the Common Name
		*/
		QString name() const;

	private:
		class Private;
		QSharedDataPointer<Private> d;
	};

	/**
	   A list of message keys
	*/
	typedef QList<SecureMessageKey> SecureMessageKeyList;

	/**
	   \class SecureMessageSignature qca_securemessage.h QtCrypto

	   SecureMessage signature
	*/
	class QCA_EXPORT SecureMessageSignature
	{
	public:
		/**
		   The result of identity verification
		*/
		enum IdentityResult
		{
			Valid,            ///< indentity is verified, matches signature
			InvalidSignature, ///< valid key provided, but signature failed
			InvalidKey,       ///< invalid key provided
			NoKey             ///< identity unknown
		};

		/**
		   Create an empty signature check object
		*/
		SecureMessageSignature();

		/**
		   Create a signature check object
		*/
		SecureMessageSignature(IdentityResult r, Validity v, const SecureMessageKey &key, const QDateTime &ts);

		/**
		   Standard copy constructor

		   \param from the source signature object
		*/
		SecureMessageSignature(const SecureMessageSignature &from);

		~SecureMessageSignature();

		/**
		   Standard assignment operator

		   \param from the source signature object
		*/
		SecureMessageSignature & operator=(const SecureMessageSignature &from);

		/**
		   get the results of the identity check on this signature
		*/
		IdentityResult identityResult() const;

		/**
		   get the results of the key validation check on this signature
		*/
		Validity keyValidity() const;

		/**
		   get the key associated with this signature
		*/
		SecureMessageKey key() const;

		/**
		   get the timestamp associated with this signature
		*/
		QDateTime timestamp() const;

	private:
		class Private;
		QSharedDataPointer<Private> d;
	};

	/**
	   A list of signatures
	*/
	typedef QList<SecureMessageSignature> SecureMessageSignatureList;

	class QCA_EXPORT SecureMessage : public QObject, public Algorithm
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
			ErrorPassphrase,       ///< passphrase was either wrong or not provided
			ErrorFormat,           ///< input format was bad
			ErrorSignerExpired,    ///< signing key is expired
			ErrorSignerInvalid,    ///< signing key is invalid in some way
			ErrorEncryptExpired,   ///< encrypting key is expired
			ErrorEncryptUntrusted, ///< encrypting key is untrusted
			ErrorEncryptInvalid,   ///< encrypting key is invalid in some way
			ErrorNeedCard,         ///< pgp card is missing
			ErrorUnknown           ///< other error
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
		void startVerify(const QByteArray &detachedSig = QByteArray());
		void startSignAndEncrypt();
		void update(const QByteArray &in);
		QByteArray read();
		int bytesAvailable() const;
		void end();
		bool waitForFinished(int msecs = 30000);

		bool success() const;
		Error errorCode() const;

		// sign
		QByteArray signature() const;
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

	class QCA_EXPORT SecureMessageSystem : public QObject, public Algorithm
	{
		Q_OBJECT
	public:
		~SecureMessageSystem();

	protected:
		SecureMessageSystem(QObject *parent, const QString &type, const QString &provider);
	};

	class QCA_EXPORT OpenPGP : public SecureMessageSystem
	{
		Q_OBJECT
	public:
		OpenPGP(QObject *parent = 0, const QString &provider = QString());
		~OpenPGP();
	};

	class QCA_EXPORT CMS : public SecureMessageSystem
	{
		Q_OBJECT
	public:
		CMS(QObject *parent = 0, const QString &provider = QString());
		~CMS();

		void setTrustedCertificates(const CertificateCollection &trusted);
		void setPrivateKeys(const SecureMessageKeyList &keys);
	};
}

#endif
