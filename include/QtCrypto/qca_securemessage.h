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

#include <qobject.h>
#include "qca_core.h"

class QDateTime;

namespace QCA
{
	class PrivateKey;
	class Certificate;
	class Store;
	class SecureMessageSystem;
	typedef QValueList<Certificate> CertificateChain;

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
		QString pgpPublicKey() const;
		QString pgpSecretKey() const;
		void setPGPPublicKey(const QString &id, const QString &name);
		void setPGPSecretKey(const QString &id);

		// x509
		CertificateChain x509CertificateChain() const;
		PrivateKey x509PrivateKey() const;
		void setX509CertificateChain(const CertificateChain &c);
		void setX509PrivateKey(const PrivateKey &k);

		// generic
		bool havePrivate() const;
		QString id() const;
		QString name() const;

	private:
		class Private;
		Private *d;
	};
	typedef QValueList<SecureMessageKey> SecureMessageKeyList;

	class SecureMessage : public QObject
	{
		Q_OBJECT
	public:
		enum Order
		{
			EncryptThenSign,
			SignThenEncrypt
		};
		enum Format
		{
			Binary, // DER/binary
			Ascii   // PEM/ascii-armored
		};
		enum Error
		{
			ErrPassphrase, // passphrase was either wrong or not provided
			ErrFormat,     // input format was bad
			ErrSigner,     // signing key is expired or invalid
			ErrUnknown     // other error
		};
		enum VerifyResult
		{
			Valid,   // indentity is verified, matches signature
			Invalid, // valid key provided, but signature failed
			BadKey,  // invalid key provided
			NoKey,   // identity unknown
		};
		SecureMessage(SecureMessageSystem *system);
		~SecureMessage();

		bool canSignMultiple() const;     // PGP can't sign multiple
		void setEnableBundleSigner(bool); // Bundle S/MIME certificate chain (default true)
		void setFormat(Format f);         // (default Binary)
		void setRecipient(const SecureMessageKey &key);
		void setRecipients(const SecureMessageKeyList &keys);
		void setSigner(const SecureMessageKey &key);
		void setSigners(const SecureMessageKeyList &keys);

		void startEncrypt();
		void startDecrypt();
		void startSign(bool detachedSignature = true);
		void startVerify(const QSecureArray &sig = QSecureArray());
		void startEncryptAndSign(Order o = EncryptThenSign);
		void startDecryptAndVerify(Order o = EncryptThenSign);
		void update(const QSecureArray &in);
		QSecureArray read(int size = -1);
		int bytesAvailable() const;
		void end();
		bool waitForFinished();

		bool success() const;
		Error errorCode() const;

		// sign
		QSecureArray signature() const;

		// verify
		VerifyResult verifyResult() const;
		CertValidity keyValidity() const;
		SecureMessageKey key() const;
		QDateTime timestamp() const;

	signals:
		void readyRead();
		void finished();

	public:
		class Private;
	private:
		friend class Private;
		Private *d;
	};

	class SecureMessageSystem : public QObject
	{
		Q_OBJECT
	public:
		SecureMessageSystem(QObject *parent = 0, const char *name = 0);
		~SecureMessageSystem();
	};

	class OpenPGP : public SecureMessageSystem, public Algorithm
	{
		Q_OBJECT
	public:
		OpenPGP(QObject *parent = 0, const char *name = 0, const QString &provider = QString());
		~OpenPGP();

		void setAllowAgent(bool);
		void submitPassphrase(const QSecureArray &passphrase);

		SecureMessageKeyList secretKeys() const;
		SecureMessageKeyList publicKeys() const;

	signals:
		void keysUpdated();
		void needPassphrase();
	};

	class SMIME : public SecureMessageSystem, public Algorithm
	{
		Q_OBJECT
	public:
		SMIME(QObject *parent = 0, const char *name = 0, const QString &provider = QString());
		~SMIME();

		void setStore(const Store &store);
		void setPrivateKeys(const QValueList<PrivateKey> &keys);
	};
}

#endif
