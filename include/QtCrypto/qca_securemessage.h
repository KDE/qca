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

	class SecureMessageKey
	{
	public:
		enum Type { None, PGP, X509 };
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
		Certificate x509Certificate() const;
		PrivateKey x509PrivateKey() const;
		void setX509Certificate(const Certificate &c);
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
		enum Mode { EncryptThenSign, SignThenEncrypt };
		enum Error { ErrBadPassphrase, ErrUnknown };
		enum VerifyResult { VerifyGood, VerifyBad, VerifyNoKey, VerifyError };
		SecureMessage(SecureMessageSystem *system);
		~SecureMessage();

		bool canEncryptMultiple() const; // can smime do multiple?
		void encrypt(const QSecureArray &in, const SecureMessageKey &key);
		void encrypt(const QSecureArray &in, const SecureMessageKeyList &keys);
		void encryptAndSign(const QSecureArray &in, const SecureMessageKey &key, const SecureMessageKey &signer, Mode m = EncryptThenSign);
		void encryptAndSign(const QSecureArray &in, const SecureMessageKeyList &keys, const SecureMessageKey &signer, Mode m = EncryptThenSign);
		void decrypt(const QString &in);
		void sign(const QSecureArray &in, const SecureMessageKey &signer);
		void verify(const QSecureArray &in, const QString &sig);
		bool waitForFinished();

		bool success() const;
		Error errorCode() const;
		QString encrypted() const;
		QSecureArray decrypted() const;
		QString signature() const;
		SecureMessageKey key() const;
		QDateTime timestamp() const;
		VerifyResult verifyResult();

	signals:
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
	};
}

#endif
