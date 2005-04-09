/*
 * qca_keystore.h - Qt Cryptographic Architecture
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

#ifndef QCA_KEYSTORE_H
#define QCA_KEYSTORE_H

#include "qca_core.h"
#include "qca_cert.h"

namespace QCA
{
	// container for any kind of object in a keystore
	class QCA_EXPORT KeyStoreEntry : public Algorithm
	{
	public:
		enum Type
		{
			TypeKeyBundle,
			TypeCertificate,
			TypeCRL,
			TypePGPSecretKey,
			TypePGPPublicKey
		};

		KeyStoreEntry();
		KeyStoreEntry(const KeyStoreEntry &from);
		~KeyStoreEntry();
		KeyStoreEntry & operator=(const KeyStoreEntry &from);

		bool isNull() const;

		Type type() const;
		QString name() const;
		QString id() const;

		KeyBundle keyBundle() const;
		Certificate certificate() const;
		CRL crl() const;
		PGPKey pgpSecretKey() const;
		PGPKey pgpPublicKey() const;
	};

	/*
	  systemstore:          System TrustedCertificates
	  accepted self-signed: Application TrustedCertificates
	  apple keychain:       User Identities
	  smartcard:            SmartCard Identities
	  gnupg:                PGPKeyring Identities,PGPPublicKeys
	*/
	class QCA_EXPORT KeyStore : public QObject, public Algorithm
	{
		Q_OBJECT
	public:
		enum Type
		{
			System,      // root certs
			User,        // Apple Keychain, KDE Wallet, and others
			Application, // for caching accepted self-signed certs
			SmartCard,   // smartcards
			PGPKeyring   // pgp keyring
		};

		Type type() const;
		QString name() const;
		QString id() const;
		bool isReadOnly() const;

		QList<KeyStoreEntry> entryList() const;
		bool holdsTrustedCertificates() const; // Certificate and CRL
		bool holdsIdentities() const;          // KeyBundle and PGPSecretKey
		bool holdsPGPPublicKeys() const;       // PGPPublicKey

		bool writeEntry(const KeyBundle &kb);
		bool writeEntry(const Certificate &cert);
		bool writeEntry(const CRL &crl);
		PGPKey writeEntry(const PGPKey &key); // returns a ref to the key in the keyring
		bool removeEntry(const QString &id);

		void submitPassphrase(const QSecureArray &passphrase);

	signals:
		void updated();
		void unavailable();
		void needPassphrase();

	private:
		friend class KeyStoreManager;
		friend class KeyStoreManagerPrivate;
		KeyStore();
		~KeyStore();
	};

	// use this to get access to keystores and monitor for their activity
	class QCA_EXPORT KeyStoreManager : public QObject
	{
		Q_OBJECT
	public:
		KeyStore *keyStore(const QString &id) const;
		QList<KeyStore*> keyStores() const;
		int count() const;

		QString diagnosticText() const;

	signals:
		void keyStoreAvailable(const QString &id);

	private:
		friend class KeyStoreManagerPrivate;
		KeyStoreManagerPrivate *d;

		friend class Global;
		KeyStoreManager();
		~KeyStoreManager();

		void scan() const;
	};
}

#endif
