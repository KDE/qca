/*
 * qca_keystore.cpp - Qt Cryptographic Architecture
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

#include "qca_keystore.h"

namespace QCA {

//----------------------------------------------------------------------------
// KeyStoreEntry
//----------------------------------------------------------------------------
KeyStoreEntry::KeyStoreEntry()
{
}

KeyStoreEntry::KeyStoreEntry(const KeyStoreEntry &from)
:Algorithm(from)
{
}

KeyStoreEntry::~KeyStoreEntry()
{
}

KeyStoreEntry & KeyStoreEntry::operator=(const KeyStoreEntry &from)
{
	Algorithm::operator=(from);
	return *this;
}

bool KeyStoreEntry::isNull() const
{
	return false;
}

KeyStoreEntry::Type KeyStoreEntry::type() const
{
	return TypeCertificate;
}

QString KeyStoreEntry::name() const
{
	return QString();
}

QString KeyStoreEntry::id() const
{
	return QString();
}

KeyBundle KeyStoreEntry::keyBundle() const
{
	return KeyBundle();
}

Certificate KeyStoreEntry::certificate() const
{
	return Certificate();
}

CRL KeyStoreEntry::crl() const
{
	return CRL();
}

PGPKey KeyStoreEntry::pgpSecretKey() const
{
	return PGPKey();
}

PGPKey KeyStoreEntry::pgpPublicKey() const
{
	return PGPKey();
}

//----------------------------------------------------------------------------
// KeyStore
//----------------------------------------------------------------------------
KeyStore::KeyStore()
{
}

KeyStore::KeyStore(const KeyStore &from)
:Algorithm(from)
{
}

KeyStore::~KeyStore()
{
}

KeyStore & KeyStore::operator=(const KeyStore &from)
{
	Algorithm::operator=(from);
	return *this;
}

bool KeyStore::isNull() const
{
	return false;
}

KeyStore::Type KeyStore::type() const
{
	return System;
}

QString KeyStore::name() const
{
	return QString();
}

QString KeyStore::id() const
{
	return QString();
}

bool KeyStore::isReadOnly() const
{
	return false;
}

QList<KeyStoreEntry> KeyStore::entryList() const
{
	return QList<KeyStoreEntry>();
}

bool KeyStore::containsTrustedCertificates() const
{
	return false;
}

bool KeyStore::containsIdentities() const
{
	return false;
}

bool KeyStore::containsPGPPublicKeys() const
{
	return false;
}

bool KeyStore::writeEntry(const KeyBundle &kb)
{
	Q_UNUSED(kb);
	return false;
}

bool KeyStore::writeEntry(const Certificate &cert)
{
	Q_UNUSED(cert);
	return false;
}

bool KeyStore::writeEntry(const CRL &crl)
{
	Q_UNUSED(crl);
	return false;
}

PGPKey KeyStore::writeEntry(const PGPKey &key)
{
	Q_UNUSED(key);
	return PGPKey();
}

bool KeyStore::removeEntry(const QString &id)
{
	Q_UNUSED(id);
	return false;
}

//----------------------------------------------------------------------------
// KeyStoreManager
//----------------------------------------------------------------------------
KeyStoreManager::KeyStoreManager()
{
}

KeyStoreManager::~KeyStoreManager()
{
}

KeyStore KeyStoreManager::keyStore(const QString &id) const
{
	Q_UNUSED(id);
	return KeyStore();
}

QList<KeyStore> KeyStoreManager::keyStores() const
{
	return QList<KeyStore>();
}

int KeyStoreManager::count() const
{
	return 0;
}

}
