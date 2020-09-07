/*
 * Copyright (C) 2003-2008  Justin Karneges <justin@affinix.com>
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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include "mykeystoreentry.h"
#include "utils.h"

using namespace QCA;

namespace gpgQCAPlugin {

MyKeyStoreEntry::MyKeyStoreEntry(const PGPKey &_pub, const PGPKey &_sec, Provider *p)
    : KeyStoreEntryContext(p)
{
    pub = _pub;
    sec = _sec;
    if (!sec.isNull())
        item_type = KeyStoreEntry::TypePGPSecretKey;
    else
        item_type = KeyStoreEntry::TypePGPPublicKey;
}

MyKeyStoreEntry::MyKeyStoreEntry(const MyKeyStoreEntry &from)
    : KeyStoreEntryContext(from)
{
}

MyKeyStoreEntry::~MyKeyStoreEntry()
{
}

Provider::Context *MyKeyStoreEntry::clone() const
{
    return new MyKeyStoreEntry(*this);
}

KeyStoreEntry::Type MyKeyStoreEntry::type() const
{
    return item_type;
}

QString MyKeyStoreEntry::name() const
{
    return pub.primaryUserId();
}

QString MyKeyStoreEntry::id() const
{
    return pub.keyId();
}

QString MyKeyStoreEntry::storeId() const
{
    return _storeId;
}

QString MyKeyStoreEntry::storeName() const
{
    return _storeName;
}

PGPKey MyKeyStoreEntry::pgpSecretKey() const
{
    return sec;
}

PGPKey MyKeyStoreEntry::pgpPublicKey() const
{
    return pub;
}

QString MyKeyStoreEntry::serialize() const
{
    // we only serialize the key id.  this means the keyring
    //   must be available to restore the data
    QStringList out;
    out += escape_string(QStringLiteral("qca-gnupg-1"));
    out += escape_string(pub.keyId());
    return out.join(QStringLiteral(":"));
}

} // end namespace gpgQCAPlugin
