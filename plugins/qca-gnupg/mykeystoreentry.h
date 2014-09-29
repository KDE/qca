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

#pragma once

#include "qcaprovider.h"

namespace gpgQCAPlugin
{

class MyKeyStoreList;

class MyKeyStoreEntry : public QCA::KeyStoreEntryContext
{
public:
	QCA::KeyStoreEntry::Type item_type;
	QCA::PGPKey pub, sec;
	QString _storeId, _storeName;

	MyKeyStoreEntry(const QCA::PGPKey &_pub, const QCA::PGPKey &_sec, QCA::Provider *p);
	MyKeyStoreEntry(const MyKeyStoreEntry &from);
	~MyKeyStoreEntry();

	// reimplemented Provider::Context
	QCA::Provider::Context *clone() const;

	// reimplemented KeyStoreEntryContext
	QCA::KeyStoreEntry::Type type() const;
	QString name() const;
	QString id() const;
	QString storeId() const;
	QString storeName() const;
	QCA::PGPKey pgpSecretKey() const;
	QCA::PGPKey pgpPublicKey() const;
	QString serialize() const;
};

} // end namespace gpgQCAPlugin
