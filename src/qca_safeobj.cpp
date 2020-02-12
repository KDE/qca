/*
 * qca_safeobj.h - Qt Cryptographic Architecture
 * Copyright (C) 2008  Justin Karneges <justin@affinix.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301  USA
 *
 */

#include "qca_safeobj.h"

namespace QCA {

// This function performs the following steps:
//   obj->disconnect(owner); // to prevent future signals to owner
//   obj->setParent(0);      // to prevent delete if parent is deleted
//   obj->deleteLater();     // now we can forget about the object
inline void releaseAndDeleteLater(QObject *owner, QObject *obj)
{
	obj->disconnect(owner);
	obj->setParent(nullptr);
	obj->deleteLater();
}

SafeSocketNotifier::SafeSocketNotifier(int socket, QSocketNotifier::Type type, QObject *parent) :
	QObject(parent)
{
	sn = new QSocketNotifier(socket, type, this);
	connect(sn, &QSocketNotifier::activated, this, &SafeSocketNotifier::activated);
}

SafeSocketNotifier::~SafeSocketNotifier()
{
	sn->setEnabled(false);
	releaseAndDeleteLater(this, sn);
}

}
