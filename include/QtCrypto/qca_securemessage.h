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

namespace QCA
{
	class SecureMessage : public QObject
	{
		Q_OBJECT
	public:
		// encrypt, decrypt, sign, verify
	};

	class SecureMessageSystem : public QObject
	{
		Q_OBJECT
	public:
		// setup, passphrase control
	};

	class OpenPGP : public SecureMessageSystem
	{
		Q_OBJECT
	public:
	};

	class SMIME : public SecureMessageSystem
	{
		Q_OBJECT
	public:
	};
}

#endif
