/*
 * qca_default.cpp - Qt Cryptographic Architecture
 * Copyright (C) 2004  Justin Karneges
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

#include "qca.h"

#include <qdatetime.h>
#include <qstringlist.h>
#include <stdlib.h>
#include "qcaprovider.h"

namespace QCA {

//----------------------------------------------------------------------------
// DefaultProvider
//----------------------------------------------------------------------------
class DefaultRandomContext : public QCA::RandomContext
{
public:
	DefaultRandomContext(QCA::Provider *p) : RandomContext(p) {}

	Context *clone() const
	{
		return new DefaultRandomContext(provider());
	}

	QSecureArray nextBytes(int size, QCA::Random::Quality)
	{
		QSecureArray buf(size);
		for(int n = 0; n < (int)buf.size(); ++n)
			buf[n] = (char)rand();
		return buf;
	}
};

class DefaultProvider : public QCA::Provider
{
public:
	void init()
	{
		QDateTime now = QDateTime::currentDateTime();
		time_t t = now.toTime_t() / now.time().msec();
		srand(t);
	}

	QString name() const
	{
		return "default";
	}

	QStringList features() const
	{
		QStringList list;
		list += "random";
		return list;
	}

	Context *createContext(const QString &type)
	{
		if(type == "random")
			return new DefaultRandomContext(this);
		else
			return 0;
	}
};

Provider *create_default_provider()
{
	return new DefaultProvider;
}

}
