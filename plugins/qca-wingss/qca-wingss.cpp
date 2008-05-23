/*
 * Copyright (C) 2008  Barracuda Networks, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301  USA
 *
 */

#include <QtCrypto>
#include <qcaprovider.h>
#include <QtPlugin>

using namespace QCA;

namespace wingssQCAPlugin {

class wingssProvider : public Provider
{
public:
	wingssProvider()
	{
	}

	virtual int qcaVersion() const
	{
		return QCA_VERSION;
	}

	virtual QString name() const
	{
		return "qca-wingss";
	}

	virtual QStringList features() const
	{
		return QStringList();
	}

	virtual Context *createContext(const QString &type)
	{
		Q_UNUSED(type);
		return 0;
	}
};

}

using namespace wingssQCAPlugin;

//----------------------------------------------------------------------------
// wingssPlugin
//----------------------------------------------------------------------------

class wingssPlugin : public QObject, public QCAPlugin
{
	Q_OBJECT
	Q_INTERFACES(QCAPlugin)

public:
	virtual Provider *createProvider() { return new wingssProvider; }
};

#include "qca-wingss.moc"

Q_EXPORT_PLUGIN2(qca_wingss, wingssPlugin)
