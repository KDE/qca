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

#include "mypgpkeycontext.h"
#include "myopenpgpcontext.h"
#include "mykeystorelist.h"
#include "qcaprovider.h"
#include <QtPlugin>

using namespace gpgQCAPlugin;

class gnupgProvider : public QCA::Provider
{
public:
	void init() override
	{
	}

	int qcaVersion() const override
	{
		return QCA_VERSION;
	}

	QString name() const override
	{
		return "qca-gnupg";
	}

	QStringList features() const override
	{
		QStringList list;
		list += "pgpkey";
		list += "openpgp";
		list += "keystorelist";
		return list;
	}

	Context *createContext(const QString &type) override
	{
		if(type == "pgpkey")
			return new MyPGPKeyContext(this);
		else if(type == "openpgp")
			return new MyOpenPGPContext(this);
		else if(type == "keystorelist")
			return new MyKeyStoreList(this);
		else
			return 0;
	}
};

class gnupgPlugin : public QObject, public QCAPlugin
{
	Q_OBJECT
#if QT_VERSION >= 0x050000
	Q_PLUGIN_METADATA(IID "com.affinix.qca.Plugin/1.0")
#endif
	Q_INTERFACES(QCAPlugin)
public:
	QCA::Provider *createProvider() override { return new gnupgProvider; }
};

#include "qca-gnupg.moc"
#if QT_VERSION < 0x050000
Q_EXPORT_PLUGIN2(qca_gnupg, gnupgPlugin)
#endif
