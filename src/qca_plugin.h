/*
 * qca_plugin.h - Qt Cryptographic Architecture
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

#ifndef QCA_PLUGIN_H
#define QCA_PLUGIN_H

// NOTE: this API is private to QCA

#include <qptrlist.h>
#include <qstringlist.h>
#include "qca.h"

namespace QCA
{
	class ProviderItem;

	class ProviderManager
	{
	public:
		ProviderManager();
		~ProviderManager();

		void scan();
		bool add(QCA::Provider *p, int priority);
		void add(QCAProvider *p); // to be obsoleted
		void unload(const QString &name);
		void unloadAll();
		void setDefault(QCA::Provider *p);
		QCA::Provider *find(const QString &name) const;
		QCA::Provider *findFor(const QString &name, const QString &type) const;
		QCAProvider *findFor(int cap) const; // to be obsoleted
		void changePriority(const QString &name, int priority);
		QStringList allFeatures(bool includeOld = true) const;
		int caps() const; // to be obsoleted
		const ProviderList & providers() const;

		static void mergeFeatures(QStringList *a, const QStringList &b);
		static QStringList capsToStringList(int cap);

	private:
		QPtrList<ProviderItem> providerItemList;
		QCA::ProviderList providerList;
		QCA::Provider *def;
		void addItem(ProviderItem *i, int priority);
		bool haveAlready(const QString &name) const;
	};
}

#endif
