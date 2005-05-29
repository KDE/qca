/*
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

#include "qca_plugin.h"

#include <QtCore>
#include "qcaprovider.h"

#define PLUGIN_SUBDIR "crypto"

namespace QCA {

class ProviderItem
{
public:
	Provider *p;
	QString fname;
	int priority;

	static ProviderItem *load(const QString &fname)
	{
		QPluginLoader *lib = new QPluginLoader(fname);
		QCAPlugin *plugin = qobject_cast<QCAPlugin*>(lib->instance());
		if(!plugin || plugin->version() != QCA_PLUGIN_VERSION)
		{
			delete lib;
			return 0;
		}

		Provider *p = plugin->createProvider();
		if(!p)
		{
			delete lib;
			return 0;
		}

		ProviderItem *i = new ProviderItem(lib, p);
		i->fname = fname;
		return i;
	}

	static ProviderItem *loadStatic(QObject *instance)
	{
		QCAPlugin *plugin = qobject_cast<QCAPlugin*>(instance);
		if(!plugin || plugin->version() != QCA_PLUGIN_VERSION)
			return 0;

		Provider *p = plugin->createProvider();
		if(!p)
			return 0;

		ProviderItem *i = new ProviderItem(0, p);
		return i;
	}

	static ProviderItem *fromClass(Provider *p)
	{
		ProviderItem *i = new ProviderItem(0, p);
		return i;
	}

	~ProviderItem()
	{
		delete p;
		delete lib;
	}

	void ensureInit()
	{
		if(init_done)
			return;
		init_done = true;
		p->init();
	}

private:
	QPluginLoader *lib;
	bool init_done;

	ProviderItem(QPluginLoader *_lib, Provider *_p)
	{
		lib = _lib;
		p = _p;
		init_done = false;
	}
};

ProviderManager::ProviderManager()
{
	def = 0;
	scanned_static = false;
}

ProviderManager::~ProviderManager()
{
	delete def;
}

void ProviderManager::scan()
{
	// check static first, but only once
	if(!scanned_static)
	{
		QObjectList list = QPluginLoader::staticInstances();
		for(int n = 0; n < list.count(); ++n)
		{
			QObject *instance = list[n];
			ProviderItem *i = ProviderItem::loadStatic(instance);
			if(!i)
				continue;

			if(i->p && haveAlready(i->p->name()))
			{
				delete i;
				continue;
			}

			addItem(i, -1);
		}
		scanned_static = true;
	}

	// check plugin files
	QStringList dirs = QCoreApplication::libraryPaths();
	for(QStringList::ConstIterator it = dirs.begin(); it != dirs.end(); ++it)
	{
		QDir libpath(*it);
		QDir dir(libpath.filePath(PLUGIN_SUBDIR));
		if(!dir.exists())
			continue;

		QStringList list = dir.entryList();
		for(QStringList::ConstIterator it = list.begin(); it != list.end(); ++it)
		{
			QFileInfo fi(dir.filePath(*it));
			if(fi.isDir())
				continue;
			QString fname = fi.filePath();

			ProviderItem *i = ProviderItem::load(fname);
			if(!i)
				continue;

			if(i->p && haveAlready(i->p->name()))
			{
				delete i;
				continue;
			}

			addItem(i, -1);
		}
	}
}

bool ProviderManager::add(Provider *p, int priority)
{
	if(haveAlready(p->name()))
		return false;

	ProviderItem *i = ProviderItem::fromClass(p);
	addItem(i, priority);
	return true;
}

void ProviderManager::unload(const QString &name)
{
	for(int n = 0; n < providerItemList.count(); ++n)
	{
		ProviderItem *i = providerItemList[n];
		if(i->p && i->p->name() == name)
		{
			delete i;
			providerItemList.removeAt(n);
			providerList.removeAt(n);
			return;
		}
	}
}

void ProviderManager::unloadAll()
{
	qDeleteAll(providerItemList);
	providerItemList.clear();
	providerList.clear();
}

void ProviderManager::setDefault(Provider *p)
{
	if(def)
		delete def;
	def = p;
	if(def)
		def->init();
}

Provider *ProviderManager::find(Provider *p) const
{
	if(p == def)
		return def;

	for(int n = 0; n < providerItemList.count(); ++n)
	{
		ProviderItem *i = providerItemList[n];
		if(i->p && i->p == p)
		{
			i->ensureInit();
			return i->p;
		}
	}
	return 0;
}

Provider *ProviderManager::find(const QString &name) const
{
	if(def && name == def->name())
		return def;

	for(int n = 0; n < providerItemList.count(); ++n)
	{
		ProviderItem *i = providerItemList[n];
		if(i->p && i->p->name() == name)
		{
			i->ensureInit();
			return i->p;
		}
	}
	return 0;
}

Provider *ProviderManager::findFor(const QString &name, const QString &type) const
{
	if(name.isEmpty())
	{
		// find the first one that can do it
		for(int n = 0; n < providerItemList.count(); ++n)
		{
			ProviderItem *i = providerItemList[n];
			i->ensureInit();
			if(i->p && i->p->features().contains(type))
				return i->p;
		}

		// try the default provider as a last resort
		if(def && def->features().contains(type))
			return def;

		return 0;
	}
	else
	{
		Provider *p = find(name);
		if(p && p->features().contains(type))
			return p;
		return 0;
	}
}

void ProviderManager::changePriority(const QString &name, int priority)
{
	ProviderItem *i = 0;
	int n = 0;
	for(; n < providerItemList.count(); ++n)
	{
		ProviderItem *pi = providerItemList[n];
		if(pi->p && pi->p->name() == name)
		{
			i = pi;
			break;
		}
	}
	if(!i)
		return;

	providerItemList.removeAt(n);
	providerList.removeAt(n);

	addItem(i, priority);
}

int ProviderManager::getPriority(const QString &name)
{
	ProviderItem *i = 0;
	for(int n = 0; n < providerItemList.count(); ++n)
	{
		ProviderItem *pi = providerItemList[n];
		if(pi->p && pi->p->name() == name)
		{
			i = pi;
			break;
		}
	}
	if(!i)
		return -1;

	return i->priority;
}

QStringList ProviderManager::allFeatures() const
{
	QStringList list;

	if(def)
		list = def->features();

	for(int n = 0; n < providerItemList.count(); ++n)
	{
		ProviderItem *i = providerItemList[n];
		if(i->p)
			mergeFeatures(&list, i->p->features());
	}

	return list;
}

const ProviderList & ProviderManager::providers() const
{
	return providerList;
}

void ProviderManager::addItem(ProviderItem *item, int priority)
{
	if(priority < 0)
	{
		// for -1, make the priority the same as the last item
		if(!providerItemList.isEmpty())
		{
			ProviderItem *last = providerItemList.last();
			item->priority = last->priority;
		}
		else
			item->priority = 0;

		providerItemList.append(item);
		providerList.append(item->p);
	}
	else
	{
		// place the item before any other items with same or greater priority
		int n = 0;
		for(; n < providerItemList.count(); ++n)
		{
			ProviderItem *i = providerItemList[n];
			if(i->priority >= priority)
				break;
		}

		item->priority = priority;
		providerItemList.insert(n, item);
		providerList.insert(n, item->p);
	}
}

bool ProviderManager::haveAlready(const QString &name) const
{
	return ((def && name == def->name()) || find(name));
}

void ProviderManager::mergeFeatures(QStringList *a, const QStringList &b)
{
	for(QStringList::ConstIterator it = b.begin(); it != b.end(); ++it)
	{
		if(!a->contains(*it))
			a->append(*it);
	}
}

}
