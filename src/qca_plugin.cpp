/*
 * qca_plugin.cpp - Qt Cryptographic Architecture
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

#include <qapplication.h>
#include <qdir.h>
#include <qfileinfo.h>
#include <qlibrary.h>
#include "qcaprovider.h"

#if defined(Q_OS_WIN32)
# define PLUGIN_EXT "dll"
#elif defined(Q_OS_MAC)
# define PLUGIN_EXT "dylib"
#else
# define PLUGIN_EXT "so"
#endif

#define PLUGIN_SUBDIR "crypto"

namespace QCA {

class ProviderItem
{
public:
	QCA::Provider *p;
	QCAProvider *p_old;
	QString fname;
	int version;
	int priority;

	static ProviderItem *load(const QString &fname)
	{
		QLibrary *lib = new QLibrary(fname);
		if(!lib->load())
		{
			delete lib;
			return 0;
		}

		int ver = 0;
		bool old;
		void *s = lib->resolve("version");
		if(s)
		{
			old = false;
			int (*versionfunc)() = (int (*)())s;
			ver = versionfunc();
		}
		else
		{
			old = true;
		}

		s = lib->resolve("createProvider");
		if(!s)
		{
			delete lib;
			return 0;
		}

		ProviderItem *i;
		if(old)
		{
			// old method
			QCAProvider *(*createProvider)() = (QCAProvider *(*)())s;
			QCAProvider *p = createProvider();
			if(!p)
			{
				delete lib;
				return 0;
			}
			ver = p->qcaVersion();
			i = new ProviderItem(lib, p);
		}
		else
		{
			// new method
			QCA::Provider *(*createProvider)() = (QCA::Provider *(*)())s;
			QCA::Provider *p = createProvider();
			if(!p)
			{
				delete lib;
				return 0;
			}
			i = new ProviderItem(lib, p);
		}

		i->fname = fname;
		i->version = ver;
		return i;
	}

	static ProviderItem *fromClass(QCA::Provider *p)
	{
		ProviderItem *i = new ProviderItem(0, p);
		return i;
	}

	static ProviderItem *fromClass(QCAProvider *p)
	{
		ProviderItem *i = new ProviderItem(0, p);
		return i;
	}

	~ProviderItem()
	{
		delete p;
		delete p_old;
		delete lib;
	}

	void ensureInit()
	{
		if(init_done)
			return;
		init_done = true;
		if(p)
			p->init();
		else
			p_old->init();
	}

private:
	QLibrary *lib;
	bool init_done;

	ProviderItem(QLibrary *_lib, QCA::Provider *_p)
	{
		lib = _lib;
		p = _p;
		p_old = 0;
		init_done = false;
	}

	ProviderItem(QLibrary *_lib, QCAProvider *_p_old)
	{
		lib = _lib;
		p = 0;
		p_old = _p_old;
		init_done = false;
	}
};

ProviderManager::ProviderManager()
{
	providerItemList.setAutoDelete(true);
	def = 0;
}

ProviderManager::~ProviderManager()
{
	delete def;
}

void ProviderManager::scan()
{
	QStringList dirs = QApplication::libraryPaths();
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
			if(fi.extension() != PLUGIN_EXT)
				continue;
			QString fname = fi.filePath();

			ProviderItem *i = ProviderItem::load(fname);
			if(!i)
				continue;
			if(i->version != QCA_PLUGIN_VERSION && i->version != 1)
			{
				delete i;
				continue;
			}

			if(i->p && haveAlready(i->p->name()))
			{
				delete i;
				continue;
			}

			addItem(i, -1);
		}
	}
}

bool ProviderManager::add(QCA::Provider *p, int priority)
{
	if(haveAlready(p->name()))
		return false;

	ProviderItem *i = ProviderItem::fromClass(p);
	addItem(i, priority);
	return true;
}

void ProviderManager::add(QCAProvider *p)
{
	ProviderItem *i = ProviderItem::fromClass(p);
	addItem(i, 0); // prepend
}

void ProviderManager::unload(const QString &name)
{
	QPtrListIterator<ProviderItem> it(providerItemList);
	ProviderListIterator pit(providerList);
	for(ProviderItem *i; (i = it.current()); ++it)
	{
		if(i->p && i->p->name() == name)
		{
			providerItemList.removeRef(i);
			providerList.removeRef(*pit);
			return;
		}
		++pit;
	}
}

void ProviderManager::unloadAll()
{
	providerItemList.clear();
	providerList.clear();
}

void ProviderManager::setDefault(QCA::Provider *p)
{
	if(def)
		delete def;
	def = p;
	if(def)
		def->init();
}

QCA::Provider *ProviderManager::find(const QString &name) const
{
	if(def && name == def->name())
		return def;

	QPtrListIterator<ProviderItem> it(providerItemList);
	for(ProviderItem *i; (i = it.current()); ++it)
	{
		if(i->p && i->p->name() == name)
		{
			i->ensureInit();
			return i->p;
		}
	}
	return 0;
}

QCA::Provider *ProviderManager::findFor(const QString &name, const QString &type) const
{
	if(name.isEmpty())
	{
		// find the first one that can do it
		QPtrListIterator<ProviderItem> it(providerItemList);
		for(ProviderItem *i; (i = it.current()); ++it)
		{
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

QCAProvider *ProviderManager::findFor(int cap) const
{
	// find the first one that can do it
	QPtrListIterator<ProviderItem> it(providerItemList);
	for(ProviderItem *i; (i = it.current()); ++it)
	{
		i->ensureInit();
		if(i->p_old && i->p_old->capabilities() & cap)
			return i->p_old;
	}
	return 0;
}

void ProviderManager::changePriority(const QString &name, int priority)
{
	QPtrListIterator<ProviderItem> it(providerItemList);
	ProviderItem *i = 0;
	for(ProviderItem *pi; (pi = it.current()); ++it)
	{
		if(pi->p && pi->p->name() == name)
		{
			i = pi;
			break;
		}
	}
	if(!i)
		return;

	providerItemList.setAutoDelete(false);
	providerItemList.removeRef(i);
	providerItemList.setAutoDelete(true);
	providerList.removeRef(i->p);

	addItem(i, priority);
}

QStringList ProviderManager::allFeatures() const
{
	QStringList list;

	if(def)
		list = def->features();

	QPtrListIterator<ProviderItem> it(providerItemList);
	for(ProviderItem *i; (i = it.current()); ++it)
	{
		if(i->p)
			mergeFeatures(&list, i->p->features());
	}

	return list;
}

int ProviderManager::caps() const
{
	int caps = 0;
	QPtrListIterator<ProviderItem> it(providerItemList);
	for(ProviderItem *i; (i = it.current()); ++it)
	{
		if(i->p_old)
			caps |= i->p_old->capabilities();
	}
	return caps;
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
		ProviderItem *last = providerItemList.getLast();
		if(last)
			item->priority = last->priority;
		else
			item->priority = 0;

		providerItemList.append(item);
		providerList.append(item->p);
	}
	else
	{
		// place the item before any other items with same or greater priority
		int at = 0;
		QPtrListIterator<ProviderItem> it(providerItemList);
		for(ProviderItem *i; (i = it.current()); ++it)
		{
			if(i->priority >= priority)
				break;
			++at;
		}

		item->priority = priority;
		providerItemList.insert(at, item);
		providerList.insert(at, item->p);
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
