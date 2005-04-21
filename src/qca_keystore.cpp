/*
 * qca_keystore.cpp - Qt Cryptographic Architecture
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

#include "qca_keystore.h"

#include "qcaprovider.h"

namespace QCA {

//----------------------------------------------------------------------------
// KeyStoreEntry
//----------------------------------------------------------------------------
KeyStoreEntry::KeyStoreEntry()
{
}

KeyStoreEntry::KeyStoreEntry(const KeyStoreEntry &from)
:Algorithm(from)
{
}

KeyStoreEntry::~KeyStoreEntry()
{
}

KeyStoreEntry & KeyStoreEntry::operator=(const KeyStoreEntry &from)
{
	Algorithm::operator=(from);
	return *this;
}

bool KeyStoreEntry::isNull() const
{
	return (!context() ? true : false);
}

KeyStoreEntry::Type KeyStoreEntry::type() const
{
	return static_cast<const KeyStoreEntryContext *>(context())->type();
}

QString KeyStoreEntry::name() const
{
	return static_cast<const KeyStoreEntryContext *>(context())->name();
}

QString KeyStoreEntry::id() const
{
	return static_cast<const KeyStoreEntryContext *>(context())->id();
}

KeyBundle KeyStoreEntry::keyBundle() const
{
	return KeyBundle();
}

Certificate KeyStoreEntry::certificate() const
{
	return static_cast<const KeyStoreEntryContext *>(context())->certificate();
}

CRL KeyStoreEntry::crl() const
{
	return static_cast<const KeyStoreEntryContext *>(context())->crl();
}

PGPKey KeyStoreEntry::pgpSecretKey() const
{
	return PGPKey();
}

PGPKey KeyStoreEntry::pgpPublicKey() const
{
	return PGPKey();
}

//----------------------------------------------------------------------------
// KeyStore
//----------------------------------------------------------------------------
KeyStore::KeyStore()
{
}

KeyStore::~KeyStore()
{
}

KeyStore::Type KeyStore::type() const
{
	return static_cast<const KeyStoreContext *>(context())->type();
}

QString KeyStore::name() const
{
	return static_cast<const KeyStoreContext *>(context())->name();
}

QString KeyStore::id() const
{
	return static_cast<const KeyStoreContext *>(context())->deviceId();
}

bool KeyStore::isReadOnly() const
{
	return static_cast<const KeyStoreContext *>(context())->isReadOnly();
}

QList<KeyStoreEntry> KeyStore::entryList() const
{
	QList<KeyStoreEntry> out;
	QList<KeyStoreEntryContext*> list = static_cast<const KeyStoreContext *>(context())->entryList();
	for(int n = 0; n < list.count(); ++n)
	{
		KeyStoreEntry entry;
		entry.change(list[n]);
		out.append(entry);
	}
	//printf("KeyStore::entryList(): %d entries\n", out.count());
	return out;
}

bool KeyStore::holdsTrustedCertificates() const
{
	QList<KeyStoreEntry::Type> list = static_cast<const KeyStoreContext *>(context())->entryTypes();
	if(list.contains(KeyStoreEntry::TypeCertificate) || list.contains(KeyStoreEntry::TypeCRL))
		return true;
	return false;
}

bool KeyStore::holdsIdentities() const
{
	QList<KeyStoreEntry::Type> list = static_cast<const KeyStoreContext *>(context())->entryTypes();
	if(list.contains(KeyStoreEntry::TypeKeyBundle) || list.contains(KeyStoreEntry::TypePGPSecretKey))
		return true;
	return false;
}

bool KeyStore::holdsPGPPublicKeys() const
{
	QList<KeyStoreEntry::Type> list = static_cast<const KeyStoreContext *>(context())->entryTypes();
	if(list.contains(KeyStoreEntry::TypePGPPublicKey))
		return true;
	return false;
}

bool KeyStore::writeEntry(const KeyBundle &kb)
{
	Q_UNUSED(kb);
	return false;
}

bool KeyStore::writeEntry(const Certificate &cert)
{
	Q_UNUSED(cert);
	return false;
}

bool KeyStore::writeEntry(const CRL &crl)
{
	Q_UNUSED(crl);
	return false;
}

PGPKey KeyStore::writeEntry(const PGPKey &key)
{
	Q_UNUSED(key);
	return PGPKey();
}

bool KeyStore::removeEntry(const QString &id)
{
	Q_UNUSED(id);
	return false;
}

void KeyStore::submitPassphrase(const QSecureArray &passphrase)
{
	static_cast<KeyStoreContext *>(context())->submitPassphrase(passphrase);
}

//----------------------------------------------------------------------------
// KeyStoreManager
//----------------------------------------------------------------------------

/*
  How this stuff works:

  KeyStoreListContext is queried for a list of KeyStoreContexts.  A signal
  is used to indicate when the list may have changed, so polling for changes
  is not necessary.  Every context object created internally by the provider
  will have a unique contextId, and this is used for detecting changes.  Even
  if a user removes and inserts the same smart card device, which has the
  same deviceId, the contextId will ALWAYS be different.  If a previously
  known contextId is missing from a later queried list, then it means the
  associated KeyStoreContext has been deleted by the provider (the manager
  here does not delete them, it just throws away any references).  It is
  recommended that the provider just use a counter for the contextId,
  incrementing the value anytime a new context is made.
*/

typedef QMap<int, KeyStoreContext*> KeyStoreMap;

static KeyStoreMap make_map(const QList<KeyStoreContext*> &list)
{
	KeyStoreMap map;
	for(int n = 0; n < list.count(); ++n)
		map.insert(list[n]->contextId(), list[n]);
	return map;
}

class KeyStoreManagerPrivate : public QObject
{
	Q_OBJECT
public:
	KeyStoreManager *q;
	QList<KeyStoreListContext*> sources;
	QMap<KeyStoreListContext*, KeyStoreMap> stores;

	class Item
	{
	public:
		KeyStore *keyStore;
		bool announced;

		Item() : keyStore(0), announced(false) {}
		Item(KeyStore *ks) : keyStore(ks), announced(false) {}
	};

	QList<Item> active;
	QList<KeyStore*> trash;

	KeyStoreManagerPrivate(KeyStoreManager *_q) : q(_q)
	{
	}

	~KeyStoreManagerPrivate()
	{
		int n;
		for(n = 0; n < trash.count(); ++n)
			delete trash[n];

		for(n = 0; n < active.count(); ++n)
		{
			KeyStore *ks = active[n].keyStore;
			ks->takeContext(); // context not ours, so use this instead of change(0)
			delete ks;
		}
	}

	void scan()
	{
		// grab providers (and default)
		ProviderList list = providers();
		list.append(defaultProvider());

		for(int n = 0; n < list.count(); ++n)
		{
			if(list[n]->features().contains("keystorelist") && !contextForProvider(list[n]))
			{
				KeyStoreListContext *c = static_cast<KeyStoreListContext *>(list[n]->createContext("keystorelist"));
				sources.append(c);
				connect(c, SIGNAL(updated(KeyStoreListContext *)), SLOT(updated(KeyStoreListContext *)));
				check(c);
			}
		}
	}

private:
	KeyStoreListContext *contextForProvider(Provider *p)
	{
		for(int n = 0; n < sources.count(); ++n)
		{
			if(sources[n]->provider() == p)
				return sources[n];
		}
		return 0;
	}

	void check(KeyStoreListContext *source)
	{
		//printf("KeyStore: query begin [%s]\n", qPrintable(source->provider()->name()));

		QList<KeyStoreContext*> added;
		QList<int> removed;

		KeyStoreMap cur = make_map(source->keyStores());
		if(stores.contains(source))
		{
			KeyStoreMap old = stores.value(source);

			KeyStoreMap::ConstIterator it;
			for(it = old.begin(); it != old.end(); ++it)
			{
				if(!cur.contains(it.key()))
					removed.append(it.key());
			}
			for(it = cur.begin(); it != cur.end(); ++it)
			{
				if(!old.contains(it.key()))
					added.append(it.value());
			}
		}
		else
		{
			added = cur.values();
		}
		stores.insert(source, cur);

		for(int n = 0; n < removed.count(); ++n)
		{
			//printf("  - <%d>\n", removed[n]);
			ctx_remove(source->provider(), removed[n]);
		}

		for(int n = 0; n < added.count(); ++n)
		{
			//printf("  + <%d> [%s]\n", added[n]->contextId(), qPrintable(added[n]->deviceId()));
			ctx_add(added[n]);
		}

		//printf("KeyStore: query end\n");
	}

	void ctx_add(KeyStoreContext *c)
	{
		// skip if we have this deviceId already
		for(int n = 0; n < active.count(); ++n)
		{
			KeyStoreContext *i = static_cast<KeyStoreContext *>(active[n].keyStore->context());
			if(c->deviceId() == i->deviceId())
			{
				//printf("KeyStore: ERROR: duplicate device id [%s], skipping\n", qPrintable(c->deviceId()));
				return;
			}
		}

		// add the keystore
		KeyStore *ks = new KeyStore;
		ks->change(c);
		active.append(Item(ks));
	}

	void ctx_remove(Provider *p, int id)
	{
		// look up and remove
		for(int n = 0; n < active.count(); ++n)
		{
			KeyStoreContext *i = static_cast<KeyStoreContext *>(active[n].keyStore->context());
			if(i->provider() == p && i->contextId() == id)
			{
				KeyStore *ks = active[n].keyStore;
				active.removeAt(n);
				ks->takeContext(); // context not ours, so use this instead of change(0)
				trash.append(ks);
			}
		}
	}

private slots:
	void updated(KeyStoreListContext *sender)
	{
		check(sender);
	}

	void handleChanged()
	{
		// signal unavailable, empty trash
		int n;
		for(n = 0; n < trash.count(); ++n)
		{
			emit trash[n]->unavailable();
			delete trash[n];
		}
		trash.clear();

		// signal available
		for(n = 0; n < active.count(); ++n)
		{
			if(!active[n].announced)
			{
				active[n].announced = true;
				emit q->keyStoreAvailable(active[n].keyStore->id());
			}
		}
	}

	void emptyTrash()
	{
		trash.clear();
	}
};

KeyStoreManager::KeyStoreManager()
{
	d = new KeyStoreManagerPrivate(this);
}

KeyStoreManager::~KeyStoreManager()
{
	delete d;
}

KeyStore *KeyStoreManager::keyStore(const QString &id) const
{
	int n;

	// see if we have it
	for(n = 0; n < d->active.count(); ++n)
	{
		if(d->active[n].keyStore->id() == id)
			return d->active[n].keyStore;
	}

	// if not, scan for more
	scan();

	// have it now?
	for(n = 0; n < d->active.count(); ++n)
	{
		if(d->active[n].keyStore->id() == id)
			return d->active[n].keyStore;
	}

	return 0;
}

QList<KeyStore*> KeyStoreManager::keyStores() const
{
	scan();

	QList<KeyStore*> list;
	for(int n = 0; n < d->active.count(); ++n)
		list.append(d->active[n].keyStore);
	return list;
}

int KeyStoreManager::count() const
{
	scan();

	return d->active.count();
}

QString KeyStoreManager::diagnosticText() const
{
	// TODO
	return QString();
}

void KeyStoreManager::scan() const
{
	scanForPlugins();
	d->scan();
}

}

#include "qca_keystore.moc"
