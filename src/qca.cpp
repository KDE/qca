/*
 * qca.cpp - Qt Cryptographic Architecture
 * Copyright (C) 2003,2004  Justin Karneges
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

#include"qca.h"

#include <qptrlist.h>
#include <qstringlist.h>
#include <qtimer.h>
#include <qhostaddress.h>
#include <qguardedptr.h>
#include <qptrdict.h>
#include <stdlib.h>
#include "qcaprovider.h"
#include "qca_plugin.h"
#include "qca_systemstore.h"

namespace QCA {

// from qca_tools
bool botan_init(int prealloc, bool mmap);
void botan_deinit();
void *botan_secure_alloc(int bytes);
void botan_secure_free(void *p, int bytes);

// from qca_default
Provider *create_default_provider();

//----------------------------------------------------------------------------
// Global
//----------------------------------------------------------------------------
static QCA::ProviderManager *manager = 0;
static QCA::Random *global_rng = 0;
static QPtrDict<int> *memtable = 0;
static bool qca_init = false;
static bool qca_secmem = false;

static bool features_have(const QStringList &have, const QStringList &want)
{
	for(QStringList::ConstIterator it = want.begin(); it != want.end(); ++it)
	{
		if(!have.contains(*it))
			return false;
	}
	return true;
}

void init()
{
	init(Practical, 64);
}

void init(MemoryMode mode, int prealloc)
{
	if(qca_init)
		return;

	qca_init = true;

	bool allow_mmap_fallback = false;
	bool drop_root = false;
	if(mode == Practical)
	{
		allow_mmap_fallback = true;
		drop_root = true;
	}
	else if(mode == Locking)
		drop_root = true;

	qca_secmem = botan_init(prealloc, allow_mmap_fallback);

	if(drop_root)
	{
#ifdef Q_OS_UNIX
		setuid(getuid());
#endif
	}

	memtable = new QPtrDict<int>;
	memtable->setAutoDelete(true);

	manager = new ProviderManager;
	manager->setDefault(create_default_provider()); // manager owns it
}

void deinit()
{
	if(!qca_init)
		return;

	delete global_rng;
	global_rng = 0;

	delete manager;
	manager = 0;

	delete memtable;
	memtable = 0;

	botan_deinit();
	qca_secmem = false;
	qca_init = false;
}

bool haveSecureMemory()
{
	return qca_secmem;
}

bool isSupported(const QStringList &features)
{
	if(!qca_init)
		return false;

	if(features_have(manager->allFeatures(), features))
		return true;

	// ok, try scanning for new stuff
	manager->scan();

	if(features_have(manager->allFeatures(), features))
		return true;

	return false;
}

bool isSupported(const char *features)
{
	return isSupported(QStringList::split(',', QString(features)));
}

QStringList supportedFeatures()
{
	init();

	// query all features
	manager->scan();
	return manager->allFeatures();
}

QStringList defaultFeatures()
{
	init();
	return manager->find("default")->features();
}

bool insertProvider(Provider *p, int priority)
{
	init();
	return manager->add(p, priority);
}

void setProviderPriority(const QString &name, int priority)
{
	if(!qca_init)
		return;

	manager->changePriority(name, priority);
}

const ProviderList & providers()
{
	init();
	return manager->providers();
}

void unloadAllPlugins()
{
	if(!qca_init)
		return;

	// if the global_rng was owned by a plugin, then delete it
	if(global_rng && (global_rng->provider() != manager->find("default")))
	{
		delete global_rng;
		global_rng = 0;
	}

	manager->unloadAll();
}

Random & globalRNG()
{
	if(!global_rng)
		global_rng = new Random;
	return *global_rng;
}

void setGlobalRNG(const QString &provider)
{
	delete global_rng;
	global_rng = new Random(provider);
}

bool haveSystemStore()
{
#ifndef QCA_NO_SYSTEMSTORE
	return qca_have_systemstore();
#else
	return false;
#endif
}

Store systemStore(const QString &provider)
{
#ifndef QCA_NO_SYSTEMSTORE
	return qca_get_systemstore(provider);
#else
	return Store(provider);
#endif
}

QString appName()
{
	return "";
}

void setAppName(const QString &)
{
}

QString arrayToHex(const QSecureArray &a)
{
	return Hex().arrayToString(a);
}

QByteArray hexToArray(const QString &str)
{
	return Hex().stringToArray(str).toByteArray();
}

} // namespace QCA

void *qca_secure_alloc(int bytes)
{
	void *p = QCA::botan_secure_alloc(bytes);
	QCA::memtable->insert(p, new int(bytes));
	return p;
}

void qca_secure_free(void *p)
{
	int *bytes = QCA::memtable->find(p);
	if(bytes)
	{
		QCA::botan_secure_free(p, *bytes);
		QCA::memtable->remove(p);
	}
}

namespace QCA {

Provider::Context *getContext(const QString &type, const QString &provider)
{
	init();

	Provider *p = 0;
	bool scanned = false;
	if(!provider.isEmpty())
	{
		// try using specific provider
		p = manager->findFor(provider, type);
		if(!p)
		{
			// maybe this provider is new, so scan and try again
			manager->scan();
			scanned = true;
			p = manager->findFor(provider, type);
		}
	}
	if(!p)
	{
		// try using some other provider
		p = manager->findFor(QString::null, type);
		if((!p || p->name() == "default") && !scanned)
		{
			// maybe there are new providers, so scan and try again
			//   before giving up or using default
			manager->scan();
			scanned = true;
			p = manager->findFor(QString::null, type);
		}
	}
	if(!p)
		return 0;

	return p->createContext(type);
}

//----------------------------------------------------------------------------
// Initializer
//----------------------------------------------------------------------------
Initializer::Initializer(MemoryMode m, int prealloc)
{
	init(m, prealloc);
}

Initializer::~Initializer()
{
	deinit();
}

//----------------------------------------------------------------------------
// Provider
//----------------------------------------------------------------------------
Provider::~Provider()
{
}

void Provider::init()
{
}

Provider::Context::Context(Provider *parent, const QString &type)
{
	_provider = parent;
	_type = type;
	refs = 0;
}

Provider::Context::~Context()
{
}

Provider *Provider::Context::provider() const
{
	return _provider;
}

QString Provider::Context::type() const
{
	return _type;
}

bool Provider::Context::sameProvider(Context *c)
{
	return (c->provider() == _provider);
}

//----------------------------------------------------------------------------
// PKeyBase
//----------------------------------------------------------------------------
int PKeyBase::maximumEncryptSize() const
{
	return 0;
}

QSecureArray PKeyBase::encrypt(const QSecureArray &)
{
	return QSecureArray();
}

bool PKeyBase::decrypt(const QSecureArray &, QSecureArray *)
{
	return false;
}

void PKeyBase::startSign()
{
}

void PKeyBase::startVerify()
{
}

void PKeyBase::update(const QSecureArray &)
{
}

QSecureArray PKeyBase::endSign()
{
	return QSecureArray();
}

bool PKeyBase::endVerify(const QSecureArray &)
{
	return false;
}

SymmetricKey PKeyBase::deriveKey(const PKeyBase &)
{
	return SymmetricKey();
}

//----------------------------------------------------------------------------
// BufferedComputation
//----------------------------------------------------------------------------
BufferedComputation::~BufferedComputation()
{
}

QSecureArray BufferedComputation::process(const QSecureArray &a)
{
	clear();
	update(a);
	return final();
}

//----------------------------------------------------------------------------
// Filter
//----------------------------------------------------------------------------
Filter::~Filter()
{
}

QSecureArray Filter::process(const QSecureArray &a)
{
	clear();
	QSecureArray buf = update(a);
	if(!ok())
		return QSecureArray();
	QSecureArray fin = final();
	if(!ok())
		return QSecureArray();
	int oldsize = buf.size();
	buf.resize(oldsize + fin.size());
	memcpy(buf.data() + oldsize, fin.data(), fin.size());
	return buf;
}

//----------------------------------------------------------------------------
// Algorithm
//----------------------------------------------------------------------------
class Algorithm::Private
{
public:
	Provider::Context *c;

	Private()
	{
		c = 0;
	}

	~Private()
	{
		delContext();
	}

	void setContext(Provider::Context *nc)
	{
		delContext();
		++(nc->refs);
		c = nc;
	}

	void delContext()
	{
		if(!c)
			return;

		--(c->refs);
		if(c->refs == 0)
			delete c;
		c = 0;
	}

	void detach()
	{
		if(!c)
			return;

		if(c->refs > 1)
		{
			Provider::Context *nc = c->clone();
			nc->refs = 0;
			setContext(nc);
		}
	}
};

Algorithm::Algorithm()
{
	d = new Private;
}

Algorithm::Algorithm(const QString &type, const QString &provider)
{
	d = new Private;
	change(type, provider);
}

Algorithm::Algorithm(const Algorithm &from)
{
	printf("algo copy\n");
	d = new Private;
	*this = from;
}

Algorithm::~Algorithm()
{
	delete d;
}

Algorithm & Algorithm::operator=(const Algorithm &from)
{
	printf("algo=\n");
	d->delContext();
	if(from.d->c)
		d->setContext(from.d->c);
	return *this;
}

QString Algorithm::type() const
{
	if(d->c)
		return d->c->type();
	else
		return QString();
}

Provider *Algorithm::provider() const
{
	if(d->c)
		return d->c->provider();
	else
		return 0;
}

void Algorithm::detach()
{
	d->detach();
}

Provider::Context *Algorithm::context() const
{
	return d->c;
}

void Algorithm::change(Provider::Context *c)
{
	d->setContext(c);
}

void Algorithm::change(const QString &type, const QString &provider)
{
	d->delContext();
	if(!type.isEmpty())
		d->setContext(getContext(type, provider));
}

//----------------------------------------------------------------------------
// SymmetricKey
//----------------------------------------------------------------------------
SymmetricKey::SymmetricKey()
{
}

SymmetricKey::SymmetricKey(int size)
{
	set(globalRNG().nextBytes(size, Random::SessionKey));
}

SymmetricKey::SymmetricKey(const QSecureArray &a)
{
	set(a);
}

SymmetricKey::SymmetricKey(const QCString &cs)
{
	set(cs);
}

//----------------------------------------------------------------------------
// InitializationVector
//----------------------------------------------------------------------------
InitializationVector::InitializationVector()
{
}

InitializationVector::InitializationVector(int size)
{
	set(globalRNG().nextBytes(size, Random::Nonce));
}

InitializationVector::InitializationVector(const QSecureArray &a)
{
	set(a);
}

InitializationVector::InitializationVector(const QCString &cs)
{
	set(cs);
}

}
