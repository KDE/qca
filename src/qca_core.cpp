/*
 * qca_core.cpp - Qt Cryptographic Architecture
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

#include "qca_core.h"

#include <QtCore>
#include "qca_plugin.h"
#include "qca_textfilter.h"
#include "qca_cert.h"
#include "qcaprovider.h"

#ifndef QCA_NO_SYSTEMSTORE
# include "qca_systemstore.h"
#endif

namespace QCA {

// from qca_tools
bool botan_init(int prealloc, bool mmap);
void botan_deinit();

// from qca_default
Provider *create_default_provider();

//----------------------------------------------------------------------------
// Global
//----------------------------------------------------------------------------
static QMutex *manager_mutex = 0;
static QString *app_name = 0;
static QCA::ProviderManager *manager = 0;
static QCA::Random *global_rng = 0;
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
	if(qca_init)
		return;

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

	manager_mutex = new QMutex;

	manager = new ProviderManager;
	manager->setDefault(create_default_provider()); // manager owns it

	app_name = new QString;
}

void deinit()
{
	if(!qca_init)
		return;

	delete global_rng;
	global_rng = 0;

	delete app_name;
	app_name = 0;

	delete manager;
	manager = 0;

	delete manager_mutex;
	manager_mutex = 0;

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

	QMutexLocker lock(manager_mutex);

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
	return isSupported(QString(features).split(',', QString::SkipEmptyParts));
}

QStringList supportedFeatures()
{
	init();

	QMutexLocker lock(manager_mutex);

	// query all features
	manager->scan();
	return manager->allFeatures();
}

QStringList defaultFeatures()
{
	init();

	QMutexLocker lock(manager_mutex);

	return manager->find("default")->features();
}

bool insertProvider(Provider *p, int priority)
{
	init();

	QMutexLocker lock(manager_mutex);

	return manager->add(p, priority);
}

void setProviderPriority(const QString &name, int priority)
{
	if(!qca_init)
		return;

	QMutexLocker lock(manager_mutex);

	manager->changePriority(name, priority);
}

int providerPriority(const QString &name)
{
	if(!qca_init)
		return -1;

	QMutexLocker lock(manager_mutex);

	return manager->getPriority(name);
}

const ProviderList & providers()
{
	init();

	QMutexLocker lock(manager_mutex);

	return manager->providers();
}

void scanForPlugins()
{
	QMutexLocker lock(manager_mutex);

	manager->scan();
}

void unloadAllPlugins()
{
	if(!qca_init)
		return;

	QMutexLocker lock(manager_mutex);

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
	if(!qca_init)
		return QString();
	return *app_name;
}

void setAppName(const QString &s)
{
	if(!qca_init)
		return;
	*app_name = s;
}

QString arrayToHex(const QSecureArray &a)
{
	return Hex().arrayToString(a);
}

QByteArray hexToArray(const QString &str)
{
	return Hex().stringToArray(str).toByteArray();
}

static Provider *getProviderForType(const QString &type, const QString &provider)
{
	QMutexLocker lock(manager_mutex);

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
		p = manager->findFor(QString(), type);
		if((!p || p->name() == "default") && !scanned)
		{
			// maybe there are new providers, so scan and try again
			//   before giving up or using default
			manager->scan();
			scanned = true;
			p = manager->findFor(QString::null, type);
		}
	}

	return p;
}

Provider::Context *getContext(const QString &type, const QString &provider)
{
	init();

	Provider *p = getProviderForType(type, provider);
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
int PKeyBase::maximumEncryptSize(EncryptionAlgorithm) const
{
	return 0;
}

QSecureArray PKeyBase::encrypt(const QSecureArray &, EncryptionAlgorithm) const
{
	return QSecureArray();
}

bool PKeyBase::decrypt(const QSecureArray &, QSecureArray *, EncryptionAlgorithm) const
{
	return false;
}

void PKeyBase::startSign(SignatureAlgorithm, SignatureFormat)
{
}

void PKeyBase::startVerify(SignatureAlgorithm, SignatureFormat)
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

SymmetricKey PKeyBase::deriveKey(const PKeyBase &) const
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
class Algorithm::Private : public QSharedData
{
public:
	Provider::Context *c;

	Private(Provider::Context *context)
	{
		c = context;
		//printf("** [%p] Algorithm Created\n", c);
	}

	Private(const Private &from) : QSharedData(from)
	{
		c = from.c->clone();
		//printf("** [%p] Algorithm Copied (to [%p])\n", from.c, c);
	}

	~Private()
	{
		//printf("** [%p] Algorithm Destroyed\n", c);
		delete c;
	}
};

Algorithm::Algorithm()
{
	d = 0;
}

Algorithm::Algorithm(const QString &type, const QString &provider)
{
	d = 0;
	change(type, provider);
}

Algorithm::Algorithm(const Algorithm &from)
{
	d = 0;
	*this = from;
}

Algorithm::~Algorithm()
{
}

Algorithm & Algorithm::operator=(const Algorithm &from)
{
	d = from.d;
	return *this;
}

QString Algorithm::type() const
{
	if(d)
		return d->c->type();
	else
		return QString();
}

Provider *Algorithm::provider() const
{
	if(d)
		return d->c->provider();
	else
		return 0;
}

Provider::Context *Algorithm::context()
{
	if(d)
		return d->c;
	else
		return 0;
}

const Provider::Context *Algorithm::context() const
{
	if(d)
		return d->c;
	else
		return 0;
}

void Algorithm::change(Provider::Context *c)
{
	if(c)
		d = new Private(c);
	else
		d = 0;
}

void Algorithm::change(const QString &type, const QString &provider)
{
	if(!type.isEmpty())
		change(getContext(type, provider));
	else
		change(0);
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

SymmetricKey::SymmetricKey(const QByteArray &a)
{
	set(QSecureArray(a));
}

/* from libgcrypt-1.2.0 */
static unsigned char desWeakKeyTable[64][8] =
{
	{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, /*w*/
	{ 0x00, 0x00, 0x1e, 0x1e, 0x00, 0x00, 0x0e, 0x0e },
	{ 0x00, 0x00, 0xe0, 0xe0, 0x00, 0x00, 0xf0, 0xf0 },
	{ 0x00, 0x00, 0xfe, 0xfe, 0x00, 0x00, 0xfe, 0xfe },
	{ 0x00, 0x1e, 0x00, 0x1e, 0x00, 0x0e, 0x00, 0x0e }, /*sw*/
	{ 0x00, 0x1e, 0x1e, 0x00, 0x00, 0x0e, 0x0e, 0x00 },
	{ 0x00, 0x1e, 0xe0, 0xfe, 0x00, 0x0e, 0xf0, 0xfe },
	{ 0x00, 0x1e, 0xfe, 0xe0, 0x00, 0x0e, 0xfe, 0xf0 },
	{ 0x00, 0xe0, 0x00, 0xe0, 0x00, 0xf0, 0x00, 0xf0 }, /*sw*/
	{ 0x00, 0xe0, 0x1e, 0xfe, 0x00, 0xf0, 0x0e, 0xfe },
	{ 0x00, 0xe0, 0xe0, 0x00, 0x00, 0xf0, 0xf0, 0x00 },
	{ 0x00, 0xe0, 0xfe, 0x1e, 0x00, 0xf0, 0xfe, 0x0e },
	{ 0x00, 0xfe, 0x00, 0xfe, 0x00, 0xfe, 0x00, 0xfe }, /*sw*/
	{ 0x00, 0xfe, 0x1e, 0xe0, 0x00, 0xfe, 0x0e, 0xf0 },
	{ 0x00, 0xfe, 0xe0, 0x1e, 0x00, 0xfe, 0xf0, 0x0e },
	{ 0x00, 0xfe, 0xfe, 0x00, 0x00, 0xfe, 0xfe, 0x00 },
	{ 0x1e, 0x00, 0x00, 0x1e, 0x0e, 0x00, 0x00, 0x0e },
	{ 0x1e, 0x00, 0x1e, 0x00, 0x0e, 0x00, 0x0e, 0x00 }, /*sw*/
	{ 0x1e, 0x00, 0xe0, 0xfe, 0x0e, 0x00, 0xf0, 0xfe },
	{ 0x1e, 0x00, 0xfe, 0xe0, 0x0e, 0x00, 0xfe, 0xf0 },
	{ 0x1e, 0x1e, 0x00, 0x00, 0x0e, 0x0e, 0x00, 0x00 },
	{ 0x1e, 0x1e, 0x1e, 0x1e, 0x0e, 0x0e, 0x0e, 0x0e }, /*w*/
	{ 0x1e, 0x1e, 0xe0, 0xe0, 0x0e, 0x0e, 0xf0, 0xf0 },
	{ 0x1e, 0x1e, 0xfe, 0xfe, 0x0e, 0x0e, 0xfe, 0xfe },
	{ 0x1e, 0xe0, 0x00, 0xfe, 0x0e, 0xf0, 0x00, 0xfe },
	{ 0x1e, 0xe0, 0x1e, 0xe0, 0x0e, 0xf0, 0x0e, 0xf0 }, /*sw*/
	{ 0x1e, 0xe0, 0xe0, 0x1e, 0x0e, 0xf0, 0xf0, 0x0e },
	{ 0x1e, 0xe0, 0xfe, 0x00, 0x0e, 0xf0, 0xfe, 0x00 },
	{ 0x1e, 0xfe, 0x00, 0xe0, 0x0e, 0xfe, 0x00, 0xf0 },
	{ 0x1e, 0xfe, 0x1e, 0xfe, 0x0e, 0xfe, 0x0e, 0xfe }, /*sw*/
	{ 0x1e, 0xfe, 0xe0, 0x00, 0x0e, 0xfe, 0xf0, 0x00 },
	{ 0x1e, 0xfe, 0xfe, 0x1e, 0x0e, 0xfe, 0xfe, 0x0e },
	{ 0xe0, 0x00, 0x00, 0xe0, 0xf0, 0x00, 0x00, 0xf0 },
	{ 0xe0, 0x00, 0x1e, 0xfe, 0xf0, 0x00, 0x0e, 0xfe },
	{ 0xe0, 0x00, 0xe0, 0x00, 0xf0, 0x00, 0xf0, 0x00 }, /*sw*/
	{ 0xe0, 0x00, 0xfe, 0x1e, 0xf0, 0x00, 0xfe, 0x0e },
	{ 0xe0, 0x1e, 0x00, 0xfe, 0xf0, 0x0e, 0x00, 0xfe },
	{ 0xe0, 0x1e, 0x1e, 0xe0, 0xf0, 0x0e, 0x0e, 0xf0 },
	{ 0xe0, 0x1e, 0xe0, 0x1e, 0xf0, 0x0e, 0xf0, 0x0e }, /*sw*/
	{ 0xe0, 0x1e, 0xfe, 0x00, 0xf0, 0x0e, 0xfe, 0x00 },
	{ 0xe0, 0xe0, 0x00, 0x00, 0xf0, 0xf0, 0x00, 0x00 },
	{ 0xe0, 0xe0, 0x1e, 0x1e, 0xf0, 0xf0, 0x0e, 0x0e },
	{ 0xe0, 0xe0, 0xe0, 0xe0, 0xf0, 0xf0, 0xf0, 0xf0 }, /*w*/
	{ 0xe0, 0xe0, 0xfe, 0xfe, 0xf0, 0xf0, 0xfe, 0xfe },
	{ 0xe0, 0xfe, 0x00, 0x1e, 0xf0, 0xfe, 0x00, 0x0e },
	{ 0xe0, 0xfe, 0x1e, 0x00, 0xf0, 0xfe, 0x0e, 0x00 },
	{ 0xe0, 0xfe, 0xe0, 0xfe, 0xf0, 0xfe, 0xf0, 0xfe }, /*sw*/
	{ 0xe0, 0xfe, 0xfe, 0xe0, 0xf0, 0xfe, 0xfe, 0xf0 },
	{ 0xfe, 0x00, 0x00, 0xfe, 0xfe, 0x00, 0x00, 0xfe },
	{ 0xfe, 0x00, 0x1e, 0xe0, 0xfe, 0x00, 0x0e, 0xf0 },
	{ 0xfe, 0x00, 0xe0, 0x1e, 0xfe, 0x00, 0xf0, 0x0e },
	{ 0xfe, 0x00, 0xfe, 0x00, 0xfe, 0x00, 0xfe, 0x00 }, /*sw*/
	{ 0xfe, 0x1e, 0x00, 0xe0, 0xfe, 0x0e, 0x00, 0xf0 },
	{ 0xfe, 0x1e, 0x1e, 0xfe, 0xfe, 0x0e, 0x0e, 0xfe },
	{ 0xfe, 0x1e, 0xe0, 0x00, 0xfe, 0x0e, 0xf0, 0x00 },
	{ 0xfe, 0x1e, 0xfe, 0x1e, 0xfe, 0x0e, 0xfe, 0x0e }, /*sw*/
	{ 0xfe, 0xe0, 0x00, 0x1e, 0xfe, 0xf0, 0x00, 0x0e },
	{ 0xfe, 0xe0, 0x1e, 0x00, 0xfe, 0xf0, 0x0e, 0x00 },
	{ 0xfe, 0xe0, 0xe0, 0xfe, 0xfe, 0xf0, 0xf0, 0xfe },
	{ 0xfe, 0xe0, 0xfe, 0xe0, 0xfe, 0xf0, 0xfe, 0xf0 }, /*sw*/
	{ 0xfe, 0xfe, 0x00, 0x00, 0xfe, 0xfe, 0x00, 0x00 },
	{ 0xfe, 0xfe, 0x1e, 0x1e, 0xfe, 0xfe, 0x0e, 0x0e },
	{ 0xfe, 0xfe, 0xe0, 0xe0, 0xfe, 0xfe, 0xf0, 0xf0 },
	{ 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe }  /*w*/
};

bool SymmetricKey::isWeakDESKey()
{
	if(size() != 8)
		return false; // dubious
	QSecureArray workingCopy(8);
	// clear parity bits
	for(uint i = 0; i < 8; i++)
		workingCopy[i] = (data()[i]) & 0xfe;
	
	for(int n = 0; n < 64; n++)
	{
		if(memcmp(workingCopy.data(), desWeakKeyTable[n], 8) == 0)
			return true;
	}
	return false;
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

InitializationVector::InitializationVector(const QByteArray &a)
{
	set(QSecureArray(a));
}

}
