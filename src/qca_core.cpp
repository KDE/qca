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
#include "qca_keystore.h"
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
class Global
{
public:
	bool secmem;
	QString app_name;
	QMutex manager_mutex;
	ProviderManager manager;
	Random *rng;
	KeyStoreManager *ksm;

	Global()
	{
		rng = 0;
		ksm = 0;
		secmem = false;
	}

	~Global()
	{
		delete rng;
	}
};

static Global *global = 0;

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
	if(global)
		return;

	init(Practical, 64);
}

void init(MemoryMode mode, int prealloc)
{
	if(global)
		return;

	bool allow_mmap_fallback = false;
	bool drop_root = false;
	if(mode == Practical)
	{
		allow_mmap_fallback = true;
		drop_root = true;
	}
	else if(mode == Locking)
		drop_root = true;

	bool secmem = botan_init(prealloc, allow_mmap_fallback);

	if(drop_root)
	{
#ifdef Q_OS_UNIX
		setuid(getuid());
#endif
	}

	global = new Global;
	global->secmem = secmem;
	global->manager.setDefault(create_default_provider()); // manager owns it
}

void deinit()
{
	if(!global)
		return;

	delete global;
	global = 0;
	botan_deinit();
}

bool haveSecureMemory()
{
	if(!global)
		return false;

	return global->secmem;
}

bool isSupported(const QStringList &features)
{
	if(!global)
		return false;

	QMutexLocker lock(&global->manager_mutex);

	if(features_have(global->manager.allFeatures(), features))
		return true;

	// ok, try scanning for new stuff
	global->manager.scan();

	if(features_have(global->manager.allFeatures(), features))
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

	QMutexLocker lock(&global->manager_mutex);

	// query all features
	global->manager.scan();
	return global->manager.allFeatures();
}

QStringList defaultFeatures()
{
	init();

	QMutexLocker lock(&global->manager_mutex);

	return global->manager.find("default")->features();
}

bool insertProvider(Provider *p, int priority)
{
	init();

	QMutexLocker lock(&global->manager_mutex);

	return global->manager.add(p, priority);
}

void setProviderPriority(const QString &name, int priority)
{
	if(!global)
		return;

	QMutexLocker lock(&global->manager_mutex);

	global->manager.changePriority(name, priority);
}

int providerPriority(const QString &name)
{
	if(!global)
		return -1;

	QMutexLocker lock(&global->manager_mutex);

	return global->manager.getPriority(name);
}

const ProviderList & providers()
{
	init();

	QMutexLocker lock(&global->manager_mutex);

	return global->manager.providers();
}

void scanForPlugins()
{
	QMutexLocker lock(&global->manager_mutex);

	global->manager.scan();
}

void unloadAllPlugins()
{
	if(!global)
		return;

	QMutexLocker lock(&global->manager_mutex);

	// if the global_rng was owned by a plugin, then delete it
	if(global->rng && (global->rng->provider() != global->manager.find("default")))
	{
		delete global->rng;
		global->rng = 0;
	}

	global->manager.unloadAll();
}

Random & globalRNG()
{
	if(!global->rng)
		global->rng = new Random;
	return *global->rng;
}

void setGlobalRNG(const QString &provider)
{
	delete global->rng;
	global->rng = new Random(provider);
}

KeyStoreManager *keyStoreManager()
{
	return global->ksm;
}

bool haveSystemStore()
{
#ifndef QCA_NO_SYSTEMSTORE
	return qca_have_systemstore();
#else
	return false;
#endif
}

CertificateCollection systemStore(const QString &provider)
{
#ifndef QCA_NO_SYSTEMSTORE
	return qca_get_systemstore(provider);
#else
	return CertificateCollection();
#endif
}

QString appName()
{
	if(!global)
		return QString();
	return global->app_name;
}

void setAppName(const QString &s)
{
	if(!global)
		return;
	global->app_name = s;
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
	QMutexLocker lock(&global->manager_mutex);

	Provider *p = 0;
	bool scanned = false;
	if(!provider.isEmpty())
	{
		// try using specific provider
		p = global->manager.findFor(provider, type);
		if(!p)
		{
			// maybe this provider is new, so scan and try again
			global->manager.scan();
			scanned = true;
			p = global->manager.findFor(provider, type);
		}
	}
	if(!p)
	{
		// try using some other provider
		p = global->manager.findFor(QString(), type);
		if((!p || p->name() == "default") && !scanned)
		{
			// maybe there are new providers, so scan and try again
			//   before giving up or using default
			global->manager.scan();
			scanned = true;
			p = global->manager.findFor(QString(), type);
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
