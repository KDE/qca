/*
 * qca_publickey.cpp - Qt Cryptographic Architecture
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

#include "qca_publickey.h"

#include <QtCore>
#include "qcaprovider.h"

namespace QCA {

Provider::Context *getContext(const QString &type, const QString &provider);

//----------------------------------------------------------------------------
// PKey
//----------------------------------------------------------------------------
class PKey::Private
{
public:
	bool sec;
};

PKey::PKey()
{
	d = new Private;
}

PKey::PKey(const QString &type, const QString &provider)
:Algorithm(type, provider)
{
	d = new Private;
}

PKey::PKey(const PKey &from)
:Algorithm(from)
{
	d = new Private;
	*this = from;
}

PKey::~PKey()
{
	delete d;
}

PKey & PKey::operator=(const PKey &from)
{
	Algorithm::operator=(from);
	*d = *from.d;
	return *this;
}

void PKey::set(const PKey &k)
{
	*this = k;
}

QList<PKey::Type> PKey::supportedTypes(const QString &provider)
{
	Q_UNUSED(provider);
	return QList<PKey::Type>();
}

bool PKey::isNull() const
{
	PKeyContext *c = (PKeyContext *)context();
	if(!c)
		return true;
	else
		return false;
}

PKey::Type PKey::type() const
{
	if(isNull())
		return RSA; // some default so we don't explode
	return (PKey::Type)((PKeyContext *)context())->type();
}

bool PKey::isRSA() const
{
	return (type() == RSA);
}

bool PKey::isDSA() const
{
	return (type() == DSA);
}

bool PKey::isDH() const
{
	return (type() == DH);
}

bool PKey::isPublic() const
{
	if(isNull())
		return false;
	return !isPrivate();
}

bool PKey::isPrivate() const
{
	if(isNull())
		return false;
	return ((PKeyContext *)context())->key()->isPrivate();
}

bool PKey::canKeyAgree() const
{
	return isDH();
}

PublicKey PKey::toPublicKey() const
{
	if(isNull())
		return PublicKey();

	PublicKey k;
	if(isRSA())
		k = toRSAPublicKey();
	else if(isDSA())
		k = toDSAPublicKey();
	else
		k = toDHPublicKey();

	// converting private to public
	if(!k.isNull() && k.isPrivate())
	{
		printf("before detach: %d\n", ((PKeyContext *)k.context())->key()->isNull());
		k.detach();
		printf("before convert: %d\n", ((PKeyContext *)k.context())->key()->isNull());
		((PKeyContext *)k.context())->key()->convertToPublic();
		printf("after convert: %d\n", ((PKeyContext *)k.context())->key()->isNull());
	}

	return k;
}

PrivateKey PKey::toPrivateKey() const
{
	if(isNull())
		return PrivateKey();

	if(isRSA())
		return toRSAPrivateKey();
	else if(isDSA())
		return toDSAPrivateKey();
	else
		return toDHPrivateKey();
}

RSAPublicKey PKey::toRSAPublicKey() const
{
	printf("to rsa public\n");
	RSAPublicKey k;
	if(!isNull() && isRSA())
	{
		printf("to rsa public set\n");
		k.set(*this);
	}
	printf("to rsa public done\n");
	return k;
}

RSAPrivateKey PKey::toRSAPrivateKey() const
{
	RSAPrivateKey k;
	if(!isNull() && isRSA() && isPrivate())
		k.set(*this);
	return k;
}

DSAPublicKey PKey::toDSAPublicKey() const
{
	DSAPublicKey k;
	if(!isNull() && isDSA())
		k.set(*this);
	return k;
}

DSAPrivateKey PKey::toDSAPrivateKey() const
{
	DSAPrivateKey k;
	if(!isNull() && isDSA() && isPrivate())
		k.set(*this);
	return k;
}

DHPublicKey PKey::toDHPublicKey() const
{
	DHPublicKey k;
	if(!isNull() && isDH())
		k.set(*this);
	return k;
}

DHPrivateKey PKey::toDHPrivateKey() const
{
	DHPrivateKey k;
	if(!isNull() && isDH() && isPrivate())
		k.set(*this);
	return k;
}

//----------------------------------------------------------------------------
// PublicKey
//----------------------------------------------------------------------------
PublicKey::PublicKey()
{
}

PublicKey::PublicKey(const QString &type, const QString &provider)
:PKey(type, provider)
{
}

PublicKey::PublicKey(const PrivateKey &k)
{
	set(k.toPublicKey());
}

PublicKey::PublicKey(const QString &fileName)
{
	Q_UNUSED(fileName);
}

RSAPublicKey PublicKey::toRSA() const
{
	return toRSAPublicKey();
}

DSAPublicKey PublicKey::toDSA() const
{
	return toDSAPublicKey();
}

DHPublicKey PublicKey::toDH() const
{
	return toDHPublicKey();
}

bool PublicKey::canEncrypt() const
{
	return isRSA();
}

bool PublicKey::canVerify() const
{
	return (isRSA() || isDSA());
}

int PublicKey::maximumEncryptSize(EncryptionAlgorithm) const
{
	return ((PKeyContext *)context())->key()->maximumEncryptSize();
}

QSecureArray PublicKey::encrypt(EncryptionAlgorithm, const QSecureArray &a)
{
	PKeyContext *pc = (PKeyContext *)context();
	RSAContext *rc = (RSAContext *)(pc->key());
	printf("rc=%p\n", rc);
	printf("rc->isnull=%d\n", rc->isNull());
	printf("pkey.isnull=%d\n", isNull());
	printf("Detaching\n");
	detach();
	printf("done\n");
	return ((PKeyContext *)context())->key()->encrypt(a);
}

void PublicKey::startVerify(SignatureAlgorithm)
{
	((PKeyContext *)context())->key()->startVerify();
}

void PublicKey::update(const QSecureArray &a)
{
	((PKeyContext *)context())->key()->update(a);
}

bool PublicKey::validSignature(const QSecureArray &sig)
{
	return ((PKeyContext *)context())->key()->endVerify(sig);
}

bool PublicKey::verifyMessage(SignatureAlgorithm alg, const QSecureArray &a, const QSecureArray &sig)
{
	startVerify(alg);
	update(a);
	return validSignature(sig);
}

QSecureArray PublicKey::toDER() const
{
	return ((PKeyContext *)context())->publicToDER();
}

QString PublicKey::toPEM() const
{
	return ((PKeyContext *)context())->publicToPEM();
}

bool PublicKey::toPEMFile(const QString &fileName) const
{
	Q_UNUSED(fileName);
	return false;
}

PublicKey PublicKey::fromDER(const QSecureArray &a, ConvertResult *result, const QString &provider)
{
	Q_UNUSED(result);
	PublicKey k;
	PKeyContext *c = (PKeyContext *)getContext("pkey", provider);
	if(c->publicFromDER(a) == PKeyContext::Good)
		k.change(c);
	return k;
}

PublicKey PublicKey::fromPEM(const QString &s, ConvertResult *result, const QString &provider)
{
	Q_UNUSED(result);
	PublicKey k;
	PKeyContext *c = (PKeyContext *)getContext("pkey", provider);
	if(c->publicFromPEM(s) == PKeyContext::Good)
		k.change(c);
	return k;
}

PublicKey PublicKey::fromPEMFile(const QString &fileName, ConvertResult *result, const QString &provider)
{
	Q_UNUSED(result);
	Q_UNUSED(fileName);
	Q_UNUSED(provider);
	return PublicKey();
}

//----------------------------------------------------------------------------
// PrivateKey
//----------------------------------------------------------------------------
PrivateKey::PrivateKey()
{
}

PrivateKey::PrivateKey(const QString &type, const QString &provider)
:PKey(type, provider)
{
}

PrivateKey::PrivateKey(const QString &fileName, const QSecureArray &passphrase)
{
	Q_UNUSED(fileName);
	Q_UNUSED(passphrase);
}

RSAPrivateKey PrivateKey::toRSA() const
{
	RSAPrivateKey key = toRSAPrivateKey();
	return key;
}

DSAPrivateKey PrivateKey::toDSA() const
{
	return toDSAPrivateKey();
}

DHPrivateKey PrivateKey::toDH() const
{
	return toDHPrivateKey();
}

bool PrivateKey::canDecrypt() const
{
	return isRSA();
}

bool PrivateKey::canSign() const
{
	return (isRSA() || isDSA());
}

bool PrivateKey::decrypt(EncryptionAlgorithm, const QSecureArray &in, QSecureArray *out)
{
	detach();
	return ((PKeyContext *)context())->key()->decrypt(in, out);
}

void PrivateKey::startSign(SignatureAlgorithm)
{
	((PKeyContext *)context())->key()->startSign();
}

void PrivateKey::update(const QSecureArray &a)
{
	((PKeyContext *)context())->key()->update(a);
}

QSecureArray PrivateKey::signature()
{
	return ((PKeyContext *)context())->key()->endSign();
}

QSecureArray PrivateKey::signMessage(SignatureAlgorithm alg, const QSecureArray &a)
{
	startSign(alg);
	update(a);
	return signature();
}

SymmetricKey PrivateKey::deriveKey(const PublicKey &theirs)
{
	PKeyContext *theirContext = (PKeyContext *)theirs.context();
	return ((PKeyContext *)context())->key()->deriveKey(*(theirContext->key()));
}

bool PrivateKey::canUsePBEAlgorithm(PBEAlgorithm algo, const QString &provider)
{
	Q_UNUSED(algo);
	Q_UNUSED(provider);
	return false;
}

QSecureArray PrivateKey::toDER(const QSecureArray &passphrase, PBEAlgorithm pbe) const
{
	Q_UNUSED(pbe);
	return ((PKeyContext *)context())->privateToDER(passphrase);
}

QString PrivateKey::toPEM(const QSecureArray &passphrase, PBEAlgorithm pbe) const
{
	Q_UNUSED(pbe);
	return ((PKeyContext *)context())->privateToPEM(passphrase);
}

bool PrivateKey::toPEMFile(const QString &fileName, const QSecureArray &passphrase, PBEAlgorithm pbe) const
{
	Q_UNUSED(fileName);
	Q_UNUSED(passphrase);
	Q_UNUSED(pbe);
	return false;
}

PrivateKey PrivateKey::fromDER(const QSecureArray &a, const QSecureArray &passphrase, ConvertResult *result, const QString &provider)
{
	Q_UNUSED(result);
	PrivateKey k;
	PKeyContext *c = (PKeyContext *)getContext("pkey", provider);
	if(c->privateFromDER(a, passphrase) == PKeyContext::Good)
		k.change(c);
	return k;
}

PrivateKey PrivateKey::fromPEM(const QString &s, const QSecureArray &passphrase, ConvertResult *result, const QString &provider)
{
	Q_UNUSED(result);
	PrivateKey k;
	PKeyContext *c = (PKeyContext *)getContext("pkey", provider);
	if(c->privateFromPEM(s, passphrase) == PKeyContext::Good)
		k.change(c);
	return k;
}

PrivateKey PrivateKey::fromPEMFile(const QString &fileName, const QSecureArray &passphrase, ConvertResult *result, const QString &provider)
{
	Q_UNUSED(result);
	Q_UNUSED(fileName);
	Q_UNUSED(passphrase);
	Q_UNUSED(provider);
	return PrivateKey();
}

//----------------------------------------------------------------------------
// KeyGenerator
//----------------------------------------------------------------------------
class KeyGenerator::Private
{
public:
	KeyGenerator *parent;
	bool blocking, wasBlocking;
	PrivateKey key;
	int type;

	QString provider;
	PKeyBase *k;

	static QHash<PKeyBase*, KeyGenerator*> *list;

	Private(KeyGenerator *_parent)
	{
		parent = _parent;
	}

	~Private()
	{
		if(k)
		{
			list_del(k);
			delete k;
		}
	}

	void list_add(PKeyBase *c)
	{
		if(!list)
			list = new QHash<PKeyBase*, KeyGenerator*>;
		list->insert(c, parent);
	}

	void list_del(PKeyBase *c)
	{
		if(!list)
			return;
		if(list->contains(c))
			list->remove(c);
		if(list->isEmpty())
		{
			delete list;
			list = 0;
		}
	}

	static void rsa_cb(RSAContext *c)
	{
		if(list->contains(c))
		{
			KeyGenerator *self = list->value(c);
			self->done();
		}
	}

	static void dsa_cb(DSAContext *c)
	{
		if(list->contains(c))
		{
			KeyGenerator *self = list->value(c);
			self->done();
		}
	}

	static void dh_cb(DHContext *c)
	{
		if(list->contains(c))
		{
			KeyGenerator *self = list->value(c);
			self->done();
		}
	}
};

QHash<PKeyBase*, KeyGenerator*> *KeyGenerator::Private::list = 0;

KeyGenerator::KeyGenerator(QObject *parent)
:QObject(parent)
{
	d = new Private(this);
	d->blocking = true;
}

KeyGenerator::~KeyGenerator()
{
	delete d;
}

bool KeyGenerator::blocking() const
{
	return d->blocking;
}

void KeyGenerator::setBlocking(bool b)
{
	d->blocking = b;
}

bool KeyGenerator::isBusy() const
{
	return (d->k ? true: false);
}

void KeyGenerator::generateRSA(int bits, int exp, const QString &provider)
{
	d->type = PKey::RSA;
	d->wasBlocking = d->blocking;
	d->provider = provider;
	d->k = (RSAContext *)getContext("rsa", provider);
	if(!d->blocking)
	{
		d->list_add(d->k);
		((RSAContext *)d->k)->createPrivate(bits, exp, Private::rsa_cb);
	}
	else
	{
		((RSAContext *)d->k)->createPrivate(bits, exp, 0);
		done();
	}
}

void KeyGenerator::generateDSA(DL_Group group, const QString &provider)
{
	d->type = PKey::DSA;
	d->wasBlocking = d->blocking;
	d->provider = provider;
	d->k = (DSAContext *)getContext("dsa", provider);
	if(!d->blocking)
	{
		d->list_add(d->k);
		((DSAContext *)d->k)->createPrivate(group, Private::dsa_cb);
	}
	else
	{
		((DSAContext *)d->k)->createPrivate(group, 0);
		done();
	}
}

void KeyGenerator::generateDH(DL_Group group, const QString &provider)
{
	d->type = PKey::DH;
	d->wasBlocking = d->blocking;
	d->provider = provider;
	d->k = (DHContext *)getContext("dh", provider);
	if(!d->blocking)
	{
		d->list_add(d->k);
		((DHContext *)d->k)->createPrivate(group, Private::dh_cb);
	}
	else
	{
		((DHContext *)d->k)->createPrivate(group, 0);
		done();
	}
}

PrivateKey KeyGenerator::result() const
{
	return d->key;
}

void KeyGenerator::done()
{
	if(!d->wasBlocking)
		d->list_del(d->k);

	PrivateKey key;

	if(!d->k->isNull())
	{
		printf("generated key!\n");
		PKeyContext *c = (PKeyContext *)getContext("pkey", d->provider);
		c->setKey(d->k);
		d->k = 0;

		key.change(c);
		printf("key.isNull = %d\n", key.isNull());
		d->key = key;
		printf("d->key.isNull = %d\n", d->key.isNull());
	}
	else
	{
		printf("generated null key\n");
		delete d->k;
		d->k = 0;
	}

	if(!d->wasBlocking)
		emit finished();
}

//----------------------------------------------------------------------------
// RSAPublicKey
//----------------------------------------------------------------------------
RSAPublicKey::RSAPublicKey()
{
}

RSAPublicKey::RSAPublicKey(const QBigInteger &n, const QBigInteger &e, const QString &provider)
{
	RSAContext *k = (RSAContext *)getContext("rsa", provider);
	k->createPublic(n, e);
	printf("pubkey k->isnull=%d\n", k->isNull());
	PKeyContext *c = (PKeyContext *)getContext("pkey", provider);
	c->setKey(k);
	change(c);
}

RSAPublicKey::RSAPublicKey(const RSAPrivateKey &k)
:PublicKey(k)
{
}

QBigInteger RSAPublicKey::n() const
{
	return ((RSAContext *)((PKeyContext *)context())->key())->n();
}

QBigInteger RSAPublicKey::e() const
{
	return ((RSAContext *)((PKeyContext *)context())->key())->e();
}

//----------------------------------------------------------------------------
// RSAPrivateKey
//----------------------------------------------------------------------------
RSAPrivateKey::RSAPrivateKey()
{
}

RSAPrivateKey::RSAPrivateKey(const QBigInteger &p, const QBigInteger &q, const QBigInteger &d, const QBigInteger &n, const QBigInteger &e, const QString &provider)
{
	RSAContext *k = (RSAContext *)getContext("rsa", provider);
	k->createPrivate(p, q, d, n, e);
	PKeyContext *c = (PKeyContext *)getContext("pkey", provider);
	c->setKey(k);
	change(c);
}

QBigInteger RSAPrivateKey::p() const
{
	return ((RSAContext *)((PKeyContext *)context())->key())->p();
}

QBigInteger RSAPrivateKey::q() const
{
	return ((RSAContext *)((PKeyContext *)context())->key())->q();
}

QBigInteger RSAPrivateKey::d() const
{
	return ((RSAContext *)((PKeyContext *)context())->key())->d();
}

QBigInteger RSAPrivateKey::n() const
{
	return ((RSAContext *)((PKeyContext *)context())->key())->n();
}

QBigInteger RSAPrivateKey::e() const
{
	return ((RSAContext *)((PKeyContext *)context())->key())->e();
}

//----------------------------------------------------------------------------
// DSAPublicKey
//----------------------------------------------------------------------------
DSAPublicKey::DSAPublicKey()
{
}

DSAPublicKey::DSAPublicKey(DL_Group group, const QBigInteger &y, const QString &provider)
{
	DSAContext *k = (DSAContext *)getContext("dsa", provider);
	k->createPublic(group, y);
	PKeyContext *c = (PKeyContext *)getContext("pkey", provider);
	c->setKey(k);
	change(c);
}

DSAPublicKey::DSAPublicKey(const DSAPrivateKey &k)
:PublicKey(k)
{
}

DL_Group DSAPublicKey::domain() const
{
	return ((DSAContext *)((PKeyContext *)context())->key())->domain();
}

QBigInteger DSAPublicKey::y() const
{
	return ((DSAContext *)((PKeyContext *)context())->key())->y();
}

//----------------------------------------------------------------------------
// DSAPrivateKey
//----------------------------------------------------------------------------
DSAPrivateKey::DSAPrivateKey()
{
}

DSAPrivateKey::DSAPrivateKey(DL_Group group, const QBigInteger &x, const QBigInteger &y, const QString &provider)
{
	DSAContext *k = (DSAContext *)getContext("dsa", provider);
	k->createPrivate(group, x, y);
	PKeyContext *c = (PKeyContext *)getContext("pkey", provider);
	c->setKey(k);
	change(c);
}

DL_Group DSAPrivateKey::domain() const
{
	return ((DSAContext *)((PKeyContext *)context())->key())->domain();
}

QBigInteger DSAPrivateKey::x() const
{
	return ((DSAContext *)((PKeyContext *)context())->key())->x();
}

QBigInteger DSAPrivateKey::y() const
{
	return ((DSAContext *)((PKeyContext *)context())->key())->y();
}

//----------------------------------------------------------------------------
// DHPublicKey
//----------------------------------------------------------------------------
DHPublicKey::DHPublicKey()
{
}

DHPublicKey::DHPublicKey(DL_Group group, const QBigInteger &y, const QString &provider)
{
	DHContext *k = (DHContext *)getContext("dh", provider);
	k->createPublic(group, y);
	PKeyContext *c = (PKeyContext *)getContext("pkey", provider);
	c->setKey(k);
	change(c);
}

DHPublicKey::DHPublicKey(const DHPrivateKey &k)
:PublicKey(k)
{
}

DL_Group DHPublicKey::domain() const
{
	return ((DHContext *)((PKeyContext *)context())->key())->domain();
}

QBigInteger DHPublicKey::y() const
{
	return ((DHContext *)((PKeyContext *)context())->key())->y();
}

//----------------------------------------------------------------------------
// DHPrivateKey
//----------------------------------------------------------------------------
DHPrivateKey::DHPrivateKey()
{
}

DHPrivateKey::DHPrivateKey(DL_Group group, const QBigInteger &x, const QBigInteger &y, const QString &provider)
{
	DHContext *k = (DHContext *)getContext("dh", provider);
	k->createPrivate(group, x, y);
	PKeyContext *c = (PKeyContext *)getContext("pkey", provider);
	c->setKey(k);
	change(c);
}

DL_Group DHPrivateKey::domain() const
{
	return ((DHContext *)((PKeyContext *)context())->key())->domain();
}

QBigInteger DHPrivateKey::x() const
{
	return ((DHContext *)((PKeyContext *)context())->key())->x();
}

QBigInteger DHPrivateKey::y() const
{
	return ((DHContext *)((PKeyContext *)context())->key())->y();
}

}
