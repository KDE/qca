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

bool stringToFile(const QString &fileName, const QString &content)
{
	QFile f(fileName);
	if(!f.open(QFile::WriteOnly))
		return false;
	QTextStream ts(&f);
	ts << content;
	return true;
}

bool stringFromFile(const QString &fileName, QString *s)
{
	QFile f(fileName);
	if(!f.open(QFile::ReadOnly))
		return false;
	QTextStream ts(&f);
	*s = ts.readAll();
	return true;
}

bool arrayToFile(const QString &fileName, const QByteArray &content)
{
	QFile f(fileName);
	if(!f.open(QFile::WriteOnly))
		return false;
	f.write(content.data(), content.size());
	return true;
}

bool arrayFromFile(const QString &fileName, QByteArray *a)
{
	QFile f(fileName);
	if(!f.open(QFile::ReadOnly))
		return false;
	*a = f.readAll();
	return true;
}

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

void PKey::assignToPublic(PKey *dest) const
{
	dest->set(*this);

	// converting private to public
	if(dest->isPrivate())
		static_cast<PKeyContext *>(dest->context())->key()->convertToPublic();
}

void PKey::assignToPrivate(PKey *dest) const
{
	dest->set(*this);
}

QList<PKey::Type> PKey::supportedTypes(const QString &provider)
{
	const PKeyContext *c = static_cast<const PKeyContext *>(getContext("pkey", provider));
	QList<Type> list = c->supportedTypes();
	delete c;
	return list;
}

bool PKey::isNull() const
{
	return (!context() ? true : false);
}

PKey::Type PKey::type() const
{
	if(isNull())
		return RSA; // some default so we don't explode
	return static_cast<const PKeyContext *>(context())->type();
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
	return static_cast<const PKeyContext *>(context())->key()->isPrivate();
}

bool PKey::canKeyAgree() const
{
	return isDH();
}

PublicKey PKey::toPublicKey() const
{
	PublicKey k;
	if(!isNull())
		assignToPublic(&k);
	return k;
}

PrivateKey PKey::toPrivateKey() const
{
	PrivateKey k;
	if(!isNull() && isPrivate())
		assignToPrivate(&k);
	return k;
}

RSAPublicKey PKey::toRSAPublicKey() const
{
	RSAPublicKey k;
	if(!isNull() && isRSA())
		assignToPublic(&k);
	return k;
}

RSAPrivateKey PKey::toRSAPrivateKey() const
{
	RSAPrivateKey k;
	if(!isNull() && isRSA() && isPrivate())
		assignToPrivate(&k);
	return k;
}

DSAPublicKey PKey::toDSAPublicKey() const
{
	DSAPublicKey k;
	if(!isNull() && isDSA())
		assignToPublic(&k);
	return k;
}

DSAPrivateKey PKey::toDSAPrivateKey() const
{
	DSAPrivateKey k;
	if(!isNull() && isDSA() && isPrivate())
		assignToPrivate(&k);
	return k;
}

DHPublicKey PKey::toDHPublicKey() const
{
	DHPublicKey k;
	if(!isNull() && isDH())
		assignToPublic(&k);
	return k;
}

DHPrivateKey PKey::toDHPrivateKey() const
{
	DHPrivateKey k;
	if(!isNull() && isDH() && isPrivate())
		assignToPrivate(&k);
	return k;
}

bool PKey::operator==(const PKey &a) const
{
	if(a.isPrivate())
		return (toPrivateKey().toDER() == a.toPrivateKey().toDER());
	else
		return (toPublicKey().toDER() == a.toPublicKey().toDER());
}

bool PKey::operator!=(const PKey &a) const
{
	return !(*this == a);
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
	*this = fromPEMFile(fileName, 0, QString());
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

int PublicKey::maximumEncryptSize(EncryptionAlgorithm alg) const
{
	return static_cast<const PKeyContext *>(context())->key()->maximumEncryptSize(alg);
}

QSecureArray PublicKey::encrypt(const QSecureArray &a, EncryptionAlgorithm alg) const
{
	return static_cast<const PKeyContext *>(context())->key()->encrypt(a, alg);
}

void PublicKey::startVerify(SignatureAlgorithm alg, SignatureFormat format)
{
	if(isDSA() && format == DefaultFormat)
		format = IEEE_1363;
	static_cast<PKeyContext *>(context())->key()->startVerify(alg, format);
}

void PublicKey::update(const QSecureArray &a)
{
	static_cast<PKeyContext *>(context())->key()->update(a);
}

bool PublicKey::validSignature(const QSecureArray &sig)
{
	return static_cast<PKeyContext *>(context())->key()->endVerify(sig);
}

bool PublicKey::verifyMessage(const QSecureArray &a, const QSecureArray &sig, SignatureAlgorithm alg, SignatureFormat format)
{
	startVerify(alg, format);
	update(a);
	return validSignature(sig);
}

QSecureArray PublicKey::toDER() const
{
	return static_cast<const PKeyContext *>(context())->publicToDER();
}

QString PublicKey::toPEM() const
{
	return static_cast<const PKeyContext *>(context())->publicToPEM();
}

bool PublicKey::toPEMFile(const QString &fileName) const
{
	return stringToFile(fileName, toPEM());
}

PublicKey PublicKey::fromDER(const QSecureArray &a, ConvertResult *result, const QString &provider)
{
	PublicKey k;
	PKeyContext *c = static_cast<PKeyContext *>(getContext("pkey", provider));
	ConvertResult r = c->publicFromDER(a);
	if(result)
		*result = r;
	if(r == ConvertGood)
		k.change(c);
	return k;
}

PublicKey PublicKey::fromPEM(const QString &s, ConvertResult *result, const QString &provider)
{
	PublicKey k;
	PKeyContext *c = static_cast<PKeyContext *>(getContext("pkey", provider));
	ConvertResult r = c->publicFromPEM(s);
	if(result)
		*result = r;
	if(r == ConvertGood)
		k.change(c);
	return k;
}

PublicKey PublicKey::fromPEMFile(const QString &fileName, ConvertResult *result, const QString &provider)
{
	QString pem;
	if(!stringFromFile(fileName, &pem))
	{
		if(result)
			*result = ErrorFile;
		return PublicKey();
	}
	return fromPEM(pem, result, provider);
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
	*this = fromPEMFile(fileName, passphrase, 0, QString());
}

RSAPrivateKey PrivateKey::toRSA() const
{
	return toRSAPrivateKey();
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

bool PrivateKey::decrypt(const QSecureArray &in, QSecureArray *out, EncryptionAlgorithm alg) const
{
	return static_cast<const PKeyContext *>(context())->key()->decrypt(in, out, alg);
}

void PrivateKey::startSign(SignatureAlgorithm alg, SignatureFormat format)
{
	if(isDSA() && format == DefaultFormat)
		format = IEEE_1363;
	static_cast<PKeyContext *>(context())->key()->startSign(alg, format);
}

void PrivateKey::update(const QSecureArray &a)
{
	static_cast<PKeyContext *>(context())->key()->update(a);
}

QSecureArray PrivateKey::signature()
{
	return static_cast<PKeyContext *>(context())->key()->endSign();
}

QSecureArray PrivateKey::signMessage(const QSecureArray &a, SignatureAlgorithm alg, SignatureFormat format)
{
	startSign(alg, format);
	update(a);
	return signature();
}

SymmetricKey PrivateKey::deriveKey(const PublicKey &theirs) const
{
	const PKeyContext *theirContext = static_cast<const PKeyContext *>(theirs.context());
	return static_cast<const PKeyContext *>(context())->key()->deriveKey(*(theirContext->key()));
}

QList<PBEAlgorithm> PrivateKey::supportedPBEAlgorithms(const QString &provider)
{
	const PKeyContext *c = static_cast<const PKeyContext *>(getContext("pkey", provider));
	QList<PBEAlgorithm> list = c->supportedPBEAlgorithms();
	delete c;
	return list;
}

QSecureArray PrivateKey::toDER(const QSecureArray &passphrase, PBEAlgorithm pbe) const
{
	return static_cast<const PKeyContext *>(context())->privateToDER(passphrase, pbe);
}

QString PrivateKey::toPEM(const QSecureArray &passphrase, PBEAlgorithm pbe) const
{
	return static_cast<const PKeyContext *>(context())->privateToPEM(passphrase, pbe);
}

bool PrivateKey::toPEMFile(const QString &fileName, const QSecureArray &passphrase, PBEAlgorithm pbe) const
{
	return stringToFile(fileName, toPEM(passphrase, pbe));
}

PrivateKey PrivateKey::fromDER(const QSecureArray &a, const QSecureArray &passphrase, ConvertResult *result, const QString &provider)
{
	PrivateKey k;
	PKeyContext *c = static_cast<PKeyContext *>(getContext("pkey", provider));
	ConvertResult r = c->privateFromDER(a, passphrase);
	if(result)
		*result = r;
	if(r == ConvertGood)
		k.change(c);
	return k;
}

PrivateKey PrivateKey::fromPEM(const QString &s, const QSecureArray &passphrase, ConvertResult *result, const QString &provider)
{
	PrivateKey k;
	PKeyContext *c = static_cast<PKeyContext *>(getContext("pkey", provider));
	ConvertResult r = c->privateFromPEM(s, passphrase);
	if(result)
		*result = r;
	if(r == ConvertGood)
		k.change(c);
	return k;
}

PrivateKey PrivateKey::fromPEMFile(const QString &fileName, const QSecureArray &passphrase, ConvertResult *result, const QString &provider)
{
	QString pem;
	if(!stringFromFile(fileName, &pem))
	{
		if(result)
			*result = ErrorFile;
		return PrivateKey();
	}
	return fromPEM(pem, passphrase, result, provider);
}

//----------------------------------------------------------------------------
// KeyGenerator
//----------------------------------------------------------------------------
class KeyGenerator::Private : public QObject
{
	Q_OBJECT
public:
	KeyGenerator *parent;
	bool blocking, wasBlocking;
	PrivateKey key;

	PKeyBase *k;
	PKeyContext *dest;

	Private(KeyGenerator *_parent)
	{
		parent = _parent;
		k = 0;
		dest = 0;
	}

	~Private()
	{
		delete k;
		delete dest;
	}

public slots:
	void done()
	{
		if(!k->isNull())
		{
			dest->setKey(k);
			k = 0;

			key.change(dest);
			dest = 0;
		}
		else
		{
			delete k;
			k = 0;
			delete dest;
			dest = 0;
		}

		if(!wasBlocking)
			emit parent->finished();
	}
};

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

PrivateKey KeyGenerator::createRSA(int bits, int exp, const QString &provider)
{
	if(isBusy())
		return PrivateKey();

	d->key = PrivateKey();
	d->wasBlocking = d->blocking;
	d->k = static_cast<RSAContext *>(getContext("rsa", provider));
	d->dest = static_cast<PKeyContext *>(getContext("pkey", d->k->provider()->name()));

	if(!d->blocking)
	{
		connect(d->k, SIGNAL(finished()), d, SLOT(done()));
		static_cast<RSAContext *>(d->k)->createPrivate(bits, exp, false);
	}
	else
	{
		static_cast<RSAContext *>(d->k)->createPrivate(bits, exp, true);
		d->done();
	}

	return d->key;
}

PrivateKey KeyGenerator::createDSA(DL_Group group, const QString &provider)
{
	if(isBusy())
		return PrivateKey();

	d->key = PrivateKey();
	d->wasBlocking = d->blocking;
	d->k = static_cast<DSAContext *>(getContext("dsa", provider));
	d->dest = static_cast<PKeyContext *>(getContext("pkey", d->k->provider()->name()));

	if(!d->blocking)
	{
		connect(d->k, SIGNAL(finished()), d, SLOT(done()));
		static_cast<DSAContext *>(d->k)->createPrivate(group, false);
	}
	else
	{
		static_cast<DSAContext *>(d->k)->createPrivate(group, true);
		d->done();
	}

	return d->key;
}

PrivateKey KeyGenerator::createDH(DL_Group group, const QString &provider)
{
	if(isBusy())
		return PrivateKey();

	d->key = PrivateKey();
	d->wasBlocking = d->blocking;
	d->k = static_cast<DHContext *>(getContext("dh", provider));
	d->dest = static_cast<PKeyContext *>(getContext("pkey", d->k->provider()->name()));

	if(!d->blocking)
	{
		connect(d->k, SIGNAL(finished()), d, SLOT(done()));
		static_cast<DHContext *>(d->k)->createPrivate(group, false);
	}
	else
	{
		static_cast<DHContext *>(d->k)->createPrivate(group, true);
		d->done();
	}

	return d->key;
}

PrivateKey KeyGenerator::result() const
{
	return d->key;
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
	PKeyContext *c = (PKeyContext *)getContext("pkey", k->provider()->name());
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
	PKeyContext *c = (PKeyContext *)getContext("pkey", k->provider()->name());
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
	PKeyContext *c = (PKeyContext *)getContext("pkey", k->provider()->name());
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
	PKeyContext *c = (PKeyContext *)getContext("pkey", k->provider()->name());
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
	PKeyContext *c = (PKeyContext *)getContext("pkey", k->provider()->name());
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
	PKeyContext *c = (PKeyContext *)getContext("pkey", k->provider()->name());
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

#include "qca_publickey.moc"
