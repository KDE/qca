/*
 * qca_basic.cpp - Qt Cryptographic Architecture
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

#include "qca.h"

#include "qcaprovider.h"

namespace QCA {

//----------------------------------------------------------------------------
// Random
//----------------------------------------------------------------------------
Random::Random(const QString &provider)
:Algorithm("random", provider)
{
}

uchar Random::nextByte(Quality q)
{
	return (uchar)(nextBytes(1, q)[0]);
}

QSecureArray Random::nextBytes(int size, Quality q)
{
	return ((RandomContext *)context())->nextBytes(size, q);
	return QSecureArray();
}

uchar Random::randomChar(Quality q)
{
	return globalRNG().nextByte(q);
}

uint Random::randomInt(Quality q)
{
	QSecureArray a = globalRNG().nextBytes(sizeof(int), q);
	uint x;
	memcpy(&x, a.data(), a.size());
	return x;
}

QSecureArray Random::randomArray(int size, Quality q)
{
	return globalRNG().nextBytes(size, q);
}

//----------------------------------------------------------------------------
// Hash
//----------------------------------------------------------------------------
Hash::Hash(const QString &type, const QString &provider)
:Algorithm(type, provider)
{
}

void Hash::clear()
{
	((HashContext *)context())->clear();
}

void Hash::update(const QSecureArray &a)
{
	((HashContext *)context())->update(a);
}

QSecureArray Hash::final()
{
	return ((HashContext *)context())->final();
}

QSecureArray Hash::hash(const QSecureArray &a)
{
	return process(a);
}

QSecureArray Hash::hash(const QCString &cs)
{
	QByteArray a(cs.length());
	memcpy(a.data(), cs.data(), a.size());
	return hash(a);
}

QString Hash::hashToString(const QSecureArray &a)
{
	return arrayToHex(hash(a));
}

QString Hash::hashToString(const QCString &cs)
{
	return arrayToHex(hash(cs));
}
/*
//----------------------------------------------------------------------------
// Cipher
//----------------------------------------------------------------------------
class Cipher::Private
{
public:
	Mode mode;
	Direction dir;
	SymmetricKey key;
	QSecureArray iv;
	bool pad;

	bool ok, done;
};

Cipher::Cipher(int cap, Mode m, Direction dir, const SymmetricKey &key, const InitializationVector &iv, bool pad, const QString &provider)
:Algorithm(cap, provider)
{
	d = new Private;
	setup(m, dir, key, iv, pad);
}

Cipher::Cipher(const Cipher &from)
:Algorithm(from), Filter(from)
{
	d = new Private;
	*this = from;
}

Cipher::~Cipher()
{
	delete d;
}

Cipher & Cipher::operator=(const Cipher &from)
{
	*d = *from.d;
	return *this;
}

KeyLength Cipher::keyLength() const
{
	return ((CipherContext *)context())->keyLength();
}

bool Cipher::validKeyLength(int n) const
{
	return ((n >= keyLength().minimum()) && (n <= keyLength().maximum()) && (n % keyLength().multiple() == 0));
}

int Cipher::blockSize() const
{
	return ((CipherContext *)context())->blockSize();
}

void Cipher::clear()
{
	d->done = false;
	((CipherContext *)context())->setup(d->key, d->mode, d->dir, d->iv, d->pad);
}

QSecureArray Cipher::update(const QSecureArray &a)
{
	QSecureArray out;
	if(d->done)
		return out;
	d->ok = ((CipherContext *)context())->update(a, &out);
	return out;
}

QSecureArray Cipher::final()
{
	QSecureArray out;
	if(d->done)
		return out;
	d->done = true;
	d->ok = ((CipherContext *)context())->final(&out);
	return out;
}

bool Cipher::ok() const
{
	return d->ok;
}

void Cipher::setup(Mode m, Direction dir, const SymmetricKey &key, const InitializationVector &iv, bool pad)
{
	d->mode = m;
	d->dir = dir;
	d->key = key;
	d->iv = iv;
	d->pad = pad;
	clear();
}

//----------------------------------------------------------------------------
// MessageAuthenticationCode
//----------------------------------------------------------------------------
class MessageAuthenticationCode::Private
{
public:
	int hash;
	SymmetricKey key;

	bool done;
	QSecureArray buf;
};

MessageAuthenticationCode::MessageAuthenticationCode(int cap, const Hash &h, const SymmetricKey &key, const QString &provider)
:Algorithm(cap, provider)
{
	d = new Private;
	setup(h, key);
}

MessageAuthenticationCode::MessageAuthenticationCode(const MessageAuthenticationCode &from)
:Algorithm(from), BufferedComputation(from)
{
	d = new Private;
	*this = from;
}

MessageAuthenticationCode::~MessageAuthenticationCode()
{
	delete d;
}

MessageAuthenticationCode & MessageAuthenticationCode::operator=(const MessageAuthenticationCode &from)
{
	*d = *from.d;
	return *this;
}

KeyLength MessageAuthenticationCode::keyLength() const
{
	return ((MACContext *)context())->keyLength();
}

bool MessageAuthenticationCode::validKeyLength(int n) const
{
	return ((n >= keyLength().minimum()) && (n <= keyLength().maximum()) && (n % keyLength().multiple() == 0));
}

void MessageAuthenticationCode::clear()
{
	d->done = false;
	((MACContext *)context())->setup(d->hash, d->key);
}

void MessageAuthenticationCode::update(const QSecureArray &a)
{
	if(d->done)
		return;
	((MACContext *)context())->update(a);
}

QSecureArray MessageAuthenticationCode::final()
{
	if(!d->done)
	{
		d->done = true;
		((MACContext *)context())->final(&d->buf);
	}
	return d->buf;
}

void MessageAuthenticationCode::setup(const Hash &h, const SymmetricKey &key)
{
	d->hash = h.cap();
	d->key = key;
	clear();
}
*/
}
