/*
 * qca_basic.cpp - Qt Cryptographic Architecture
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

#include "qca_basic.h"

#include <QtCore>
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
	//detach();
	((HashContext *)context())->clear();
}

void Hash::update(const QSecureArray &a)
{
	//detach();
	((HashContext *)context())->update(a);
}

void Hash::update(const QByteArray &a)
{
	update( QSecureArray( a ) );
}

void Hash::update(const char *data, int len)
{
	if ( len < 0 )
		len = qstrlen( data );
	if ( 0 == len )
		return;

	update(QByteArray::fromRawData(data, len));
}

// Reworked from KMD5, from KDE's kdelibs
void Hash::update(QIODevice &file)
{
	char buffer[1024];
	int len;

	while ((len=file.read(reinterpret_cast<char*>(buffer), sizeof(buffer))) > 0)
		update(buffer, len);
}

QSecureArray Hash::final()
{
	//detach();
	return ((HashContext *)context())->final();
}

QSecureArray Hash::hash(const QSecureArray &a)
{
	return process(a);
}

QString Hash::hashToString(const QSecureArray &a)
{
	return arrayToHex(hash(a));
}

//----------------------------------------------------------------------------
// Cipher
//----------------------------------------------------------------------------
class Cipher::Private
{
public:
	Mode mode;
	Direction dir;
	SymmetricKey key;
	InitializationVector iv;
	Padding pad;

	bool ok, done;
};

Cipher::Cipher(const QString &type, Mode m, Direction dir, const SymmetricKey &key, const InitializationVector &iv, Padding pad, const QString &provider)
:Algorithm(type, provider)
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
	Algorithm::operator=(from);
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

unsigned int Cipher::blockSize() const
{
	return ((CipherContext *)context())->blockSize();
}

void Cipher::clear()
{
	//detach();
	d->done = false;
	((CipherContext *)context())->setup(d->key, (CipherContext::Mode)d->mode, d->dir, d->iv);
}

QSecureArray Cipher::update(const QSecureArray &a)
{
	//detach();
	QSecureArray out;
	if(d->done)
		return out;
	d->ok = ((CipherContext *)context())->update(a, &out);
	return out;
}

QSecureArray Cipher::final()
{
	//detach();
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

void Cipher::setup(Mode m, Direction dir, const SymmetricKey &key, const InitializationVector &iv,  Padding pad)
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
	SymmetricKey key;

	bool done;
	QSecureArray buf;
};

MessageAuthenticationCode::MessageAuthenticationCode(const QString &type, const SymmetricKey &key, const QString &provider)
:Algorithm(type, provider)
{
	d = new Private;
	setup(key);
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
	//detach();
	d->done = false;
	((MACContext *)context())->setup(d->key);
}

void MessageAuthenticationCode::update(const QSecureArray &a)
{
	//detach();
	if(d->done)
		return;
	((MACContext *)context())->update(a);
}

QSecureArray MessageAuthenticationCode::final()
{
	//detach();
	if(!d->done)
	{
		d->done = true;
		((MACContext *)context())->final(&d->buf);
	}
	return d->buf;
}

void MessageAuthenticationCode::setup(const SymmetricKey &key)
{
	d->key = key;
	clear();
}

QString MessageAuthenticationCode::withAlgorithm(const QString &macType, const QString &algType)
{
	return (macType + '(' + algType + ')');
}

//----------------------------------------------------------------------------
// Key Derivation Function
//----------------------------------------------------------------------------
class KeyDerivationFunction::Private
{
public:
    QSecureArray secret;
    InitializationVector salt;
    int keyLength;
    int iterationCount;

    SymmetricKey buf;
};

KeyDerivationFunction::KeyDerivationFunction(const QString &type, const QString &provider)
:Algorithm(type, provider)
{
	d = new Private;
}

KeyDerivationFunction::KeyDerivationFunction(const KeyDerivationFunction &from)
:Algorithm(from)
{
	d = new Private;
	*this = from;
}

KeyDerivationFunction::~KeyDerivationFunction()
{
	delete d;
}

SymmetricKey KeyDerivationFunction::makeKey(const QSecureArray &secret,
				     const InitializationVector &salt,
				     unsigned int keyLength,
				     unsigned int iterationCount)
{
	d->secret = secret;
	d->salt = salt;
	d->keyLength = keyLength;
	d->iterationCount = iterationCount;

	return d->buf;
}

QString KeyDerivationFunction::withAlgorithm(const QString &kdfType, const QString &algType)
{
	return (kdfType + '(' + algType + ')');
}

}
