/*
 * qca_tools.cpp - Qt Cryptographic Architecture
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

#include "qca_tools.h"

#ifdef Q_OS_UNIX
# include <stdlib.h>
# include <sys/mman.h>
#endif
#include "botantools/botantools.h"

using namespace QCA;

static bool can_lock()
{
#ifdef Q_OS_UNIX
	bool ok = false;
	void *d = malloc(256);
	if(mlock(d, 256) == 0)
	{
		munlock(d, 256);
		ok = true;
	}
	free(d);
	return ok;
#else
	return true;
#endif
}

static void add_mmap()
{
#ifdef Q_OS_UNIX
	Botan::add_allocator_type("mmap", new Botan::MemoryMapping_Allocator);
	Botan::set_default_allocator("mmap");
#endif
}

namespace QCA {

// Botan shouldn't throw any exceptions in our init/deinit.

static const Botan::SecureAllocator *alloc = 0;

bool botan_init(int prealloc, bool mmap)
{
	// 64k minimum
	if(prealloc < 64)
		prealloc = 64;

	Botan::botan_memory_chunk = 64 * 1024;
	Botan::botan_prealloc = prealloc / 64;
	if(prealloc % 64 != 0)
		++Botan::botan_prealloc;

	Botan::Init::set_mutex_type(new Botan::Qt_Mutex);
	Botan::Init::startup_memory_subsystem();

	bool secmem = false;
	if(can_lock())
	{
		Botan::set_default_allocator("locking");
		secmem = true;
	}
	else if(mmap)
	{
		add_mmap();
		secmem = true;
	}
	alloc = Botan::get_allocator("default");

	return secmem;
}

void botan_deinit()
{
	alloc = 0;
	Botan::Init::shutdown_memory_subsystem();
	Botan::Init::set_mutex_type(0);
}

void *botan_secure_alloc(int bytes)
{
	return alloc->allocate((Botan::u32bit)bytes);
}

void botan_secure_free(void *p, int bytes)
{
	alloc->deallocate(p, (Botan::u32bit)bytes);
}

}

//----------------------------------------------------------------------------
// QSecureArray
//----------------------------------------------------------------------------
class QSecureArray::Private
{
public:
	Private(uint size) : buf((Botan::u32bit)size), refs(1) {}
	Private(const Botan::SecureVector<Botan::byte> &a) : buf(a), refs(1) {}

	Botan::SecureVector<Botan::byte> buf;
	int refs;
};

QSecureArray::QSecureArray()
{
	d = 0;
}

QSecureArray::QSecureArray(int size)
{
	if(size > 0)
		d = new Private(size);
	else
		d = 0;
}

QSecureArray::QSecureArray(const QByteArray &a)
{
	d = 0;
	*this = a;
}

QSecureArray::QSecureArray(const QCString &cs)
{
	d = 0;
	*this = cs;
}

QSecureArray::QSecureArray(const QSecureArray &from)
{
	d = 0;
	*this = from;
}

QSecureArray::~QSecureArray()
{
	reset();
}

void QSecureArray::reset()
{
	if(d)
	{
		--d->refs;
		if(d->refs == 0)
			delete d;
		d = 0;
	}
}

void QSecureArray::fill(char fillChar, int fillToPosition)
{
	detach();
	if(!d)
		return;
	int len;
	if ( (fillToPosition = -1)|| (fillToPosition > (int)size() ) ) {
		len = size();
	} else {
		len = fillToPosition;
	}
	memset( d->buf, (int)fillChar, len );

}

QSecureArray & QSecureArray::operator=(const QSecureArray &from)
{
	reset();

	if(from.d)
	{
		d = from.d;
		++d->refs;
	}
	return *this;
}

QSecureArray & QSecureArray::operator=(const QByteArray &from)
{
	reset();

	if(!from.isEmpty())
	{
		d = new Private(from.size());
		Botan::byte *p = (Botan::byte *)d->buf;
		memcpy(p, from.data(), from.size());
	}

	return *this;
}

QSecureArray & QSecureArray::operator=(const QCString &cs)
{
	reset();

	if(!cs.isEmpty())
	{
		int size = cs.length();
		d = new Private(size);
		Botan::byte *p = (Botan::byte *)d->buf;
		memcpy(p, cs.data(), size);
	}

	return *this;
}

char & QSecureArray::operator[](int index)
{
	return at(index);
}

const char & QSecureArray::operator[](int index) const
{
	return at(index);
}

const char & QSecureArray::at(uint index) const
{
	return (char &)(*((Botan::byte *)d->buf + index));
}

char & QSecureArray::at(uint index)
{
	detach();
	return (char &)(*((Botan::byte *)d->buf + index));
}

const char *QSecureArray::data() const
{
	if(!d)
		return 0;
	const Botan::byte *p = (const Botan::byte *)d->buf;
	return ((const char *)p);
}

char *QSecureArray::data()
{
	detach();
	if(!d)
		return 0;
	Botan::byte *p = (Botan::byte *)d->buf;
	return ((char *)p);
}

uint QSecureArray::size() const
{
	return (d ? d->buf.size() : 0);
}

bool QSecureArray::isEmpty() const
{
	return (size() == 0);
}

bool QSecureArray::resize(uint size)
{
	int cur_size = (d ? d->buf.size() : 0);
	if(cur_size == (int)size)
		return true;

	detach();

	if(size > 0)
	{
		Private *d2 = new Private(size);
		Botan::byte *p2 = (Botan::byte *)d2->buf;
		if(d)
		{
			Botan::byte *p = (Botan::byte *)d->buf;
			memcpy(p2, p, QMIN((int)size, cur_size));
			delete d;
		}
		d = d2;
	}
	else
	{
		delete d;
		d = 0;
	}
	return true;
}

QSecureArray QSecureArray::copy() const
{
	QSecureArray a = *this;
	a.detach();
	return a;
}

void QSecureArray::detach()
{
	if(!d || d->refs <= 1)
		return;
	--d->refs;
	d = new Private(d->buf);
}

QByteArray QSecureArray::toByteArray() const
{
	if(isEmpty())
		return QByteArray();

	QByteArray buf(size());
	memcpy(buf.data(), data(), size());
	return buf;
}

void QSecureArray::set(const QSecureArray &from)
{
	*this = from;
}

void QSecureArray::set(const QCString &cs)
{
	*this = cs;
}

QSecureArray & QSecureArray::append(const QSecureArray &a)
{
	detach();
	int oldsize = size();
	resize( oldsize + a.size() );
	memcpy( data() + oldsize, a.data(), a.size() );
	return *this;
}

bool operator==(const QSecureArray &a, const QSecureArray &b)
{
	if(&a == &b)
		return true;
	if(a.size() == b.size() && memcmp(a.data(), b.data(), a.size()) == 0)
		return true;
	return false;
}

bool operator!=(const QSecureArray &a, const QSecureArray &b)
{
	return !(a == b);
}
       
//----------------------------------------------------------------------------
// QBigInteger
//----------------------------------------------------------------------------
static void negate_binary(char *a, int size)
{
	// negate = two's compliment + 1
	bool done = false;
	for(int n = size - 1; n >= 0; --n)
	{
		a[n] = ~a[n];
		if(!done)
		{
			if((unsigned char)a[n] < 0xff)
			{
				++a[n];
				done = true;
			}
			else
				a[n] = 0;
		}
	}
}

class QBigInteger::Private
{
public:
	Botan::BigInt n;
};

QBigInteger::QBigInteger()
{
	d = new Private;
}

QBigInteger::QBigInteger(int i)
{
	d = new Private;
	if(i < 0)
	{
		d->n = Botan::BigInt(i * (-1));
		d->n.set_sign(Botan::BigInt::Negative);
	}
	else
	{
		d->n = Botan::BigInt(i);
		d->n.set_sign(Botan::BigInt::Positive);
	}
}

QBigInteger::QBigInteger(const QString &s)
{
	d = new Private;
	fromString(s);
}

QBigInteger::QBigInteger(const QSecureArray &a)
{
	d = new Private;
	fromArray(a);
}

QBigInteger::QBigInteger(const QBigInteger &from)
{
	d = new Private;
	*this = from;
}

QBigInteger::~QBigInteger()
{
	delete d;
}

QBigInteger & QBigInteger::operator=(const QBigInteger &from)
{
	d->n = from.d->n;
	return *this;
}

QBigInteger & QBigInteger::operator+=(const QBigInteger &i)
{
	d->n += i.d->n;
	return *this;
}

QBigInteger & QBigInteger::operator-=(const QBigInteger &i)
{
	d->n -= i.d->n;
	return *this;
}

QBigInteger & QBigInteger::operator=(const QString &s)
{
	fromString(s);
	return *this;
}

int QBigInteger::compare(const QBigInteger &n) const
{
	return ( (d->n).cmp( n.d->n, true) );
}

QTextStream &operator<<(QTextStream &stream, const QBigInteger& b)
{
	stream << b.toString();
	return stream;
}

QSecureArray QBigInteger::toArray() const
{
	int size = d->n.encoded_size(Botan::BigInt::Binary);

	// return at least 8 bits
	if(size == 0)
	{
		QSecureArray a(1);
		a[0] = 0;
		return a;
	}

	int offset = 0;
	QSecureArray a;

	// make room for a sign bit if needed
	if(d->n.get_bit((size * 8) - 1))
	{
		++size;
		a.resize(size);
		a[0] = 0;
		++offset;
	}
	else
		a.resize(size);

	Botan::BigInt::encode((Botan::byte *)a.data() + offset, d->n, Botan::BigInt::Binary);

	if(d->n.is_negative())
		negate_binary(a.data(), a.size());

	return a;
}

void QBigInteger::fromArray(const QSecureArray &_a)
{
	if(_a.isEmpty())
	{
		d->n = Botan::BigInt(0);
		return;
	}
	QSecureArray a = _a;

	Botan::BigInt::Sign sign = Botan::BigInt::Positive;
	if(a[0] & 0x80)
		sign = Botan::BigInt::Negative;

	if(sign == Botan::BigInt::Negative)
		negate_binary(a.data(), a.size());

	d->n = Botan::BigInt::decode((const Botan::byte *)a.data(), a.size(), Botan::BigInt::Binary);
	d->n.set_sign(sign);
}

QString QBigInteger::toString() const
{
	QCString cs;
	try
	{
		QByteArray a(d->n.encoded_size(Botan::BigInt::Decimal));
		Botan::BigInt::encode((Botan::byte *)a.data(), d->n, Botan::BigInt::Decimal);
		cs = QCString(a.data(), a.size() + 1);
	}
	catch(std::exception &)
	{
		return QString::null;
	}

	QString str;
	if(d->n.is_negative())
		str += '-';
	str += QString::fromLatin1(cs);
	return str;
}

bool QBigInteger::fromString(const QString &s)
{
	if(s.isEmpty())
		return false;
	QCString cs = s.latin1();

	bool neg = false;
	if(s[0] == '-')
		neg = true;

	try
	{
		d->n = Botan::BigInt::decode((const Botan::byte *)cs.data() + (neg ? 1 : 0), cs.length() - (neg ? 1 : 0), Botan::BigInt::Decimal);
	}
	catch(std::exception &)
	{
		return false;
	}

	if(neg)
		d->n.set_sign(Botan::BigInt::Negative);
	else
		d->n.set_sign(Botan::BigInt::Positive);
	return true;
}
