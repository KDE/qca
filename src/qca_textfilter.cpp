/*
 * qca_textfilter.cpp - Qt Cryptographic Architecture
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

namespace QCA {

//----------------------------------------------------------------------------
// TextFilter
//----------------------------------------------------------------------------
TextFilter::TextFilter(Direction dir)
{
	setup(dir);
}

void TextFilter::setup(Direction dir)
{
	_dir = dir;
}

QSecureArray TextFilter::encode(const QSecureArray &a)
{
	setup(Encode);
	return process(a);
}

QSecureArray TextFilter::decode(const QSecureArray &a)
{
	setup(Decode);
	return process(a);
}

QString TextFilter::arrayToString(const QSecureArray &a)
{
	QByteArray b = encode(a).toByteArray();
	QCString c;
	c.resize(b.size() + 1);
	memcpy(c.data(), b.data(), b.size());
	return QString::fromLatin1(c);
}

QSecureArray TextFilter::stringToArray(const QString &s)
{
	if(s.isEmpty())
		return QSecureArray();
	const char *c = s.latin1();
	int len = strlen(c);
	QSecureArray b(len);
	memcpy(b.data(), c, len);
	return decode(b);
}

QString TextFilter::encodeString(const QString &s)
{
	QCString c = s.utf8();
	int len = c.length();
	QSecureArray b(len);
	memcpy(b.data(), c.data(), len);
	return arrayToString(b);
}

QString TextFilter::decodeString(const QString &s)
{
	QSecureArray a = stringToArray(s);
	QCString c;
	c.resize(a.size() + 1);
	memcpy(c.data(), a.data(), a.size());
	return QString::fromUtf8(c);
}

//----------------------------------------------------------------------------
// Hex
//----------------------------------------------------------------------------
static int enhex(uchar c)
{
	if(c < 10)
		return c + '0';
	else if(c < 16)
		return c - 10 + 'a';
	else
		return -1;
}

static int dehex(char c)
{
	if(c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	else if(c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	else if(c >= '0' && c <= '9')
		return c - '0';
	else
		return -1;
}

Hex::Hex(Direction dir)
:TextFilter(dir)
{
	clear();
}

void Hex::clear()
{
	partial = false;
	_ok = true;
}

QSecureArray Hex::update(const QSecureArray &a)
{
	if(_dir == Encode)
	{
		QSecureArray out(a.size() * 2);
		int at = 0;
		int c;
		for(int n = 0; n < (int)a.size(); ++n)
		{
			uchar lo = (uchar)a[n] & 0x0f;
			uchar hi = (uchar)a[n] >> 4;
			c = enhex(hi);
			if(c == -1)
			{
				_ok = false;
				break;
			}
			out[at++] = (char)c;
			c = enhex(lo);
			if(c == -1)
			{
				_ok = false;
				break;
			}
			out[at++] = (char)c;
		}
		if(!_ok)
			return QSecureArray();

		return out;
	}
	else
	{
		uchar lo = 0;
		uchar hi = 0;
		bool flag = false;
		if(partial)
		{
			hi = val;
			flag = true;
		}

		QByteArray out(a.size() / 2);
		int at = 0;
		int c;
		for(int n = 0; n < (int)a.size(); ++n)
		{
			c = dehex((char)a[n]);
			if(c == -1)
			{
				_ok = false;
				break;
			}
			if(flag)
			{
				lo = (uchar)c;
				uchar full = ((hi & 0x0f) << 4) + (lo & 0x0f);
				out[at++] = full;
				flag = false;
			}
			else
			{
				hi = (uchar)c;
				flag = true;
			}
		}
		if(!_ok)
			return QSecureArray();

		if(flag)
		{
			val = hi;
			partial = true;
		}
		return out;
	}
}

QSecureArray Hex::final()
{
	if(partial)
		_ok = false;
	return QSecureArray();
}

bool Hex::ok() const
{
	return _ok;
}

//----------------------------------------------------------------------------
// Base64
//----------------------------------------------------------------------------
Base64::Base64(Direction dir)
:TextFilter(dir)
{
}

void Base64::clear()
{
	partial.resize(0);
	_ok = true;
}

static QSecureArray b64encode(const QSecureArray &s)
{
	int i;
	int len = s.size();
	static char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
	int a, b, c;

	QSecureArray p((len + 2) / 3 * 4);
	int at = 0;
	for(i = 0; i < len; i += 3)
	{
		a = ((unsigned char)s[i] & 3) << 4;
		if(i + 1 < len)
		{
			a += (unsigned char)s[i + 1] >> 4;
			b = ((unsigned char)s[i + 1] & 0xf) << 2;
			if(i + 2 < len)
			{
				b += (unsigned char)s[i + 2] >> 6;
				c = (unsigned char)s[i + 2] & 0x3f;
			}
			else
				c = 64;
		}
		else
			b = c = 64;

		p[at++] = tbl[(unsigned char)s[i] >> 2];
		p[at++] = tbl[a];
		p[at++] = tbl[b];
		p[at++] = tbl[c];
	}
	return p;
}

static QSecureArray b64decode(const QSecureArray &s, bool *ok)
{
	// -1 specifies invalid
	// 64 specifies eof
	// everything else specifies data

	static char tbl[] =
	{
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
		52,53,54,55,56,57,58,59,60,61,-1,-1,-1,64,-1,-1,
		-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
		15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
		-1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
		41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
		-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	};

	// return value
	QSecureArray p;
	*ok = true;

	// this should be a multiple of 4
	int len = s.size();
	if(len % 4)
	{
		*ok = false;
		return p;
	}

	p.resize(len / 4 * 3);

	int i;
	int at = 0;

	int a, b, c, d;
	c = d = 0;

	for(i = 0; i < len; i += 4)
	{
		a = tbl[(int)s[i]];
		b = tbl[(int)s[i + 1]];
		c = tbl[(int)s[i + 2]];
		d = tbl[(int)s[i + 3]];
		if((a == 64 || b == 64) || (a < 0 || b < 0 || c < 0 || d < 0))
		{
			p.resize(0);
			*ok = false;
			return p;
		}
		p[at++] = ((a & 0x3F) << 2) | ((b >> 4) & 0x03);
		p[at++] = ((b & 0x0F) << 4) | ((c >> 2) & 0x0F);
		p[at++] = ((c & 0x03) << 6) | ((d >> 0) & 0x3F);
	}

	if(c & 64)
		p.resize(at - 2);
	else if(d & 64)
		p.resize(at - 1);

	return p;
}

static void appendArray(QSecureArray *a, const QSecureArray &b)
{
	int oldsize = a->size();
	a->resize(oldsize + b.size());
	memcpy(a->data() + oldsize, b.data(), b.size());
}

QSecureArray Base64::update(const QSecureArray &a)
{
	if(a.isEmpty())
		return QSecureArray();

	int chunk;
	if(_dir == Encode)
		chunk = 3;
	else
		chunk = 4;

	int size = partial.size() + a.size();
	if(size < chunk)
	{
		appendArray(&partial, a);
		return QSecureArray();
	}

	int eat = size % chunk;

	// s = partial + a - eat
	QSecureArray s(partial.size() + a.size() - eat);
	memcpy(s.data(), partial.data(), partial.size());
	memcpy(s.data() + partial.size(), a.data(), a.size() - eat);

	partial.resize(eat);
	memcpy(partial.data(), a.data() + a.size() - eat, eat);

	if(_dir == Encode)
	{
		return b64encode(s);
	}
	else
	{
		bool ok;
		QSecureArray out = b64decode(s, &ok);
		if(!ok)
			_ok = false;
		return out;
	}
}

QSecureArray Base64::final()
{
	if(_dir == Encode)
	{
		return b64encode(partial);
	}
	else
	{
		bool ok;
		QSecureArray out = b64decode(partial, &ok);
		if(!ok)
			_ok = false;
		return out;
	}
}

bool Base64::ok() const
{
	return _ok;
}

}
