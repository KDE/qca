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
}

QSecureArray Base64::update(const QSecureArray &)
{
	return QSecureArray();
}

QSecureArray Base64::final()
{
	return QSecureArray();
}

bool Base64::ok() const
{
	return false;
}

}
