/*
 * base64.cpp - Base64 converting functions
 * Copyright (C) 2003  Justin Karneges
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

#include"base64.h"

//! \class Base64 base64.h
//! \brief Base64 conversion functions.
//!
//! Converts Base64 data between arrays and strings.
//!
//! \code
//! #include "base64.h"
//!
//! ...
//!
//! // encode a block of data into base64
//! QByteArray block(1024);
//! QByteArray enc = Base64::encode(block);
//!
//!  \endcode

//!
//! Encodes array \a s and returns the result.
QByteArray Base64::encode(const QByteArray &s)
{
	int i;
	int len = s.size();
	char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
	int a, b, c;

	QByteArray p((len+2)/3*4);
	int at = 0;
	for( i = 0; i < len; i += 3 ) {
		a = ((unsigned char)s[i] & 3) << 4;
		if(i + 1 < len) {
			a += (unsigned char)s[i + 1] >> 4;
			b = ((unsigned char)s[i + 1] & 0xF) << 2;
			if(i + 2 < len) {
				b += (unsigned char)s[i + 2] >> 6;
				c = (unsigned char)s[i + 2] & 0x3F;
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

//!
//! Decodes array \a s and returns the result.
QByteArray Base64::decode(const QByteArray &s)
{
	// return value
	QByteArray p;

	// -1 specifies invalid
	// 64 specifies eof
	// everything else specifies data

	char tbl[] = {
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

	// this should be a multiple of 4
	int len = s.size();

	if(len % 4)
		return p;

	p.resize(len / 4 * 3);

	int i;
	int at = 0;

	int a, b, c, d;
	c = d = 0;

	for( i = 0; i < len; i += 4 ) {
		a = tbl[s[i]];
		b = tbl[s[i + 1]];
		c = tbl[s[i + 2]];
		d = tbl[s[i + 3]];
		if((a == 64 || b == 64) || (a < 0 || b < 0 || c < 0 || d < 0)) {
			p.resize(0);
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

//!
//! Encodes array \a a and returns the result as a string.
QString Base64::arrayToString(const QByteArray &a)
{
	QByteArray b = encode(a);
	QCString c;
	c.resize(b.size()+1);
	memcpy(c.data(), b.data(), b.size());
	return QString::fromLatin1(c);
}

//!
//! Decodes string \a s and returns the result as an array.
QByteArray Base64::stringToArray(const QString &s)
{
	if(s.isEmpty())
		return QByteArray();
	const char *c = s.latin1();
	int len = strlen(c);
	QByteArray b(len);
	memcpy(b.data(), c, len);
	QByteArray a = decode(b);
	return a;
}

//!
//! Encodes string \a s and returns the result as a string.
QString Base64::encodeString(const QString &s)
{
	QCString c = s.utf8();
	int len = c.length();
	QByteArray b(len);
	memcpy(b.data(), c.data(), len);
	return arrayToString(b);
}
