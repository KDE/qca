/*
 * qca_default.cpp - Qt Cryptographic Architecture
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

#include <qdatetime.h>
#include <qstringlist.h>
#include <stdlib.h>
#include "qcaprovider.h"

namespace QCA {

//----------------------------------------------------------------------------
// DefaultProvider
//----------------------------------------------------------------------------
class DefaultRandomContext : public QCA::RandomContext
{
public:
	DefaultRandomContext(QCA::Provider *p) : RandomContext(p) {}

	Context *clone() const
	{
		return new DefaultRandomContext(provider());
	}

	QSecureArray nextBytes(int size, QCA::Random::Quality)
	{
		QSecureArray buf(size);
		for(int n = 0; n < (int)buf.size(); ++n)
			buf[n] = (char)rand();
		return buf;
	}
};


/*
  The following code is based on L. Peter Deutsch's implementation,
  as provided at http://sourceforge.net/projects/libmd5-rfc/
  
  The original code contained:

  Copyright (C) 1999, 2000, 2002 Aladdin Enterprises.  All rights reserved.

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.

  L. Peter Deutsch
  ghost@aladdin.com

 */
/*
  Independent implementation of MD5 (RFC 1321).

  This code implements the MD5 Algorithm defined in RFC 1321, whose
  text is available at
	http://www.ietf.org/rfc/rfc1321.txt
  The code is derived from the text of the RFC, including the test suite
  (section A.5) but excluding the rest of Appendix A.  It does not include
  any code or documentation that is identified in the RFC as being
  copyrighted.

  The original and principal author of md5.c is L. Peter Deutsch
  <ghost@aladdin.com>.  Other authors are noted in the change history
  that follows (in reverse chronological order):

  2002-04-13 lpd Clarified derivation from RFC 1321; now handles byte order
	either statically or dynamically; added missing #include <string.h>
	in library.
  2002-03-11 lpd Corrected argument list for main(), and added int return
	type, in test program and T value program.
  2002-02-21 lpd Added missing #include <stdio.h> in test program.
  2000-07-03 lpd Patched to eliminate warnings about "constant is
	unsigned in ANSI C, signed in traditional"; made test program
	self-checking.
  1999-11-04 lpd Edited comments slightly for automatic TOC extraction.
  1999-10-18 lpd Fixed typo in header comment (ansi2knr rather than md5).
  1999-05-03 lpd Original version.
 */

class DefaultMD5Context : public QCA::HashContext
{
public:
        DefaultMD5Context(QCA::Provider *p) : HashContext(p, "md5")
        {
                clear();
        }

        Context *clone() const
        {
                return new DefaultMD5Context(*this);
        }

        void clear()
        {
		buf.resize(64);
		buf.fill(0);
		count[0] = count[1] = 0;
		abcd[0] = 0x67452301;
		abcd[1] = 0xefcdab89;
		abcd[2] = 0x98badcfe;
		abcd[3] = 0x10325476;
	}

        void update(const QSecureArray &a)
        {
		const unsigned char *p = (const unsigned char*)a.data();
		int left = a.size();
		int offset = (count[0] >> 3) & 63;
		Q_UINT32 nbits = (Q_UINT32)(a.size() << 3);

		if (a.size() <= 0)
			return;

		/* Update the message length. */
		count[1] += a.size() >> 29;
		count[0] += nbits;
		if (count[0] < nbits)
			count[1]++;

		/* Process an initial partial block. */
		if (offset) {
			int copy = (offset + a.size() > 64 ? 64 - offset : a.size());

			memcpy(buf.data() + offset, p, copy);
			if (offset + copy < 64)
				return;
			p += copy;
			left -= copy;
			md5_process(buf);
		}

		/* Process full blocks. */
		for (; left >= 64; p += 64, left -= 64) {
			QSecureArray thisBlock(64);
			memcpy(thisBlock.data(), p, 64);
			md5_process(thisBlock);
		}

		/* Process a final partial block. */
		if (left)
			memcpy(buf.data(), p, left);
	}

        QSecureArray final()
        {
		QSecureArray a(16);
		QSecureArray data(8);
		unsigned int i;
    
		/* Save the length before padding. */
		for (i = 0; i < 8; ++i)
			data[i] = (count[i >> 2] >> ((i & 3) << 3));
		/* Pad to 56 bytes mod 64. */
		QSecureArray padding(((55 - (count[0] >> 3)) & 63) + 1);
		if (padding.size() > 0 ) {
			padding[0] = 0x80;
			if (padding.size() > 1 ) {
				for (i = 1; i < padding.size(); ++i) {
					padding[i] = 0x00;
				}
			}
			update(padding); 
		}
		/* Append the length. */
		update(data);
		for (i = 0; i < 16; ++i)
			a[i] = (abcd[i >> 2] >> ((i & 3) << 3));
		return a;
        }

private:

/* Define the state of the MD5 Algorithm. */
	Q_UINT32 count[2];	/* message length in bits, lsw first */
	Q_UINT32 abcd[4];		/* digest buffer */
	QSecureArray  buf;		/* accumulate block */

	void md5_process(QSecureArray data)
	{
		Q_UINT32 a,b,c,d;
		a = abcd[0];
		b = abcd[1];
		c = abcd[2];
		d = abcd[3];
		
		Q_UINT32 t;
		Q_UINT32 xbuf[16];
		const Q_UINT32 *X;
		
		{
			/*
			 * Determine dynamically whether this is a big-endian or
			 * little-endian machine, since we can use a more efficient
			 * algorithm on the latter.
			 */
			static const int w = 1;
			
			if (*((const Q_UINT8 *)&w)) /* little-endian */
			{
				/*
				 * On little-endian machines, we can process properly aligned
				 * data without copying it.
				 */
				if (!((data.data() - (const char *)0) & 3)) {
					/* data are properly aligned */
					X = (const Q_UINT32 *)data.data();
				} else {
					/* not aligned */
					memcpy(xbuf, data.data(), 64);
					X = xbuf;
				}
			}
			else			/* big-endian */
			{
				/*
				 * On big-endian machines, we must arrange the bytes in the
				 * right order.
				 */
				const char *xp = data.data();
				int i;
				
				X = xbuf;
				for (i = 0; i < 16; ++i, xp += 4)
					xbuf[i] = xp[0] + (xp[1] << 8) + (xp[2] << 16) + (xp[3] << 24);
			}
		}
		
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
		
		/* Round 1. */
		/* Let [abcd k s i] denote the operation
		   a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s). */
#define F(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define SET(a, b, c, d, k, s, Ti)		\
		t = a + F(b,c,d) + X[k] + Ti;	\
		a = ROTATE_LEFT(t, s) + b
		/* Do the following 16 operations. */
		SET(a, b, c, d,  0,  7,  0xd76aa478);
		SET(d, a, b, c,  1, 12,  0xe8c7b756);
		SET(c, d, a, b,  2, 17,  0x242070db);
		SET(b, c, d, a,  3, 22, 0xc1bdceee);
		SET(a, b, c, d,  4,  7, 0xf57c0faf);
		SET(d, a, b, c,  5, 12, 0x4787c62a);
		SET(c, d, a, b,  6, 17, 0xa8304613);
		SET(b, c, d, a,  7, 22, 0xfd469501);
		SET(a, b, c, d,  8,  7, 0x698098d8);
		SET(d, a, b, c,  9, 12, 0x8b44f7af);
		SET(c, d, a, b, 10, 17, 0xffff5bb1);
		SET(b, c, d, a, 11, 22, 0x895cd7be);
		SET(a, b, c, d, 12,  7, 0x6b901122);
		SET(d, a, b, c, 13, 12, 0xfd987193);
		SET(c, d, a, b, 14, 17, 0xa679438e);
		SET(b, c, d, a, 15, 22, 0x49b40821);
#undef SET
		
		/* Round 2. */
		/* Let [abcd k s i] denote the operation
		   a = b + ((a + G(b,c,d) + X[k] + T[i]) <<< s). */
#define G(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define SET(a, b, c, d, k, s, Ti)		\
		t = a + G(b,c,d) + X[k] + Ti;	\
		a = ROTATE_LEFT(t, s) + b
	/* Do the following 16 operations. */
		SET(a, b, c, d,  1,  5, 0xf61e2562);
		SET(d, a, b, c,  6,  9, 0xc040b340);
		SET(c, d, a, b, 11, 14, 0x265e5a51);
		SET(b, c, d, a,  0, 20, 0xe9b6c7aa);
		SET(a, b, c, d,  5,  5, 0xd62f105d);
		SET(d, a, b, c, 10,  9, 0x02441453);
		SET(c, d, a, b, 15, 14, 0xd8a1e681);
		SET(b, c, d, a,  4, 20, 0xe7d3fbc8);
		SET(a, b, c, d,  9,  5, 0x21e1cde6);
		SET(d, a, b, c, 14,  9, 0xc33707d6);
		SET(c, d, a, b,  3, 14, 0xf4d50d87);
		SET(b, c, d, a,  8, 20, 0x455a14ed);
		SET(a, b, c, d, 13,  5, 0xa9e3e905);
		SET(d, a, b, c,  2,  9, 0xfcefa3f8);
		SET(c, d, a, b,  7, 14, 0x676f02d9);
		SET(b, c, d, a, 12, 20, 0x8d2a4c8a);
#undef SET

		/* Round 3. */
		/* Let [abcd k s t] denote the operation
		   a = b + ((a + H(b,c,d) + X[k] + T[i]) <<< s). */
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define SET(a, b, c, d, k, s, Ti)		\
		t = a + H(b,c,d) + X[k] + Ti;	\
		a = ROTATE_LEFT(t, s) + b
		/* Do the following 16 operations. */
		SET(a, b, c, d,  5,  4, 0xfffa3942);
		SET(d, a, b, c,  8, 11, 0x8771f681);
		SET(c, d, a, b, 11, 16, 0x6d9d6122);
		SET(b, c, d, a, 14, 23, 0xfde5380c);
		SET(a, b, c, d,  1,  4, 0xa4beea44);
		SET(d, a, b, c,  4, 11, 0x4bdecfa9);
		SET(c, d, a, b,  7, 16, 0xf6bb4b60);
		SET(b, c, d, a, 10, 23, 0xbebfbc70);
		SET(a, b, c, d, 13,  4, 0x289b7ec6);
		SET(d, a, b, c,  0, 11, 0xeaa127fa);
		SET(c, d, a, b,  3, 16, 0xd4ef3085);
		SET(b, c, d, a,  6, 23, 0x04881d05);
		SET(a, b, c, d,  9,  4, 0xd9d4d039);
		SET(d, a, b, c, 12, 11, 0xe6db99e5);
		SET(c, d, a, b, 15, 16, 0x1fa27cf8);
		SET(b, c, d, a,  2, 23, 0xc4ac5665);
#undef SET
		
	/* Round 4. */
		/* Let [abcd k s t] denote the operation
		   a = b + ((a + I(b,c,d) + X[k] + T[i]) <<< s). */
#define I(x, y, z) ((y) ^ ((x) | ~(z)))
#define SET(a, b, c, d, k, s, Ti)		\
		t = a + I(b,c,d) + X[k] + Ti;	\
		a = ROTATE_LEFT(t, s) + b
		/* Do the following 16 operations. */
		SET(a, b, c, d,  0,  6, 0xf4292244);
		SET(d, a, b, c,  7, 10, 0x432aff97);
		SET(c, d, a, b, 14, 15, 0xab9423a7);
		SET(b, c, d, a,  5, 21, 0xfc93a039);
		SET(a, b, c, d, 12,  6, 0x655b59c3);
		SET(d, a, b, c,  3, 10, 0x8f0ccc92);
		SET(c, d, a, b, 10, 15, 0xffeff47d);
		SET(b, c, d, a,  1, 21, 0x85845dd1);
		SET(a, b, c, d,  8,  6, 0x6fa87e4f);
		SET(d, a, b, c, 15, 10, 0xfe2ce6e0);
		SET(c, d, a, b,  6, 15, 0xa3014314);
		SET(b, c, d, a, 13, 21, 0x4e0811a1);
		SET(a, b, c, d,  4,  6, 0xf7537e82);
		SET(d, a, b, c, 11, 10, 0xbd3af235);
		SET(c, d, a, b,  2, 15, 0x2ad7d2bb);
		SET(b, c, d, a,  9, 21, 0xeb86d391);
#undef SET
		
		/* Then perform the following additions. (That is increment each
		   of the four registers by the value it had before this block
		   was started.) */
		abcd[0] += a;
		abcd[1] += b;
		abcd[2] += c;
		abcd[3] += d;
	}
	
};


class DefaultProvider : public QCA::Provider
{
public:
	void init()
	{
		QDateTime now = QDateTime::currentDateTime();
		time_t t = now.toTime_t() / now.time().msec();
		srand(t);
	}

	QString name() const
	{
		return "default";
	}

	QStringList features() const
	{
		QStringList list;
		list += "random";
		list += "md5";
		return list;
	}

	Context *createContext(const QString &type)
	{
		if(type == "random")
			return new DefaultRandomContext(this);
		else if(type == "md5")
			return new DefaultMD5Context(this);
		else
			return 0;
	}
};

Provider *create_default_provider()
{
	return new DefaultProvider;
}

}
