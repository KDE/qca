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
  as provided at http://sourceforge.net/projects/libmd5-rfc/. A 
  fair number of changes have been made to that code.
  
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
		count = 0;
		abcd[0] = 0x67452301;
		abcd[1] = 0xefcdab89;
		abcd[2] = 0x98badcfe;
		abcd[3] = 0x10325476;
	}

        void update(const QSecureArray &a)
        {
		const unsigned char *p = (const unsigned char*)a.data();
		int left = a.size();
		int offset = (count >> 3) & 63;
		Q_UINT32 nbits = (Q_UINT32)(a.size() << 3);

		if (a.size() <= 0)
			return;

		/* Update the message length. */
		count += nbits;

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
		//for (i = 0; i < 8; ++i)
		// count[0] is lsw, count[1] is msw
		//data[i] = (count[i >> 2] >> ((i & 3) << 3));
		data[0] = (count >> 0);
		data[1] = (count >> 8);
		data[2] = (count >> 16);
		data[3] = (count >> 24);
		data[4] = (count >> 32);
		data[5] = (count >> 40);
		data[6] = (count >> 48);
		data[7] = (count >> 56);
		/* Pad to 56 bytes mod 64. */
		QSecureArray padding(((55 - (count >> 3)) & 63) + 1);
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
	Q_UINT64 count;	                /* message length in bits */
	Q_UINT32 abcd[4];		/* digest buffer */
	QSecureArray  buf;		/* accumulate block */

	Q_UINT32 rotateLeft(Q_UINT32 x, Q_UINT32 n)
	{
		return (((x) << (n)) | ((x) >> (32 - (n))));
	}

	Q_UINT32 F(Q_UINT32 x, Q_UINT32 y, Q_UINT32 z)
	{
		return (((x) & (y)) | (~(x) & (z)));
	}

	Q_UINT32 G(Q_UINT32 x, Q_UINT32 y, Q_UINT32 z)
	{
		return (((x) & (z)) | ((y) & ~(z)));
	}

	Q_UINT32 H(Q_UINT32 x, Q_UINT32 y, Q_UINT32 z)
	{
		return ((x) ^ (y) ^ (z));
	}

	Q_UINT32 I(Q_UINT32 x, Q_UINT32 y, Q_UINT32 z)
	{
		return ((y) ^ ((x) | ~(z)));
	}

	Q_UINT32 round1(Q_UINT32 a, Q_UINT32 b, Q_UINT32 c, Q_UINT32 d, Q_UINT32 Xk, Q_UINT32 s, Q_UINT32 Ti)
	{
		Q_UINT32 t = a + F(b,c,d) + Xk + Ti;
		return ( rotateLeft(t, s) + b );
	}

	Q_UINT32 round2(Q_UINT32 a, Q_UINT32 b, Q_UINT32 c, Q_UINT32 d, Q_UINT32 Xk, Q_UINT32 s, Q_UINT32 Ti)
	{
		Q_UINT32 t = a + G(b,c,d) + Xk + Ti;
		return ( rotateLeft(t, s) + b );
	}

	Q_UINT32 round3(Q_UINT32 a, Q_UINT32 b, Q_UINT32 c, Q_UINT32 d, Q_UINT32 Xk, Q_UINT32 s, Q_UINT32 Ti)
	{
		Q_UINT32 t = a + H(b,c,d) + Xk + Ti;
		return ( rotateLeft(t, s) + b );
	}

	Q_UINT32 round4(Q_UINT32 a, Q_UINT32 b, Q_UINT32 c, Q_UINT32 d, Q_UINT32 Xk, Q_UINT32 s, Q_UINT32 Ti)
	{
		Q_UINT32 t = a + I(b,c,d) + Xk + Ti;
		return ( rotateLeft(t, s) + b );
	}

	void md5_process(QSecureArray data)
	{
		Q_UINT32 a,b,c,d;
		a = abcd[0];
		b = abcd[1];
		c = abcd[2];
		d = abcd[3];
		
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
		
		/* Round 1. */
		/* Do the following 16 operations. */
		a = round1(a, b, c, d,  X[0],  7,  0xd76aa478);
		d = round1(d, a, b, c,  X[1], 12,  0xe8c7b756);
		c = round1(c, d, a, b,  X[2], 17,  0x242070db);
		b = round1(b, c, d, a,  X[3], 22, 0xc1bdceee);
		a = round1(a, b, c, d,  X[4],  7, 0xf57c0faf);
		d = round1(d, a, b, c,  X[5], 12, 0x4787c62a);
		c = round1(c, d, a, b,  X[6], 17, 0xa8304613);
		b = round1(b, c, d, a,  X[7], 22, 0xfd469501);
		a = round1(a, b, c, d,  X[8],  7, 0x698098d8);
		d = round1(d, a, b, c,  X[9], 12, 0x8b44f7af);
		c = round1(c, d, a, b, X[10], 17, 0xffff5bb1);
		b = round1(b, c, d, a, X[11], 22, 0x895cd7be);
		a = round1(a, b, c, d, X[12],  7, 0x6b901122);
		d = round1(d, a, b, c, X[13], 12, 0xfd987193);
		c = round1(c, d, a, b, X[14], 17, 0xa679438e);
		b = round1(b, c, d, a, X[15], 22, 0x49b40821);
		
		/* Round 2. */
		a = round2(a, b, c, d,  X[1],  5, 0xf61e2562);
		d = round2(d, a, b, c,  X[6],  9, 0xc040b340);
		c = round2(c, d, a, b, X[11], 14, 0x265e5a51);
		b = round2(b, c, d, a,  X[0], 20, 0xe9b6c7aa);
		a = round2(a, b, c, d,  X[5],  5, 0xd62f105d);
		d = round2(d, a, b, c, X[10],  9, 0x02441453);
		c = round2(c, d, a, b, X[15], 14, 0xd8a1e681);
		b = round2(b, c, d, a,  X[4], 20, 0xe7d3fbc8);
		a = round2(a, b, c, d,  X[9],  5, 0x21e1cde6);
		d = round2(d, a, b, c, X[14],  9, 0xc33707d6);
		c = round2(c, d, a, b,  X[3], 14, 0xf4d50d87);
		b = round2(b, c, d, a,  X[8], 20, 0x455a14ed);
		a = round2(a, b, c, d, X[13],  5, 0xa9e3e905);
		d = round2(d, a, b, c,  X[2],  9, 0xfcefa3f8);
		c = round2(c, d, a, b,  X[7], 14, 0x676f02d9);
		b = round2(b, c, d, a, X[12], 20, 0x8d2a4c8a);

		/* Round 3. */
		a = round3(a, b, c, d,  X[5],  4, 0xfffa3942);
		d = round3(d, a, b, c,  X[8], 11, 0x8771f681);
		c = round3(c, d, a, b, X[11], 16, 0x6d9d6122);
		b = round3(b, c, d, a, X[14], 23, 0xfde5380c);
		a = round3(a, b, c, d,  X[1],  4, 0xa4beea44);
		d = round3(d, a, b, c,  X[4], 11, 0x4bdecfa9);
		c = round3(c, d, a, b,  X[7], 16, 0xf6bb4b60);
		b = round3(b, c, d, a, X[10], 23, 0xbebfbc70);
		a = round3(a, b, c, d, X[13],  4, 0x289b7ec6);
		d = round3(d, a, b, c,  X[0], 11, 0xeaa127fa);
		c = round3(c, d, a, b,  X[3], 16, 0xd4ef3085);
		b = round3(b, c, d, a,  X[6], 23, 0x04881d05);
		a = round3(a, b, c, d,  X[9],  4, 0xd9d4d039);
		d = round3(d, a, b, c, X[12], 11, 0xe6db99e5);
		c = round3(c, d, a, b, X[15], 16, 0x1fa27cf8);
		b = round3(b, c, d, a,  X[2], 23, 0xc4ac5665);
		
		/* Round 4. */
		a = round4(a, b, c, d,  X[0],  6, 0xf4292244);
		d = round4(d, a, b, c,  X[7], 10, 0x432aff97);
		c = round4(c, d, a, b, X[14], 15, 0xab9423a7);
		b = round4(b, c, d, a,  X[5], 21, 0xfc93a039);
		a = round4(a, b, c, d, X[12],  6, 0x655b59c3);
		d = round4(d, a, b, c,  X[3], 10, 0x8f0ccc92);
		c = round4(c, d, a, b, X[10], 15, 0xffeff47d);
		b = round4(b, c, d, a,  X[1], 21, 0x85845dd1);
		a = round4(a, b, c, d,  X[8],  6, 0x6fa87e4f);
		d = round4(d, a, b, c, X[15], 10, 0xfe2ce6e0);
		c = round4(c, d, a, b,  X[6], 15, 0xa3014314);
		b = round4(b, c, d, a, X[13], 21, 0x4e0811a1);
		a = round4(a, b, c, d,  X[4],  6, 0xf7537e82);
		d = round4(d, a, b, c, X[11], 10, 0xbd3af235);
		c = round4(c, d, a, b,  X[2], 15, 0x2ad7d2bb);
		b = round4(b, c, d, a,  X[9], 21, 0xeb86d391);
		
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
