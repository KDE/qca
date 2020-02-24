/*
 * Copyright (C) 2003-2005  Justin Karneges <justin@affinix.com>
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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 */

#include "lineconverter.h"

namespace gpgQCAPlugin {

void LineConverter::setup(LineConverter::Mode m)
{
	state = Normal;
	mode = m;
	prebytes = 0;
	list.clear();
}

QByteArray LineConverter::update(const QByteArray &buf)
{
	if(mode == Read)
	{
		// Convert buf to UNIX line ending style
		// If buf ends with '\r' set state to Partival

		QByteArray out;

		if(state == Normal)
		{
			out = buf;
		}
		else
		{
			out.resize(buf.size() + 1);
			out[0] = '\r';
			memcpy(out.data() + 1, buf.data(), buf.size());
		}

		int n = 0;
		while(true)
		{
			n = out.indexOf('\r', n);
			// not found
			if(n == -1)
			{
				break;
			}
			// found, not last character
			if(n < (buf.size() - 1))
			{
				// found windows line ending "\r\n"
				if(out[n + 1] == '\n')
				{
					// clip out the '\r'
					memmove(out.data() + n, out.data() + n + 1, out.size() - n - 1);
					out.resize(out.size() - 1);
				}
			}
			// found, last character
			else
			{
				state = Partial;
				break;
			}
			++n;
		}

		return out;
	}
	else
	{
		// On Windows use DOS line ending style.
		// On UNIX don't do any convertation. Return buf as is.
#ifdef Q_OS_WIN
		QByteArray out;
		int prev = 0;
		int at = 0;

		while(1)
		{
			int n = buf.indexOf('\n', at);
			if(n == -1)
				break;

			int chunksize = n - at;
			const int oldsize = out.size();
			out.resize(oldsize + chunksize + 2);
			memcpy(out.data() + oldsize, buf.data() + at, chunksize);
			memcpy(out.data() + oldsize + chunksize, "\r\n", 2);

			list.append(prebytes + n + 1 - prev);
			prebytes = 0;
			prev = n;

			at = n + 1;
		}
		if(at < buf.size())
		{
			const int chunksize = buf.size() - at;
			const int oldsize = out.size();
			out.resize(oldsize + chunksize);
			memcpy(out.data() + oldsize, buf.data() + at, chunksize);
		}

		prebytes += buf.size() - prev;
		return out;
#else
		return buf;
#endif
	}
}

QByteArray LineConverter::final()
{
	if(mode == Read)
	{
		QByteArray out;
		if(state == Partial)
		{
			out.resize(1);
			out[0] = '\n';
		}
		return out;
	}
	else
	{
		return QByteArray();
	}
}

QByteArray LineConverter::process(const QByteArray &buf)
{
	return update(buf) + final();
}

int LineConverter::writtenToActual(int bytes)
{
#ifdef Q_OS_WIN
	int n = 0;
	int counter = bytes;
	while(counter > 0)
	{
		if(!list.isEmpty() && bytes >= list.first())
		{
			++n;
			counter -= list.takeFirst();
		}
		else
		{
			if(list.isEmpty())
				prebytes -= counter;
			else
				list.first() -= counter;

			if(prebytes < 0)
			{
				bytes += prebytes;
				prebytes = 0;
			}

			break;
		}
	}
	return bytes - n;
#else
	return bytes;
#endif
}

} // end namespace gpgQCAPlugin
