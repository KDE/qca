/*
 * qca_textfilter.h - Qt Cryptographic Architecture
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

#ifndef QCA_TEXTFILTER_H
#define QCA_TEXTFILTER_H

#include "qca_core.h"

namespace QCA
{
	class QCA_EXPORT TextFilter : public Filter
	{
	public:
		TextFilter(Direction dir);

		void setup(Direction dir);
		QSecureArray encode(const QSecureArray &a);
		QSecureArray decode(const QSecureArray &a);
		QString arrayToString(const QSecureArray &a);
		QSecureArray stringToArray(const QString &s);
		QString encodeString(const QString &s);
		QString decodeString(const QString &s);

	protected:
		Direction _dir;
	};

	class QCA_EXPORT Hex : public TextFilter
	{
	public:
		Hex(Direction dir = Encode);

		virtual void clear();
		virtual QSecureArray update(const QSecureArray &a);
		virtual QSecureArray final();
		virtual bool ok() const;

	private:
		uchar val;
		bool partial;
		bool _ok;
	};

	class QCA_EXPORT Base64 : public TextFilter
	{
	public:
		Base64(Direction dir = Encode);

		virtual void clear();
		virtual QSecureArray update(const QSecureArray &a);
		virtual QSecureArray final();
		virtual bool ok() const;

	private:
		QSecureArray partial;
		bool _ok;
	};
}

#endif
