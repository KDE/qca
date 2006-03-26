/*
 * qca_support.h - Qt Cryptographic Architecture
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

/**
   \file qca_support.h

   Header file for "support" classes used in %QCA

   The classes in this header do not have any cryptographic
   content - they are used in %QCA, and are included for convenience. 

   \note You should not use this header directly from an
   application. You should just use <tt> \#include \<QtCrypto>
   </tt> instead.
*/

#ifndef QCA_SUPPORT_H
#define QCA_SUPPORT_H

#include <QString>
#include <QObject>
#include "qca_export.h"

namespace QCA
{
	class QCA_EXPORT Synchronizer : public QObject
	{
		Q_OBJECT
	public:
		Synchronizer(QObject *parent);
		~Synchronizer();

		bool waitForCondition(int msecs = -1);
		void conditionMet();

	private:
		class Private;
		Private *d;
	};

	class QCA_EXPORT DirWatch : public QObject
	{
		Q_OBJECT
	public:
		DirWatch(const QString &dir = QString(), QObject *parent = 0);
		~DirWatch();

		QString dirName() const;
		void setDirName(const QString &dir);

		// DirWatch still works even if this returns false,
		// but it will be inefficient
		static bool platformSupported();

	signals:
		void changed();

	private:
		class Private;
		friend class Private;
		Private *d;
	};

	class QCA_EXPORT FileWatch : public QObject
	{
		Q_OBJECT
	public:
		FileWatch(const QString &file = QString(), QObject *parent = 0);
		~FileWatch();

		QString fileName() const;
		void setFileName(const QString &file);

	signals:
		void changed();

	private:
		class Private;
		friend class Private;
		Private *d;
	};
}

#endif
