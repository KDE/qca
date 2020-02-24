/*
 * Copyright (C) 2003-2008  Justin Karneges <justin@affinix.com>
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
 */

// since keyring files are often modified by creating a new copy and
//   overwriting the original file, this messes up Qt's file watching
//   capability since the original file goes away.  to work around this
//   problem, we'll watch the directories containing the keyring files
//   instead of watching the actual files themselves.
//
// FIXME: qca 2.0.1 FileWatch has this logic already, so we can probably
//   simplify this class.

#include "qca_safetimer.h"
#include "qca_support.h"
#include "ringwatch.h"
#include <QFileInfo>

using namespace QCA;

namespace gpgQCAPlugin
{

RingWatch::RingWatch(QObject *parent)
	: QObject(parent)
{
}

RingWatch::~RingWatch()
{
	clear();
}

void RingWatch::add(const QString &filePath)
{
	QFileInfo fi(filePath);
	// Try to avoid symbolic links
	QString path = fi.canonicalPath();
	if (path.isEmpty())
		path = fi.absolutePath();

	// watching this path already?
	DirWatch *dirWatch = nullptr;
	foreach(const DirItem &di, dirs)
	{
		if(di.dirWatch->dirName() == path)
		{
			dirWatch = di.dirWatch;
			break;
		}
	}

	// if not, make a watcher
	if(!dirWatch)
	{
		//printf("creating dirwatch for [%s]\n", qPrintable(path));

		DirItem di;
		di.dirWatch = new DirWatch(path, this);
		connect(di.dirWatch, &DirWatch::changed, this, &RingWatch::dirChanged);

		di.changeTimer = new SafeTimer(this);
		di.changeTimer->setSingleShot(true);
		connect(di.changeTimer, &SafeTimer::timeout, this, &RingWatch::handleChanged);

		dirWatch = di.dirWatch;
		dirs += di;
	}

	FileItem i;
	i.dirWatch = dirWatch;
	i.fileName = fi.fileName();
	i.exists = fi.exists();
	if(i.exists)
	{
		i.size = fi.size();
		i.lastModified = fi.lastModified();
	}
	files += i;

	//printf("watching [%s] in [%s]\n", qPrintable(fi.fileName()), qPrintable(i.dirWatch->dirName()));
}

void RingWatch::clear()
{
	files.clear();

	foreach(const DirItem &di, dirs)
	{
		delete di.changeTimer;
		delete di.dirWatch;
	}

	dirs.clear();
}

void RingWatch::dirChanged()
{
	DirWatch *dirWatch = (DirWatch *)sender();

	int at = -1;
	for(int n = 0; n < dirs.count(); ++n)
	{
		if(dirs[n].dirWatch == dirWatch)
		{
			at = n;
			break;
		}
	}
	if(at == -1)
		return;

	// we get a ton of change notifications for the dir when
	//   something happens..   let's collect them and only
	//   report after 100ms

	if(!dirs[at].changeTimer->isActive())
		dirs[at].changeTimer->start(100);
}

void RingWatch::handleChanged()
{
	SafeTimer *t = (SafeTimer *)sender();

	int at = -1;
	for(int n = 0; n < dirs.count(); ++n)
	{
		if(dirs[n].changeTimer == t)
		{
			at = n;
			break;
		}
	}
	if(at == -1)
		return;

	DirWatch *dirWatch = dirs[at].dirWatch;
	const QString dir = dirWatch->dirName();

	// see which files changed
	QStringList changeList;
	for(int n = 0; n < files.count(); ++n)
	{
		FileItem &i = files[n];
		QString filePath = dir + QLatin1Char('/') + i.fileName;
		QFileInfo fi(filePath);

		// if the file didn't exist, and still doesn't, skip
		if(!i.exists && !fi.exists())
			continue;

		// size/lastModified should only get checked here if
		//   the file existed and still exists
		if(fi.exists() != i.exists || fi.size() != i.size || fi.lastModified() != i.lastModified)
		{
			changeList += filePath;

			i.exists = fi.exists();
			if(i.exists)
			{
				i.size = fi.size();
				i.lastModified = fi.lastModified();
			}
		}
	}

	foreach(const QString &s, changeList)
	emit changed(s);
}

} // end namespace gpgQCAPlugin
