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

#pragma once

#include <QDateTime>
#include <QList>
#include <QObject>

namespace QCA {

class SafeTimer;
class DirWatch;

}

namespace gpgQCAPlugin {

class RingWatch : public QObject
{
    Q_OBJECT
public:
    class DirItem
    {
    public:
        QCA::DirWatch * dirWatch;
        QCA::SafeTimer *changeTimer;
    };

    class FileItem
    {
    public:
        QCA::DirWatch *dirWatch;
        QString        fileName;
        bool           exists;
        qint64         size;
        QDateTime      lastModified;
    };

    QList<DirItem>  dirs;
    QList<FileItem> files;

    RingWatch(QObject *parent = nullptr);
    ~RingWatch() override;

    void add(const QString &filePath);
    void clear();

Q_SIGNALS:
    void changed(const QString &filePath);

private Q_SLOTS:
    void dirChanged();
    void handleChanged();
};

} // end namespace gpgQCAPlugin
