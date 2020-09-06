/*
 * qca_safeobj.h - Qt Cryptographic Architecture
 * Copyright (C) 2008  Justin Karneges <justin@affinix.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301  USA
 *
 */

#ifndef QCA_SAFEOBJ_H
#define QCA_SAFEOBJ_H

// NOTE: this API is private to QCA

#include <QSocketNotifier>
#include <cstdio>

namespace QCA {

class SafeSocketNotifier : public QObject
{
    Q_OBJECT
public:
    SafeSocketNotifier(int socket, QSocketNotifier::Type type, QObject *parent = nullptr);

    ~SafeSocketNotifier() override;

    bool isEnabled() const
    {
        return sn->isEnabled();
    }
    int socket() const
    {
        return sn->socket();
    }
    QSocketNotifier::Type type() const
    {
        return sn->type();
    }

public Q_SLOTS:
    void setEnabled(bool enable)
    {
        sn->setEnabled(enable);
    }

Q_SIGNALS:
    void activated(int socket);

private:
    QSocketNotifier *sn;
};

}

#endif
