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

#include "gpgop.h"
#include "qcaprovider.h"
#include "ringwatch.h"

namespace gpgQCAPlugin {

class MyPGPKeyContext : public QCA::PGPKeyContext
{
    Q_OBJECT
public:
    QCA::PGPKeyContextProps _props;

    // keys loaded externally (not from the keyring) need to have these
    //   values cached, since we can't extract them later
    QByteArray cacheExportBinary;
    QString    cacheExportAscii;

    MyPGPKeyContext(QCA::Provider *p);

    // reimplemented Provider::Context
    QCA::Provider::Context *clone() const override;

    // reimplemented PGPKeyContext
    const QCA::PGPKeyContextProps *props() const override;

    QByteArray         toBinary() const override;
    QCA::ConvertResult fromBinary(const QByteArray &a) override;

    QString            toAscii() const override;
    QCA::ConvertResult fromAscii(const QString &s) override;

    void        set(const GpgOp::Key &i, bool isSecret, bool inKeyring, bool isTrusted);
    static void cleanup_temp_keyring(const QString &name);
};

} // end namespace gpgQCAPlugin
