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

#include "mykeystorelist.h"
#include "myopenpgpcontext.h"
#include "mypgpkeycontext.h"
#include "qcaprovider.h"
#include <QtPlugin>

using namespace gpgQCAPlugin;

class gnupgProvider : public QCA::Provider
{
public:
    void init() override
    {
    }

    int qcaVersion() const override
    {
        return QCA_VERSION;
    }

    QString name() const override
    {
        return QStringLiteral("qca-gnupg");
    }

    QStringList features() const override
    {
        QStringList list;
        list += QStringLiteral("pgpkey");
        list += QStringLiteral("openpgp");
        list += QStringLiteral("keystorelist");
        return list;
    }

    Context *createContext(const QString &type) override
    {
        if (type == QLatin1String("pgpkey"))
            return new MyPGPKeyContext(this);
        else if (type == QLatin1String("openpgp"))
            return new MyOpenPGPContext(this);
        else if (type == QLatin1String("keystorelist"))
            return new MyKeyStoreList(this);
        else
            return nullptr;
    }
};

class gnupgPlugin : public QObject, public QCAPlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "com.affinix.qca.Plugin/1.0")
    Q_INTERFACES(QCAPlugin)
public:
    QCA::Provider *createProvider() override
    {
        return new gnupgProvider;
    }
};

#include "qca-gnupg.moc"
