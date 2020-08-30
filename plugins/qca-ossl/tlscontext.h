/*
 * Copyright (C) 2004-2007  Justin Karneges <justin@affinix.com>
 * Copyright (C) 2004-2006  Brad Hards <bradh@frogmouth.net>
 * Copyright (C) 2013-2016  Ivan Romanov <drizt@land.ru>
 * Copyright (C) 2017       Fabian Vogt <fabian@ritter-vogt.de>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 *
 */

#pragma once

#include "basetlscontext.h"

using namespace QCA;
namespace opensslQCAPlugin {

class OsslTLSContext : public BaseOsslTLSContext
{
    Q_OBJECT
public:
    QByteArray sendQueue;
    QByteArray recvQueue;

    QByteArray result_to_net;
    QByteArray result_plain;

    OsslTLSContext(Provider *p);

    void       reset() override;
    void       start() override;
    void       update(const QByteArray &from_net, const QByteArray &from_app) override;
    bool       priv_startClient();
    bool       priv_startServer();
    Result     priv_handshake(const QByteArray &from_net, QByteArray *to_net);
    Result     priv_shutdown(const QByteArray &from_net, QByteArray *to_net);
    bool       priv_encode(const QByteArray &plain, QByteArray *to_net, int *enc);
    bool       priv_decode(const QByteArray &from_net, QByteArray *plain, QByteArray *to_net);
    QByteArray to_net() override;
    QByteArray to_app() override;
};

}
