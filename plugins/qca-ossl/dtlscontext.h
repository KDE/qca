/*
Copyright (C) 2007 Justin Karneges <justin@affinix.com>
Copyright (C) 2020 Sergey Ilinykh <rion4ik@gmail.com>

  Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#pragma once

#include "basetlscontext.h"

#include <QQueue>

using namespace QCA;
namespace opensslQCAPlugin {

class OsslDTLSContext : public BaseOsslTLSContext
{
    Q_OBJECT
public:
    QQueue<QByteArray> sendQueue;
    QQueue<QByteArray> recvQueue;

    QQueue<QByteArray> result_to_net;
    QQueue<QByteArray> result_plain;

    int mtuSize = 1200;

    OsslDTLSContext(Provider *p);

    void reset() override;
    void start() override;
    void update(const QByteArray &from_net, const QByteArray &from_app) override;
    void setMTU(int size) override;
    BIO *makeWriteBIO() override;

    bool       priv_startClient();
    bool       priv_startServer();
    Result     priv_handshake(const QByteArray &from_net);
    Result     priv_shutdown(const QByteArray &from_net);
    bool       priv_encode(const QByteArray &plain, int *enc);
    bool       priv_decode(const QByteArray &from_net, QQueue<QByteArray> &plain);
    QByteArray to_net() override;
    QByteArray to_app() override;
};

}
