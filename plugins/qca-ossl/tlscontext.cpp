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

#include "tlscontext.h"

#include <openssl/err.h>

namespace opensslQCAPlugin {

OsslTLSContext::OsslTLSContext(Provider *p) : BaseOsslTLSContext(p, QStringLiteral("tls")) { }

void OsslTLSContext::reset()
{
    BaseOsslTLSContext::reset();
    sendQueue.resize(0);
    recvQueue.resize(0);
}

void OsslTLSContext::start()
{
    bool ok;
    if (serv)
        ok = priv_startServer();
    else
        ok = priv_startClient();
    result_result = ok ? Success : Error;

    doResultsReady();
}

void OsslTLSContext::update(const QByteArray &from_net, const QByteArray &from_app)
{
    if (mode == Active) {
        bool ok = true;
        if (!from_app.isEmpty())
            ok = priv_encode(from_app, &result_to_net, &result_encoded);
        if (ok)
            ok = priv_decode(from_net, &result_plain, &result_to_net);
        result_result = ok ? Success : Error;
    } else if (mode == Closing)
        result_result = priv_shutdown(from_net, &result_to_net);
    else
        result_result = priv_handshake(from_net, &result_to_net);

    // printf("update (from_net=%d, to_net=%d, from_app=%d, to_app=%d)\n", from_net.size(), result_to_net.size(),
    // from_app.size(), result_plain.size());

    doResultsReady();
}

bool OsslTLSContext::priv_startClient()
{
    // serv = false;
    method = TLS_client_method();
    if (!init())
        return false;
    mode = Connect;
    return true;
}

bool OsslTLSContext::priv_startServer()
{
    // serv = true;
    method = TLS_server_method();
    if (!init())
        return false;
    mode = Accept;
    return true;
}

TLSContext::Result OsslTLSContext::priv_handshake(const QByteArray &from_net, QByteArray *to_net)
{
    if (!from_net.isEmpty())
        BIO_write(rbio, from_net.data(), from_net.size());

    if (mode == Connect) {
        int ret = doConnect();
        if (ret == Good) {
            mode = Handshake;
        } else if (ret == Bad) {
            reset();
            return Error;
        }
    }

    if (mode == Accept) {
        int ret = doAccept();
        if (ret == Good) {
            getCert();
            mode = Active;
        } else if (ret == Bad) {
            reset();
            return Error;
        }
    }

    if (mode == Handshake) {
        int ret = doHandshake();
        if (ret == Good) {
            getCert();
            mode = Active;
        } else if (ret == Bad) {
            reset();
            return Error;
        }
    }

    // process outgoing
    *to_net = readOutgoing();

    if (mode == Active)
        return Success;
    else
        return Continue;
}

TLSContext::Result OsslTLSContext::priv_shutdown(const QByteArray &from_net, QByteArray *to_net)
{
    if (!from_net.isEmpty())
        BIO_write(rbio, from_net.data(), from_net.size());

    int ret = doShutdown();
    if (ret == Bad) {
        reset();
        return Error;
    }

    *to_net = readOutgoing();

    if (ret == Good) {
        mode = Idle;
        return Success;
    } else {
        // mode = Closing;
        return Continue;
    }
}

bool OsslTLSContext::priv_encode(const QByteArray &plain, QByteArray *to_net, int *enc)
{
    if (mode != Active)
        return false;
    sendQueue.append(plain);

    int encoded = 0;
    if (sendQueue.size() > 0) {
        int ret = SSL_write(ssl, sendQueue.data(), sendQueue.size());

        enum
        {
            Good,
            Continue,
            Done,
            Error
        };
        int m;
        if (ret <= 0) {
            int x = SSL_get_error(ssl, ret);
            if (x == SSL_ERROR_WANT_READ || x == SSL_ERROR_WANT_WRITE)
                m = Continue;
            else if (x == SSL_ERROR_ZERO_RETURN)
                m = Done;
            else
                m = Error;
        } else {
            m             = Good;
            encoded       = ret;
            int   newsize = sendQueue.size() - encoded;
            char *r       = sendQueue.data();
            memmove(r, r + encoded, newsize);
            sendQueue.resize(newsize);
        }

        if (m == Done) {
            sendQueue.resize(0);
            v_eof = true;
            return false;
        }
        if (m == Error) {
            sendQueue.resize(0);
            return false;
        }
    }

    *to_net += readOutgoing();
    *enc = encoded;
    return true;
}

bool OsslTLSContext::priv_decode(const QByteArray &from_net, QByteArray *plain, QByteArray *to_net)
{
    if (mode != Active)
        return false;
    if (!from_net.isEmpty())
        BIO_write(rbio, from_net.data(), from_net.size());

    QByteArray a;
    while (!v_eof) {
        a.resize(8192);
        int ret = SSL_read(ssl, a.data(), a.size());
        // printf("SSL_read = %d\n", ret);
        if (ret > 0) {
            if (ret != (int)a.size())
                a.resize(ret);
            // printf("SSL_read chunk: [%s]\n", qPrintable(arrayToHex(a)));
            recvQueue.append(a);
        } else if (ret <= 0) {
            ERR_print_errors_cb(&BaseOsslTLSContext::ssl_error_callback, this);
            int x = SSL_get_error(ssl, ret);
            // printf("SSL_read error = %d\n", x);
            if (x == SSL_ERROR_WANT_READ || x == SSL_ERROR_WANT_WRITE)
                break;
            else if (x == SSL_ERROR_ZERO_RETURN)
                v_eof = true;
            else
                return false;
        }
    }

    *plain = recvQueue;
    recvQueue.resize(0);

    // could be outgoing data also
    *to_net += readOutgoing();
    return true;
}

QByteArray OsslTLSContext::to_net()
{
    const QByteArray a = result_to_net;
    result_to_net.clear();
    return a;
}

QByteArray OsslTLSContext::to_app()
{
    const QByteArray a = result_plain;
    result_plain.clear();
    return a;
}

}
