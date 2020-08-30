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

#include "dtlscontext.h"

#include <openssl/err.h>

namespace opensslQCAPlugin {

static int createDTLSBio(BIO *bio)
{
    BIO_set_init(bio, 1);
    BIO_set_data(bio, NULL);
    BIO_set_shutdown(bio, 0);
    return 1;
}

static int freeDTLSBio(BIO *bio)
{
    if (bio == NULL) {
        return 0;
    }
    BIO_set_data(bio, NULL);
    return 1;
}

static int writeDTLSBio(BIO *bio, const char *in, int inl)
{
    QCA_logTextMessage(QStringLiteral("dtls: writeDTLSBio: %1 %2").arg(QString::number(quintptr(in), 16)).arg(inl),
                       Logger::Debug);
    if (inl <= 0) {
        QCA_logTextMessage(QStringLiteral("dtls: writeDTLSBio: negative or zero data size: %1").arg(inl),
                           Logger::Error);
        return inl;
    }
    auto dtls = reinterpret_cast<OsslDTLSContext *>(BIO_get_data(bio));
    if (dtls == NULL) {
        QCA_logTextMessage(QStringLiteral("dtls: writeDTLSBio: invalid bio w/o DTLSContext"), Logger::Error);
        return -1;
    }

    if (inl > 1500) {
        QCA_logTextMessage(
            QStringLiteral("The DTLS stack is trying to send a packet of %1 bytes, this may be larger than the "
                           "MTU and get dropped!")
                .arg(inl),
            Logger::Warning);
    }
    dtls->result_to_net.enqueue(QByteArray(in, inl));
    return inl;
}

static long ctrlDTLSBio(BIO *bio, int cmd, [[maybe_unused]] long num, [[maybe_unused]] void *ptr)
{
    auto dtls = reinterpret_cast<OsslDTLSContext *>(BIO_get_data(bio));
    if (dtls == NULL) {
        QCA_logTextMessage(QStringLiteral("dtls: ctrlDTLSBio failed to get private data"), Logger::Error);
        return 0L;
    }
    switch (cmd) {
    case BIO_CTRL_FLUSH:
        /* The OpenSSL library needs this */
        return 1;
    case BIO_CTRL_DGRAM_QUERY_MTU:
        QCA_logTextMessage(QStringLiteral("dtls: ctrlDTLSBio force MTU: %1").arg(dtls->mtuSize), Logger::Information);
        return dtls->mtuSize; // this is already w/o overhead, so return 0 below
    case BIO_CTRL_DGRAM_GET_MTU_OVERHEAD:
        return 0L;
    case BIO_CTRL_WPENDING:
    case BIO_CTRL_PENDING:
    case BIO_CTRL_PUSH: // OpenSSL ignores those for some BIOs too (e.g BIO_s_mem)
    case BIO_CTRL_POP:  // OpenSSL ignores those for some BIOs too (e.g BIO_s_mem)
        return 0L;
    default:
        QCA_logTextMessage(QStringLiteral("dtls: ctrlDTLSBio cmd: %1").arg(cmd), Logger::Debug);
    }
    return 0L;
}

OsslDTLSContext::OsslDTLSContext(Provider *p) : BaseOsslTLSContext(p, QStringLiteral("dtls")) { }

void OsslDTLSContext::reset()
{
    BaseOsslTLSContext::reset();
    sendQueue.clear();
    recvQueue.clear();
}

void OsslDTLSContext::start()
{
    bool ok;
    if (serv)
        ok = priv_startServer();
    else
        ok = priv_startClient();
    result_result = ok ? Success : Error;

    doResultsReady();
}

void OsslDTLSContext::update(const QByteArray &from_net, const QByteArray &from_app)
{
    if (mode == Active) {
        bool ok = true;
        if (!from_app.isEmpty())
            ok = priv_encode(from_app, &result_encoded);
        if (ok)
            ok = priv_decode(from_net, result_plain);
        result_result = ok ? Success : Error;
    } else if (mode == Closing)
        result_result = priv_shutdown(from_net);
    else
        result_result = priv_handshake(from_net);

    // printf("update (from_net=%d, to_net=%d, from_app=%d, to_app=%d)\n", from_net.size(), result_to_net.size(),
    // from_app.size(), result_plain.size());

    doResultsReady();
}

void OsslDTLSContext::setMTU(int size)
{
    if (size < 0)
        return;
    mtuSize = size;
}

BIO *OsslDTLSContext::makeWriteBIO()
{
    static BIO_METHOD *methods = nullptr;
    if (!methods) {
        methods = BIO_meth_new(BIO_TYPE_BIO, "qca writer");
        if (!methods) {
            return nullptr;
        }
        BIO_meth_set_write(methods, writeDTLSBio);
        BIO_meth_set_ctrl(methods, ctrlDTLSBio);
        BIO_meth_set_create(methods, createDTLSBio);
        BIO_meth_set_destroy(methods, freeDTLSBio);
    }
    BIO *bio = BIO_new(methods);
    if (bio == NULL) {
        return NULL;
    }
    BIO_set_data(bio, this);
    return bio;
}

bool OsslDTLSContext::priv_startClient()
{
    // serv = false;
    method = DTLS_client_method();
    if (!init())
        return false;
    mode = Connect;
    return true;
}

bool OsslDTLSContext::priv_startServer()
{
    // serv = true;
    method = DTLS_server_method();
    if (!init())
        return false;
    mode = Accept;
    return true;
}

TLSContext::Result OsslDTLSContext::priv_handshake(const QByteArray &from_net)
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

    if (mode == Active)
        return Success;
    else
        return Continue;
}

TLSContext::Result OsslDTLSContext::priv_shutdown(const QByteArray &from_net)
{
    if (!from_net.isEmpty())
        BIO_write(rbio, from_net.data(), from_net.size());

    int ret = doShutdown();
    if (ret == Bad) {
        reset();
        return Error;
    }

    if (ret == Good) {
        mode = Idle;
        return Success;
    } else {
        // mode = Closing;
        return Continue;
    }
}

bool OsslDTLSContext::priv_encode(const QByteArray &plain, int *enc)
{
    if (mode != Active)
        return false;

    if (plain.size())
        sendQueue.enqueue(plain);

    int encoded = 0;
    while (sendQueue.size() > 0) {
        auto const &head = sendQueue.head();
        int         ret  = SSL_write(ssl, head.data(), head.size());

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
            if (x == SSL_ERROR_WANT_WRITE) // SSL_ERROR_WANT_READ is likely an error with dtls
                m = Continue;
            else if (x == SSL_ERROR_ZERO_RETURN)
                m = Done;
            else
                m = Error;
        } else if (ret != head.size()) {
            m = Error;
        } else {
            sendQueue.dequeue();
            m = Good;
            encoded += ret;
        }

        if (m == Done) {
            sendQueue.clear();
            v_eof = true;
            return false;
        }
        if (m == Error) {
            sendQueue.clear();
            return false;
        }
    }

    *enc = encoded;
    return true;
}

bool OsslDTLSContext::priv_decode(const QByteArray &from_net, QQueue<QByteArray> &plain)
{
    if (mode != Active)
        return false;
    if (!from_net.isEmpty()) {
        int ret = BIO_write(rbio, from_net.data(), from_net.size());
        if (ret <= 0) {
            QCA_logTextMessage(QStringLiteral("dtls: BIO_write failed: %1").arg(ret), Logger::Warning);
        }
    }

    QByteArray a;
    if (!v_eof) {
        int pending = SSL_pending(ssl);
        a.resize(pending ? pending : 16384);
        int ret = SSL_read(ssl, a.data(), a.size());
        // printf("SSL_read = %d\n", ret);
        if (ret > 0) {
            if (ret != int(a.size()))
                a.resize(ret);
            // printf("SSL_read chunk: [%s]\n", qPrintable(arrayToHex(a)));
            recvQueue.enqueue(a);
        } else if (ret <= 0) {
            int x = SSL_get_error(ssl, ret);
            // printf("SSL_read error = %d\n", x);
            if (x == SSL_ERROR_ZERO_RETURN)
                v_eof = true;
            else if (!(x == SSL_ERROR_WANT_READ || x == SSL_ERROR_WANT_WRITE)) {
                QCA_logTextMessage(QStringLiteral("dtls: SSL_read failed: %1").arg(x), Logger::Error);
                return false;
            }
        }
    }

    plain = recvQueue;
    recvQueue.clear();
    return true;
}

QByteArray OsslDTLSContext::to_net()
{
    if (result_to_net.size())
        return result_to_net.dequeue();
    return QByteArray();
}

QByteArray OsslDTLSContext::to_app()
{
    if (result_plain.size())
        return result_plain.dequeue();
    return QByteArray();
}

}
