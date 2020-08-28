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

#include "basetlscontext.h"

#include "certcontext.h"
#include "pkeycontext.h"
#include "utils.h"

#include <QDebug>

namespace opensslQCAPlugin {
// TODO: test to ensure there is no cert-test lag
static bool ssl_init = false;

BaseOsslTLSContext::BaseOsslTLSContext(Provider *p) : TLSContext(p, QStringLiteral("tls"))
{
    if (!ssl_init) {
        SSL_library_init();
        SSL_load_error_strings();
        ssl_init = true;
    }

    ssl     = nullptr;
    context = nullptr;
    reset();
}

BaseOsslTLSContext::~BaseOsslTLSContext() { reset(); }

Provider::Context *BaseOsslTLSContext::clone() const { return nullptr; }

bool BaseOsslTLSContext::canCompress() const
{
    // TODO
    return false;
}

bool BaseOsslTLSContext::canSetHostName() const
{
    // TODO
    return false;
}

int BaseOsslTLSContext::maxSSF() const
{
    // TODO
    return 256;
}

void BaseOsslTLSContext::setConstraints(int minSSF, int maxSSF)
{
    // TODO
    Q_UNUSED(minSSF);
    Q_UNUSED(maxSSF);
}

void BaseOsslTLSContext::setConstraints(const QStringList &cipherSuiteList)
{
    // TODO
    Q_UNUSED(cipherSuiteList);
}

void BaseOsslTLSContext::setup(bool serverMode, const QString &hostName, bool compress)
{
    serv = serverMode;
    if (false == serverMode) {
        // client
        targetHostName = hostName;
    }
    Q_UNUSED(compress); // TODO
}

void BaseOsslTLSContext::setTrustedCertificates(const CertificateCollection &_trusted) { trusted = _trusted; }

void BaseOsslTLSContext::setIssuerList(const QList<CertificateInfoOrdered> &issuerList)
{
    Q_UNUSED(issuerList); // TODO
}

void BaseOsslTLSContext::setCertificate(const CertificateChain &_cert, const PrivateKey &_key)
{
    if (!_cert.isEmpty())
        cert = _cert.primary(); // TODO: take the whole chain
    key = _key;
}

void BaseOsslTLSContext::setSessionId(const TLSSessionContext &id)
{
    // TODO
    Q_UNUSED(id);
}

bool BaseOsslTLSContext::clientHelloReceived() const
{
    // TODO
    return false;
}

bool BaseOsslTLSContext::serverHelloReceived() const
{
    // TODO
    return false;
}

QString BaseOsslTLSContext::hostName() const
{
    // TODO
    return QString();
}

bool BaseOsslTLSContext::certificateRequested() const
{
    // TODO
    return false;
}

QList<CertificateInfoOrdered> BaseOsslTLSContext::issuerList() const
{
    // TODO
    return QList<CertificateInfoOrdered>();
}

bool BaseOsslTLSContext::waitForResultsReady(int msecs)
{
    // TODO: for now, all operations block anyway
    Q_UNUSED(msecs);
    return true;
}

TLSContext::Result BaseOsslTLSContext::result() const { return result_result; }

int BaseOsslTLSContext::encoded() const { return result_encoded; }

bool BaseOsslTLSContext::eof() const { return v_eof; }

Validity BaseOsslTLSContext::peerCertificateValidity() const { return vr; }

CertificateChain BaseOsslTLSContext::peerCertificateChain() const
{
    // TODO: support whole chain
    CertificateChain chain;
    chain.append(peercert);
    return chain;
}

void BaseOsslTLSContext::doResultsReady() { QMetaObject::invokeMethod(this, "resultsReady", Qt::QueuedConnection); }

int BaseOsslTLSContext::doConnect()
{
    int ret = SSL_connect(ssl);
    if (ret < 0) {
        int x = SSL_get_error(ssl, ret);
        if (x == SSL_ERROR_WANT_CONNECT || x == SSL_ERROR_WANT_READ || x == SSL_ERROR_WANT_WRITE)
            return TryAgain;
        else
            return Bad;
    } else if (ret == 0)
        return Bad;
    return Good;
}

int BaseOsslTLSContext::doAccept()
{
    int ret = SSL_accept(ssl);
    if (ret < 0) {
        int x = SSL_get_error(ssl, ret);
        if (x == SSL_ERROR_WANT_CONNECT || x == SSL_ERROR_WANT_READ || x == SSL_ERROR_WANT_WRITE)
            return TryAgain;
        else
            return Bad;
    } else if (ret == 0)
        return Bad;
    return Good;
}

int BaseOsslTLSContext::doHandshake()
{
    int ret = SSL_do_handshake(ssl);
    if (ret < 0) {
        int x = SSL_get_error(ssl, ret);
        if (x == SSL_ERROR_WANT_READ || x == SSL_ERROR_WANT_WRITE)
            return TryAgain;
        else
            return Bad;
    } else if (ret == 0)
        return Bad;
    return Good;
}

void BaseOsslTLSContext::shutdown() { mode = Closing; }

int BaseOsslTLSContext::doShutdown()
{
    int ret = SSL_shutdown(ssl);
    if (ret >= 1)
        return Good;
    else {
        if (ret == 0)
            return TryAgain;
        int x = SSL_get_error(ssl, ret);
        if (x == SSL_ERROR_WANT_READ || x == SSL_ERROR_WANT_WRITE)
            return TryAgain;
        return Bad;
    }
}

QByteArray BaseOsslTLSContext::unprocessed()
{
    QByteArray a;
    int        size = BIO_pending(rbio);
    if (size <= 0)
        return a;
    a.resize(size);

    int r = BIO_read(rbio, a.data(), size);
    if (r <= 0) {
        a.resize(0);
        return a;
    }
    if (r != size)
        a.resize(r);
    return a;
}

void BaseOsslTLSContext::reset()
{
    if (ssl) {
        SSL_free(ssl);
        ssl = nullptr;
    }
    if (context) {
        SSL_CTX_free(context);
        context = nullptr;
    }

    cert = Certificate();
    key  = PrivateKey();

    mode     = Idle;
    peercert = Certificate();
    vr       = ErrorValidityUnknown;
    v_eof    = false;
}

int BaseOsslTLSContext::ssl_verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    Q_UNUSED(preverify_ok);
    Q_UNUSED(x509_ctx);

    // don't terminate handshake in case of verification failure
    return 1;
}

int BaseOsslTLSContext::ssl_error_callback(const char *message, size_t len, void *user_data)
{
    Q_UNUSED(len)
    auto context = reinterpret_cast<BaseOsslTLSContext *>(user_data);
    qDebug() << "BaseOsslTLSContext:" << context << " " << message;
    return 1;
}

QStringList BaseOsslTLSContext::supportedCipherSuites(const TLS::Version &version) const
{
    OpenSSL_add_ssl_algorithms();
    SSL_CTX *ctx = nullptr;

    // most likely scenario first
    if ((version >= TLS::TLS_vMIN && version <= TLS::TLS_vMAX) || version == TLS::TLS_v1) {
        static struct
        {
            TLS::Version ver;
            int          ssl_ver;
        } limits[] = { { TLS::TLS_v1, TLS1_VERSION },     { TLS::TLS_v1_1, TLS1_1_VERSION },
                       { TLS::TLS_v1_2, TLS1_2_VERSION }, { TLS::TLS_v1_3, TLS1_3_VERSION },
                       { TLS::DTLS_v1, TLS1_1_VERSION },  { TLS::DTLS_v1_2, TLS1_2_VERSION },
                       { TLS::DTLS_v1_3, TLS1_3_VERSION } };
        for (size_t i = 0; i < sizeof(limits) / sizeof(limits[0]); i++) {
            if (limits[i].ver == version) {
                auto method = (limits[i].ver >= TLS::DTLS_v1 && limits[i].ver <= TLS::DTLS_vMAX) ? DTLS_client_method()
                                                                                                 : TLS_client_method();
                ctx = SSL_CTX_new(method);
                SSL_CTX_set_min_proto_version(ctx, limits[i].ssl_ver);
                SSL_CTX_set_max_proto_version(ctx, limits[i].ssl_ver);
                break;
            }
        }
    }
#ifndef OPENSSL_NO_SSL3_METHOD
    else if (version == TLS::SSL_v3) {
        // Here should be used TLS_client_method() but on Fedora
        // it doesn't return any SSL ciphers.
        ctx = SSL_CTX_new(SSLv3_client_method());
        SSL_CTX_set_min_proto_version(ctx, SSL3_VERSION);
        SSL_CTX_set_max_proto_version(ctx, SSL3_VERSION);
    }
#endif
    else {
        qWarning("Unexpected enum in cipherSuites");
        ctx = nullptr;
    }

    if (nullptr == ctx)
        return QStringList();

    SSL *ssl = SSL_new(ctx);
    if (nullptr == ssl) {
        SSL_CTX_free(ctx);
        return QStringList();
    }

    STACK_OF(SSL_CIPHER) *sk = SSL_get1_supported_ciphers(ssl);
    QStringList cipherList;
    for (int i = 0; i < sk_SSL_CIPHER_num(sk); ++i) {
        const SSL_CIPHER *thisCipher = sk_SSL_CIPHER_value(sk, i);
        cipherList += QString::fromLatin1(SSL_CIPHER_standard_name(thisCipher));
    }
    sk_SSL_CIPHER_free(sk);

    SSL_free(ssl);
    SSL_CTX_free(ctx);

    return cipherList;
}

TLSContext::SessionInfo BaseOsslTLSContext::sessionInfo() const
{
    SessionInfo sessInfo;

    SSL_SESSION *session  = SSL_get0_session(ssl);
    sessInfo.isCompressed = (0 != SSL_SESSION_get_compress_id(session));
    int ssl_version       = SSL_version(ssl);

    if (ssl_version == TLS1_3_VERSION)
        sessInfo.version = TLS::TLS_v1_3;
    else if (ssl_version == TLS1_2_VERSION)
        sessInfo.version = TLS::TLS_v1_2;
    else if (ssl_version == TLS1_1_VERSION)
        sessInfo.version = TLS::TLS_v1_1;
    else if (ssl_version == TLS1_VERSION)
        sessInfo.version = TLS::TLS_v1;
    else if (ssl_version == SSL3_VERSION)
        sessInfo.version = TLS::SSL_v3;
    else if (ssl_version == SSL2_VERSION)
        sessInfo.version = TLS::SSL_v2;
    else {
        qDebug("unexpected version response: %s", SSL_get_version(ssl));
        sessInfo.version = TLS::TLS_v1_2;
    }

    sessInfo.cipherSuite = QString::fromLatin1(SSL_CIPHER_standard_name(SSL_get_current_cipher(ssl)));

    sessInfo.cipherMaxBits = SSL_get_cipher_bits(ssl, &(sessInfo.cipherBits));

    sessInfo.id = nullptr; // TODO: session resuming

    return sessInfo;
}

bool BaseOsslTLSContext::init()
{
    context = SSL_CTX_new(method);
    if (!context)
        return false;

    // setup the cert store
    {
        X509_STORE *             store     = SSL_CTX_get_cert_store(context);
        const QList<Certificate> cert_list = trusted.certificates();
        const QList<CRL>         crl_list  = trusted.crls();
        int                      n;
        for (n = 0; n < cert_list.count(); ++n) {
            const MyCertContext *cc = static_cast<const MyCertContext *>(cert_list[n].context());
            X509 *               x  = cc->item.cert;
            // CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509);
            X509_STORE_add_cert(store, x);
        }
        for (n = 0; n < crl_list.count(); ++n) {
            const MyCRLContext *cc = static_cast<const MyCRLContext *>(crl_list[n].context());
            X509_CRL *          x  = cc->item.crl;
            // CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509_CRL);
            X509_STORE_add_crl(store, x);
        }
    }

    ssl = SSL_new(context);
    if (!ssl) {
        SSL_CTX_free(context);
        context = nullptr;
        return false;
    }
    SSL_set_ssl_method(ssl, method); // can this return error?

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
    if (targetHostName.isEmpty() == false) {
        // we have a target
        // this might fail, but we ignore that for now
        char *hostname = targetHostName.toLatin1().data();
        SSL_set_tlsext_host_name(ssl, hostname);
    }
#endif

    // setup the memory bio
    rbio = BIO_new(BIO_s_mem());
    wbio = BIO_new(BIO_s_mem());

    // this passes control of the bios to ssl.  we don't need to free them.
    SSL_set_bio(ssl, rbio, wbio);

    // FIXME: move this to after server hello
    // setup the cert to send
    if (!cert.isNull() && !key.isNull()) {
        PrivateKey nkey = key;

        const PKeyContext *tmp_kc = static_cast<const PKeyContext *>(nkey.context());

        if (!tmp_kc->sameProvider(this)) {
            // fprintf(stderr, "experimental: private key supplied by a different provider\n");

            // make a pkey pointing to the existing private key
            EVP_PKEY *pkey;
            pkey = EVP_PKEY_new();
            EVP_PKEY_assign_RSA(pkey, createFromExisting(nkey.toRSA()));

            // make a new private key object to hold it
            MyPKeyContext *pk = new MyPKeyContext(provider());
            PKeyBase *     k  = pk->pkeyToBase(pkey, true); // does an EVP_PKEY_free()
            pk->k             = k;
            nkey.change(pk);
        }

        const MyCertContext *cc = static_cast<const MyCertContext *>(cert.context());
        const MyPKeyContext *kc = static_cast<const MyPKeyContext *>(nkey.context());

        if (SSL_use_certificate(ssl, cc->item.cert) != 1) {
            SSL_free(ssl);
            SSL_CTX_free(context);
            return false;
        }
        if (SSL_use_PrivateKey(ssl, kc->get_pkey()) != 1) {
            SSL_free(ssl);
            SSL_CTX_free(context);
            return false;
        }
    }

    // request a certificate from the client, if in server mode
    if (serv) {
        SSL_set_verify(ssl, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, ssl_verify_callback);
    }

    return true;
}

void BaseOsslTLSContext::getCert()
{
    // verify the certificate
    Validity code           = ErrorValidityUnknown;
    STACK_OF(X509) *x_chain = SSL_get_peer_cert_chain(ssl);
    // X509 *x = SSL_get_peer_certificate(ssl);
    if (x_chain) {
        CertificateChain chain;

        if (serv) {
            X509 *         x  = SSL_get_peer_certificate(ssl);
            MyCertContext *cc = new MyCertContext(provider());
            cc->fromX509(x);
            Certificate cert;
            cert.change(cc);
            chain += cert;
        }

        for (int n = 0; n < sk_X509_num(x_chain); ++n) {
            X509 *         x  = sk_X509_value(x_chain, n);
            MyCertContext *cc = new MyCertContext(provider());
            cc->fromX509(x);
            Certificate cert;
            cert.change(cc);
            chain += cert;
        }

        peercert = chain.primary();

#ifdef Q_OS_MAC
        code = chain.validate(trusted);
#else
        int ret = SSL_get_verify_result(ssl);
        if (ret == X509_V_OK)
            code = ValidityGood;
        else
            code = convert_verify_error(ret);
#endif
    } else {
        peercert = Certificate();
    }
    vr = code;
}

QByteArray BaseOsslTLSContext::readOutgoing()
{
    QByteArray a;
    int        size = BIO_pending(wbio);
    if (size <= 0)
        return a;
    a.resize(size);

    int r = BIO_read(wbio, a.data(), size);
    if (r <= 0) {
        a.resize(0);
        return a;
    }
    if (r != size)
        a.resize(r);
    return a;
}

}
