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

#include <openssl/ssl.h>
#include <qcaprovider.h>

using namespace QCA;

namespace opensslQCAPlugin {

class BaseOsslTLSContext : public TLSContext
{
    Q_OBJECT
public:
    enum
    {
        Good,
        TryAgain,
        Bad
    };
    enum
    {
        Idle,
        Connect,
        Accept,
        Handshake,
        Active,
        Closing
    };

    bool serv; // true if we are acting as a server
    int  mode;

    CertificateCollection trusted;
    Certificate           cert, peercert; // TODO: support cert chains
    PrivateKey            key;
    QString               targetHostName;

    Result result_result;
    int    result_encoded;

    SSL *             ssl;
    const SSL_METHOD *method;
    SSL_CTX *         context;
    BIO *             rbio, *wbio;
    Validity          vr;
    bool              v_eof;

    BaseOsslTLSContext(Provider *p, const QString &type);
    ~BaseOsslTLSContext() override;
    Provider::Context *clone() const override;

    void reset() override;

    // dummy verification function for SSL_set_verify()
    static int ssl_verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx);
    static int ssl_error_callback(const char *message, size_t len, void *user_data);

    QStringList                   supportedCipherSuites(const TLS::Version &version) const override;
    bool                          canCompress() const override;
    bool                          canSetHostName() const override;
    int                           maxSSF() const override;
    void                          setConstraints(int minSSF, int maxSSF) override;
    void                          setConstraints(const QStringList &cipherSuiteList) override;
    void                          setup(bool serverMode, const QString &hostName, bool compress) override;
    void                          setTrustedCertificates(const CertificateCollection &_trusted) override;
    void                          setIssuerList(const QList<CertificateInfoOrdered> &issuerList) override;
    void                          setCertificate(const CertificateChain &_cert, const PrivateKey &_key) override;
    void                          setSessionId(const TLSSessionContext &id) override;
    bool                          clientHelloReceived() const override;
    bool                          serverHelloReceived() const override;
    QString                       hostName() const override;
    bool                          certificateRequested() const override;
    QList<CertificateInfoOrdered> issuerList() const override;
    SessionInfo                   sessionInfo() const override;
    bool                          waitForResultsReady(int msecs) override;
    Result                        result() const override;
    int                           encoded() const override;
    bool                          eof() const override;
    Validity                      peerCertificateValidity() const override;
    CertificateChain              peerCertificateChain() const override;
    void                          shutdown() override;
    QByteArray                    unprocessed() override;

    virtual BIO *makeWriteBIO();
    virtual BIO *makeReadBIO();

    void       doResultsReady();
    bool       init();
    void       getCert();
    int        doConnect();
    int        doAccept();
    int        doHandshake();
    int        doShutdown();
    QByteArray readOutgoing();
};

}
