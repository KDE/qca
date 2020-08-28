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

#include "qcaprovider.h"

#include <openssl/x509v3.h>

using namespace QCA;
namespace opensslQCAPlugin {

class X509Item
{
public:
    X509 *    cert;
    X509_REQ *req;
    X509_CRL *crl;

    enum Type
    {
        TypeCert,
        TypeReq,
        TypeCRL
    };

    X509Item();
    X509Item(const X509Item &from);
    ~X509Item();

    X509Item &operator=(const X509Item &from);

    void          reset();
    bool          isNull() const;
    QByteArray    toDER() const;
    QString       toPEM() const;
    ConvertResult fromDER(const QByteArray &in, Type t);
    ConvertResult fromPEM(const QString &s, Type t);
};

//----------------------------------------------------------------------------
// MyCRLContext
//----------------------------------------------------------------------------
class MyCRLContext : public CRLContext
{
    Q_OBJECT
public:
    X509Item        item;
    CRLContextProps _props;

    MyCRLContext(Provider *p);
    MyCRLContext(const MyCRLContext &from);

    Provider::Context *clone() const override;

    QByteArray             toDER() const override;
    QString                toPEM() const override;
    ConvertResult          fromDER(const QByteArray &a) override;
    ConvertResult          fromPEM(const QString &s) override;
    void                   fromX509(X509_CRL *x);
    const CRLContextProps *props() const override;
    bool                   compare(const CRLContext *other) const override;
    void                   make_props();
};

// TODO: support read/write of multiple info values with the same name
class MyCertContext : public QCA::CertContext
{
    Q_OBJECT
public:
    X509Item         item;
    CertContextProps _props;

    MyCertContext(Provider *p);
    MyCertContext(const MyCertContext &from);
    ~MyCertContext() override;

    Provider::Context *clone() const override;

    QByteArray    toDER() const override;
    QString       toPEM() const override;
    ConvertResult fromDER(const QByteArray &a) override;
    ConvertResult fromPEM(const QString &s) override;
    void          fromX509(X509 *x);
    bool          createSelfSigned(const CertificateOptions &opts, const PKeyContext &priv) override;

    const CertContextProps *props() const override;
    bool                    compare(const CertContext *other) const override;

    // does a new
    PKeyContext *subjectPublicKey() const override;
    bool         isIssuerOf(const CertContext *other) const override;
    // implemented later because it depends on MyCRLContext
    Validity validate(const QList<CertContext *> &trusted, const QList<CertContext *> &untrusted,
                      const QList<CRLContext *> &crls, UsageMode u, ValidateFlags vf) const override;
    Validity validate_chain(const QList<CertContext *> &chain, const QList<CertContext *> &trusted,
                            const QList<CRLContext *> &crls, UsageMode u, ValidateFlags vf) const override;
    void     make_props();
};

// Thanks to Pascal Patry
class MyPKeyContext;
class MyCAContext : public CAContext
{
    Q_OBJECT
public:
    X509Item       caCert;
    MyPKeyContext *privateKey;

    MyCAContext(Provider *p);
    MyCAContext(const MyCAContext &from);
    ~MyCAContext() override;

    CertContext *      certificate() const override;
    CertContext *      createCertificate(const PKeyContext &pub, const CertificateOptions &opts) const override;
    CRLContext *       createCRL(const QDateTime &nextUpdate) const override;
    void               setup(const CertContext &cert, const PKeyContext &priv) override;
    CertContext *      signRequest(const CSRContext &req, const QDateTime &notValidAfter) const override;
    CRLContext *       updateCRL(const CRLContext &crl, const QList<CRLEntry> &entries,
                                 const QDateTime &nextUpdate) const override;
    Provider::Context *clone() const override;
};

class MyCSRContext : public CSRContext
{
    Q_OBJECT
public:
    X509Item         item;
    CertContextProps _props;

    MyCSRContext(Provider *p);
    MyCSRContext(const MyCSRContext &from);

    Provider::Context *     clone() const override;
    QByteArray              toDER() const override;
    QString                 toPEM() const override;
    ConvertResult           fromDER(const QByteArray &a) override;
    ConvertResult           fromPEM(const QString &s) override;
    bool                    canUseFormat(CertificateRequestFormat f) const override;
    bool                    createRequest(const CertificateOptions &opts, const PKeyContext &priv) override;
    const CertContextProps *props() const override;
    bool                    compare(const CSRContext *other) const override;
    PKeyContext *           subjectPublicKey() const override;
    QString                 toSPKAC() const override;
    ConvertResult           fromSPKAC(const QString &s) override;
    void                    make_props();
};

}
