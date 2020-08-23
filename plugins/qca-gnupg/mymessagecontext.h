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

namespace gpgQCAPlugin {

class MyOpenPGPContext;

class MyMessageContext : public QCA::MessageContext
{
    Q_OBJECT
public:
    MyOpenPGPContext *sms;

    QString                        signerId;
    QStringList                    recipIds;
    QCA::MessageContext::Operation op;
    QCA::SecureMessage::SignMode   signMode;
    QCA::SecureMessage::Format     format;
    QByteArray                     in, out, sig;
    int                            wrote;
    bool                           ok, wasSigned;
    GpgOp::Error                   op_err;
    QCA::SecureMessageSignature    signer;
    GpgOp                          gpg;
    bool                           _finished;
    QString                        dtext;

    QCA::PasswordAsker asker;
    QCA::TokenAsker    tokenAsker;

    MyMessageContext(MyOpenPGPContext *_sms, QCA::Provider *p);

    // reimplemented Provider::Context
    QCA::Provider::Context *clone() const override;

    // reimplemented MessageContext
    bool                     canSignMultiple() const override;
    QCA::SecureMessage::Type type() const override;
    void                     reset() override;
    void                     setupEncrypt(const QCA::SecureMessageKeyList &keys) override;
    void       setupSign(const QCA::SecureMessageKeyList &keys, QCA::SecureMessage::SignMode m, bool, bool) override;
    void       setupVerify(const QByteArray &detachedSig) override;
    void       start(QCA::SecureMessage::Format f, QCA::MessageContext::Operation op) override;
    void       update(const QByteArray &in) override;
    QByteArray read() override;
    int        written() override;
    void       end() override;
    bool       finished() const override;
    bool       waitForFinished(int msecs) override;
    bool       success() const override;
    QCA::SecureMessage::Error       errorCode() const override;
    QByteArray                      signature() const override;
    QString                         hashName() const override;
    QCA::SecureMessageSignatureList signers() const override;
    QString                         diagnosticText() const override;

    void seterror();
    void complete();

private Q_SLOTS:
    void gpg_readyRead();
    void gpg_bytesWritten(int bytes);
    void gpg_finished();
    void gpg_needPassphrase(const QString &in_keyId);
    void gpg_needCard();
    void gpg_readyReadDiagnosticText();
    void asker_responseReady();
    void tokenAsker_responseReady();
};

} // end namespace gpgQCAPlugin
