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

#include "mymessagecontext.h"
#include "mykeystorelist.h"
#include "mypgpkeycontext.h"
#include "utils.h"

using namespace QCA;

namespace gpgQCAPlugin {

MyMessageContext::MyMessageContext(MyOpenPGPContext *_sms, Provider *p)
    : MessageContext(p, QStringLiteral("pgpmsg"))
    , sms(_sms)
    , op(Sign)
    , signMode(SecureMessage::Detached)
    , format(SecureMessage::Ascii)
    , wrote(0)
    , ok(false)
    , wasSigned(false)
    , op_err(GpgOp::ErrorUnknown)
    , gpg(find_bin())
    , _finished(false)
{
    connect(&gpg, &GpgOp::readyRead, this, &MyMessageContext::gpg_readyRead);
    connect(&gpg, &GpgOp::bytesWritten, this, &MyMessageContext::gpg_bytesWritten);
    connect(&gpg, &GpgOp::finished, this, &MyMessageContext::gpg_finished);
    connect(&gpg, &GpgOp::needPassphrase, this, &MyMessageContext::gpg_needPassphrase);
    connect(&gpg, &GpgOp::needCard, this, &MyMessageContext::gpg_needCard);
    connect(&gpg, &GpgOp::readyReadDiagnosticText, this, &MyMessageContext::gpg_readyReadDiagnosticText);

    connect(&asker, &QCA::PasswordAsker::responseReady, this, &MyMessageContext::asker_responseReady);
    connect(&tokenAsker, &QCA::TokenAsker::responseReady, this, &MyMessageContext::tokenAsker_responseReady);
}

Provider::Context *MyMessageContext::clone() const
{
    return nullptr;
}

bool MyMessageContext::canSignMultiple() const
{
    return false;
}

SecureMessage::Type MyMessageContext::type() const
{
    return SecureMessage::OpenPGP;
}

void MyMessageContext::reset()
{
    wrote     = 0;
    ok        = false;
    wasSigned = false;
}

void MyMessageContext::setupEncrypt(const SecureMessageKeyList &keys)
{
    recipIds.clear();
    for (int n = 0; n < keys.count(); ++n)
        recipIds += keys[n].pgpPublicKey().keyId();
}

void MyMessageContext::setupSign(const SecureMessageKeyList &keys, SecureMessage::SignMode m, bool, bool)
{
    signerId = keys.first().pgpSecretKey().keyId();
    signMode = m;
}

void MyMessageContext::setupVerify(const QByteArray &detachedSig)
{
    sig = detachedSig;
}

void MyMessageContext::start(SecureMessage::Format f, Operation op)
{
    _finished = false;
    format    = f;
    this->op  = op;

    if (getProperty(QStringLiteral("pgp-always-trust")).toBool())
        gpg.setAlwaysTrust(true);

    if (format == SecureMessage::Ascii)
        gpg.setAsciiFormat(true);
    else
        gpg.setAsciiFormat(false);

    if (op == Encrypt) {
        gpg.doEncrypt(recipIds);
    } else if (op == Decrypt) {
        gpg.doDecrypt();
    } else if (op == Sign) {
        if (signMode == SecureMessage::Message) {
            gpg.doSign(signerId);
        } else if (signMode == SecureMessage::Clearsign) {
            gpg.doSignClearsign(signerId);
        } else // SecureMessage::Detached
        {
            gpg.doSignDetached(signerId);
        }
    } else if (op == Verify) {
        if (!sig.isEmpty())
            gpg.doVerifyDetached(sig);
        else
            gpg.doDecrypt();
    } else if (op == SignAndEncrypt) {
        gpg.doSignAndEncrypt(signerId, recipIds);
    }
}

void MyMessageContext::update(const QByteArray &in)
{
    gpg.write(in);
    // this->in.append(in);
}

QByteArray MyMessageContext::read()
{
    const QByteArray a = out;
    out.clear();
    return a;
}

int MyMessageContext::written()
{
    int x = wrote;
    wrote = 0;
    return x;
}

void MyMessageContext::end()
{
    gpg.endWrite();
}

void MyMessageContext::seterror()
{
    gpg.reset();
    _finished = true;
    ok        = false;
    op_err    = GpgOp::ErrorUnknown;
}

void MyMessageContext::complete()
{
    _finished = true;

    dtext = gpg.readDiagnosticText();

    ok = gpg.success();
    if (ok) {
        if (op == Sign && signMode == SecureMessage::Detached)
            sig = gpg.read();
        else
            out = gpg.read();
    }

    if (ok) {
        if (gpg.wasSigned()) {
            const QString             signerId = gpg.signerId();
            const QDateTime           ts       = gpg.timestamp();
            const GpgOp::VerifyResult vr       = gpg.verifyResult();

            SecureMessageSignature::IdentityResult ir;
            Validity                               v;
            if (vr == GpgOp::VerifyGood) {
                ir = SecureMessageSignature::Valid;
                v  = ValidityGood;
            } else if (vr == GpgOp::VerifyBad) {
                ir = SecureMessageSignature::InvalidSignature;
                v  = ValidityGood; // good key, bad sig
            } else                 // GpgOp::VerifyNoKey
            {
                ir = SecureMessageSignature::NoKey;
                v  = ErrorValidityUnknown;
            }

            SecureMessageKey key;
            PGPKey           pub = publicKeyFromId(signerId);
            if (pub.isNull()) {
                MyPGPKeyContext *kc = new MyPGPKeyContext(provider());
                kc->_props.keyId    = signerId;
                pub.change(kc);
            }
            key.setPGPPublicKey(pub);

            signer    = SecureMessageSignature(ir, v, key, ts);
            wasSigned = true;
        }
    } else
        op_err = gpg.errorCode();
}

bool MyMessageContext::finished() const
{
    return _finished;
}

bool MyMessageContext::waitForFinished(int msecs)
{
    // FIXME
    Q_UNUSED(msecs);
    MyKeyStoreList *keyStoreList = MyKeyStoreList::instance();

    while (true) {
        // TODO: handle token prompt events

        GpgOp::Event e = gpg.waitForEvent(-1);
        if (e.type == GpgOp::Event::NeedPassphrase) {
            // TODO

            QString keyId;
            PGPKey  sec = secretKeyFromId(e.keyId);
            if (!sec.isNull())
                keyId = sec.keyId();
            else
                keyId = e.keyId;
            QStringList out;
            out += escape_string(QStringLiteral("qca-gnupg-1"));
            out += escape_string(keyId);
            QString serialized = out.join(QStringLiteral(":"));

            KeyStoreEntry         kse;
            KeyStoreEntryContext *c = keyStoreList->entryPassive(serialized);
            if (c)
                kse.change(c);

            asker.ask(Event::StylePassphrase,
                      KeyStoreInfo(KeyStore::PGPKeyring, keyStoreList->storeId(0), keyStoreList->name(0)),
                      kse,
                      nullptr);
            asker.waitForResponse();

            if (!asker.accepted()) {
                seterror();
                return true;
            }

            gpg.submitPassphrase(asker.password());
        } else if (e.type == GpgOp::Event::NeedCard) {
            tokenAsker.ask(KeyStoreInfo(KeyStore::PGPKeyring, keyStoreList->storeId(0), keyStoreList->name(0)),
                           KeyStoreEntry(),
                           nullptr);

            if (!tokenAsker.accepted()) {
                seterror();
                return true;
            }

            gpg.cardOkay();
        } else if (e.type == GpgOp::Event::Finished)
            break;
    }

    complete();
    return true;
}

bool MyMessageContext::success() const
{
    return ok;
}

SecureMessage::Error MyMessageContext::errorCode() const
{
    SecureMessage::Error e = SecureMessage::ErrorUnknown;
    if (op_err == GpgOp::ErrorProcess)
        e = SecureMessage::ErrorUnknown;
    else if (op_err == GpgOp::ErrorPassphrase)
        e = SecureMessage::ErrorPassphrase;
    else if (op_err == GpgOp::ErrorFormat)
        e = SecureMessage::ErrorFormat;
    else if (op_err == GpgOp::ErrorSignerExpired)
        e = SecureMessage::ErrorSignerExpired;
    else if (op_err == GpgOp::ErrorSignerRevoked)
        e = SecureMessage::ErrorSignerRevoked;
    else if (op_err == GpgOp::ErrorSignatureExpired)
        e = SecureMessage::ErrorSignatureExpired;
    else if (op_err == GpgOp::ErrorEncryptExpired)
        e = SecureMessage::ErrorEncryptExpired;
    else if (op_err == GpgOp::ErrorEncryptRevoked)
        e = SecureMessage::ErrorEncryptRevoked;
    else if (op_err == GpgOp::ErrorEncryptUntrusted)
        e = SecureMessage::ErrorEncryptUntrusted;
    else if (op_err == GpgOp::ErrorEncryptInvalid)
        e = SecureMessage::ErrorEncryptInvalid;
    else if (op_err == GpgOp::ErrorDecryptNoKey)
        e = SecureMessage::ErrorUnknown;
    else if (op_err == GpgOp::ErrorUnknown)
        e = SecureMessage::ErrorUnknown;
    return e;
}

QByteArray MyMessageContext::signature() const
{
    return sig;
}

QString MyMessageContext::hashName() const
{
    // TODO
    return QStringLiteral("sha1");
}

SecureMessageSignatureList MyMessageContext::signers() const
{
    SecureMessageSignatureList list;
    if (ok && wasSigned)
        list += signer;
    return list;
}

QString MyMessageContext::diagnosticText() const
{
    return dtext;
}

void MyMessageContext::gpg_readyRead()
{
    emit updated();
}

void MyMessageContext::gpg_bytesWritten(int bytes)
{
    wrote += bytes;
}

void MyMessageContext::gpg_finished()
{
    complete();
    emit updated();
}

void MyMessageContext::gpg_needPassphrase(const QString &in_keyId)
{
    // FIXME: copied from above, clean up later

    QString keyId;
    PGPKey  sec = secretKeyFromId(in_keyId);
    if (!sec.isNull())
        keyId = sec.keyId();
    else
        keyId = in_keyId;
    // emit keyStoreList->storeNeedPassphrase(0, 0, keyId);
    QStringList out;
    out += escape_string(QStringLiteral("qca-gnupg-1"));
    out += escape_string(keyId);
    QString serialized = out.join(QStringLiteral(":"));

    KeyStoreEntry         kse;
    MyKeyStoreList *      keyStoreList = MyKeyStoreList::instance();
    KeyStoreEntryContext *c            = keyStoreList->entryPassive(serialized);
    if (c)
        kse.change(c);

    asker.ask(Event::StylePassphrase,
              KeyStoreInfo(KeyStore::PGPKeyring, keyStoreList->storeId(0), keyStoreList->name(0)),
              kse,
              nullptr);
}

void MyMessageContext::gpg_needCard()
{
    MyKeyStoreList *keyStoreList = MyKeyStoreList::instance();
    tokenAsker.ask(
        KeyStoreInfo(KeyStore::PGPKeyring, keyStoreList->storeId(0), keyStoreList->name(0)), KeyStoreEntry(), nullptr);
}

void MyMessageContext::gpg_readyReadDiagnosticText()
{
    // TODO ?
}

void MyMessageContext::asker_responseReady()
{
    if (!asker.accepted()) {
        seterror();
        emit updated();
        return;
    }

    const SecureArray a = asker.password();
    gpg.submitPassphrase(a);
}

void MyMessageContext::tokenAsker_responseReady()
{
    if (!tokenAsker.accepted()) {
        seterror();
        emit updated();
        return;
    }

    gpg.cardOkay();
}

} // end namespace gpgQCAPlugin
