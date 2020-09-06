/*
 * Copyright (C) 2003-2005  Justin Karneges <justin@affinix.com>
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
 *
 */

#include "gpgop.h"
#include "gpgaction.h"
#include "gpgop_p.h"

namespace gpgQCAPlugin {

//----------------------------------------------------------------------------
// GpgOp
//----------------------------------------------------------------------------
GpgOp::Private::Private(GpgOp *_q)
    : QObject(_q)
    , sync(_q)
    , q(_q)
    , act(nullptr)
    , waiting(false)
{
    reset(ResetAll);
}

GpgOp::Private::~Private()
{
    reset(ResetAll);
}

void GpgOp::Private::reset(ResetMode mode)
{
    if (act) {
        act->disconnect(this);
        act->setParent(nullptr);
        act->deleteLater();

        act = nullptr;
    }

    if (mode >= ResetSessionAndData) {
        output = GpgAction::Output();
        result.clear();
        diagnosticText = QString();
        eventList.clear();
    }

    if (mode >= ResetAll) {
        opt_ascii       = false;
        opt_noagent     = false;
        opt_alwaystrust = false;
        opt_pubfile     = QString();
        opt_secfile     = QString();
    }
}

void GpgOp::Private::make_act(GpgOp::Type _op)
{
    reset(ResetSessionAndData);

    op = _op;

    act = new GpgAction(this);

    connect(act, &GpgAction::readyRead, this, &GpgOp::Private::act_readyRead);
    connect(act, &GpgAction::bytesWritten, this, &GpgOp::Private::act_bytesWritten);
    connect(act, &GpgAction::needPassphrase, this, &GpgOp::Private::act_needPassphrase);
    connect(act, &GpgAction::needCard, this, &GpgOp::Private::act_needCard);
    connect(act, &GpgAction::finished, this, &GpgOp::Private::act_finished);
    connect(act, &GpgAction::readyReadDiagnosticText, this, &GpgOp::Private::act_readyReadDiagnosticText);

    act->input.bin             = bin;
    act->input.op              = op;
    act->input.opt_ascii       = opt_ascii;
    act->input.opt_noagent     = opt_noagent;
    act->input.opt_alwaystrust = opt_alwaystrust;
    act->input.opt_pubfile     = opt_pubfile;
    act->input.opt_secfile     = opt_secfile;
}

void GpgOp::Private::eventReady(const GpgOp::Event &e)
{
    eventList += e;
    sync.conditionMet();
}

void GpgOp::Private::eventReady(GpgOp::Event::Type type)
{
    GpgOp::Event e;
    e.type = type;
    eventReady(e);
}

void GpgOp::Private::eventReady(GpgOp::Event::Type type, int written)
{
    GpgOp::Event e;
    e.type    = type;
    e.written = written;
    eventReady(e);
}

void GpgOp::Private::eventReady(GpgOp::Event::Type type, const QString &keyId)
{
    GpgOp::Event e;
    e.type  = type;
    e.keyId = keyId;
    eventReady(e);
}

void GpgOp::Private::act_readyRead()
{
    if (waiting)
        eventReady(GpgOp::Event::ReadyRead);
    else
        emit q->readyRead();
}

void GpgOp::Private::act_bytesWritten(int bytes)
{
    if (waiting)
        eventReady(GpgOp::Event::BytesWritten, bytes);
    else
        emit q->bytesWritten(bytes);
}

void GpgOp::Private::act_needPassphrase(const QString &keyId)
{
    if (waiting)
        eventReady(GpgOp::Event::NeedPassphrase, keyId);
    else
        emit q->needPassphrase(keyId);
}

void GpgOp::Private::act_needCard()
{
    if (waiting)
        eventReady(GpgOp::Event::NeedCard);
    else
        emit q->needCard();
}

void GpgOp::Private::act_readyReadDiagnosticText()
{
    const QString s = act->readDiagnosticText();
    // printf("dtext ready: [%s]\n", qPrintable(s));
    diagnosticText += s;

    if (waiting)
        eventReady(GpgOp::Event::ReadyReadDiagnosticText);
    else
        emit q->readyReadDiagnosticText();
}

void GpgOp::Private::act_finished()
{
#ifdef GPG_PROFILE
    if (op == GpgOp::Encrypt)
        printf("<< doEncrypt: %d >>\n", timer.elapsed());
#endif

    result = act->read();
    diagnosticText += act->readDiagnosticText();
    output = act->output;

    QMap<int, QString> errmap;
    errmap[GpgOp::ErrorProcess]          = QStringLiteral("ErrorProcess");
    errmap[GpgOp::ErrorPassphrase]       = QStringLiteral("ErrorPassphrase");
    errmap[GpgOp::ErrorFormat]           = QStringLiteral("ErrorFormat");
    errmap[GpgOp::ErrorSignerExpired]    = QStringLiteral("ErrorSignerExpired");
    errmap[GpgOp::ErrorEncryptExpired]   = QStringLiteral("ErrorEncryptExpired");
    errmap[GpgOp::ErrorEncryptUntrusted] = QStringLiteral("ErrorEncryptUntrusted");
    errmap[GpgOp::ErrorEncryptInvalid]   = QStringLiteral("ErrorEncryptInvalid");
    errmap[GpgOp::ErrorDecryptNoKey]     = QStringLiteral("ErrorDecryptNoKey");
    errmap[GpgOp::ErrorUnknown]          = QStringLiteral("ErrorUnknown");
    if (output.success)
        diagnosticText += QStringLiteral("GpgAction success\n");
    else
        diagnosticText += QStringLiteral("GpgAction error: %1\n").arg(errmap[output.errorCode]);

    if (output.wasSigned) {
        QString s;
        if (output.verifyResult == GpgOp::VerifyGood)
            s = QStringLiteral("VerifyGood");
        else if (output.verifyResult == GpgOp::VerifyBad)
            s = QStringLiteral("VerifyBad");
        else
            s = QStringLiteral("VerifyNoKey");
        diagnosticText += QStringLiteral("wasSigned: verifyResult: %1\n").arg(s);
    }

    // printf("diagnosticText:\n%s", qPrintable(diagnosticText));

    reset(ResetSession);

    if (waiting)
        eventReady(GpgOp::Event::Finished);
    else
        emit q->finished();
}

GpgOp::GpgOp(const QString &bin, QObject *parent)
    : QObject(parent)
{
    d      = new Private(this);
    d->bin = bin;
}

GpgOp::~GpgOp()
{
    delete d;
}

void GpgOp::reset()
{
    d->reset(ResetAll);
}

bool GpgOp::isActive() const
{
    return (d->act ? true : false);
}

GpgOp::Type GpgOp::op() const
{
    return d->op;
}

void GpgOp::setAsciiFormat(bool b)
{
    d->opt_ascii = b;
}

void GpgOp::setDisableAgent(bool b)
{
    d->opt_noagent = b;
}

void GpgOp::setAlwaysTrust(bool b)
{
    d->opt_alwaystrust = b;
}

void GpgOp::setKeyrings(const QString &pubfile, const QString &secfile)
{
    d->opt_pubfile = pubfile;
    d->opt_secfile = secfile;
}

void GpgOp::doCheck()
{
    d->make_act(Check);
    d->act->start();
}

void GpgOp::doSecretKeyringFile()
{
    d->make_act(SecretKeyringFile);
    d->act->start();
}

void GpgOp::doPublicKeyringFile()
{
    d->make_act(PublicKeyringFile);
    d->act->start();
}

void GpgOp::doSecretKeys()
{
    d->make_act(SecretKeys);
    d->act->start();
}

void GpgOp::doPublicKeys()
{
    d->make_act(PublicKeys);
    d->act->start();
}

void GpgOp::doEncrypt(const QStringList &recip_ids)
{
#ifdef GPG_PROFILE
    d->timer.start();
    printf("<< doEncrypt >>\n");
#endif

    d->make_act(Encrypt);
    d->act->input.recip_ids = recip_ids;
    d->act->start();
}

void GpgOp::doDecrypt()
{
    d->make_act(Decrypt);
    d->act->start();
}

void GpgOp::doSign(const QString &signer_id)
{
    d->make_act(Sign);
    d->act->input.signer_id = signer_id;
    d->act->start();
}

void GpgOp::doSignAndEncrypt(const QString &signer_id, const QStringList &recip_ids)
{
    d->make_act(SignAndEncrypt);
    d->act->input.signer_id = signer_id;
    d->act->input.recip_ids = recip_ids;
    d->act->start();
}

void GpgOp::doSignClearsign(const QString &signer_id)
{
    d->make_act(SignClearsign);
    d->act->input.signer_id = signer_id;
    d->act->start();
}

void GpgOp::doSignDetached(const QString &signer_id)
{
    d->make_act(SignDetached);
    d->act->input.signer_id = signer_id;
    d->act->start();
}

void GpgOp::doVerify()
{
    d->make_act(Verify);
    d->act->start();
}

void GpgOp::doVerifyDetached(const QByteArray &sig)
{
    d->make_act(VerifyDetached);
    d->act->input.sig = sig;
    d->act->start();
}

void GpgOp::doImport(const QByteArray &in)
{
    d->make_act(Import);
    d->act->input.inkey = in;
    d->act->start();
}

void GpgOp::doExport(const QString &key_id)
{
    d->make_act(Export);
    d->act->input.export_key_id = key_id;
    d->act->start();
}

void GpgOp::doDeleteKey(const QString &key_fingerprint)
{
    d->make_act(DeleteKey);
    d->act->input.delete_key_fingerprint = key_fingerprint;
    d->act->start();
}

#ifdef QPIPE_SECURE
void GpgOp::submitPassphrase(const QCA::SecureArray &a)
#else
void GpgOp::submitPassphrase(const QByteArray &a)
#endif
{
    d->act->submitPassphrase(a);
}

void GpgOp::cardOkay()
{
    d->act->cardOkay();
}

QByteArray GpgOp::read()
{
    if (d->act) {
        return d->act->read();
    } else {
        const QByteArray a = d->result;
        d->result.clear();
        return a;
    }
}

void GpgOp::write(const QByteArray &in)
{
    d->act->write(in);
}

void GpgOp::endWrite()
{
    d->act->endWrite();
}

QString GpgOp::readDiagnosticText()
{
    QString s         = d->diagnosticText;
    d->diagnosticText = QString();
    return s;
}

GpgOp::Event GpgOp::waitForEvent(int msecs)
{
    if (!d->eventList.isEmpty())
        return d->eventList.takeFirst();

    if (!d->act)
        return GpgOp::Event();

    d->waiting = true;
    d->sync.waitForCondition(msecs);
    d->waiting = false;
    if (!d->eventList.isEmpty())
        return d->eventList.takeFirst();
    else
        return GpgOp::Event();
}

bool GpgOp::success() const
{
    return d->output.success;
}

GpgOp::Error GpgOp::errorCode() const
{
    return d->output.errorCode;
}

GpgOp::KeyList GpgOp::keys() const
{
    return d->output.keys;
}

QString GpgOp::keyringFile() const
{
    return d->output.keyringFile;
}

QString GpgOp::homeDir() const
{
    return d->output.homeDir;
}

QString GpgOp::encryptedToId() const
{
    return d->output.encryptedToId;
}

bool GpgOp::wasSigned() const
{
    return d->output.wasSigned;
}

QString GpgOp::signerId() const
{
    return d->output.signerId;
}

QDateTime GpgOp::timestamp() const
{
    return d->output.timestamp;
}

GpgOp::VerifyResult GpgOp::verifyResult() const
{
    return d->output.verifyResult;
}

}
