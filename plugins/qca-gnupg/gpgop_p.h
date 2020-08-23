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

#pragma once

#include "gpgaction.h"
#include "gpgop.h"
#include "gpgproc_p.h"
#include <QObject>

namespace gpgQCAPlugin {

class GpgOp::Private : public QObject
{
    Q_OBJECT
public:
    QCA::Synchronizer   sync;
    GpgOp *             q;
    GpgAction *         act;
    QString             bin;
    GpgOp::Type         op;
    GpgAction::Output   output;
    QByteArray          result;
    QString             diagnosticText;
    QList<GpgOp::Event> eventList;
    bool                waiting;

    bool    opt_ascii, opt_noagent, opt_alwaystrust;
    QString opt_pubfile, opt_secfile;

#ifdef GPG_PROFILE
    QTime timer;
#endif

    Private(GpgOp *_q);
    ~Private() override;
    void reset(ResetMode mode);
    void make_act(GpgOp::Type _op);
    void eventReady(const GpgOp::Event &e);
    void eventReady(GpgOp::Event::Type type);
    void eventReady(GpgOp::Event::Type type, int written);
    void eventReady(GpgOp::Event::Type type, const QString &keyId);

public Q_SLOTS:
    void act_readyRead();
    void act_bytesWritten(int bytes);
    void act_needPassphrase(const QString &keyId);
    void act_needCard();
    void act_readyReadDiagnosticText();
    void act_finished();
};

} // namespace gpgQCAPlugin
