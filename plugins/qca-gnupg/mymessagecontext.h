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

#include "qcaprovider.h"
#include "gpgop.h"

namespace gpgQCAPlugin
{

class MyOpenPGPContext;

class MyMessageContext : public QCA::MessageContext
{
	Q_OBJECT
public:
	MyOpenPGPContext *sms;

	QString signerId;
	QStringList recipIds;
	QCA::MessageContext::Operation op;
	QCA::SecureMessage::SignMode signMode;
	QCA::SecureMessage::Format format;
	QByteArray in, out, sig;
	int wrote;
	bool ok, wasSigned;
	GpgOp::Error op_err;
	QCA::SecureMessageSignature signer;
	GpgOp gpg;
	bool _finished;
	QString dtext;

	QCA::PasswordAsker asker;
	QCA::TokenAsker tokenAsker;

	MyMessageContext(MyOpenPGPContext *_sms, QCA::Provider *p);

	// reimplemented Provider::Context
	QCA::Provider::Context *clone() const;

	// reimplemented MessageContext
	bool canSignMultiple() const;
	QCA::SecureMessage::Type type() const;
	void reset();
	void setupEncrypt(const QCA::SecureMessageKeyList &keys);
	void setupSign(const QCA::SecureMessageKeyList &keys, QCA::SecureMessage::SignMode m, bool, bool);
	void setupVerify(const QByteArray &detachedSig);
	void start(QCA::SecureMessage::Format f, QCA::MessageContext::Operation op);
	void update(const QByteArray &in);
	QByteArray read();
	int written();
	void end();
	bool finished() const;
	bool waitForFinished(int msecs);
	bool success() const;
	QCA::SecureMessage::Error errorCode() const;
	QByteArray signature() const;
	QString hashName() const;
	QCA::SecureMessageSignatureList signers() const;
	QString diagnosticText() const;

	void seterror();
	void complete();

private slots:
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
