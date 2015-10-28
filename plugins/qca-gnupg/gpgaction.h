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

#include "lineconverter.h"
#include "qca_safetimer.h"
#include "gpgop.h"
#include "gpgproc.h"
#include <QObject>
#include <QStringList>
#include <QByteArray>

#ifdef GPG_PROFILE
#include <QTime>
#endif

namespace gpgQCAPlugin {

class GpgAction : public QObject
{
	Q_OBJECT
public:
	struct Input
	{
		QString bin;
		GpgOp::Type op;
		bool opt_ascii, opt_noagent, opt_alwaystrust;
		QString opt_pubfile, opt_secfile;
		QStringList recip_ids;
		QString signer_id;
		QByteArray sig;
		QByteArray inkey;
		QString export_key_id;
		QString delete_key_fingerprint;

		Input() : opt_ascii(false), opt_noagent(false), opt_alwaystrust(false) {}
	};

	struct Output
	{
		bool success;
		GpgOp::Error errorCode;
		GpgOp::KeyList keys;
		QString keyringFile;
		QString encryptedToId;
		bool wasSigned;
		QString signerId;
		QDateTime timestamp;
		GpgOp::VerifyResult verifyResult;
		QString homeDir;

		Output() : success(false), errorCode(GpgOp::ErrorUnknown), wasSigned(false) {}
	};

	Input input;
	Output output;

	GpgAction(QObject *parent = 0);
	~GpgAction();
	void reset();
	void start();
#ifdef QPIPE_SECURE
	void submitPassphrase(const QCA::SecureArray &a);
#else
	void submitPassphrase(const QByteArray &a);
#endif

public slots:
	QByteArray read();
	void write(const QByteArray &in);
	void endWrite();
	void cardOkay();
	QString readDiagnosticText();

signals:
	void readyRead();
	void bytesWritten(int bytes);
	void finished();
	void needPassphrase(const QString &keyId);
	void needCard();
	void readyReadDiagnosticText();

private:
	void submitCommand(const QByteArray &a);

	// since str is taken as a value, it is ok to use the same variable for 'rest'
	QString nextArg(QString str, QString *rest = 0);
	void processStatusLine(const QString &line);
	void processResult(int code);
	void ensureDTextEmit();

	GPGProc proc;
	bool collectOutput, allowInput;
	LineConverter readConv, writeConv;
	bool readText, writeText;
	QByteArray buf_stdout, buf_stderr;
	bool useAux;
	QString passphraseKeyId;
	bool signing, decryptGood, signGood;
	GpgOp::Error curError;
	bool badPassphrase;
	bool need_submitPassphrase, need_cardOkay;
	QString diagnosticText;
	QCA::SafeTimer dtextTimer;
	bool utf8Output;

#ifdef GPG_PROFILE
	QTime timer;
#endif

private slots:
	void t_dtext();
	void proc_error(gpgQCAPlugin::GPGProc::Error e);
	void proc_finished(int exitCode);
	void proc_readyReadStdout();
	void proc_readyReadStderr();
	void proc_readyReadStatusLines();
	void proc_bytesWrittenStdin(int bytes);
	void proc_bytesWrittenAux(int bytes);
	void proc_bytesWrittenCommand(int);
	void proc_debug(const QString &str);
	void appendDiagnosticText(const QString &line);
};


} // end namespace gpgQCAPlugin
