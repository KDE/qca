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

// #define GPGOP_DEBUG

#include "gpgaction.h"

#ifdef GPGOP_DEBUG
#include "stdio.h"
#endif

namespace gpgQCAPlugin {

static QDateTime getTimestamp(const QString &s)
{
	if(s.isEmpty())
		return QDateTime();

	if(s.contains('T'))
	{
		return QDateTime::fromString(s, Qt::ISODate);
	}
	else
	{
		QDateTime dt;
		dt.setTime_t(s.toInt());
		return dt;
	}
}

static QByteArray getCString(const QByteArray &a)
{
	QByteArray out;

	// convert the "backslash" C-string syntax
	for(int n = 0; n < a.size(); ++n)
	{
		if(a[n] == '\\' && n + 1 < a.size())
		{
			++n;
			unsigned char c = (unsigned char)a[n];
			if(c == '\\')
			{
				out += '\\';
			}
			else if(c == 'x' && n + 2 < a.size())
			{
				++n;
				QByteArray hex = a.mid(n, 2);
				++n; // only skip one, loop will skip the next

				bool ok;
				uint val = hex.toInt(&ok, 16);
				if(ok)
				{
					out += (unsigned char)val;
				}
				else
				{
					out += "\\x";
					out += hex;
				}
			}
		}
		else
		{
			out += a[n];
		}
	}

	return out;
}

static bool stringToKeyList(const QString &outstr, GpgOp::KeyList *_keylist, QString *_keyring)
{
	GpgOp::KeyList keyList;
	QStringList lines = outstr.split('\n');

	if(lines.count() < 1)
		return false;

	QStringList::ConstIterator it = lines.constBegin();

	// first line is keyring file
	QString keyring = *(it++);

	// if the second line isn't a divider, we are dealing
	// with a new version of gnupg that doesn't give us
	// the keyring file on gpg --list-keys --with-colons
	if(it == lines.constEnd() || (*it).isEmpty() || (*it).at(0) != '-')
	{
		// first line wasn't the keyring name...
		keyring.clear();
		// ...so read the first line again
		it--;
	}
	else
	{
		// this was the divider line - skip it
		it++;
	}

	for(; it != lines.constEnd(); ++it)
	{
		QStringList f = (*it).split(':');
		if(f.count() < 1)
			continue;
		QString type = f[0];

		bool key = false; // key or not
		bool primary = false; // primary key or sub key
		// bool sec = false; // private key or not

		if(type == "pub")
		{
			key = true;
			primary = true;
		}
		else if(type == "sec")
		{
			key = true;
			primary = true;
			// sec = true;
		}
		else if(type == "sub")
		{
			key = true;
		}
		else if(type == "ssb")
		{
			key = true;
			// sec = true;
		}

		if(key)
		{
			if(primary)
			{
				keyList += GpgOp::Key();

				QString trust = f[1];
				if(trust == "f" || trust == "u")
					keyList.last().isTrusted = true;
			}

			int key_type = f[3].toInt();
			QString caps = f[11];

			GpgOp::KeyItem item;
			item.bits = f[2].toInt();
			if(key_type == 1)
				item.type = GpgOp::KeyItem::RSA;
			else if(key_type == 16)
				item.type = GpgOp::KeyItem::ElGamal;
			else if(key_type == 17)
				item.type = GpgOp::KeyItem::DSA;
			else
				item.type = GpgOp::KeyItem::Unknown;
			item.id = f[4];
			item.creationDate = getTimestamp(f[5]);
			item.expirationDate = getTimestamp(f[6]);
			if(caps.contains('e'))
				item.caps |= GpgOp::KeyItem::Encrypt;
			if(caps.contains('s'))
				item.caps |= GpgOp::KeyItem::Sign;
			if(caps.contains('c'))
				item.caps |= GpgOp::KeyItem::Certify;
			if(caps.contains('a'))
				item.caps |= GpgOp::KeyItem::Auth;

			keyList.last().keyItems += item;
		}
		else if(type == "uid")
		{
			QByteArray uid = getCString(f[9].toUtf8());
			keyList.last().userIds.append(QString::fromUtf8(uid));
		}
		else if(type == "fpr")
		{
			QString s = f[9];
			keyList.last().keyItems.last().fingerprint = s;
		}
	}

	if(_keylist)
		*_keylist = keyList;
	if(_keyring)
		*_keyring = keyring;

	return true;
}

static bool findKeyringFilename(const QString &outstr, QString *_keyring)
{
	QStringList lines = outstr.split('\n');
	if(lines.count() < 1)
		return false;

	*_keyring = lines[0];
	return true;
}

GpgAction::GpgAction(QObject *parent)
	: QObject(parent)
	, proc(this)
	, dtextTimer(this)
	, utf8Output(false)
{
	dtextTimer.setSingleShot(true);

	connect(&proc, SIGNAL(error(gpgQCAPlugin::GPGProc::Error)), SLOT(proc_error(gpgQCAPlugin::GPGProc::Error)));
	connect(&proc, SIGNAL(finished(int)), SLOT(proc_finished(int)));
	connect(&proc, SIGNAL(readyReadStdout()), SLOT(proc_readyReadStdout()));
	connect(&proc, SIGNAL(readyReadStderr()), SLOT(proc_readyReadStderr()));
	connect(&proc, SIGNAL(readyReadStatusLines()), SLOT(proc_readyReadStatusLines()));
	connect(&proc, SIGNAL(bytesWrittenStdin(int)), SLOT(proc_bytesWrittenStdin(int)));
	connect(&proc, SIGNAL(bytesWrittenAux(int)), SLOT(proc_bytesWrittenAux(int)));
	connect(&proc, SIGNAL(bytesWrittenCommand(int)), SLOT(proc_bytesWrittenCommand(int)));
	connect(&proc, SIGNAL(debug(const QString &)), SLOT(proc_debug(const QString &)));
	connect(&dtextTimer, SIGNAL(timeout()), SLOT(t_dtext()));

	reset();
}

GpgAction::~GpgAction()
{
	reset();
}

void GpgAction::reset()
{
	collectOutput = true;
	allowInput = false;
	readConv.setup(LineConverter::Read);
	writeConv.setup(LineConverter::Write);
	readText = false;
	writeText = false;
	useAux = false;
	passphraseKeyId = QString();
	signing = false;
	decryptGood = false;
	signGood = false;
	curError = GpgOp::ErrorUnknown;
	badPassphrase = false;
	need_submitPassphrase = false;
	need_cardOkay = false;
	diagnosticText = QString();
	dtextTimer.stop();

	output = Output();

	proc.reset();
}

void GpgAction::start()
{
	reset();

	QStringList args;
	bool extra = false;

	if(input.opt_ascii)
		args += "--armor";

	if(input.opt_noagent)
		args += "--no-use-agent";

	if(input.opt_alwaystrust)
		args += "--always-trust";

	if(!input.opt_pubfile.isEmpty() && !input.opt_secfile.isEmpty())
	{
		args += "--no-default-keyring";
		args += "--keyring";
		args += input.opt_pubfile;
		args += "--secret-keyring";
		args += input.opt_secfile;
	}

	switch(input.op)
	{
	case GpgOp::Check:
	{
		args += "--version";
		readText = true;
		break;
	}
	case GpgOp::SecretKeyringFile:
	{
#ifndef Q_OS_WIN
		args += "--display-charset=utf-8";
#endif
		args += "--list-secret-keys";
		readText = true;
		break;
	}
	case GpgOp::PublicKeyringFile:
	{
#ifndef Q_OS_WIN
		args += "--display-charset=utf-8";
#endif
		args += "--list-public-keys";
		readText = true;
		break;
	}
	case GpgOp::SecretKeys:
	{
		args += "--fixed-list-mode";
		args += "--with-colons";
		args += "--with-fingerprint";
		args += "--with-fingerprint";
		args += "--list-secret-keys";
		utf8Output = true;
		readText = true;
		break;
	}
	case GpgOp::PublicKeys:
	{
		args += "--fixed-list-mode";
		args += "--with-colons";
		args += "--with-fingerprint";
		args += "--with-fingerprint";
		args += "--list-public-keys";
		utf8Output = true;
		readText = true;
		break;
	}
	case GpgOp::Encrypt:
	{
		args += "--encrypt";

		// recipients
		for(QStringList::ConstIterator it = input.recip_ids.constBegin(); it != input.recip_ids.constEnd(); ++it)
		{
			args += "--recipient";
			args += QString("0x") + *it;
		}
		extra = true;
		collectOutput = false;
		allowInput = true;
		if(input.opt_ascii)
			readText = true;
		break;
	}
	case GpgOp::Decrypt:
	{
		args += "--decrypt";
		extra = true;
		collectOutput = false;
		allowInput = true;
		if(input.opt_ascii)
			writeText = true;
		break;
	}
	case GpgOp::Sign:
	{
		args += "--default-key";
		args += QString("0x") + input.signer_id;
		args += "--sign";
		extra = true;
		collectOutput = false;
		allowInput = true;
		if(input.opt_ascii)
			readText = true;
		signing = true;
		break;
	}
	case GpgOp::SignAndEncrypt:
	{
		args += "--default-key";
		args += QString("0x") + input.signer_id;
		args += "--sign";
		args += "--encrypt";

		// recipients
		for(QStringList::ConstIterator it = input.recip_ids.constBegin(); it != input.recip_ids.constEnd(); ++it)
		{
			args += "--recipient";
			args += QString("0x") + *it;
		}
		extra = true;
		collectOutput = false;
		allowInput = true;
		if(input.opt_ascii)
			readText = true;
		signing = true;
		break;
	}
	case GpgOp::SignClearsign:
	{
		args += "--default-key";
		args += QString("0x") + input.signer_id;
		args += "--clearsign";
		extra = true;
		collectOutput = false;
		allowInput = true;
		if(input.opt_ascii)
			readText = true;
		signing = true;
		break;
	}
	case GpgOp::SignDetached:
	{
		args += "--default-key";
		args += QString("0x") + input.signer_id;
		args += "--detach-sign";
		extra = true;
		collectOutput = false;
		allowInput = true;
		if(input.opt_ascii)
			readText = true;
		signing = true;
		break;
	}
	case GpgOp::Verify:
	{
		args += "--verify";
		args += "-"; //krazy:exclude=doublequote_chars
		extra = true;
		allowInput = true;
		if(input.opt_ascii)
			writeText = true;
		break;
	}
	case GpgOp::VerifyDetached:
	{
		args += "--verify";
		args += "-"; //krazy:exclude=doublequote_chars
		args += "-&?";
		extra = true;
		allowInput = true;
		useAux = true;
		break;
	}
	case GpgOp::Import:
	{
		args += "--import";
		readText = true;
		if(input.opt_ascii)
			writeText = true;
		break;
	}
	case GpgOp::Export:
	{
		args += "--export";
		args += QString("0x") + input.export_key_id;
		collectOutput = false;
		if(input.opt_ascii)
			readText = true;
		break;
	}
	case GpgOp::DeleteKey:
	{
		args += "--batch";
		args += "--delete-key";
		args += QString("0x") + input.delete_key_fingerprint;
		break;
	}
	}

#ifdef GPG_PROFILE
	timer.start();
	printf("<< launch >>\n");
#endif
	proc.start(input.bin, args, extra ? GPGProc::ExtendedMode : GPGProc::NormalMode);

	// detached sig
	if(input.op == GpgOp::VerifyDetached)
	{
		QByteArray a = input.sig;
		if(input.opt_ascii)
		{
			LineConverter conv;
			conv.setup(LineConverter::Write);
			a = conv.process(a);
		}
		proc.writeStdin(a);
		proc.closeStdin();
	}

	// import
	if(input.op == GpgOp::Import)
	{
		QByteArray a = input.inkey;
		if(writeText)
		{
			LineConverter conv;
			conv.setup(LineConverter::Write);
			a = conv.process(a);
		}
		proc.writeStdin(a);
		proc.closeStdin();
	}
}

#ifdef QPIPE_SECURE
void GpgAction::submitPassphrase(const QCA::SecureArray &a)
#else
	void GpgAction::submitPassphrase(const QByteArray &a)
#endif
{
	if(!need_submitPassphrase)
		return;

	need_submitPassphrase = false;

#ifdef QPIPE_SECURE
	QCA::SecureArray b;
#else
	QByteArray b;
#endif
	// filter out newlines, since that's the delimiter used
	// to indicate a submitted passphrase
	b.resize(a.size());
	int at = 0;
	for(int n = 0; n < a.size(); ++n)
	{
		if(a[n] != '\n')
			b[at++] = a[n];
	}
	b.resize(at);

	// append newline
	b.resize(b.size() + 1);
	b[b.size() - 1] = '\n';
	proc.writeCommand(b);
}

QByteArray GpgAction::read()
{
	if(collectOutput)
		return QByteArray();

	QByteArray a = proc.readStdout();
	if(readText)
		a = readConv.update(a);
	if(!proc.isActive())
		a += readConv.final();
	return a;
}

void GpgAction::write(const QByteArray &in)
{
	if(!allowInput)
		return;

	QByteArray a = in;
	if(writeText)
		a = writeConv.update(in);

	if(useAux)
		proc.writeAux(a);
	else
		proc.writeStdin(a);
}

void GpgAction::endWrite()
{
	if(!allowInput)
		return;

	if(useAux)
		proc.closeAux();
	else
		proc.closeStdin();
}

void GpgAction::cardOkay()
{
	if(need_cardOkay)
	{
		need_cardOkay = false;
		submitCommand("\n");
	}
}

QString GpgAction::readDiagnosticText()
{
	QString s = diagnosticText;
	diagnosticText = QString();
	return s;
}

void GpgAction::submitCommand(const QByteArray &a)
{
	proc.writeCommand(a);
}

// since str is taken as a value, it is ok to use the same variable for 'rest'
QString GpgAction::nextArg(QString str, QString *rest)
{
	QString out;
	int n = str.indexOf(' ');
	if(n == -1)
	{
		if(rest)
			*rest = QString();
		return str;
	}
	else
	{
		if(rest)
			*rest = str.mid(n + 1);
		return str.mid(0, n);
	}
}

void GpgAction::processStatusLine(const QString &line)
{
	appendDiagnosticText("{" + line + "}");
	ensureDTextEmit();

	if(!proc.isActive())
		return;

	QString s, rest;
	s = nextArg(line, &rest);

	if(s == "NODATA")
	{
		// only set this if it'll make it better
		if(curError == GpgOp::ErrorUnknown)
			curError = GpgOp::ErrorFormat;
	}
	else if(s == "UNEXPECTED")
	{
		if(curError == GpgOp::ErrorUnknown)
			curError = GpgOp::ErrorFormat;
	}
	else if(s == "EXPKEYSIG")
	{
		curError = GpgOp::ErrorSignerExpired;
	}
	else if(s == "REVKEYSIG")
	{
		curError = GpgOp::ErrorSignerRevoked;
	}
	else if(s == "EXPSIG")
	{
		curError = GpgOp::ErrorSignatureExpired;
	}
	else if(s == "INV_RECP")
	{
		int r = nextArg(rest).toInt();

		if(curError == GpgOp::ErrorUnknown)
		{
			if(r == 10)
				curError = GpgOp::ErrorEncryptUntrusted;
			else if(r == 4)
				curError = GpgOp::ErrorEncryptRevoked;
			else if(r == 5)
				curError = GpgOp::ErrorEncryptExpired;
			else
				// due to GnuPG bug #1650
				// <https://bugs.g10code.com/gnupg/issue1650>
				// encrypting to expired and revoked keys will
				// not specify any reason for failing,
				// defaulting to this
				curError = GpgOp::ErrorEncryptInvalid;
		}
	}
	else if(s == "NO_SECKEY")
	{
		output.encryptedToId = nextArg(rest);

		if(curError == GpgOp::ErrorUnknown)
			curError = GpgOp::ErrorDecryptNoKey;
	}
	else if(s == "DECRYPTION_OKAY")
	{
		decryptGood = true;

		// message could be encrypted with several keys
		if(curError == GpgOp::ErrorDecryptNoKey)
			curError = GpgOp::ErrorUnknown;
	}
	else if(s == "SIG_CREATED")
	{
		signGood = true;
	}
	else if(s == "USERID_HINT")
	{
		passphraseKeyId = nextArg(rest);
	}
	else if(s == "GET_HIDDEN")
	{
		QString arg = nextArg(rest);
		if(arg == "passphrase.enter" || arg == "passphrase.pin.ask")
		{
			need_submitPassphrase = true;

			// for signal-safety, emit later
			QMetaObject::invokeMethod(this, "needPassphrase", Qt::QueuedConnection, Q_ARG(QString, passphraseKeyId));
		}
	}
	else if(s == "GET_LINE")
	{
		QString arg = nextArg(rest);
		if(arg == "cardctrl.insert_card.okay")
		{
			need_cardOkay = true;

			QMetaObject::invokeMethod(this, "needCard", Qt::QueuedConnection);
		}
	}
	else if(s == "GET_BOOL")
	{
		QString arg = nextArg(rest);
		if(arg == "untrusted_key.override")
			submitCommand("no\n");
	}
	else if(s == "GOOD_PASSPHRASE")
	{
		badPassphrase = false;
	}
	else if(s == "BAD_PASSPHRASE")
	{
		badPassphrase = true;
	}
	else if(s == "GOODSIG")
	{
		output.wasSigned = true;
		output.signerId = nextArg(rest);
		output.verifyResult = GpgOp::VerifyGood;
	}
	else if(s == "BADSIG")
	{
		output.wasSigned = true;
		output.signerId = nextArg(rest);
		output.verifyResult = GpgOp::VerifyBad;
	}
	else if(s == "ERRSIG")
	{
		output.wasSigned = true;
		QStringList list = rest.split(' ', QString::SkipEmptyParts);
		output.signerId = list[0];
		output.timestamp = getTimestamp(list[4]);
		output.verifyResult = GpgOp::VerifyNoKey;
	}
	else if(s == "VALIDSIG")
	{
		QStringList list = rest.split(' ', QString::SkipEmptyParts);
		output.timestamp = getTimestamp(list[2]);
	}
}

void GpgAction::processResult(int code)
{
#ifdef GPG_PROFILE
	printf("<< launch: %d >>\n", timer.elapsed());
#endif

	// put stdout and stderr into QStrings

	QString outstr;
	QString errstr;
	
#ifdef Q_OS_WIN
	if (!utf8Output)
	{
		outstr = QString::fromLocal8Bit(buf_stdout);
		errstr = QString::fromLocal8Bit(buf_stderr);
	}
	else
	{
#endif
		outstr = QString::fromUtf8(buf_stdout);
		errstr = QString::fromUtf8(buf_stderr);
#ifdef Q_OS_WIN
	}
#endif

	if(collectOutput)
		appendDiagnosticText(QString("stdout: [%1]").arg(outstr));
	appendDiagnosticText(QString("stderr: [%1]").arg(errstr));
	ensureDTextEmit();

	if(badPassphrase)
	{
		output.errorCode = GpgOp::ErrorPassphrase;
	}
	else if(curError != GpgOp::ErrorUnknown)
	{
		output.errorCode = curError;
	}
	else if(code == 0)
	{
		if(input.op == GpgOp::Check)
		{
			QStringList strList = outstr.split("\n");
			foreach (const QString &str, strList)
			{
				if (!str.startsWith("Home: "))
					continue;

				output.homeDir = str.section(' ', 1);
				break;
			}
			output.success = true;
		}
		else if(input.op == GpgOp::SecretKeyringFile || input.op == GpgOp::PublicKeyringFile)
		{
			if(findKeyringFilename(outstr, &output.keyringFile))
				output.success = true;
		}
		else if(input.op == GpgOp::SecretKeys || input.op == GpgOp::PublicKeys)
		{
			if(stringToKeyList(outstr, &output.keys, &output.keyringFile))
				output.success = true;
		}
		else
			output.success = true;
	}
	else
	{
		// decrypt and sign success based on status only.
		// this is mainly because gpg uses fatal return
		// values if there is trouble with gpg-agent, even
		// though the operation otherwise works.

		if(input.op == GpgOp::Decrypt && decryptGood)
			output.success = true;
		if(signing && signGood)
			output.success = true;

		// gpg will indicate failure for bad sigs, but we don't
		// consider this to be operation failure.

		bool signedMakesItGood = false;
		if(input.op == GpgOp::Verify || input.op == GpgOp::VerifyDetached)
			signedMakesItGood = true;

		if(signedMakesItGood && output.wasSigned)
			output.success = true;
	}

	emit finished();
}

void GpgAction::ensureDTextEmit()
{
	if(!dtextTimer.isActive())
		dtextTimer.start();
}

void GpgAction::t_dtext()
{
	emit readyReadDiagnosticText();
}

void GpgAction::proc_error(gpgQCAPlugin::GPGProc::Error e)
{
	QString str;
	if(e == GPGProc::FailedToStart)
		str = "FailedToStart";
	else if(e == GPGProc::UnexpectedExit)
		str = "UnexpectedExit";
	else if(e == GPGProc::ErrorWrite)
		str = "ErrorWrite";

	appendDiagnosticText(QString("GPG Process Error: %1").arg(str));
	ensureDTextEmit();

	output.errorCode = GpgOp::ErrorProcess;
	emit finished();
}

void GpgAction::proc_finished(int exitCode)
{
	appendDiagnosticText(QString("GPG Process Finished: exitStatus=%1").arg(exitCode));
	ensureDTextEmit();

	processResult(exitCode);
}

void GpgAction::proc_readyReadStdout()
{
	if(collectOutput)
	{
		QByteArray a = proc.readStdout();
		if(readText)
			a = readConv.update(a);
		buf_stdout.append(a);
	}
	else
		emit readyRead();
}

void GpgAction::proc_readyReadStderr()
{
	buf_stderr.append(proc.readStderr());
}

void GpgAction::proc_readyReadStatusLines()
{
	QStringList lines = proc.readStatusLines();
	for(int n = 0; n < lines.count(); ++n)
		processStatusLine(lines[n]);
}

void GpgAction::proc_bytesWrittenStdin(int bytes)
{
	if(!useAux)
	{
		int actual = writeConv.writtenToActual(bytes);
		emit bytesWritten(actual);
	}
}

void GpgAction::proc_bytesWrittenAux(int bytes)
{
	if(useAux)
	{
		int actual = writeConv.writtenToActual(bytes);
		emit bytesWritten(actual);
	}
}

void GpgAction::proc_bytesWrittenCommand(int)
{
	// don't care about this
}

void GpgAction::proc_debug(const QString &str)
{
	appendDiagnosticText("GPGProc: " + str);
	ensureDTextEmit();
}

void GpgAction::appendDiagnosticText(const QString &line)
{
#ifdef GPGOP_DEBUG
	printf("%s\n", qPrintable(line));
#endif
	diagnosticText += line;
}

} // end namespace gpgQCAPlugin
