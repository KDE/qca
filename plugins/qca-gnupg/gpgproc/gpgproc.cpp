/*
 * Copyright (C) 2003-2007  Justin Karneges <justin@affinix.com>
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

#include "gpgproc_p.h"

#ifdef Q_OS_MAC
#define QT_PIPE_HACK
#endif


using namespace QCA;

namespace gpgQCAPlugin {

void releaseAndDeleteLater(QObject *owner, QObject *obj)
{
	obj->disconnect(owner);
	obj->setParent(nullptr);
	obj->deleteLater();
}


GPGProc::Private::Private(GPGProc *_q)
	: QObject(_q)
	, q(_q)
	, pipeAux(this)
	, pipeCommand(this)
	, pipeStatus(this)
	, startTrigger(this)
	, doneTrigger(this)
{
	qRegisterMetaType<gpgQCAPlugin::GPGProc::Error>("gpgQCAPlugin::GPGProc::Error");

	proc = nullptr;
	proc_relay = nullptr;
	startTrigger.setSingleShot(true);
	doneTrigger.setSingleShot(true);

	connect(&pipeAux.writeEnd(), &QCA::QPipeEnd::bytesWritten, this, &GPGProc::Private::aux_written);
	connect(&pipeAux.writeEnd(), &QCA::QPipeEnd::error, this, &GPGProc::Private::aux_error);
	connect(&pipeCommand.writeEnd(), &QCA::QPipeEnd::bytesWritten, this, &GPGProc::Private::command_written);
	connect(&pipeCommand.writeEnd(), &QCA::QPipeEnd::error, this, &GPGProc::Private::command_error);
	connect(&pipeStatus.readEnd(), &QCA::QPipeEnd::readyRead, this, &GPGProc::Private::status_read);
	connect(&pipeStatus.readEnd(), &QCA::QPipeEnd::error, this, &GPGProc::Private::status_error);
	connect(&startTrigger, &QCA::SafeTimer::timeout, this, &GPGProc::Private::doStart);
	connect(&doneTrigger, &QCA::SafeTimer::timeout, this, &GPGProc::Private::doTryDone);

	reset(ResetSessionAndData);
}

GPGProc::Private::~Private()
{
	reset(ResetSession);
}

void GPGProc::Private::closePipes()
{
#ifdef QT_PIPE_HACK
	pipeAux.readEnd().reset();
	pipeCommand.readEnd().reset();
	pipeStatus.writeEnd().reset();
#endif

	pipeAux.reset();
	pipeCommand.reset();
	pipeStatus.reset();
}

void GPGProc::Private::reset(ResetMode mode)
{
#ifndef QT_PIPE_HACK
	closePipes();
#endif

	if(proc)
	{
		proc->disconnect(this);

		if(proc->state() != QProcess::NotRunning)
		{
			// Before try to correct end proccess
			// Terminate if failed
			proc->close();
			bool finished = proc->waitForFinished(5000);
			if (!finished)
				proc->terminate();
		}

		proc->setParent(nullptr);
		releaseAndDeleteLater(this, proc_relay);
		proc_relay = nullptr;
		delete proc; // should be safe to do thanks to relay
		proc = nullptr;
	}

#ifdef QT_PIPE_HACK
	closePipes();
#endif

	startTrigger.stop();
	doneTrigger.stop();

	pre_stdin.clear();
	pre_aux.clear();
	pre_command.clear();
	pre_stdin_close = false;
	pre_aux_close = false;
	pre_command_close = false;

	need_status = false;
	fin_process = false;
	fin_status = false;

	if(mode >= ResetSessionAndData)
	{
		statusBuf.clear();
		statusLines.clear();
		leftover_stdout.clear();
		leftover_stderr.clear();
		error = GPGProc::FailedToStart;
		exitCode = -1;
	}
}

bool GPGProc::Private::setupPipes(bool makeAux)
{
	if(makeAux && !pipeAux.create())
	{
		closePipes();
		emit q->debug(QStringLiteral("Error creating pipeAux"));
		return false;
	}

#ifdef QPIPE_SECURE
	if(!pipeCommand.create(true)) // secure
#else
		if(!pipeCommand.create())
#endif
		{
			closePipes();
			emit q->debug(QStringLiteral("Error creating pipeCommand"));
			return false;
		}

	if(!pipeStatus.create())
	{
		closePipes();
		emit q->debug(QStringLiteral("Error creating pipeStatus"));
		return false;
	}

	return true;
}

void GPGProc::Private::setupArguments()
{
	QStringList fullargs;
	fullargs += QStringLiteral("--no-tty");
	fullargs += QStringLiteral("--pinentry-mode");
	fullargs += QStringLiteral("loopback");

	if(mode == ExtendedMode)
	{
		fullargs += QStringLiteral("--enable-special-filenames");

		fullargs += QStringLiteral("--status-fd");
		fullargs += QString::number(pipeStatus.writeEnd().idAsInt());

		fullargs += QStringLiteral("--command-fd");
		fullargs += QString::number(pipeCommand.readEnd().idAsInt());
	}

	for(int n = 0; n < args.count(); ++n)
	{
		QString a = args[n];
		if(mode == ExtendedMode && a == QLatin1String("-&?"))
			fullargs += QStringLiteral("-&") + QString::number(pipeAux.readEnd().idAsInt());
		else
			fullargs += a;
	}

	QString fullcmd = fullargs.join(QStringLiteral(" "));
	emit q->debug(QStringLiteral("Running: [") + bin + QLatin1Char(' ') + fullcmd + QLatin1Char(']'));

	args = fullargs;
}

void GPGProc::Private::doStart()
{
#ifdef Q_OS_WIN
	// Note: for unix, inheritability is set in SProcess
	if(pipeAux.readEnd().isValid())
		pipeAux.readEnd().setInheritable(true);
	if(pipeCommand.readEnd().isValid())
		pipeCommand.readEnd().setInheritable(true);
	if(pipeStatus.writeEnd().isValid())
		pipeStatus.writeEnd().setInheritable(true);
#endif

	setupArguments();

	proc->start(bin, args);
	proc->waitForStarted();

	pipeAux.readEnd().close();
	pipeCommand.readEnd().close();
	pipeStatus.writeEnd().close();
}

void GPGProc::Private::aux_written(int x)
{
	emit q->bytesWrittenAux(x);
}

void GPGProc::Private::aux_error(QCA::QPipeEnd::Error)
{
	emit q->debug(QStringLiteral("Aux: Pipe error"));
	reset(ResetSession);
	emit q->error(GPGProc::ErrorWrite);
}

void GPGProc::Private::command_written(int x)
{
	emit q->bytesWrittenCommand(x);
}

void GPGProc::Private::command_error(QCA::QPipeEnd::Error)
{
	emit q->debug(QStringLiteral("Command: Pipe error"));
	reset(ResetSession);
	emit q->error(GPGProc::ErrorWrite);
}

void GPGProc::Private::status_read()
{
	if(readAndProcessStatusData())
		emit q->readyReadStatusLines();
}

void GPGProc::Private::status_error(QCA::QPipeEnd::Error e)
{
	if(e == QPipeEnd::ErrorEOF)
		emit q->debug(QStringLiteral("Status: Closed (EOF)"));
	else
		emit q->debug(QStringLiteral("Status: Closed (gone)"));

	fin_status = true;
	doTryDone();
}

void GPGProc::Private::proc_started()
{
	emit q->debug(QStringLiteral("Process started"));

	// Note: we don't close these here anymore.  instead we
	//   do it just after calling proc->start().
	// close these, we don't need them
	/*pipeAux.readEnd().close();
	  pipeCommand.readEnd().close();
	  pipeStatus.writeEnd().close();*/

	// do the pre* stuff
	if(!pre_stdin.isEmpty())
	{
		proc->write(pre_stdin);
		pre_stdin.clear();
	}
	if(!pre_aux.isEmpty())
	{
		pipeAux.writeEnd().write(pre_aux);
		pre_aux.clear();
	}
	if(!pre_command.isEmpty())
	{
#ifdef QPIPE_SECURE
		pipeCommand.writeEnd().writeSecure(pre_command);
#else
		pipeCommand.writeEnd().write(pre_command);
#endif
		pre_command.clear();
	}

	if(pre_stdin_close)
	{
		proc->waitForBytesWritten();
		proc->closeWriteChannel();
	}

	if(pre_aux_close)
		pipeAux.writeEnd().close();
	if(pre_command_close)
		pipeCommand.writeEnd().close();
}

void GPGProc::Private::proc_readyReadStandardOutput()
{
	emit q->readyReadStdout();
}

void GPGProc::Private::proc_readyReadStandardError()
{
	emit q->readyReadStderr();
}

void GPGProc::Private::proc_bytesWritten(qint64 lx)
{
	int x = (int)lx;
	emit q->bytesWrittenStdin(x);
}

void GPGProc::Private::proc_finished(int x)
{
	emit q->debug(QStringLiteral("Process finished: %1").arg(x));
	exitCode = x;

	fin_process = true;
	fin_process_success = true;

	if(need_status && !fin_status)
	{
		pipeStatus.readEnd().finalize();
		fin_status = true;
		if(readAndProcessStatusData())
		{
			doneTrigger.start();
			emit q->readyReadStatusLines();
			return;
		}
	}

	doTryDone();
}

void GPGProc::Private::proc_error(QProcess::ProcessError x)
{
	QMap<int, QString> errmap;
	errmap[QProcess::FailedToStart] = QStringLiteral("FailedToStart");
	errmap[QProcess::Crashed]       = QStringLiteral("Crashed");
	errmap[QProcess::Timedout]      = QStringLiteral("Timedout");
	errmap[QProcess::WriteError]    = QStringLiteral("WriteError");
	errmap[QProcess::ReadError]     = QStringLiteral("ReadError");
	errmap[QProcess::UnknownError]  = QStringLiteral("UnknownError");

	emit q->debug(QStringLiteral("Process error: %1").arg(errmap[x]));

	if(x == QProcess::FailedToStart)
		error = GPGProc::FailedToStart;
	else if(x == QProcess::WriteError)
		error = GPGProc::ErrorWrite;
	else
		error = GPGProc::UnexpectedExit;

	fin_process = true;
	fin_process_success = false;

#ifdef QT_PIPE_HACK
	// If the process fails to start, then the ends of the pipes
	// intended for the child process are still open.  Some Mac
	// users experience a lockup if we close our ends of the pipes
	// when the child's ends are still open.  If we ensure the
	// child's ends are closed, we prevent this lockup.  I have no
	// idea why the problem even happens or why this fix should
	// work.
	pipeAux.readEnd().reset();
	pipeCommand.readEnd().reset();
	pipeStatus.writeEnd().reset();
#endif

	if(need_status && !fin_status)
	{
		pipeStatus.readEnd().finalize();
		fin_status = true;
		if(readAndProcessStatusData())
		{
			doneTrigger.start();
			emit q->readyReadStatusLines();
			return;
		}
	}

	doTryDone();
}

void GPGProc::Private::doTryDone()
{
	if(!fin_process)
		return;

	if(need_status && !fin_status)
		return;

	emit q->debug(QStringLiteral("Done"));

	// get leftover data
	proc->setReadChannel(QProcess::StandardOutput);
	leftover_stdout = proc->readAll();

	proc->setReadChannel(QProcess::StandardError);
	leftover_stderr = proc->readAll();

	reset(ResetSession);
	if(fin_process_success)
		emit q->finished(exitCode);
	else
		emit q->error(error);
}

bool GPGProc::Private::readAndProcessStatusData()
{
	const QByteArray buf = pipeStatus.readEnd().read();
	if(buf.isEmpty())
		return false;

	return processStatusData(buf);
}

// return true if there are newly parsed lines available
bool GPGProc::Private::processStatusData(const QByteArray &buf)
{
	statusBuf.append(buf);

	// extract all lines
	QStringList list;
	while(true)
	{
		int n = statusBuf.indexOf('\n');
		if(n == -1)
			break;

		// extract the string from statusbuf
		++n;
		char *p = (char *)statusBuf.data();
		QByteArray cs(p, n);
		const int newsize = statusBuf.size() - n;
		memmove(p, p + n, newsize);
		statusBuf.resize(newsize);

		// convert to string without newline
		QString str = QString::fromUtf8(cs);
		str.truncate(str.length() - 1);

		// ensure it has a proper header
		if(str.left(9) != QLatin1String("[GNUPG:] "))
			continue;

		// take it off
		str = str.mid(9);

		// add to the list
		list += str;
	}

	if(list.isEmpty())
		return false;

	statusLines += list;
	return true;
}

GPGProc::GPGProc(QObject *parent)
:QObject(parent)
{
	d = new Private(this);
}

GPGProc::~GPGProc()
{
	delete d;
}

void GPGProc::reset()
{
	d->reset(ResetAll);
}

bool GPGProc::isActive() const
{
	return (d->proc ? true : false);
}

void GPGProc::start(const QString &bin, const QStringList &args, Mode mode)
{
	if(isActive())
		d->reset(ResetSessionAndData);

	if(mode == ExtendedMode)
	{
		if(!d->setupPipes(args.contains(QStringLiteral("-&?"))))
		{
			d->error = FailedToStart;

			// emit later
			QMetaObject::invokeMethod(this, "error", Qt::QueuedConnection, Q_ARG(gpgQCAPlugin::GPGProc::Error, d->error));
			return;
		}

		d->need_status = true;

		emit debug(QStringLiteral("Pipe setup complete"));
	}

	d->proc = new SProcess(d);

#ifdef Q_OS_UNIX
	QList<int> plist;
	if(d->pipeAux.readEnd().isValid())
		plist += d->pipeAux.readEnd().id();
	if(d->pipeCommand.readEnd().isValid())
		plist += d->pipeCommand.readEnd().id();
	if(d->pipeStatus.writeEnd().isValid())
		plist += d->pipeStatus.writeEnd().id();
	d->proc->setInheritPipeList(plist);
#endif

	// enable the pipes we want
	if(d->pipeAux.writeEnd().isValid())
		d->pipeAux.writeEnd().enable();
	if(d->pipeCommand.writeEnd().isValid())
		d->pipeCommand.writeEnd().enable();
	if(d->pipeStatus.readEnd().isValid())
		d->pipeStatus.readEnd().enable();

	d->proc_relay = new QProcessSignalRelay(d->proc, d);
	connect(d->proc_relay, &QProcessSignalRelay::started, d, &GPGProc::Private::proc_started);
	connect(d->proc_relay, &QProcessSignalRelay::readyReadStandardOutput, d, &GPGProc::Private::proc_readyReadStandardOutput);
	connect(d->proc_relay, &QProcessSignalRelay::readyReadStandardError, d, &GPGProc::Private::proc_readyReadStandardError);
	connect(d->proc_relay, &QProcessSignalRelay::bytesWritten, d, &GPGProc::Private::proc_bytesWritten);
	connect(d->proc_relay, &QProcessSignalRelay::finished, d, &GPGProc::Private::proc_finished);
	connect(d->proc_relay, &QProcessSignalRelay::error, d, &GPGProc::Private::proc_error);

	d->bin = bin;
	d->args = args;
	d->mode = mode;
	d->startTrigger.start();
}

QByteArray GPGProc::readStdout()
{
	if(d->proc)
	{
		d->proc->setReadChannel(QProcess::StandardOutput);
		return d->proc->readAll();
	}
	else
	{
		const QByteArray a = d->leftover_stdout;
		d->leftover_stdout.clear();
		return a;
	}
}

QByteArray GPGProc::readStderr()
{
	if(d->proc)
	{
		d->proc->setReadChannel(QProcess::StandardError);
		return d->proc->readAll();
	}
	else
	{
		const QByteArray a = d->leftover_stderr;
		d->leftover_stderr.clear();
		return a;
	}
}

QStringList GPGProc::readStatusLines()
{
	const QStringList out = d->statusLines;
	d->statusLines.clear();
	return out;
}

void GPGProc::writeStdin(const QByteArray &a)
{
	if(!d->proc || a.isEmpty())
		return;

	if(d->proc->state() == QProcess::Running)
		d->proc->write(a);
	else
		d->pre_stdin += a;
}

void GPGProc::writeAux(const QByteArray &a)
{
	if(!d->proc || a.isEmpty())
		return;

	if(d->proc->state() == QProcess::Running)
		d->pipeAux.writeEnd().write(a);
	else
		d->pre_aux += a;
}

#ifdef QPIPE_SECURE
void GPGProc::writeCommand(const SecureArray &a)
#else
void GPGProc::writeCommand(const QByteArray &a)
#endif
{
	if(!d->proc || a.isEmpty())
		return;

	if(d->proc->state() == QProcess::Running)
#ifdef QPIPE_SECURE
		d->pipeCommand.writeEnd().writeSecure(a);
#else
		d->pipeCommand.writeEnd().write(a);
#endif
	else
		d->pre_command += a;
}

void GPGProc::closeStdin()
{
	if(!d->proc)
		return;

	if(d->proc->state() == QProcess::Running)
	{
		d->proc->waitForBytesWritten();
		d->proc->closeWriteChannel();
	}
	else
	{
		d->pre_stdin_close = true;
	}
}

void GPGProc::closeAux()
{
	if(!d->proc)
		return;

	if(d->proc->state() == QProcess::Running)
		d->pipeAux.writeEnd().close();
	else
		d->pre_aux_close = true;
}

void GPGProc::closeCommand()
{
	if(!d->proc)
		return;

	if(d->proc->state() == QProcess::Running)
		d->pipeCommand.writeEnd().close();
	else
		d->pre_command_close = true;
}

}
