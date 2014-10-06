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

#pragma once

#define QPROC_SIGNAL_RELAY

#include "qpipe.h"
#include "sprocess.h"
#include "gpgproc.h"
#include <QObject>

namespace gpgQCAPlugin {

class QProcessSignalRelay : public QObject
{
	Q_OBJECT
public:
	QProcessSignalRelay(QProcess *proc, QObject *parent = 0)
	:QObject(parent)
	{
		qRegisterMetaType<QProcess::ProcessError>("QProcess::ProcessError");
		connect(proc, SIGNAL(started()), SLOT(proc_started()), Qt::QueuedConnection);
		connect(proc, SIGNAL(readyReadStandardOutput()), SLOT(proc_readyReadStandardOutput()), Qt::QueuedConnection);
		connect(proc, SIGNAL(readyReadStandardError()), SLOT(proc_readyReadStandardError()), Qt::QueuedConnection);
		connect(proc, SIGNAL(bytesWritten(qint64)), SLOT(proc_bytesWritten(qint64)), Qt::QueuedConnection);
		connect(proc, SIGNAL(finished(int)), SLOT(proc_finished(int)), Qt::QueuedConnection);
		connect(proc, SIGNAL(error(QProcess::ProcessError)), SLOT(proc_error(QProcess::ProcessError)), Qt::QueuedConnection);
	}

signals:
	void started();
	void readyReadStandardOutput();
	void readyReadStandardError();
	void bytesWritten(qint64);
	void finished(int);
	void error(QProcess::ProcessError);

public slots:
	void proc_started()
	{
		emit started();
	}

	void proc_readyReadStandardOutput()
	{
		emit readyReadStandardOutput();
	}

	void proc_readyReadStandardError()
	{
		emit readyReadStandardError();
	}

	void proc_bytesWritten(qint64 x)
	{
		emit bytesWritten(x);
	}

	void proc_finished(int x)
	{
		emit finished(x);
	}

	void proc_error(QProcess::ProcessError x)
	{
		emit error(x);
	}
};

enum ResetMode
{
	ResetSession        = 0,
	ResetSessionAndData = 1,
	ResetAll            = 2
};

class GPGProc::Private : public QObject
{
	Q_OBJECT
public:
	GPGProc *q;
	QString bin;
	QStringList args;
	GPGProc::Mode mode;
	SProcess *proc;
#ifdef QPROC_SIGNAL_RELAY
	QProcessSignalRelay *proc_relay;
#endif
	QCA::QPipe pipeAux, pipeCommand, pipeStatus;
	QByteArray statusBuf;
	QStringList statusLines;
	GPGProc::Error error;
	int exitCode;
	QCA::SafeTimer startTrigger, doneTrigger;

	QByteArray pre_stdin, pre_aux;
#ifdef QPIPE_SECURE
	QCA::SecureArray pre_command;
#else
	QByteArray pre_command;
#endif
	bool pre_stdin_close, pre_aux_close, pre_command_close;

	bool need_status, fin_process, fin_process_success, fin_status;
	QByteArray leftover_stdout;
	QByteArray leftover_stderr;

	Private(GPGProc *_q);
	~Private();
	void closePipes();
	void reset(ResetMode mode);
	bool setupPipes(bool makeAux);
	void setupArguments();

public slots:
	void doStart();
	void aux_written(int x);
	void aux_error(QCA::QPipeEnd::Error);
	void command_written(int x);
	void command_error(QCA::QPipeEnd::Error);
	void status_read();
	void status_error(QCA::QPipeEnd::Error e);
	void proc_started();
	void proc_readyReadStandardOutput();
	void proc_readyReadStandardError();
	void proc_bytesWritten(qint64 lx);
	void proc_finished(int x);
	void proc_error(QProcess::ProcessError x);
	void doTryDone();

private:
	bool readAndProcessStatusData();
	// return true if there are newly parsed lines available
	bool processStatusData(const QByteArray &buf);
	
	
};

} // end namespace gpgQCAPlugin
