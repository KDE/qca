/*
 * Copyright (C) 2006  Justin Karneges <justin@affinix.com>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "qca_support.h"

#include <QtCore>
#include "qpipe.h"

#ifdef Q_OS_WIN
# include <windows.h>
#else
# include <sys/termios.h>
# include <unistd.h>
# include <fcntl.h>
#endif

namespace QCA {

//----------------------------------------------------------------------------
// ConsoleWorker
//----------------------------------------------------------------------------
class ConsoleWorker : public QObject
{
	Q_OBJECT
private:
	QPipeEnd in, out;
	bool started;
	QByteArray in_left, out_left;

public:
	ConsoleWorker(QObject *parent = 0) : QObject(parent), in(this), out(this)
	{
		started = false;
	}

	~ConsoleWorker()
	{
		stop();
	}

	void start(Q_PIPE_ID in_id, Q_PIPE_ID out_id)
	{
		Q_ASSERT(!started);

		if(in_id != INVALID_Q_PIPE_ID)
		{
			in.take(in_id, QPipeDevice::Read);
			connect(&in, SIGNAL(readyRead()), SLOT(in_readyRead()));
			connect(&in, SIGNAL(closed()), SLOT(in_closed()));
			connect(&in, SIGNAL(error(QCA::QPipeEnd::Error)), SLOT(in_error(QCA::QPipeEnd::Error)));
			in.enable();
		}

		if(out_id != INVALID_Q_PIPE_ID)
		{
			out.take(out_id, QPipeDevice::Write);
			connect(&out, SIGNAL(bytesWritten(int)), SLOT(out_bytesWritten(int)));
			out.enable();
		}

		started = true;
	}

	void stop()
	{
		if(!started)
			return;

		if(in.isValid())
			in.finalizeAndRelease();
		if(out.isValid())
			out.release();

		in_left = in.read();
		out_left = out.takeBytesToWrite();

		started = false;
	}

public slots:
	bool isValid() const
	{
		return in.isValid();
	}

	void setSecurityEnabled(bool enabled)
	{
		in.setSecurityEnabled(enabled);
	}

	QByteArray read(int bytes = -1)
	{
		return in.read(bytes);
	}

	void write(const QByteArray &a)
	{
		out.write(a);
	}

	QSecureArray readSecure(int bytes = -1)
	{
		return in.readSecure(bytes);
	}

	void writeSecure(const QSecureArray &a)
	{
		out.writeSecure(a);
	}

	int bytesAvailable() const
	{
		return in.bytesAvailable();
	}

	int bytesToWrite() const
	{
		return in.bytesToWrite();
	}

public:
	QByteArray takeBytesToRead()
	{
		QByteArray a = in_left;
		in_left.clear();
		return a;
	}

	QByteArray takeBytesToWrite()
	{
		QByteArray a = out_left;
		out_left.clear();
		return a;
	}

signals:
	void readyRead();
	void bytesWritten(int bytes);
	void closed();

private slots:
	void in_readyRead()
	{
		emit readyRead();
	}

	void out_bytesWritten(int bytes)
	{
		emit bytesWritten(bytes);
	}

	void in_closed()
	{
		emit closed();
	}

	void in_error(QCA::QPipeEnd::Error)
	{
		emit closed();
	}
};

//----------------------------------------------------------------------------
// ConsoleThread
//----------------------------------------------------------------------------
class ConsoleThread : public SyncThread
{
	Q_OBJECT
public:
	ConsoleWorker *worker;
	QMutex m;
	QWaitCondition w;
	Q_PIPE_ID _in_id, _out_id;
	QByteArray in_left, out_left;

	ConsoleThread(QObject *parent = 0) : SyncThread(parent)
	{
		qRegisterMetaType<QSecureArray>("QSecureArray");
	}

	~ConsoleThread()
	{
		stop();
	}

	void start(Q_PIPE_ID in_id, Q_PIPE_ID out_id)
	{
		_in_id = in_id;
		_out_id = out_id;
		SyncThread::start();
	}

	void stop()
	{
		SyncThread::stop();
	}

	QVariant mycall(QObject *obj, const char *method, const QVariantList &args = QVariantList())
	{
		QVariant ret;
		bool ok;
		ret = call(obj, method, args, &ok);
		Q_ASSERT(ok);
		return ret;
	}

	bool isValid()
	{
		return mycall(worker, "isValid").toBool();
	}

	void setSecurityEnabled(bool enabled)
	{
		mycall(worker, "setSecurityEnabled", QVariantList() << enabled);
	}

	QByteArray read(int bytes = -1)
	{
		return mycall(worker, "read", QVariantList() << bytes).toByteArray();
	}

	void write(const QByteArray &a)
	{
		mycall(worker, "write", QVariantList() << a);
	}

	QSecureArray readSecure(int bytes = -1)
	{
		return qVariantValue<QSecureArray>(mycall(worker, "readSecure", QVariantList() << bytes));
	}

	void writeSecure(const QSecureArray &a)
	{
		mycall(worker, "writeSecure", QVariantList() << qVariantFromValue<QSecureArray>(a));
	}

	int bytesAvailable()
	{
		return mycall(worker, "bytesAvailable").toInt();
	}

	int bytesToWrite()
	{
		return mycall(worker, "bytesToWrite").toInt();
	}

	QByteArray takeBytesToRead()
	{
		QByteArray a = in_left;
		in_left.clear();
		return a;
	}

	QByteArray takeBytesToWrite()
	{
		QByteArray a = out_left;
		out_left.clear();
		return a;
	}

signals:
	void readyRead();
	void bytesWritten(int);
	void closed();

protected:
	virtual void atStart()
	{
		worker = new ConsoleWorker;

		// use direct connections here, so that the emits come from
		//   the other thread.  we can also connect to our own
		//   signals to avoid having to make slots just to emit.
		connect(worker, SIGNAL(readyRead()), SIGNAL(readyRead()), Qt::DirectConnection);
		connect(worker, SIGNAL(bytesWritten(int)), SIGNAL(bytesWritten(int)), Qt::DirectConnection);
		connect(worker, SIGNAL(closed()), SIGNAL(closed()), Qt::DirectConnection);

		worker->start(_in_id, _out_id);
	}

	virtual void atEnd()
	{
		in_left = worker->takeBytesToRead();
		out_left = worker->takeBytesToWrite();
		delete worker;
	}
};

//----------------------------------------------------------------------------
// Console
//----------------------------------------------------------------------------
class ConsolePrivate : public QObject
{
	Q_OBJECT
public:
	Console *q;

	bool started;
	Console::TerminalMode mode;
	ConsoleThread *thread;
	ConsoleReference *ref;

#ifdef Q_OS_WIN
	DWORD old_mode;
#else
	struct termios old_term_attr;
#endif

	ConsolePrivate(Console *_q) : QObject(_q), q(_q)
	{
		started = false;
		mode = Console::Default;
		thread = new ConsoleThread(this);
		ref = 0;
	}

	~ConsolePrivate()
	{
		delete thread;
		setInteractive(Console::Default);
	}

	void setInteractive(Console::TerminalMode m)
	{
		// no change
		if(m == mode)
			return;

		if(m == Console::Interactive)
		{
#ifdef Q_OS_WIN
			HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
			GetConsoleMode(h, &old_mode);
			SetConsoleMode(h, old_mode & (~ENABLE_LINE_INPUT & ~ENABLE_ECHO_INPUT));
#else
			int fd = 0; // stdin
			struct termios attr;
			tcgetattr(fd, &attr);
			old_term_attr = attr;

			attr.c_lflag &= ~(ECHO);    // turn off the echo flag
			attr.c_lflag &= ~(ICANON);  // no wait for a newline
			attr.c_cc[VMIN] = 1;        // read at least 1 char
			attr.c_cc[VTIME] = 0;       // set wait time to zero

			// set the new attributes
			tcsetattr(fd, TCSAFLUSH, &attr);
#endif
		}
		else
		{
#ifdef Q_OS_WIN
			HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
			SetConsoleMode(h, old_mode);
#else
			int fd = 0; // stdin
			tcsetattr(fd, TCSANOW, &old_term_attr);
#endif
		}

		mode = m;
	}
};

static Console *g_console = 0;

Console::Console(ChannelMode cmode, TerminalMode tmode, QObject *parent)
:QObject(parent)
{
	Q_ASSERT(g_console == 0);
	g_console = this;

	d = new ConsolePrivate(this);

	Q_PIPE_ID in = INVALID_Q_PIPE_ID;
	Q_PIPE_ID out = INVALID_Q_PIPE_ID;

#ifdef Q_OS_WIN
	in = GetStdHandle(STD_INPUT_HANDLE);
#else
	in = 0;
#endif
	if(cmode == ReadWrite)
	{
#ifdef Q_OS_WIN
		out = GetStdHandle(STD_OUTPUT_HANDLE);
#else
		out = 1;
#endif
	}

	d->setInteractive(tmode);
	d->thread->start(in, out);
}

Console::~Console()
{
	shutdown();
	delete d;
	g_console = 0;
}

Console *Console::instance()
{
	return g_console;
}

void Console::shutdown()
{
	d->thread->stop();
}

QByteArray Console::bytesLeftToRead()
{
	return d->thread->takeBytesToRead();
}

QByteArray Console::bytesLeftToWrite()
{
	return d->thread->takeBytesToWrite();
}

//----------------------------------------------------------------------------
// ConsoleReference
//----------------------------------------------------------------------------
class ConsoleReferencePrivate : public QObject
{
	Q_OBJECT
public:
	ConsoleReference *q;

	Console *console;
	ConsoleThread *thread;
	QTimer lateTrigger;
	bool late_read, late_close;

	ConsoleReferencePrivate(ConsoleReference *_q) : QObject(_q), q(_q), lateTrigger(this)
	{
		console = 0;
		thread = 0;
		connect(&lateTrigger, SIGNAL(timeout()), SLOT(doLate()));
		lateTrigger.setSingleShot(true);
	}

private slots:
	void doLate()
	{
		QPointer<QObject> self = this;
		if(late_read)
			emit q->readyRead();
		if(!self)
			return;
		if(late_close)
			emit q->closed();
	}
};

ConsoleReference::ConsoleReference(QObject *parent)
:QObject(parent)
{
	d = new ConsoleReferencePrivate(this);
}

ConsoleReference::~ConsoleReference()
{
	stop();
	delete d;
}

bool ConsoleReference::start(SecurityMode mode)
{
	Q_ASSERT(!d->console);

	Console *c = Console::instance();
	if(!c)
		return false;

	// one console reference at a time
	Q_ASSERT(c->d->ref == 0);

	d->console = c;
	d->thread = d->console->d->thread;
	d->console->d->ref = this;

	bool valid = d->thread->isValid();
	int avail = d->thread->bytesAvailable();

	// pipe already closed and no data?  consider this an error
	if(!valid && avail == 0)
	{
		d->console->d->ref = 0;
		d->thread = 0;
		d->console = 0;
		return false;
	}

	// enable security?  it will last for this active session only
	if(mode == SecurityEnabled)
		d->thread->setSecurityEnabled(true);

	connect(d->thread, SIGNAL(readyRead()), SIGNAL(readyRead()));
	connect(d->thread, SIGNAL(bytesWritten(int)), SIGNAL(bytesWritten(int)));
	connect(d->thread, SIGNAL(closed()), SIGNAL(closed()));

	d->late_read = false;
	d->late_close = false;

	if(avail > 0)
		d->late_read = true;

	if(!valid)
		d->late_close = true;

	if(d->late_read || d->late_close)
		d->lateTrigger.start();

	return true;
}

void ConsoleReference::stop()
{
	if(!d->console)
		return;

	d->lateTrigger.stop();

	disconnect(d->thread, 0, this, 0);

	// automatically disable security when we go inactive
	d->thread->setSecurityEnabled(false);

	d->console->d->ref = 0;
	d->thread = 0;
	d->console = 0;
}

QByteArray ConsoleReference::read(int bytes)
{
	return d->thread->read(bytes);
}

void ConsoleReference::write(const QByteArray &a)
{
	d->thread->write(a);
}

QSecureArray ConsoleReference::readSecure(int bytes)
{
	return d->thread->readSecure(bytes);
}

void ConsoleReference::writeSecure(const QSecureArray &a)
{
	d->thread->writeSecure(a);
}

int ConsoleReference::bytesAvailable() const
{
	return d->thread->bytesAvailable();
}

int ConsoleReference::bytesToWrite() const
{
	return d->thread->bytesToWrite();
}

//----------------------------------------------------------------------------
// ConsolePrompt
//----------------------------------------------------------------------------
class ConsolePrompt::Private : public QObject
{
	Q_OBJECT
public:
	Synchronizer sync;
	ConsoleReference console;
	QSecureArray result;
	int at;
	bool done;
	bool enter;

	Private() : sync(this), console(this)
	{
		connect(&console, SIGNAL(readyRead()), SLOT(con_readyRead()));
		connect(&console, SIGNAL(closed()), SLOT(con_closed()));
	}

	bool start(bool enterMode)
	{
		result.clear();
		at = 0;
		done = false;
		enter = enterMode;
		if(!console.start(QCA::ConsoleReference::SecurityEnabled))
		{
			printf("Console input not available or closed\n");
			return false;
		}
		sync.waitForCondition();
		return true;
	}

	bool processChar(unsigned char c)
	{
		if(c == '\r' || c == '\n')
		{
			printf("\n");
			if(!done)
			{
				sync.conditionMet();
				done = true;
			}
			return false;
		}

		if(enter)
			return true;

		if(c == '\b' || c == 0x7f)
		{
			if(at > 0)
			{
				--at;
				printf("\b \b");
				fflush(stdout);
				result.resize(at);
			}
			return true;
		}
		else if(c < 0x20)
			return true;

		if(at + 1 > result.size())
			result.resize(at + 1);
		result[at++] = c;
	
		printf("*");
		fflush(stdout);
		return true;
	}

private slots:
	void con_readyRead()
	{
		while(console.bytesAvailable() > 0)
		{
			QSecureArray buf = console.readSecure(1);
			if(buf.isEmpty())
				continue;
			if(!processChar(buf[0]))
				break;
		}
	}

	void con_closed()
	{
		printf("Console closed\n");
		if(!done)
		{
			sync.conditionMet();
			done = true;
		}
	}
};

ConsolePrompt::ConsolePrompt(QObject *parent)
:QObject(parent)
{
	d = new Private;
}

ConsolePrompt::~ConsolePrompt()
{
	delete d;
}

QCA_EXPORT QSecureArray ConsolePrompt::getHidden(const QString &promptStr)
{
	printf("%s: ", qPrintable(promptStr));
	fflush(stdout);
	ConsolePrompt p;
	if(!p.d->start(false))
		return QSecureArray();
	return p.d->result;
}

QCA_EXPORT void ConsolePrompt::waitForEnter()
{
	ConsolePrompt p;
	p.d->start(true);
}

}

#include "console.moc"
