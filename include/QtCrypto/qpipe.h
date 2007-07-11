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

/**
   \file qpipe.h

   Header file for the QPipe FIFO class

   \note You should not use this header directly from an
   application. You should just use <tt> \#include \<QtCrypto>
   </tt> instead.
*/

#ifndef QPIPE_H
#define QPIPE_H

#ifndef DOXYGEN_SHOULD_SKIP_THIS

#ifndef QPIPE_NO_SECURE
# define QPIPE_SECURE
#endif

#ifdef QPIPE_SECURE
# include <QtCrypto>
#else
# define QCA_EXPORT
#endif

// defs adapted qprocess_p.h
#ifdef Q_OS_WIN
#include <windows.h>
typedef HANDLE Q_PIPE_ID;
#define INVALID_Q_PIPE_ID INVALID_HANDLE_VALUE
#else
typedef int Q_PIPE_ID;
#define INVALID_Q_PIPE_ID -1
#endif

#endif

// Note: for Windows console, I/O must be in UTF-8.  Reads are guaranteed to
//   to completely decode (no partial characters).  Likewise, writes must
//   not contain partial characters.

namespace QCA {

// unbuffered direct pipe
class QCA_EXPORT QPipeDevice : public QObject
{
	Q_OBJECT
public:
        /**
	   The type of device
	*/
	enum Type
	{
		Read, ///< The pipe end can be read from
		Write ///< The pipe end can be written to
	};

	QPipeDevice(QObject *parent = 0);
	~QPipeDevice();

	Type type() const;                     // Read or Write
	bool isValid() const;                  // indicates if a pipe is held
	Q_PIPE_ID id() const;                  // pipe id (Win=HANDLE, Unix=int)
	int idAsInt() const;                   // pipe id turned into an integer

	void take(Q_PIPE_ID id, Type t);       // take over the pipe id, close the old
	void enable();                         // enables usage (read/write) of the pipe
	void close();                          // close the pipe
	void release();                        // let go of the pipe but don't close
	bool setInheritable(bool enabled);     // note: on windows, this operation changes the id

	int bytesAvailable() const;            // bytes available to read
	int read(char *data, int maxsize);     // return number read, 0 = EOF, -1 = error
	int write(const char *data, int size); // return number taken, ptr must stay valid. -1 on error
	int writeResult(int *written) const;   // 0 = success (wrote all), -1 = error (see written)

Q_SIGNALS:
	void notify();                         // can read or can write, depending on type

private:
	Q_DISABLE_COPY(QPipeDevice)

	class Private;
	friend class Private;
	Private *d;
};

/**
   A buffered higher-level pipe end

   This is either the read end or write end of a QPipe.
*/
class QCA_EXPORT QPipeEnd : public QObject
{
	Q_OBJECT
public:
	enum Error
	{
		ErrorEOF,
		ErrorBroken
	};

	QPipeEnd(QObject *parent = 0);
	~QPipeEnd();

	void reset();

	/**
	   The type of pipe end (either read or write)
	*/
	QPipeDevice::Type type() const;

	/**
	   Determine whether the pipe end is valid.

	   \note This does not mean the pipe is ready to be used - you
	   may need to call enable() first
	*/
	bool isValid() const;
	Q_PIPE_ID id() const;
	int idAsInt() const;

	void take(Q_PIPE_ID id, QPipeDevice::Type t);
#ifdef QPIPE_SECURE
	void setSecurityEnabled(bool secure);
#endif
	/**
	   Enable the endpoint for the pipe

	   When endpoint is created, it is not
	   able to be used until it is enabled.
	*/
	void enable();

	/**
	   Close the end of the pipe
	   
	   \sa closed()
	*/
	void close();
	void release();
	bool setInheritable(bool enabled);

	void finalize(); // do an immediate read, and invalidate
	void finalizeAndRelease(); // same as above, but don't close pipe

	/**
	   Determine how many bytes are available to be read.

	   This only makes sense at the read end of the pipe

	   \sa readyRead() for a signal that can be used to determine
	   when there are bytes available to read.
	*/
	int bytesAvailable() const;
	int bytesToWrite() const;

	// normal i/o
	/**
	   Read bytes from the pipe. 

	   You can only call this on the read end of the pipe

	   \param bytes the number of bytes to read (-1 for all 
	   content).
	*/
	QByteArray read(int bytes = -1);
	void write(const QByteArray &a);

#ifdef QPIPE_SECURE
	// secure i/o
	SecureArray readSecure(int bytes = -1);
	void writeSecure(const SecureArray &a);
#endif

	QByteArray takeBytesToWrite();

#ifdef QPIPE_SECURE
	SecureArray takeBytesToWriteSecure();
#endif

Q_SIGNALS:
	/**
	   Emitted when there are bytes available to be read
	   from the read end of the pipe.

	   \sa bytesAvailable()
	*/
	void readyRead();

	/**
	   Emitted when bytes have been written to the 
	   write end of the pipe.

	   \param bytes the number of bytes written
	*/
	void bytesWritten(int bytes);

	/**
	   Emitted when the pipe is closed.

	   This is applicable to both the read end and write end of
	   the pipe. 
	*/
	void closed();
	void error(QCA::QPipeEnd::Error e);

private:
	Q_DISABLE_COPY(QPipeEnd)

	class Private;
	friend class Private;
	Private *d;
};

/**
   A FIFO buffer (named pipe) abstraction

   This class creates a full buffer, consisting of two ends
   (QPipeEnd). You can obtain each end (after calling create()) using
   readEnd() and writeEnd(), however you must call enable() on each end
   before using the pipe.

   By default, the pipe ends are not inheritable by child processes.  On
   Windows, the pipe is created with inheritability disabled.  On Unix, the
   FD_CLOEXEC flag is set on each end's file descriptor.
*/
class QCA_EXPORT QPipe
{
public:
	/**
	   Standard constructor

	   \note You must call create() before using the pipe ends.

	   \param parent the parent object for this object
	*/
	QPipe(QObject *parent = 0);

	~QPipe();

	/**
	   Reset the pipe.

	   At this point, the readEnd() and writeEnd() calls
	   will no longer be valid.
	*/
	void reset();

#ifdef QPIPE_SECURE
	/**
	   Create the pipe

	   \param secure whether to use secure memory (true) or not (false)
	*/
	bool create(bool secure = false);
#else
	/**
	   Create the pipe
	*/
	bool create();
#endif

	/**
	   The read end of the pipe.
	*/
	QPipeEnd & readEnd() { return i; }

	/**
	   The write end of the pipe.
	*/
	QPipeEnd & writeEnd() { return o; }

private:
	Q_DISABLE_COPY(QPipe)

	QPipeEnd i, o;
};

}

#endif
