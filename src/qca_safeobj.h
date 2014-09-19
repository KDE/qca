/*
 * qca_safeobj.h - Qt Cryptographic Architecture
 * Copyright (C) 2008  Justin Karneges <justin@affinix.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301  USA
 *
 */

#ifndef QCA_SAFEOBJ_H
#define QCA_SAFEOBJ_H

// NOTE: this API is private to QCA

#include <QTimer>
#include <QSocketNotifier>
#include <QEvent>
#include <stdio.h>

namespace QCA {

// This function performs the following steps:
//   obj->disconnect(owner); // to prevent future signals to owner
//   obj->setParent(0);      // to prevent delete if parent is deleted
//   obj->deleteLater();     // now we can forget about the object
void releaseAndDeleteLater(QObject *owner, QObject *obj);

class SafeTimer : public QObject
{
	Q_OBJECT
public:
	SafeTimer(QObject *parent = 0);
	~SafeTimer();

	int interval() const;
	bool isActive() const;
	bool isSingleShot() const;
	void setInterval(int msec);
	void setSingleShot(bool singleShot);
	int timerId() const;

public slots:
	void start(int msec);
	void start();
	void stop();

signals:
	void timeout();

protected:
	bool event(QEvent *event);
	void timerEvent(QTimerEvent *event);

private:
	// Functions is used internally. Outer world mustn't have access them.
	void startTimer() {}
	void killTimer(int) {}

	class Private;
	Private *d;
};

class SafeSocketNotifier : public QObject
{
	Q_OBJECT
public:
	SafeSocketNotifier(int socket, QSocketNotifier::Type type,
		QObject *parent = 0) :
		QObject(parent)
	{
		sn = new QSocketNotifier(socket, type, this);
		connect(sn, SIGNAL(activated(int)), SIGNAL(activated(int)));
	}

	~SafeSocketNotifier()
	{
		sn->setEnabled(false);
		releaseAndDeleteLater(this, sn);
	}

	bool isEnabled() const             { return sn->isEnabled(); }
	int socket() const                 { return sn->socket(); }
	QSocketNotifier::Type type() const { return sn->type(); }

public slots:
	void setEnabled(bool enable)       { sn->setEnabled(enable); }

signals:
	void activated(int socket);

private:
	QSocketNotifier *sn;
};

}

#endif
