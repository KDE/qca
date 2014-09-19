/*
 * qca_safeobj.cpp - Qt Cryptographic Architecture
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

#include "qca_safeobj.h"
#include <QElapsedTimer>
#include <qmath.h>

namespace QCA
{

void releaseAndDeleteLater(QObject *owner, QObject *obj)
{
	obj->disconnect(owner);
	obj->setParent(0);
	obj->deleteLater();
}

class SafeTimer::Private : public QObject
{
	Q_OBJECT
	friend class SafeTimer;

public:
	Private(QObject *parent = 0);

	int timerId;
	bool isSingleShot;
	int interval;
	QElapsedTimer elapsedTimer;

public slots:
	void fixTimer();

signals:
	void needFix();

protected:
	void timerEvent(QTimerEvent *event);
};

SafeTimer::Private::Private(QObject *parent)
	: QObject(parent)
	, timerId(0)
	, isSingleShot(false)
	, interval(0)
	, elapsedTimer(QElapsedTimer())
{
	connect(this, SIGNAL(needFix()), SLOT(fixTimer()));
}

void SafeTimer::Private::fixTimer()
{
	// Start special timer to align ressurected old timer
	int msec = qMax(0, interval - static_cast<int>(elapsedTimer.elapsed()));
	startTimer(msec);
}

void SafeTimer::Private::timerEvent(QTimerEvent *event)
{
	killTimer(event->timerId());
	SafeTimer *safeTimer = qobject_cast<SafeTimer*>(parent());
	// Emulate timeout signal of not yet ressurected timer
	emit safeTimer->timeout();
	// Ressurect timer here
	safeTimer->start();
}

SafeTimer::SafeTimer(QObject *parent)
	: QObject(parent)
	, d(new Private(this))
{
}

SafeTimer::~SafeTimer()
{
}

int SafeTimer::interval() const
{
	return d->interval;
}

bool SafeTimer::isActive() const
{
	return d->timerId != 0;
}

bool SafeTimer::isSingleShot() const
{
	return d->isSingleShot;
}

void SafeTimer::setInterval(int msec)
{
	d->interval = msec;
}

void SafeTimer::setSingleShot(bool singleShot)
{
	d->isSingleShot = singleShot;
}

int SafeTimer::timerId() const
{
	return d->timerId;
}

void SafeTimer::start(int msec)
{
	d->interval = msec;
	start();
}

void SafeTimer::start()
{
	if (d->timerId)
		killTimer(d->timerId);

	d->elapsedTimer.start();
	d->timerId = QObject::startTimer(d->interval);
}

void SafeTimer::stop()
{
	if (d->timerId) {
		QObject::killTimer(d->timerId);
		d->timerId = 0;
	}
}

bool SafeTimer::event(QEvent *event)
{
	if (event->type() == QEvent::ThreadChange && d->timerId /* timer is actived */) {
		// Timer dies when an object changes owner thread. This trick
		// used to ressurect old timer in the new thread.
		// Signal is emited in the old thread but will be gotten in the new one.
		emit d->needFix();
		stop();
	}

	return QObject::event(event);
}

void SafeTimer::timerEvent(QTimerEvent *event)
{
	Q_UNUSED(event);

	emit timeout();
	if (d->isSingleShot)
		stop();
}

} // end namespace QCA

#include "qca_safeobj.moc"
