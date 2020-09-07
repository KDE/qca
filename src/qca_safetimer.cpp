/*
 * qca_safetimer.cpp - Qt Cryptographic Architecture
 * Copyright (C) 2014  Ivan Romanov <drizt@land.ru>
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

#include "qca_safetimer.h"
#include <QElapsedTimer>
#include <QTimerEvent>
#include <qmath.h>

// #define SAFETIMER_DEBUG

#ifdef SAFETIMER_DEBUG
#include <QDebug>
#endif

namespace QCA {

class SafeTimer::Private : public QObject
{
    Q_OBJECT
    friend class SafeTimer;

public:
    Private(QObject *parent = nullptr);

    int           timerId;
    int           fixerTimerId;
    bool          isSingleShot;
    int           interval;
    bool          isActive;
    QElapsedTimer elapsedTimer;

public Q_SLOTS:
    void fixTimer();

Q_SIGNALS:
    void needFix();

protected:
    bool event(QEvent *event) override;
    void timerEvent(QTimerEvent *event) override;
};

SafeTimer::Private::Private(QObject *parent)
    : QObject(parent)
    , timerId(0)
    , fixerTimerId(0)
    , isSingleShot(false)
    , interval(0)
    , isActive(false)
    , elapsedTimer(QElapsedTimer())
{
    connect(this, &Private::needFix, this, &Private::fixTimer, Qt::QueuedConnection);
}

void SafeTimer::Private::fixTimer()
{
    // Start special timer to align ressurected old timer
    const int msec = qMax(0, interval - static_cast<int>(elapsedTimer.elapsed()));

    fixerTimerId = startTimer(msec);
#ifdef SAFETIMER_DEBUG
    qDebug() << "START FIXTIMER: id =" << fixerTimerId << ", thread =" << thread() << ", interval =" << msec
             << parent();
#endif
}

bool SafeTimer::Private::event(QEvent *event)
{
    if (event->type() == QEvent::ThreadChange && fixerTimerId /* timer is actived */) {
        // Timer dies when an object changes owner thread. This trick
        // used to ressurect old timer in the new thread.
        // Signal is emited in the old thread but will be gotten in the new one.
#ifdef SAFETIMER_DEBUG
        qDebug() << "STOP FIXTIMER ON CHANGE THREAD: id =" << fixerTimerId << ", thread =" << thread() << parent();
#endif
        killTimer(fixerTimerId);
        fixerTimerId = 0;
        emit needFix();
    }

    return QObject::event(event);
}

void SafeTimer::Private::timerEvent(QTimerEvent *event)
{
    if (event->timerId() == fixerTimerId) {
#ifdef SAFETIMER_DEBUG
        qDebug() << "STOP FIXTIMER ON TIMEOUT: id =" << fixerTimerId << ", thread =" << thread() << parent();
#endif
        killTimer(fixerTimerId);
        fixerTimerId = 0;

        SafeTimer *safeTimer = qobject_cast<SafeTimer *>(parent());
        // Emulate timeout signal of not yet ressurected timer
        emit safeTimer->timeout();
        // Ressurect timer here if not a singleshot
        if (!isSingleShot)
            safeTimer->start();
        else
            isActive = false;
    } else {
#ifdef SAFETIMER_DEBUG
        qDebug() << "BAD PRIVATE TIME EVENT: id =" << timerId << ", thread =" << thread() << this
                 << ", badId =" << event->timerId() << parent();
#endif
    }
}

SafeTimer::SafeTimer(QObject *parent)
    : QObject()
    , d(new Private())
{
    // It must be done here. Initialization list can't be used.
    // Need to have proper class name. Look at TimerFixer::hook.
    setParent(parent);
    d->setParent(this);
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
    return d->isActive;
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

void SafeTimer::start(int msec)
{
    d->interval = msec;
    start();
}

void SafeTimer::start()
{
    stop();

    d->elapsedTimer.start();
    d->timerId  = QObject::startTimer(d->interval);
    d->isActive = d->timerId > 0;

#ifdef SAFETIMER_DEBUG
    qDebug() << "START TIMER: id =" << d->timerId << ", thread =" << thread() << ", interval =" << d->interval << this;
#endif
}

void SafeTimer::stop()
{
    if (d->timerId) {
        QObject::killTimer(d->timerId);
#ifdef SAFETIMER_DEBUG
        qDebug() << "STOP TIMER: id =" << d->timerId << ", thread =" << thread() << this;
#endif
        d->timerId = 0;
    }

    if (d->fixerTimerId) {
#ifdef SAFETIMER_DEBUG
        qDebug() << "STOP FIXER TIMER: id =" << d->fixerTimerId << ", thread =" << thread() << this;
#endif
        d->killTimer(d->fixerTimerId);
        d->fixerTimerId = 0;
    }
    d->isActive = false;
}

bool SafeTimer::event(QEvent *event)
{
    if (event->type() == QEvent::ThreadChange && d->timerId /* timer is actived */) {
        // Timer dies when an object changes owner thread. This trick
        // used to ressurect old timer in the new thread.
        // Signal is emited in the old thread but will be gotten in the new one.
#ifdef SAFETIMER_DEBUG
        qDebug() << "CHANGE THREAD: id =" << d->timerId << ", thread =" << thread() << this;
#endif
        killTimer(d->timerId);
        d->timerId = 0;
        emit d->needFix();
    }

    return QObject::event(event);
}

void SafeTimer::timerEvent(QTimerEvent *event)
{
    if (event->timerId() == d->timerId) {
        if (d->isSingleShot)
            stop();
        emit timeout();
    } else {
#ifdef SAFETIMER_DEBUG
        qDebug() << "BAD TIME EVENT: id =" << d->timerId << ", thread =" << thread() << this
                 << ", badId =" << event->timerId() << this;
#endif
    }
}

} // end namespace QCA

#include "qca_safetimer.moc"
