/*
 * Copyright (C) 2005  Justin Karneges <justin@affinix.com>
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
#include "qca_support.h"

#include <QAbstractEventDispatcher>
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEvent>
#include <QMutex>
#include <QPair>
#include <QWaitCondition>

// #define TIMERFIXER_DEBUG

#ifdef TIMERFIXER_DEBUG
#include <stdio.h>
#endif

namespace QCA {

//----------------------------------------------------------------------------
// TimerFixer
//----------------------------------------------------------------------------
class TimerFixer : public QObject
{
    Q_OBJECT
public:
    struct TimerInfo
    {
        int           id;
        int           interval;
        QElapsedTimer time;
        bool          fixInterval;

        TimerInfo()
            : fixInterval(false)
        {
        }
    };

    TimerFixer         *fixerParent;
    QList<TimerFixer *> fixerChildren;

    QObject                  *target;
    QAbstractEventDispatcher *ed;
    QList<TimerInfo>          timers;

    static bool haveFixer(QObject *obj)
    {
        return obj->findChild<TimerFixer *>() ? true : false;
    }

    TimerFixer(QObject *_target, TimerFixer *_fp = nullptr)
        : QObject(_target)
    {
        ed = nullptr;

        target      = _target;
        fixerParent = _fp;
        if (fixerParent)
            fixerParent->fixerChildren.append(this);

#ifdef TIMERFIXER_DEBUG
        printf("TimerFixer[%p] pairing with %p (%s)\n", this, target, target->metaObject()->className());
#endif
        edlink();
        target->installEventFilter(this);

        const QObjectList list = target->children();
        for (int n = 0; n < list.count(); ++n)
            hook(list[n]);
    }

    ~TimerFixer() override
    {
        if (fixerParent)
            fixerParent->fixerChildren.removeAll(this);

        QList<TimerFixer *> list = fixerChildren;
        for (int n = 0; n < list.count(); ++n)
            delete list[n];
        list.clear();

        updateTimerList(); // do this just to trip debug output

        target->removeEventFilter(this);
        edunlink();
#ifdef TIMERFIXER_DEBUG
        printf("TimerFixer[%p] unpaired with %p (%s)\n", this, target, target->metaObject()->className());
#endif
    }

    bool event(QEvent *e) override
    {
        switch (e->type()) {
        case QEvent::ThreadChange: // this happens second
            // printf("TimerFixer[%p] self changing threads\n", this);
            edunlink();
            QMetaObject::invokeMethod(this, "fixTimers", Qt::QueuedConnection);
            break;
        default:
            break;
        }

        return QObject::event(e);
    }

    bool eventFilter(QObject *, QEvent *e) override
    {
        switch (e->type()) {
        case QEvent::ChildAdded:
            hook(((QChildEvent *)e)->child());
            break;
        case QEvent::ChildRemoved:
            unhook(((QChildEvent *)e)->child());
            break;
        case QEvent::Timer:
            handleTimerEvent(((QTimerEvent *)e)->timerId());
            break;
        case QEvent::ThreadChange: // this happens first
#ifdef TIMERFIXER_DEBUG
            printf("TimerFixer[%p] target changing threads\n", this);
#endif
            break;
        default:
            break;
        }

        return false;
    }

private Q_SLOTS:
    void edlink()
    {
        ed = QAbstractEventDispatcher::instance();
        // printf("TimerFixer[%p] linking to dispatcher %p\n", this, ed);
        connect(ed, &QAbstractEventDispatcher::aboutToBlock, this, &TimerFixer::ed_aboutToBlock);
    }

    void edunlink()
    {
        // printf("TimerFixer[%p] unlinking from dispatcher %p\n", this, ed);
        if (ed) {
            disconnect(ed, &QAbstractEventDispatcher::aboutToBlock, this, &TimerFixer::ed_aboutToBlock);
            ed = nullptr;
        }
    }

    void ed_aboutToBlock()
    {
        // printf("TimerFixer[%p] aboutToBlock\n", this);
        updateTimerList();
    }

    void fixTimers()
    {
        updateTimerList();
        edlink();

        for (int n = 0; n < timers.count(); ++n) {
            TimerInfo &info = timers[n];

            QThread                  *objectThread = target->thread();
            QAbstractEventDispatcher *ed           = QAbstractEventDispatcher::instance(objectThread);

            const int timeLeft = qMax(info.interval - static_cast<int>(info.time.elapsed()), 0);
            info.fixInterval   = true;
            ed->unregisterTimer(info.id);
            info.id = ed->registerTimer(timeLeft, Qt::CoarseTimer, target);

#ifdef TIMERFIXER_DEBUG
            printf("TimerFixer[%p] adjusting [%d] to %d\n", this, info.id, timeLeft);
#endif
        }
    }

private:
    void hook(QObject *obj)
    {
        // don't watch a fixer or any object that already has one
        // SafeTimer has own method to fix timers, skip it too
        if (obj == this || qobject_cast<TimerFixer *>(obj) || haveFixer(obj) || qobject_cast<SafeTimer *>(obj))
            return;

        new TimerFixer(obj, this);
    }

    void unhook(QObject *obj)
    {
        TimerFixer *t = nullptr;
        for (int n = 0; n < fixerChildren.count(); ++n) {
            if (fixerChildren[n]->target == obj)
                t = fixerChildren[n];
        }
        delete t;
    }

    void handleTimerEvent(int id)
    {
        bool found = false;
        int  n;
        for (n = 0; n < timers.count(); ++n) {
            if (timers[n].id == id) {
                found = true;
                break;
            }
        }
        if (!found) {
            // printf("*** unrecognized timer [%d] activated ***\n", id);
            return;
        }

        TimerInfo &info = timers[n];
#ifdef TIMERFIXER_DEBUG
        printf("TimerFixer[%p] timer [%d] activated!\n", this, info.id);
#endif

        if (info.fixInterval) {
#ifdef TIMERFIXER_DEBUG
            printf("restoring correct interval (%d)\n", info.interval);
#endif
            info.fixInterval = false;
            ed->unregisterTimer(info.id);
            info.id = ed->registerTimer(info.interval, Qt::CoarseTimer, target);
        }

        info.time.start();
    }

    void updateTimerList()
    {
        QList<QAbstractEventDispatcher::TimerInfo> edtimers;
        if (ed)
            edtimers = ed->registeredTimers(target);

        // removed?
        for (int n = 0; n < timers.count(); ++n) {
            bool found = false;
            int  id    = timers[n].id;
            for (int i = 0; i < edtimers.count(); ++i) {
                if (edtimers[i].timerId == id) {
                    found = true;
                    break;
                }
            }

            if (!found) {
                timers.removeAt(n);
                --n;
#ifdef TIMERFIXER_DEBUG
                printf("TimerFixer[%p] timer [%d] removed\n", this, id);
#endif
            }
        }

        // added?
        for (int n = 0; n < edtimers.count(); ++n) {
            int  id    = edtimers[n].timerId;
            bool found = false;
            for (int i = 0; i < timers.count(); ++i) {
                if (timers[i].id == id) {
                    found = true;
                    break;
                }
            }

            if (!found) {
                TimerInfo info;
                info.id       = id;
                info.interval = edtimers[n].interval;
                info.time.start();
                timers += info;
#ifdef TIMERFIXER_DEBUG
                printf("TimerFixer[%p] timer [%d] added (interval=%d)\n", this, info.id, info.interval);
#endif
            }
        }
    }
};

//----------------------------------------------------------------------------
// Synchronizer
//----------------------------------------------------------------------------
class SynchronizerAgent : public QObject
{
    Q_OBJECT
public:
    SynchronizerAgent(QObject *parent = nullptr)
        : QObject(parent)
    {
        QMetaObject::invokeMethod(this, "started", Qt::QueuedConnection);
    }

Q_SIGNALS:
    void started();
};

class Synchronizer::Private : public QThread
{
    Q_OBJECT
public:
    Synchronizer *q;

    bool active;
    bool do_quit;
    bool cond_met;

    QObject           *obj;
    QEventLoop        *loop;
    SynchronizerAgent *agent;
    TimerFixer        *fixer;
    QMutex             m;
    QWaitCondition     w;
    QThread           *orig_thread;

    Private(QObject *_obj, Synchronizer *_q)
        : QThread(_q)
        , q(_q)
        , active(false)
        , do_quit(false)
        , cond_met(false)
        , obj(_obj)
        , loop(nullptr)
        , agent(nullptr)
        , fixer(nullptr)
        , m()
        , w()
        , orig_thread(nullptr)
    {
        // SafeTimer has own method to fix timers, skip it too
        if (!qobject_cast<SafeTimer *>(obj))
            fixer = new TimerFixer(obj);
    }

    ~Private() override
    {
        stop();
        delete fixer;
    }

    void start()
    {
        if (active)
            return;

        m.lock();
        active  = true;
        do_quit = false;
        QThread::start();
        w.wait(&m);
        m.unlock();
    }

    void stop()
    {
        if (!active)
            return;

        m.lock();
        do_quit = true;
        w.wakeOne();
        m.unlock();
        wait();
        active = false;
    }

    bool waitForCondition(int msecs)
    {
        unsigned long time = ULONG_MAX;
        if (msecs != -1)
            time = msecs;

        // move object to the worker thread
        cond_met    = false;
        orig_thread = QThread::currentThread();
        q->setParent(nullptr); // don't follow the object
        QObject *orig_parent = obj->parent();
        obj->setParent(nullptr); // unparent the target or the move will fail
        obj->moveToThread(this);

        // tell the worker thread to start, wait for completion
        m.lock();
        w.wakeOne();
        if (!w.wait(&m, time)) {
            if (loop) {
                // if we timed out, tell the worker to quit
                QMetaObject::invokeMethod(loop, "quit");
                w.wait(&m);
            }
        }

        // at this point the worker is done.  cleanup and return
        m.unlock();

        // restore parents
        obj->setParent(orig_parent);
        q->setParent(obj);

        return cond_met;
    }

    void conditionMet()
    {
        if (!loop)
            return;
        loop->quit();
        cond_met = true;
    }

protected:
    void run() override
    {
        m.lock();
        QEventLoop eventLoop;

        while (true) {
            // thread now sleeps, waiting for work
            w.wakeOne();
            w.wait(&m);
            if (do_quit) {
                m.unlock();
                break;
            }

            loop  = &eventLoop;
            agent = new SynchronizerAgent;
            connect(agent, &SynchronizerAgent::started, this, &Private::agent_started, Qt::DirectConnection);

            // run the event loop
            eventLoop.exec();

            delete agent;
            agent = nullptr;

            // eventloop done, flush pending events
            QCoreApplication::instance()->sendPostedEvents();
            QCoreApplication::instance()->sendPostedEvents(nullptr, QEvent::DeferredDelete);

            // and move the object back
            obj->moveToThread(orig_thread);

            m.lock();
            loop = nullptr;
            w.wakeOne();
        }
    }

private Q_SLOTS:
    void agent_started()
    {
        m.unlock();
    }
};

Synchronizer::Synchronizer(QObject *parent)
    : QObject(parent)
{
    d = new Private(parent, this);
}

Synchronizer::~Synchronizer()
{
    delete d;
}

bool Synchronizer::waitForCondition(int msecs)
{
    d->start();
    return d->waitForCondition(msecs);
}

void Synchronizer::conditionMet()
{
    d->conditionMet();
}

}

#include "synchronizer.moc"
