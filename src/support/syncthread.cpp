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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301  USA
 *
 */

#include "qca_support.h"

#include <QEventLoop>
#include <QMetaMethod>
#include <QMutexLocker>
#include <QWaitCondition>

namespace QCA {

#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
int methodReturnType(const QMetaObject *obj, const QByteArray &method, const QList<QByteArray> &argTypes)
#else
QByteArray methodReturnType(
    const QMetaObject *     obj,
    const QByteArray &      method,
    const QList<QByteArray> argTypes) // clazy:exclude=function-args-by-ref NOLINT(performance-unnecessary-value-param)
                                      // TODO make argTypes const & when we break ABI
#endif
{
    for (int n = 0; n < obj->methodCount(); ++n) {
        QMetaMethod      m      = obj->method(n);
        const QByteArray sig    = m.methodSignature();
        int              offset = sig.indexOf('(');
        if (offset == -1)
            continue;
        const QByteArray name = sig.mid(0, offset);
        if (name != method)
            continue;
        if (m.parameterTypes() != argTypes)
            continue;

#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
        return m.returnType();
#else
        return m.typeName();
#endif
    }
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    return QMetaType::UnknownType;
#else
    return QByteArray();
#endif
}

bool invokeMethodWithVariants(QObject *           obj,
                              const QByteArray &  method,
                              const QVariantList &args,
                              QVariant *          ret,
                              Qt::ConnectionType  type)
{
    // QMetaObject::invokeMethod() has a 10 argument maximum
    if (args.count() > 10)
        return false;

    QList<QByteArray> argTypes;
    for (int n = 0; n < args.count(); ++n) {
        argTypes += args[n].typeName();
    }

    // get return type
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    const auto metatype = methodReturnType(obj->metaObject(), method, argTypes);
    if (metatype == QMetaType::UnknownType) {
        return false;
    }
#else
    int              metatype    = QMetaType::Void;
    const QByteArray retTypeName = methodReturnType(obj->metaObject(), method, argTypes);
    if (!retTypeName.isEmpty() && retTypeName != "void") {
        metatype = QMetaType::type(retTypeName.data());
        if (metatype == QMetaType::UnknownType) // lookup failed
            return false;
    }
#endif

    QGenericArgument arg[10];
    for (int n = 0; n < args.count(); ++n)
        arg[n] = QGenericArgument(args[n].typeName(), args[n].constData());

    QGenericReturnArgument retarg;
    QVariant               retval;

    if (metatype != QMetaType::Void) {
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
        retval = QVariant(QMetaType {metatype}, (const void *)nullptr);
#else
        retval = QVariant(metatype, (const void *)nullptr);
#endif
        retarg = QGenericReturnArgument(retval.typeName(), retval.data());
    }

    if (!QMetaObject::invokeMethod(obj,
                                   method.data(),
                                   type,
                                   retarg,
                                   arg[0],
                                   arg[1],
                                   arg[2],
                                   arg[3],
                                   arg[4],
                                   arg[5],
                                   arg[6],
                                   arg[7],
                                   arg[8],
                                   arg[9]))
        return false;

    if (retval.isValid() && ret)
        *ret = retval;
    return true;
}

//----------------------------------------------------------------------------
// SyncThread
//----------------------------------------------------------------------------
class SyncThreadAgent;

class SyncThread::Private : public QObject
{
    Q_OBJECT
public:
    SyncThread *     q;
    QMutex           m;
    QWaitCondition   w;
    QEventLoop *     loop;
    SyncThreadAgent *agent;
    bool             last_success;
    QVariant         last_ret;

    Private(SyncThread *_q)
        : QObject(_q)
        , q(_q)
    {
        loop  = nullptr;
        agent = nullptr;
    }

public Q_SLOTS:
    void agent_started();
    void agent_call_ret(bool success, const QVariant &ret);
};

class SyncThreadAgent : public QObject
{
    Q_OBJECT
public:
    SyncThreadAgent(QObject *parent = nullptr)
        : QObject(parent)
    {
        QMetaObject::invokeMethod(this, "started", Qt::QueuedConnection);
    }

Q_SIGNALS:
    void started();
    void call_ret(bool success, const QVariant &ret);

public Q_SLOTS:
    void call_do(QObject *obj, const QByteArray &method, const QVariantList &args)
    {
        QVariant ret;
        bool     ok = invokeMethodWithVariants(obj, method, args, &ret, Qt::DirectConnection);
        emit     call_ret(ok, ret);
    }
};

SyncThread::SyncThread(QObject *parent)
    : QThread(parent)
{
    d = new Private(this);
    qRegisterMetaType<QVariant>("QVariant");
    qRegisterMetaType<QVariantList>("QVariantList");
}

SyncThread::~SyncThread()
{
    stop();
    delete d;
}

void SyncThread::start()
{
    QMutexLocker locker(&d->m);
    Q_ASSERT(!d->loop);
    QThread::start();
    d->w.wait(&d->m);
}

void SyncThread::stop()
{
    QMutexLocker locker(&d->m);
    if (!d->loop)
        return;
    QMetaObject::invokeMethod(d->loop, "quit");
    d->w.wait(&d->m);
    wait();
}

QVariant SyncThread::call(QObject *obj, const QByteArray &method, const QVariantList &args, bool *ok)
{
    QMutexLocker locker(&d->m);
    bool         ret;
    Q_UNUSED(ret); // In really ret is used. I use this hack to suppress a compiler warning
    // clang-format off
    // Otherwise the QObject* gets turned into Object * that is not normalized and is slightly slower
    ret = QMetaObject::invokeMethod(d->agent, "call_do",
                                    Qt::QueuedConnection, Q_ARG(QObject*, obj),
                                    Q_ARG(QByteArray, method), Q_ARG(QVariantList, args));
    // clang-format on
    Q_ASSERT(ret);
    d->w.wait(&d->m);
    if (ok)
        *ok = d->last_success;
    QVariant v  = d->last_ret;
    d->last_ret = QVariant();
    return v;
}

void SyncThread::run()
{
    d->m.lock();
    d->loop  = new QEventLoop;
    d->agent = new SyncThreadAgent;
    connect(d->agent, &SyncThreadAgent::started, d, &Private::agent_started, Qt::DirectConnection);
    connect(d->agent, &SyncThreadAgent::call_ret, d, &Private::agent_call_ret, Qt::DirectConnection);
    d->loop->exec();
    d->m.lock();
    atEnd();
    delete d->agent;
    delete d->loop;
    d->agent = nullptr;
    d->loop  = nullptr;
    d->w.wakeOne();
    d->m.unlock();
}

void SyncThread::Private::agent_started()
{
    q->atStart();
    w.wakeOne();
    m.unlock();
}

void SyncThread::Private::agent_call_ret(bool success, const QVariant &ret)
{
    QMutexLocker locker(&m);
    last_success = success;
    last_ret     = ret;
    w.wakeOne();
}

}

#include "syncthread.moc"
