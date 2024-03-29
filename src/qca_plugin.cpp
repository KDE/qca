/*
 * Copyright (C) 2004-2008  Justin Karneges  <justin@affinix.com>
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

// Note: The basic thread-safety approach with the plugin manager is that
//   it is safe to add/get providers, however it is unsafe to remove them.
//   The expectation is that providers will almost always be unloaded on
//   application shutdown.  For safe provider unload, ensure no threads are
//   using the manager, the provider in question, nor any sub-objects from
//   the provider.

#include "qca_plugin.h"

#include "qcaprovider.h"

#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QLibrary>
#include <QPluginLoader>

#define PLUGIN_SUBDIR QStringLiteral("crypto")

namespace QCA {

// from qca_core.cpp
QVariantMap getProviderConfig_internal(Provider *p);

// from qca_default.cpp
QStringList skip_plugins(Provider *defaultProvider);
QStringList plugin_priorities(Provider *defaultProvider);

// stupidly simple log truncation function.  if the log exceeds size chars,
//   then throw out the top half, to nearest line.
QString truncate_log(const QString &in, int size)
{
    if (size < 2 || in.length() < size)
        return in;

    // start by pointing at the last chars
    int at = in.length() - (size / 2);

    // if the previous char is a newline, then this is a perfect cut.
    //   otherwise, we need to skip to after the next newline.
    if (in[at - 1] != QLatin1Char('\n')) {
        while (at < in.length() && in[at] != QLatin1Char('\n')) {
            ++at;
        }

        // at this point we either reached a newline, or end of
        //   the entire buffer

        if (in[at] == QLatin1Char('\n'))
            ++at;
    }

    return in.mid(at);
}

static ProviderManager *g_pluginman = nullptr;

static void logDebug(const QString &str)
{
    if (g_pluginman)
        g_pluginman->appendDiagnosticText(str + QLatin1Char('\n'));
}

static bool validVersion(int ver)
{
    // major version must be equal, minor version must be equal or lesser
    if ((ver & 0xff0000) == (QCA_VERSION & 0xff0000) && (ver & 0xff00) <= (QCA_VERSION & 0xff00))
        return true;
    return false;
}

class PluginInstance
{
private:
    QPluginLoader *_loader;
    QObject       *_instance;
    bool           _ownInstance;

    PluginInstance()
    {
    }

public:
    static PluginInstance *fromFile(const QString &fname, QString *errstr = nullptr)
    {
        QPluginLoader *loader = new QPluginLoader(fname);
        if (!loader->load()) {
            if (errstr)
                *errstr = QStringLiteral("failed to load: %1").arg(loader->errorString());
            delete loader;
            return nullptr;
        }
        QObject *obj = loader->instance();
        if (!obj) {
            if (errstr)
                *errstr = QStringLiteral("failed to get instance");
            loader->unload();
            delete loader;
            return nullptr;
        }
        PluginInstance *i = new PluginInstance;
        i->_loader        = loader;
        i->_instance      = obj;
        i->_ownInstance   = true;
        return i;
    }

    static PluginInstance *fromStatic(QObject *obj)
    {
        PluginInstance *i = new PluginInstance;
        i->_loader        = nullptr;
        i->_instance      = obj;
        i->_ownInstance   = false;
        return i;
    }

    static PluginInstance *fromInstance(QObject *obj)
    {
        PluginInstance *i = new PluginInstance;
        i->_loader        = nullptr;
        i->_instance      = obj;
        i->_ownInstance   = true;
        return i;
    }

    ~PluginInstance()
    {
        if (_ownInstance)
            delete _instance;

        if (_loader) {
            _loader->unload();
            delete _loader;
        }
    }

    PluginInstance(const PluginInstance &)            = delete;
    PluginInstance &operator=(const PluginInstance &) = delete;

    void claim()
    {
        if (_loader)
            _loader->moveToThread(nullptr);
        if (_ownInstance)
            _instance->moveToThread(nullptr);
    }

    QObject *instance()
    {
        return _instance;
    }
};

class ProviderItem
{
public:
    QString   fname;
    Provider *p;
    int       priority;
    QMutex    m;

    static ProviderItem *load(const QString &fname, QString *out_errstr = nullptr)
    {
        QString         errstr;
        PluginInstance *i = PluginInstance::fromFile(fname, &errstr);
        if (!i) {
            if (out_errstr)
                *out_errstr = errstr;
            return nullptr;
        }
        QCAPlugin *plugin = qobject_cast<QCAPlugin *>(i->instance());
        if (!plugin) {
            if (out_errstr)
                *out_errstr = QStringLiteral("does not offer QCAPlugin interface");
            delete i;
            return nullptr;
        }

        Provider *p = plugin->createProvider();
        if (!p) {
            if (out_errstr)
                *out_errstr = QStringLiteral("unable to create provider");
            delete i;
            return nullptr;
        }

        ProviderItem *pi = new ProviderItem(i, p);
        pi->fname        = fname;
        return pi;
    }

    static ProviderItem *loadStatic(QObject *instance, QString *errstr = nullptr)
    {
        PluginInstance *i      = PluginInstance::fromStatic(instance);
        QCAPlugin      *plugin = qobject_cast<QCAPlugin *>(i->instance());
        if (!plugin) {
            if (errstr)
                *errstr = QStringLiteral("does not offer QCAPlugin interface");
            delete i;
            return nullptr;
        }

        Provider *p = plugin->createProvider();
        if (!p) {
            if (errstr)
                *errstr = QStringLiteral("unable to create provider");
            delete i;
            return nullptr;
        }

        ProviderItem *pi = new ProviderItem(i, p);
        return pi;
    }

    static ProviderItem *fromClass(Provider *p)
    {
        ProviderItem *pi = new ProviderItem(nullptr, p);
        return pi;
    }

    ~ProviderItem()
    {
        delete p;
        delete instance;
    }

    void ensureInit()
    {
        QMutexLocker locker(&m);
        if (init_done)
            return;
        init_done = true;

        p->init();

        // load config
        QVariantMap conf = getProviderConfig_internal(p);
        if (!conf.isEmpty())
            p->configChanged(conf);
    }

    bool initted() const
    {
        return init_done;
    }

    // null if not a plugin
    QObject *objectInstance() const
    {
        if (instance)
            return instance->instance();
        else
            return nullptr;
    }

private:
    PluginInstance *instance;
    bool            init_done;

    ProviderItem(PluginInstance *_instance, Provider *_p)
    {
        instance  = _instance;
        p         = _p;
        init_done = false;

        // disassociate from threads
        if (instance)
            instance->claim();
    }
};

ProviderManager::ProviderManager()
{
    g_pluginman    = this;
    def            = nullptr;
    scanned_static = false;
}

ProviderManager::~ProviderManager()
{
    if (def)
        def->deinit();
    unloadAll();
    delete def;
    g_pluginman = nullptr;
}

void ProviderManager::scan()
{
    QMutexLocker locker(&providerMutex);

    // check static first, but only once
    if (!scanned_static) {
        logDebug(QStringLiteral("Checking Qt static plugins:"));
        const QObjectList list = QPluginLoader::staticInstances();
        if (list.isEmpty())
            logDebug(QStringLiteral("  (none)"));
        for (int n = 0; n < list.count(); ++n) {
            QObject      *instance  = list[n];
            const QString className = QString::fromLatin1(instance->metaObject()->className());

            QString       errstr;
            ProviderItem *i = ProviderItem::loadStatic(instance, &errstr);
            if (!i) {
                logDebug(QStringLiteral("  %1: %2").arg(className, errstr));
                continue;
            }

            const QString providerName = i->p->name();
            if (haveAlready(providerName)) {
                logDebug(
                    QStringLiteral("  %1: (as %2) already loaded provider, skipping").arg(className, providerName));
                delete i;
                continue;
            }

            const int ver = i->p->qcaVersion();
            if (!validVersion(ver)) {
                errstr = QString::asprintf("plugin version 0x%06x is in the future", ver);
                logDebug(QStringLiteral("  %1: (as %2) %3").arg(className, providerName, errstr));
                delete i;
                continue;
            }

            addItem(i, get_default_priority(providerName));
            logDebug(QStringLiteral("  %1: loaded as %2").arg(className, providerName));
        }
        scanned_static = true;
    }

#ifndef QCA_NO_PLUGINS
    if (qgetenv("QCA_NO_PLUGINS") == "1")
        return;

    const QStringList dirs = pluginPaths();
    if (dirs.isEmpty())
        logDebug(QStringLiteral("No Qt Library Paths"));
    for (const QString &dirIt : dirs) {
#ifdef DEVELOPER_MODE
        logDebug(QStringLiteral("Checking QCA build tree Path: %1").arg(QDir::toNativeSeparators(dirIt)));
#else
        logDebug(QStringLiteral("Checking Qt Library Path: %1").arg(QDir::toNativeSeparators(dirIt)));
#endif
        QDir libpath(dirIt);
        QDir dir(libpath.filePath(PLUGIN_SUBDIR));
        if (!dir.exists()) {
            logDebug(QStringLiteral("  (No 'crypto' subdirectory)"));
            continue;
        }

        const QStringList entryList = dir.entryList(QDir::Files);
        if (entryList.isEmpty()) {
            logDebug(QStringLiteral("  (No files in 'crypto' subdirectory)"));
            continue;
        }

        foreach (const QString &maybeFile, entryList) {
            const QFileInfo fi(dir.filePath(maybeFile));

            const QString filePath = fi.filePath(); // file name with path
            const QString fileName = fi.fileName(); // just file name

            if (!QLibrary::isLibrary(filePath)) {
                logDebug(QStringLiteral("  %1: not a library, skipping").arg(fileName));
                continue;
            }

            // make sure we haven't loaded this file before
            bool haveFile = false;
            for (int n = 0; n < providerItemList.count(); ++n) {
                ProviderItem *pi = providerItemList[n];
                if (!pi->fname.isEmpty() && pi->fname == filePath) {
                    haveFile = true;
                    break;
                }
            }
            if (haveFile) {
                logDebug(QStringLiteral("  %1: already loaded file, skipping").arg(fileName));
                continue;
            }

            QString       errstr;
            ProviderItem *i = ProviderItem::load(filePath, &errstr);
            if (!i) {
                logDebug(QStringLiteral("  %1: %2").arg(fileName, errstr));
                continue;
            }

            const QString className = QString::fromLatin1(i->objectInstance()->metaObject()->className());

            const QString providerName = i->p->name();
            if (haveAlready(providerName)) {
                logDebug(QStringLiteral("  %1: (class: %2, as %3) already loaded provider, skipping")
                             .arg(fileName, className, providerName));
                delete i;
                continue;
            }

            const int ver = i->p->qcaVersion();
            if (!validVersion(ver)) {
                errstr = QString::asprintf("plugin version 0x%06x is in the future", ver);
                logDebug(QStringLiteral("  %1: (class: %2, as %3) %4").arg(fileName, className, providerName, errstr));
                delete i;
                continue;
            }

            if (skip_plugins(def).contains(providerName)) {
                logDebug(QStringLiteral("  %1: (class: %2, as %3) explicitly disabled, skipping")
                             .arg(fileName, className, providerName));
                delete i;
                continue;
            }

            addItem(i, get_default_priority(providerName));
            logDebug(QStringLiteral("  %1: (class: %2) loaded as %3").arg(fileName, className, providerName));
        }
    }
#endif
}

bool ProviderManager::add(Provider *p, int priority)
{
    QMutexLocker locker(&providerMutex);

    const QString providerName = p->name();

    if (haveAlready(providerName)) {
        logDebug(QStringLiteral("Directly adding: %1: already loaded provider, skipping").arg(providerName));
        return false;
    }

    const int ver = p->qcaVersion();
    if (!validVersion(ver)) {
        QString errstr = QString::asprintf("plugin version 0x%06x is in the future", ver);
        logDebug(QStringLiteral("Directly adding: %1: %2").arg(providerName, errstr));
        return false;
    }

    ProviderItem *i = ProviderItem::fromClass(p);
    addItem(i, priority);
    logDebug(QStringLiteral("Directly adding: %1: loaded").arg(providerName));
    return true;
}

bool ProviderManager::unload(const QString &name)
{
    for (int n = 0; n < providerItemList.count(); ++n) {
        ProviderItem *i = providerItemList[n];
        if (i->p && i->p->name() == name) {
            if (i->initted())
                i->p->deinit();

            delete i;
            providerItemList.removeAt(n);
            providerList.removeAt(n);

            logDebug(QStringLiteral("Unloaded: %1").arg(name));
            return true;
        }
    }

    return false;
}

void ProviderManager::unloadAll()
{
    foreach (ProviderItem *i, providerItemList) {
        if (i->initted())
            i->p->deinit();
    }

    while (!providerItemList.isEmpty()) {
        ProviderItem *i    = providerItemList.first();
        const QString name = i->p->name();
        delete i;
        providerItemList.removeFirst();
        providerList.removeFirst();

        logDebug(QStringLiteral("Unloaded: %1").arg(name));
    }
}

void ProviderManager::setDefault(Provider *p)
{
    QMutexLocker locker(&providerMutex);

    if (def)
        delete def;
    def = p;
    if (def) {
        def->init();
        QVariantMap conf = getProviderConfig_internal(def);
        if (!conf.isEmpty())
            def->configChanged(conf);
    }
}

Provider *ProviderManager::find(Provider *_p) const
{
    ProviderItem *i = nullptr;
    Provider     *p = nullptr;

    providerMutex.lock();
    if (_p == def) {
        p = def;
    } else {
        for (int n = 0; n < providerItemList.count(); ++n) {
            ProviderItem *pi = providerItemList[n];
            if (pi->p && pi->p == _p) {
                i = pi;
                p = pi->p;
                break;
            }
        }
    }
    providerMutex.unlock();

    if (i)
        i->ensureInit();
    return p;
}

Provider *ProviderManager::find(const QString &name) const
{
    ProviderItem *i = nullptr;
    Provider     *p = nullptr;

    providerMutex.lock();
    if (def && name == def->name()) {
        p = def;
    } else {
        for (int n = 0; n < providerItemList.count(); ++n) {
            ProviderItem *pi = providerItemList[n];
            if (pi->p && pi->p->name() == name) {
                i = pi;
                p = pi->p;
                break;
            }
        }
    }
    providerMutex.unlock();

    if (i)
        i->ensureInit();
    return p;
}

Provider *ProviderManager::findFor(const QString &name, const QString &type) const
{
    if (name.isEmpty()) {
        providerMutex.lock();
        const QList<ProviderItem *> list = providerItemList;
        providerMutex.unlock();

        // find the first one that can do it
        for (int n = 0; n < list.count(); ++n) {
            ProviderItem *pi = list[n];
            pi->ensureInit();
            if (pi->p && pi->p->features().contains(type))
                return pi->p;
        }

        // try the default provider as a last resort
        providerMutex.lock();
        Provider *p = def;
        providerMutex.unlock();
        if (p && p->features().contains(type))
            return p;

        return nullptr;
    } else {
        Provider *p = find(name);
        if (p && p->features().contains(type))
            return p;
        return nullptr;
    }
}

void ProviderManager::changePriority(const QString &name, int priority)
{
    QMutexLocker locker(&providerMutex);

    ProviderItem *i = nullptr;
    int           n = 0;
    for (; n < providerItemList.count(); ++n) {
        ProviderItem *pi = providerItemList[n];
        if (pi->p && pi->p->name() == name) {
            i = pi;
            break;
        }
    }
    if (!i)
        return;

    providerItemList.removeAt(n);
    providerList.removeAt(n);

    addItem(i, priority);
}

int ProviderManager::getPriority(const QString &name)
{
    QMutexLocker locker(&providerMutex);

    ProviderItem *i = nullptr;
    for (int n = 0; n < providerItemList.count(); ++n) {
        ProviderItem *pi = providerItemList[n];
        if (pi->p && pi->p->name() == name) {
            i = pi;
            break;
        }
    }
    if (!i)
        return -1;

    return i->priority;
}

QStringList ProviderManager::allFeatures() const
{
    QStringList featureList;

    providerMutex.lock();
    Provider *p = def;
    providerMutex.unlock();
    if (p)
        featureList = p->features();

    providerMutex.lock();
    const QList<ProviderItem *> list = providerItemList;
    providerMutex.unlock();
    for (int n = 0; n < list.count(); ++n) {
        ProviderItem *i = list[n];
        if (i->p)
            mergeFeatures(&featureList, i->p->features());
    }

    return featureList;
}

ProviderList ProviderManager::providers() const
{
    QMutexLocker locker(&providerMutex);

    return providerList;
}

QString ProviderManager::diagnosticText() const
{
    QMutexLocker locker(&logMutex);

    return dtext;
}

void ProviderManager::appendDiagnosticText(const QString &str)
{
    QMutexLocker locker(&logMutex);

    dtext += str;
    dtext = truncate_log(dtext, 20000);
}

void ProviderManager::clearDiagnosticText()
{
    QMutexLocker locker(&logMutex);

    dtext = QString();
}

void ProviderManager::addItem(ProviderItem *item, int priority)
{
    if (priority < 0) {
        // for -1, make the priority the same as the last item
        if (!providerItemList.isEmpty()) {
            const ProviderItem *last = providerItemList.last();
            item->priority           = last->priority;
        } else
            item->priority = 0;

        providerItemList.append(item);
        providerList.append(item->p);
    } else {
        // place the item before any other items with same or greater priority
        int n = 0;
        for (; n < providerItemList.count(); ++n) {
            const ProviderItem *i = providerItemList[n];
            if (i->priority >= priority)
                break;
        }

        item->priority = priority;
        providerItemList.insert(n, item);
        providerList.insert(n, item->p);
    }
}

bool ProviderManager::haveAlready(const QString &name) const
{
    if (def && name == def->name())
        return true;

    for (int n = 0; n < providerItemList.count(); ++n) {
        ProviderItem *pi = providerItemList[n];
        if (pi->p && pi->p->name() == name)
            return true;
    }

    return false;
}

void ProviderManager::mergeFeatures(QStringList *a, const QStringList &b)
{
    for (const QString &s : b) {
        if (!a->contains(s))
            a->append(s);
    }
}

int ProviderManager::get_default_priority(const QString &name) const
{
    const QStringList list = plugin_priorities(def);
    foreach (const QString &s, list) {
        // qca_default already sanity checks the strings
        const int     n     = s.indexOf(QLatin1Char(':'));
        const QString sname = s.mid(0, n);
#if QT_VERSION >= QT_VERSION_CHECK(5, 15, 2)
        const int spriority = QStringView(s).mid(n + 1).toInt();
#else
        const int spriority = s.midRef(n + 1).toInt();
#endif
        if (sname == name)
            return spriority;
    }
    return -1;
}

}
