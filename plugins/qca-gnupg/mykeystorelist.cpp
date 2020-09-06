/*
 * Copyright (C) 2003-2008  Justin Karneges <justin@affinix.com>
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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include "mykeystorelist.h"
#include "mypgpkeycontext.h"
#include "utils.h"
#include <QFileInfo>
#include <QMutexLocker>

using namespace QCA;

namespace gpgQCAPlugin {

Q_GLOBAL_STATIC(QMutex, ksl_mutex)

static MyKeyStoreList *keyStoreList = nullptr;
MyKeyStoreList::MyKeyStoreList(Provider *p)
    : KeyStoreListContext(p)
    , initialized(false)
    , gpg(find_bin(), this)
    , pubdirty(false)
    , secdirty(false)
    , ringWatch(this)
{
    QMutexLocker locker(ksl_mutex());
    keyStoreList = this;

    connect(&gpg, &GpgOp::finished, this, &MyKeyStoreList::gpg_finished);
    connect(&ringWatch, &RingWatch::changed, this, &MyKeyStoreList::ring_changed);
}

MyKeyStoreList::~MyKeyStoreList()
{
    QMutexLocker locker(ksl_mutex());
    keyStoreList = nullptr;
}

Provider::Context *MyKeyStoreList::clone() const
{
    return nullptr;
}

QString MyKeyStoreList::name(int) const
{
    return QStringLiteral("GnuPG Keyring");
}

KeyStore::Type MyKeyStoreList::type(int) const
{
    return KeyStore::PGPKeyring;
}

QString MyKeyStoreList::storeId(int) const
{
    return QStringLiteral("qca-gnupg");
}

QList<int> MyKeyStoreList::keyStores()
{
    // we just support one fixed keyring, if any
    QList<int> list;
    if (initialized)
        list += 0;
    return list;
}

void MyKeyStoreList::start()
{
    // kick start our init procedure:
    //   ensure gpg is installed
    //   obtain keyring file names for monitoring
    //   cache initial keyrings

    init_step = 0;
    gpg.doCheck();
}

bool MyKeyStoreList::isReadOnly(int) const
{
    return false;
}

QList<KeyStoreEntry::Type> MyKeyStoreList::entryTypes(int) const
{
    QList<KeyStoreEntry::Type> list;
    list += KeyStoreEntry::TypePGPSecretKey;
    list += KeyStoreEntry::TypePGPPublicKey;
    return list;
}

QList<KeyStoreEntryContext *> MyKeyStoreList::entryList(int)
{
    QMutexLocker locker(&ringMutex);

    QList<KeyStoreEntryContext *> out;

    foreach (const GpgOp::Key &pkey, pubkeys) {
        PGPKey pub, sec;

        const QString id = pkey.keyItems.first().id;

        MyPGPKeyContext *kc = new MyPGPKeyContext(provider());
        // not secret, in keyring
        kc->set(pkey, false, true, pkey.isTrusted);
        pub.change(kc);

        // optional
        sec = getSecKey(id, pkey.userIds);

        MyKeyStoreEntry *c = new MyKeyStoreEntry(pub, sec, provider());
        c->_storeId        = storeId(0);
        c->_storeName      = name(0);
        out.append(c);
    }

    return out;
}

KeyStoreEntryContext *MyKeyStoreList::entry(int, const QString &entryId)
{
    QMutexLocker locker(&ringMutex);

    PGPKey pub = getPubKey(entryId);
    if (pub.isNull())
        return nullptr;

    // optional
    const PGPKey sec = getSecKey(entryId, static_cast<MyPGPKeyContext *>(pub.context())->_props.userIds);

    MyKeyStoreEntry *c = new MyKeyStoreEntry(pub, sec, provider());
    c->_storeId        = storeId(0);
    c->_storeName      = name(0);
    return c;
}

KeyStoreEntryContext *MyKeyStoreList::entryPassive(const QString &serialized)
{
    QMutexLocker locker(&ringMutex);

    const QStringList parts = serialized.split(QLatin1Char(':'));
    if (parts.count() < 2)
        return nullptr;
    if (unescape_string(parts[0]) != QLatin1String("qca-gnupg-1"))
        return nullptr;

    QString entryId = unescape_string(parts[1]);
    if (entryId.isEmpty())
        return nullptr;

    PGPKey pub = getPubKey(entryId);
    if (pub.isNull())
        return nullptr;

    // optional
    const PGPKey sec = getSecKey(entryId, static_cast<MyPGPKeyContext *>(pub.context())->_props.userIds);

    MyKeyStoreEntry *c = new MyKeyStoreEntry(pub, sec, provider());
    c->_storeId        = storeId(0);
    c->_storeName      = name(0);
    return c;
}

// TODO: cache should reflect this change immediately
QString MyKeyStoreList::writeEntry(int, const PGPKey &key)
{
    const MyPGPKeyContext *kc  = static_cast<const MyPGPKeyContext *>(key.context());
    const QByteArray       buf = kc->toBinary();

    GpgOp gpg(find_bin());
    gpg.doImport(buf);
    gpg_waitForFinished(&gpg);
    gpg_keyStoreLog(gpg.readDiagnosticText());
    if (!gpg.success())
        return QString();

    return kc->_props.keyId;
}

// TODO: cache should reflect this change immediately
bool MyKeyStoreList::removeEntry(int, const QString &entryId)
{
    ringMutex.lock();
    PGPKey pub = getPubKey(entryId);
    ringMutex.unlock();

    const MyPGPKeyContext *kc          = static_cast<const MyPGPKeyContext *>(pub.context());
    QString                fingerprint = kc->_props.fingerprint;

    GpgOp gpg(find_bin());
    gpg.doDeleteKey(fingerprint);
    gpg_waitForFinished(&gpg);
    gpg_keyStoreLog(gpg.readDiagnosticText());
    return gpg.success();
}

MyKeyStoreList *MyKeyStoreList::instance()
{
    QMutexLocker locker(ksl_mutex());
    return keyStoreList;
}

void MyKeyStoreList::ext_keyStoreLog(const QString &str)
{
    if (str.isEmpty())
        return;

    // FIXME: collect and emit in one pass
    QMetaObject::invokeMethod(this, "diagnosticText", Qt::QueuedConnection, Q_ARG(QString, str));
}

PGPKey MyKeyStoreList::getPubKey(const QString &keyId) const
{
    int at = -1;
    for (int n = 0; n < pubkeys.count(); ++n) {
        if (pubkeys[n].keyItems.first().id == keyId) {
            at = n;
            break;
        }
    }
    if (at == -1)
        return PGPKey();

    const GpgOp::Key &pkey = pubkeys[at];

    PGPKey           pub;
    MyPGPKeyContext *kc = new MyPGPKeyContext(provider());
    // not secret, in keyring
    kc->set(pkey, false, true, pkey.isTrusted);
    pub.change(kc);

    return pub;
}

PGPKey MyKeyStoreList::getSecKey(const QString &keyId, const QStringList &userIdsOverride) const
{
    Q_UNUSED(userIdsOverride);

    int at = -1;
    for (int n = 0; n < seckeys.count(); ++n) {
        if (seckeys[n].keyItems.first().id == keyId) {
            at = n;
            break;
        }
    }
    if (at == -1)
        return PGPKey();

    const GpgOp::Key &skey = seckeys[at];

    PGPKey           sec;
    MyPGPKeyContext *kc = new MyPGPKeyContext(provider());
    // secret, in keyring, trusted
    kc->set(skey, true, true, true);
    // kc->_props.userIds = userIdsOverride;
    sec.change(kc);

    return sec;
}

PGPKey MyKeyStoreList::publicKeyFromId(const QString &keyId)
{
    QMutexLocker locker(&ringMutex);

    int at = -1;
    for (int n = 0; n < pubkeys.count(); ++n) {
        const GpgOp::Key &pkey = pubkeys[n];
        for (int k = 0; k < pkey.keyItems.count(); ++k) {
            const GpgOp::KeyItem &ki = pkey.keyItems[k];
            if (ki.id == keyId) {
                at = n;
                break;
            }
        }
        if (at != -1)
            break;
    }
    if (at == -1)
        return PGPKey();

    const GpgOp::Key &pkey = pubkeys[at];

    PGPKey           pub;
    MyPGPKeyContext *kc = new MyPGPKeyContext(provider());
    // not secret, in keyring
    kc->set(pkey, false, true, pkey.isTrusted);
    pub.change(kc);

    return pub;
}

PGPKey MyKeyStoreList::secretKeyFromId(const QString &keyId)
{
    QMutexLocker locker(&ringMutex);

    int at = -1;
    for (int n = 0; n < seckeys.count(); ++n) {
        const GpgOp::Key &skey = seckeys[n];
        for (int k = 0; k < skey.keyItems.count(); ++k) {
            const GpgOp::KeyItem &ki = skey.keyItems[k];
            if (ki.id == keyId) {
                at = n;
                break;
            }
        }
        if (at != -1)
            break;
    }
    if (at == -1)
        return PGPKey();

    const GpgOp::Key &skey = seckeys[at];

    PGPKey           sec;
    MyPGPKeyContext *kc = new MyPGPKeyContext(provider());
    // secret, in keyring, trusted
    kc->set(skey, true, true, true);
    sec.change(kc);

    return sec;
}

void MyKeyStoreList::gpg_finished()
{
    gpg_keyStoreLog(gpg.readDiagnosticText());

    if (!initialized) {
        // any steps that fail during init, just give up completely
        if (!gpg.success()) {
            ringWatch.clear();
            emit busyEnd();
            return;
        }

        // check
        if (init_step == 0) {
            // obtain keyring file names for monitoring
            init_step = 1;
            homeDir   = gpg.homeDir();
            gpg.doSecretKeyringFile();
        }
        // secret keyring filename
        else if (init_step == 1) {
            secring = QFileInfo(gpg.keyringFile()).canonicalFilePath();

            if (secring.isEmpty()) {
                secring = homeDir + QStringLiteral("/secring.gpg");
            }
            ringWatch.add(secring);

            // obtain keyring file names for monitoring
            init_step = 2;
            gpg.doPublicKeyringFile();
        }
        // public keyring filename
        else if (init_step == 2) {
            pubring = QFileInfo(gpg.keyringFile()).canonicalFilePath();
            if (pubring.isEmpty()) {
                pubring = homeDir + QStringLiteral("/pubring.gpg");
            }
            ringWatch.add(pubring);

            // cache initial keyrings
            init_step = 3;
            gpg.doSecretKeys();
        } else if (init_step == 3) {
            ringMutex.lock();
            seckeys = gpg.keys();
            ringMutex.unlock();

            // cache initial keyrings
            init_step = 4;
            gpg.doPublicKeys();
        } else if (init_step == 4) {
            ringMutex.lock();
            pubkeys = gpg.keys();
            ringMutex.unlock();

            initialized = true;
            handleDirtyRings();
            emit busyEnd();
        }
    } else {
        if (!gpg.success())
            return;

        const GpgOp::Type op = gpg.op();
        if (op == GpgOp::SecretKeys) {
            ringMutex.lock();
            seckeys = gpg.keys();
            ringMutex.unlock();

            secdirty = false;
        } else if (op == GpgOp::PublicKeys) {
            ringMutex.lock();
            pubkeys = gpg.keys();
            ringMutex.unlock();

            pubdirty = false;
        }

        if (!secdirty && !pubdirty) {
            emit storeUpdated(0);
            return;
        }

        handleDirtyRings();
    }
}

void MyKeyStoreList::ring_changed(const QString &filePath)
{
    ext_keyStoreLog(QStringLiteral("ring_changed: [%1]\n").arg(filePath));

    if (filePath == secring)
        sec_changed();
    else if (filePath == pubring)
        pub_changed();
}

void MyKeyStoreList::pub_changed()
{
    pubdirty = true;
    handleDirtyRings();
}

void MyKeyStoreList::sec_changed()
{
    secdirty = true;
    handleDirtyRings();
}

void MyKeyStoreList::handleDirtyRings()
{
    if (!initialized || gpg.isActive())
        return;

    if (secdirty)
        gpg.doSecretKeys();
    else if (pubdirty)
        gpg.doPublicKeys();
}

} // end namespace gpgQCAPlugin
