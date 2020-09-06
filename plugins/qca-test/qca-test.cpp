/*
 * Copyright (C) 2007  Justin Karneges <justin@affinix.com>
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

#include <QtCore>
#include <QtCrypto>

using namespace QCA;

static char cert_pem[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBsTCCAVugAwIBAgIBADANBgkqhkiG9w0BAQUFADA4MRQwEgYDVQQDEwtUZXN0\n"
    "IENlcnQgMTELMAkGA1UEBhMCVVMxEzARBgNVBAoTClRlc3QgT3JnIDEwHhcNMDcw\n"
    "NjE5MjAzOTI4WhcNMTIwNjE5MjAzOTI4WjA4MRQwEgYDVQQDEwtUZXN0IENlcnQg\n"
    "MTELMAkGA1UEBhMCVVMxEzARBgNVBAoTClRlc3QgT3JnIDEwXDANBgkqhkiG9w0B\n"
    "AQEFAANLADBIAkEA3645RS/xBlWnjju6moaRYQuIDo7fwM+GxhE91HECLAg3Hnkr\n"
    "I+qx96VXd006olOn8MrkbjSqcTJ4LcDaCGI1YwIDAQABo1AwTjAdBgNVHQ4EFgQU\n"
    "nm5lNkkblHdoB0gLeh8mB6Ed+TMwDwYDVR0TAQH/BAUwAwIBADAcBgNVHREEFTAT\n"
    "gRF0ZXN0MUBleGFtcGxlLmNvbTANBgkqhkiG9w0BAQUFAANBAFTtXtwfYcJZBsXJ\n"
    "+Ckm9qbg7qR/XRERDzeR0yhHZE7F/jU5YQv7+iJL4l95iH9PkZNOk15Tu/Kzzekx\n"
    "6CTXzKA=\n"
    "-----END CERTIFICATE-----";

static char key_n_dec[] =
    "1171510158037441543813157379806833168225785177834459013412026750"
    "9262193808059395366696241600386200064326196137137376912654785051"
    "560621331316573341676090723";

static char key_e_dec[] = "65537";

//----------------------------------------------------------------------------
// TestProvider
//----------------------------------------------------------------------------
class TestProvider : public Provider
{
public:
    TestProvider()
    {
        appendPluginDiagnosticText("TestProvider constructed\n");
    }

    void init()
    {
        appendPluginDiagnosticText("TestProvider initialized\n");
    }

    void deinit()
    {
        appendPluginDiagnosticText("TestProvider deinitialized\n");
    }

    ~TestProvider()
    {
        appendPluginDiagnosticText("TestProvider destructed\n");
    }

    int version() const
    {
        return 0x010203; // 1.2.3
    }

    int qcaVersion() const
    {
        return QCA_VERSION;
    }

    QString name() const
    {
        return "qca-test";
    }

    QStringList features() const
    {
        QStringList list;
        list += "keystorelist";
        return list;
    }

    Context *createContext(const QString &type);
};

//----------------------------------------------------------------------------
// TestData
//----------------------------------------------------------------------------
class TestKeyStore
{
public:
    int            contextId;
    KeyStore::Type type;
    QString        storeId;
    QString        name;
    bool           readOnly;
    bool           avail; // for simplicity, all items share this global toggle

    QList<KeyBundle> certs;

    TestKeyStore()
        : contextId(-1)
        , type(KeyStore::SmartCard)
        , readOnly(true)
        , avail(true)
    {
    }
};

class TestData
{
public:
    int                 context_at;
    QList<TestKeyStore> stores;

    TestData()
        : context_at(0)
    {
    }
};

//----------------------------------------------------------------------------
// TestRSAContext
//----------------------------------------------------------------------------
static KeyStoreEntry make_entry(Provider *p, TestKeyStore *store);

class TestRSAContext : public RSAContext
{
    Q_OBJECT
public:
    bool          priv;
    TestKeyStore *store;

    TestRSAContext(Provider *p)
        : RSAContext(p)
        , priv(true)
        , store(0)
    {
    }

    TestRSAContext(const TestRSAContext &from)
        : RSAContext(from)
        , priv(from.priv)
        , store(from.store)
    {
    }

    Context *clone() const
    {
        return new TestRSAContext(*this);
    }

    virtual bool isNull() const
    {
        return false;
    }

    virtual PKey::Type type() const
    {
        return PKey::RSA;
    }

    virtual bool isPrivate() const
    {
        return priv;
    }

    virtual bool canExport() const
    {
        return false;
    }

    virtual void convertToPublic()
    {
        priv = false;
    }

    virtual int bits() const
    {
        return 2048;
    }

    virtual void startSign(SignatureAlgorithm alg, SignatureFormat format)
    {
        Q_UNUSED(alg);
        Q_UNUSED(format);
    }

    virtual void update(const MemoryRegion &in)
    {
        Q_UNUSED(in);
    }

    virtual QByteArray endSign()
    {
        if (!store)
            return QByteArray();

        while (store->contextId == -1 || !store->avail) {
            KeyStoreInfo  info(store->type, store->storeId, store->name);
            KeyStoreEntry entry = make_entry(provider(), store);

            TokenAsker asker;
            asker.ask(info, entry, 0);
            asker.waitForResponse();
            if (!asker.accepted())
                return QByteArray();
        }

        return "foobar";
    }

    virtual void createPrivate(int bits, int exp, bool block)
    {
        Q_UNUSED(bits);
        Q_UNUSED(exp);
        Q_UNUSED(block);
    }

    virtual void createPrivate(const BigInteger &n,
                               const BigInteger &e,
                               const BigInteger &p,
                               const BigInteger &q,
                               const BigInteger &d)
    {
        Q_UNUSED(n);
        Q_UNUSED(e);
        Q_UNUSED(p);
        Q_UNUSED(q);
        Q_UNUSED(d);
    }

    virtual void createPublic(const BigInteger &n, const BigInteger &e)
    {
        Q_UNUSED(n);
        Q_UNUSED(e);
    }

    virtual BigInteger n() const
    {
        return BigInteger(QString(key_n_dec));
    }

    virtual BigInteger e() const
    {
        return BigInteger(QString(key_e_dec));
    }

    virtual BigInteger p() const
    {
        return BigInteger();
    }

    virtual BigInteger q() const
    {
        return BigInteger();
    }

    virtual BigInteger d() const
    {
        return BigInteger();
    }
};

//----------------------------------------------------------------------------
// TestPKeyContext
//----------------------------------------------------------------------------
class TestPKeyContext : public PKeyContext
{
    Q_OBJECT
public:
    TestRSAContext *_key;

    TestPKeyContext(Provider *p)
        : PKeyContext(p)
        , _key(0)
    {
    }

    TestPKeyContext(const TestPKeyContext &from)
        : PKeyContext(from)
        , _key(0)
    {
        if (from._key)
            _key = (TestRSAContext *)from._key->clone();
    }

    ~TestPKeyContext()
    {
        delete _key;
    }

    Context *clone() const
    {
        return new TestPKeyContext(*this);
    }

    virtual QList<PKey::Type> supportedTypes() const
    {
        QList<PKey::Type> list;
        list += PKey::RSA;
        return list;
    }

    virtual QList<PKey::Type> supportedIOTypes() const
    {
        return QList<PKey::Type>();
    }

    virtual QList<PBEAlgorithm> supportedPBEAlgorithms() const
    {
        return QList<PBEAlgorithm>();
    }

    virtual PKeyBase *key()
    {
        return _key;
    }

    virtual const PKeyBase *key() const
    {
        return _key;
    }

    virtual void setKey(PKeyBase *key)
    {
        delete _key;
        _key = (TestRSAContext *)key;
    }

    virtual bool importKey(const PKeyBase *key)
    {
        Q_UNUSED(key);
        return false;
    }
};

//----------------------------------------------------------------------------
// TestCertContext
//----------------------------------------------------------------------------
class TestCertContext : public CertContext
{
    Q_OBJECT
public:
    CertContextProps _props;

    TestCertContext(Provider *p)
        : CertContext(p)
    {
    }

    Context *clone() const
    {
        return new TestCertContext(*this);
    }

    virtual QByteArray toDER() const
    {
        QStringList lines = toPEM().split('\n');
        lines.removeFirst();
        lines.removeLast();
        QString enc = lines.join("");
        return Base64().stringToArray(enc).toByteArray();
    }

    virtual QString toPEM() const
    {
        return QString(cert_pem);
    }

    virtual ConvertResult fromDER(const QByteArray &a)
    {
        Q_UNUSED(a);
        return ErrorDecode;
    }

    virtual ConvertResult fromPEM(const QString &s)
    {
        Q_UNUSED(s);
        return ErrorDecode;
    }

    virtual bool createSelfSigned(const CertificateOptions &opts, const PKeyContext &priv)
    {
        Q_UNUSED(opts);
        Q_UNUSED(priv);
        return false;
    }

    virtual const CertContextProps *props() const
    {
        return &_props;
    }

    virtual bool compare(const CertContext *other) const
    {
        Q_UNUSED(other);
        return false;
    }

    virtual PKeyContext *subjectPublicKey() const
    {
        TestRSAContext *rsa1 = new TestRSAContext(provider());
        rsa1->priv           = false;
        TestPKeyContext *kc1 = new TestPKeyContext(provider());
        kc1->setKey(rsa1);
        return kc1;
    }

    virtual bool isIssuerOf(const CertContext *other) const
    {
        Q_UNUSED(other);
        return false;
    }

    virtual Validity validate(const QList<CertContext *> &trusted,
                              const QList<CertContext *> &untrusted,
                              const QList<CRLContext *> & crls,
                              UsageMode                   u,
                              ValidateFlags               vf) const
    {
        Q_UNUSED(trusted);
        Q_UNUSED(untrusted);
        Q_UNUSED(crls);
        Q_UNUSED(u);
        Q_UNUSED(vf);
        return ErrorValidityUnknown;
    }

    virtual Validity validate_chain(const QList<CertContext *> &chain,
                                    const QList<CertContext *> &trusted,
                                    const QList<CRLContext *> & crls,
                                    UsageMode                   u,
                                    ValidateFlags               vf) const
    {
        Q_UNUSED(chain);
        Q_UNUSED(trusted);
        Q_UNUSED(crls);
        Q_UNUSED(u);
        Q_UNUSED(vf);
        return ErrorValidityUnknown;
    }
};

//----------------------------------------------------------------------------
// TestKeyStoreEntryContext
//----------------------------------------------------------------------------
class TestKeyStoreEntryContext : public KeyStoreEntryContext
{
    Q_OBJECT
public:
    QString       _id, _name, _storeId, _storeName;
    KeyBundle     kb;
    TestKeyStore *store;

    TestKeyStoreEntryContext(Provider *p)
        : KeyStoreEntryContext(p)
    {
    }

    virtual Context *clone() const
    {
        return new TestKeyStoreEntryContext(*this);
    }

    virtual KeyStoreEntry::Type type() const
    {
        return KeyStoreEntry::TypeKeyBundle;
    }

    virtual QString id() const
    {
        return _id;
    }

    virtual QString name() const
    {
        return _name;
    }

    virtual QString storeId() const
    {
        return _storeId;
    }

    virtual QString storeName() const
    {
        return _storeName;
    }

    virtual bool isAvailable() const
    {
        return store->avail;
    }

    virtual QString serialize() const
    {
        return QString("qca-test-1/fake_serialized");
    }

    virtual KeyBundle keyBundle() const
    {
        return kb;
    }

    virtual bool ensureAccess()
    {
        return true;
    }
};

KeyStoreEntry make_entry(Provider *p, TestKeyStore *store)
{
    KeyStoreEntry             entry;
    TestKeyStoreEntryContext *kse = new TestKeyStoreEntryContext(p);
    kse->_id                      = QString::number(0);
    kse->_name                    = store->certs[0].certificateChain().primary().commonName();
    kse->_storeId                 = store->storeId;
    kse->_storeName               = store->name;
    kse->kb                       = store->certs[0];
    kse->store                    = store;
    entry.change(kse);
    return entry;
}

//----------------------------------------------------------------------------
// TestKeyStoreListContext
//----------------------------------------------------------------------------
class TestKeyStoreListContext : public KeyStoreListContext
{
    Q_OBJECT
public:
    TestData data;
    int      step;
    QTimer   t;
    bool     first;
    int      next_id;

    TestKeyStoreListContext(Provider *p)
        : KeyStoreListContext(p)
        , t(this)
    {
        step    = 0;
        next_id = 1;

        KeyBundle        cert1;
        Certificate      pub1;
        TestCertContext *cc1 = new TestCertContext(provider());
        cc1->_props.subject += CertificateInfoPair(CertificateInfoType(CommonName), "Test Cert 1");
        pub1.change(cc1);
        PrivateKey       sec1;
        TestRSAContext * rsa1 = new TestRSAContext(provider());
        TestPKeyContext *kc1  = new TestPKeyContext(provider());
        kc1->setKey(rsa1);
        sec1.change(kc1);
        cert1.setCertificateChainAndKey(pub1, sec1);

        TestKeyStore ks1;
        ks1.storeId = "store1";
        ks1.name    = "Test Store 1";
        ks1.certs += cert1;
        ks1.avail = false;
        data.stores += ks1;

        TestKeyStore ks2;
        ks2.storeId  = "store2";
        ks2.name     = "Test Store 2";
        ks2.readOnly = false;
        data.stores += ks2;

        rsa1->store = &data.stores[0];

        connect(&t, SIGNAL(timeout()), SLOT(do_step()));
    }

    int findStore(int contextId) const
    {
        for (int n = 0; n < data.stores.count(); ++n) {
            if (data.stores[n].contextId == contextId)
                return n;
        }
        return -1;
    }

    virtual Context *clone() const
    {
        return 0;
    }

    virtual void start()
    {
        first = true;
        emit diagnosticText("qca-test: TestKeyStoreListContext started\n");
        t.start(2000);
    }

    virtual void setUpdatesEnabled(bool enabled)
    {
        Q_UNUSED(enabled);
    }

    virtual QList<int> keyStores()
    {
        QList<int> list;
        for (int n = 0; n < data.stores.count(); ++n) {
            int id = data.stores[n].contextId;
            if (id != -1)
                list += id;
        }
        return list;
    }

    virtual KeyStore::Type type(int id) const
    {
        int at = findStore(id);
        if (at == -1)
            return KeyStore::SmartCard;
        return data.stores[at].type;
    }

    virtual QString storeId(int id) const
    {
        int at = findStore(id);
        if (at == -1)
            return QString();
        return data.stores[at].storeId;
    }

    virtual QString name(int id) const
    {
        int at = findStore(id);
        if (at == -1)
            return QString();
        return data.stores[at].name;
    }

    virtual bool isReadOnly(int id) const
    {
        int at = findStore(id);
        if (at == -1)
            return true;
        return data.stores[at].readOnly;
    }

    virtual QList<KeyStoreEntry::Type> entryTypes(int id) const
    {
        Q_UNUSED(id);
        QList<KeyStoreEntry::Type> list;
        list += KeyStoreEntry::TypeKeyBundle;
        return list;
    }

    virtual QList<KeyStoreEntryContext *> entryList(int id)
    {
        QList<KeyStoreEntryContext *> out;
        int                           at = findStore(id);
        if (at == -1)
            return out;
        TestKeyStore &store = data.stores[at];
        for (int n = 0; n < store.certs.count(); ++n) {
            TestKeyStoreEntryContext *kse = new TestKeyStoreEntryContext(provider());
            kse->_id                      = QString::number(n);
            kse->_name                    = store.certs[n].certificateChain().primary().commonName();
            kse->_storeId                 = store.storeId;
            kse->_storeName               = store.name;
            kse->kb                       = store.certs[n];
            kse->store                    = &store;
            out += kse;
        }
        return out;
    }

    virtual KeyStoreEntryContext *entryPassive(const QString &serialized)
    {
        if (serialized == "qca-test-1/fake_serialized") {
            TestKeyStore &            store = data.stores[0];
            TestKeyStoreEntryContext *kse   = new TestKeyStoreEntryContext(provider());
            kse->_id                        = QString::number(0);
            kse->_name                      = store.certs[0].certificateChain().primary().commonName();
            kse->_storeId                   = store.storeId;
            kse->_storeName                 = store.name;
            kse->kb                         = store.certs[0];
            kse->store                      = &store;
            return kse;
        } else
            return 0;
    }

    virtual QString writeEntry(int id, const KeyBundle &kb)
    {
        int at = findStore(id);
        if (at == -1)
            return QString();
        if (data.stores[at].readOnly)
            return QString();
        data.stores[at].certs += kb;
        return QString::number(data.stores[at].certs.count() - 1);
    }

    virtual bool removeEntry(int id, const QString &entryId)
    {
        int at = findStore(id);
        if (at == -1)
            return false;
        if (data.stores[at].readOnly)
            return false;
        int index = entryId.toInt();
        if (index < 0 || index >= data.stores[at].certs.count())
            return false;
        data.stores[at].certs.removeAt(index);
        return true;
    }

private Q_SLOTS:
    void do_step()
    {
        emit diagnosticText(QString("qca-test: TestKeyStoreListContext do_step %1\n").arg(step));

        if (step == 0) {
            // make first store available
            data.stores[0].contextId = next_id++;
            if (first) {
                first = false;
                emit busyEnd();
            } else
                emit updated();
        } else if (step == 1) {
            // make second store available
            data.stores[1].contextId = next_id++;
            emit updated();
        } else if (step == 2) {
            // make items in the first store available
            data.stores[0].avail = true;
            emit storeUpdated(data.stores[0].contextId);
        } else if (step == 3) {
            // make the first store unavailable
            data.stores[0].contextId = -1;
            emit updated();
        } else if (step == 4) {
            // make the first store available
            data.stores[0].contextId = next_id++;
            emit updated();
        } else if (step == 5) {
            // make the second store unavailable
            data.stores[1].contextId = -1;
            emit updated();
        } else if (step == 6) {
            // make the first store unavailable
            data.stores[0].contextId = -1;
            emit updated();
        } else if (step == 7) {
            // do it all over again in 10 seconds
            // (2 seconds before, 6 seconds here, 2 seconds after)
            t.start(6000);
        } else {
            step                 = 0;
            data.stores[0].avail = false;

            // set interval to 2 seconds
            t.start(2000);
            return;
        }

        ++step;
    }
};

//----------------------------------------------------------------------------
// TestProvider
//----------------------------------------------------------------------------
Provider::Context *TestProvider::createContext(const QString &type)
{
    if (type == "keystorelist")
        return new TestKeyStoreListContext(this);
    else
        return 0;
}

//----------------------------------------------------------------------------
// TestPlugin
//----------------------------------------------------------------------------
class TestPlugin : public QObject, public QCAPlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "com.affinix.qca.Plugin/1.0")
    Q_INTERFACES(QCAPlugin)
public:
    virtual Provider *createProvider()
    {
        return new TestProvider;
    }
};

#include "qca-test.moc"
