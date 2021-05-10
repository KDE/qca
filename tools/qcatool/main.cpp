/*
 * Copyright (C) 2005-2007  Justin Karneges <justin@affinix.com>
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

#include <QtCrypto>

#include <QCoreApplication>
#include <QDebug>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTextStream>
#include <QTimer>

#ifdef QT_STATICPLUGIN
#include "import_plugins.h"
#endif

const char *const APPNAME = "qcatool";
const char *const EXENAME = "qcatool";
const char *const VERSION = QCA_VERSION_STR;

static QStringList wrapstring(const QString &str, int width)
{
    QStringList out;
    QString     simp = str.simplified();
    QString     rest = simp;
    while (true) {
        int lastSpace = -1;
        int n;
        for (n = 0; n < rest.length(); ++n) {
            if (rest[n].isSpace())
                lastSpace = n;
            if (n == width)
                break;
        }
        if (n == rest.length()) {
            out += rest;
            break;
        }

        QString line;
        if (lastSpace != -1) {
            line = rest.mid(0, lastSpace);
            rest = rest.mid(lastSpace + 1);
        } else {
            line = rest.mid(0, n);
            rest = rest.mid(n);
        }
        out += line;
    }
    return out;
}

class StreamLogger : public QCA::AbstractLogDevice
{
    Q_OBJECT
public:
    StreamLogger(QTextStream &stream)
        : QCA::AbstractLogDevice(QStringLiteral("Stream logger"))
        , _stream(stream)
    {
        QCA::logger()->registerLogDevice(this);
    }

    ~StreamLogger() override
    {
        QCA::logger()->unregisterLogDevice(name());
    }

    void logTextMessage(const QString &message, enum QCA::Logger::Severity severity) override
    {
        _stream << now() << " " << severityName(severity) << " " << message << Qt::endl;
    }

    void logBinaryMessage(const QByteArray &blob, enum QCA::Logger::Severity severity) override
    {
        Q_UNUSED(blob);
        _stream << now() << " " << severityName(severity) << " "
                << "Binary blob not implemented yet" << Qt::endl;
    }

private:
    inline const char *severityName(enum QCA::Logger::Severity severity)
    {
        if (severity <= QCA::Logger::Debug) {
            return s_severityNames[severity];
        } else {
            return s_severityNames[QCA::Logger::Debug + 1];
        }
    }

    inline QString now()
    {
        static QString format = QStringLiteral("yyyy-MM-dd hh:mm:ss");
        return QDateTime::currentDateTime().toString(format);
    }

private:
    static const char *s_severityNames[];
    QTextStream &      _stream;
};

const char *StreamLogger::s_severityNames[] = {"Q", "M", "A", "C", "E", "W", "N", "I", "D", "U"};

static void output_plugin_diagnostic_text()
{
    QString str = QCA::pluginDiagnosticText();
    QCA::clearPluginDiagnosticText();
    if (str[str.length() - 1] == QLatin1Char('\n'))
        str.truncate(str.length() - 1);
    const QStringList lines = str.split(QLatin1Char('\n'), Qt::KeepEmptyParts);
    for (int n = 0; n < lines.count(); ++n)
        fprintf(stderr, "plugin: %s\n", qPrintable(lines[n]));
}

static void output_keystore_diagnostic_text()
{
    QString str = QCA::KeyStoreManager::diagnosticText();
    QCA::KeyStoreManager::clearDiagnosticText();
    if (str[str.length() - 1] == QLatin1Char('\n'))
        str.truncate(str.length() - 1);
    const QStringList lines = str.split(QLatin1Char('\n'), Qt::KeepEmptyParts);
    for (int n = 0; n < lines.count(); ++n)
        fprintf(stderr, "keystore: %s\n", qPrintable(lines[n]));
}

static void output_message_diagnostic_text(QCA::SecureMessage *msg)
{
    QString str = msg->diagnosticText();
    if (str[str.length() - 1] == QLatin1Char('\n'))
        str.truncate(str.length() - 1);
    const QStringList lines = str.split(QLatin1Char('\n'), Qt::KeepEmptyParts);
    for (int n = 0; n < lines.count(); ++n)
        fprintf(stderr, "message: %s\n", qPrintable(lines[n]));
}

class AnimatedKeyGen : public QObject
{
    Q_OBJECT
public:
    static QCA::PrivateKey makeKey(QCA::PKey::Type type, int bits, QCA::DLGroupSet set)
    {
        AnimatedKeyGen kg;
        kg.type = type;
        kg.bits = bits;
        kg.set  = set;
        QEventLoop eventLoop;
        kg.eventLoop = &eventLoop;
        QTimer::singleShot(0, &kg, &AnimatedKeyGen::start);
        eventLoop.exec();
        QCA::PrivateKey key = kg.key;
        return key;
    }

private:
    QCA::PKey::Type   type;
    int               bits;
    QCA::DLGroupSet   set;
    QEventLoop *      eventLoop;
    QCA::KeyGenerator gen;
    QCA::DLGroup      group;
    QCA::PrivateKey   key;
    QTimer            t;
    int               x;

    AnimatedKeyGen()
    {
        gen.setBlockingEnabled(false);
        connect(&gen, &QCA::KeyGenerator::finished, this, &AnimatedKeyGen::gen_finished);
        connect(&t, &QTimer::timeout, this, &AnimatedKeyGen::t_timeout);
    }

private Q_SLOTS:
    void start()
    {
        printf("Generating Key ...  ");
        fflush(stdout);
        x = 0;
        t.start(125);

        if (type == QCA::PKey::RSA)
            gen.createRSA(bits);
        else
            gen.createDLGroup(set);
    }

    void gen_finished()
    {
        if (type == QCA::PKey::DSA || type == QCA::PKey::DH) {
            if (group.isNull()) {
                group = gen.dlGroup();

                if (type == QCA::PKey::DSA)
                    gen.createDSA(group);
                else
                    gen.createDH(group);
                return;
            }
        }

        key = gen.key();

        printf("\b");
        if (!key.isNull())
            printf("Done\n");
        else
            printf("Error\n");

        eventLoop->exit();
    }

    void t_timeout()
    {
        if (x == 0)
            printf("\b/");
        else if (x == 1)
            printf("\b-");
        else if (x == 2)
            printf("\b\\");
        else if (x == 3)
            printf("\b|");
        fflush(stdout);

        ++x;
        x %= 4;
    }
};

class KeyStoreMonitor : public QObject
{
    Q_OBJECT
public:
    static void monitor()
    {
        KeyStoreMonitor monitor;
        QEventLoop      eventLoop;
        monitor.eventLoop = &eventLoop;
        QTimer::singleShot(0, &monitor, &KeyStoreMonitor::start);
        eventLoop.exec();
    }

private:
    QEventLoop *           eventLoop;
    QCA::KeyStoreManager * ksm;
    QList<QCA::KeyStore *> keyStores;
    QCA::ConsolePrompt *   prompt;

private Q_SLOTS:
    void start()
    {
        // user can quit the monitoring by pressing enter
        printf("Monitoring keystores, press 'q' to quit.\n");
        prompt = new QCA::ConsolePrompt(this);
        connect(prompt, &QCA::ConsolePrompt::finished, this, &KeyStoreMonitor::prompt_finished);
        prompt->getChar();

        // kick off the subsystem
        QCA::KeyStoreManager::start();

        // setup keystore manager for monitoring
        ksm = new QCA::KeyStoreManager(this);
        connect(ksm, &QCA::KeyStoreManager::keyStoreAvailable, this, &KeyStoreMonitor::ks_available);
        foreach (const QString &keyStoreId, ksm->keyStores())
            ks_available(keyStoreId);
    }

    void ks_available(const QString &keyStoreId)
    {
        QCA::KeyStore *ks = new QCA::KeyStore(keyStoreId, ksm);
        connect(ks, &QCA::KeyStore::updated, this, &KeyStoreMonitor::ks_updated);
        connect(ks, &QCA::KeyStore::unavailable, this, &KeyStoreMonitor::ks_unavailable);
        keyStores += ks;

        printf("  available:   %s\n", qPrintable(ks->name()));
    }

    void ks_updated()
    {
        QCA::KeyStore *ks = (QCA::KeyStore *)sender();

        printf("  updated:     %s\n", qPrintable(ks->name()));
    }

    void ks_unavailable()
    {
        QCA::KeyStore *ks = (QCA::KeyStore *)sender();

        printf("  unavailable: %s\n", qPrintable(ks->name()));
        keyStores.removeAll(ks);
        delete ks;
    }

    void prompt_finished()
    {
        QChar c = prompt->resultChar();
        if (c == QLatin1Char('q') || c == QLatin1Char('Q')) {
            eventLoop->exit();
            return;
        }
        prompt->getChar();
    }
};

class PassphrasePrompt : public QObject
{
    Q_OBJECT
public:
    class Item
    {
    public:
        QString    promptStr;
        int        id;
        QCA::Event event;
    };

    QCA::EventHandler   handler;
    bool                allowPrompt;
    bool                warned;
    bool                have_pass;
    bool                used_pass;
    QCA::SecureArray    pass;
    QCA::ConsolePrompt *prompt;
    int                 prompt_id;
    QCA::Event          prompt_event;
    QList<Item>         pending;
    bool                auto_accept;

    QCA::KeyStoreManager   ksm;
    QList<QCA::KeyStore *> keyStores;

    PassphrasePrompt()
        : handler(this)
        , ksm(this)
    {
        allowPrompt = true;
        warned      = false;
        have_pass   = false;
        auto_accept = false;

        prompt = nullptr;

        connect(&handler, &QCA::EventHandler::eventReady, this, &PassphrasePrompt::ph_eventReady);
        handler.start();

        connect(&ksm, &QCA::KeyStoreManager::keyStoreAvailable, this, &PassphrasePrompt::ks_available);
        foreach (const QString &keyStoreId, ksm.keyStores())
            ks_available(keyStoreId);
    }

    ~PassphrasePrompt() override
    {
        qDeleteAll(keyStores);

        if (prompt) {
            handler.reject(prompt_id);
            delete prompt;
        }

        while (!pending.isEmpty())
            handler.reject(pending.takeFirst().id);
    }

    void setExplicitPassword(const QCA::SecureArray &_pass)
    {
        have_pass = true;
        used_pass = false;
        pass      = _pass;
    }

private Q_SLOTS:
    void ph_eventReady(int id, const QCA::Event &e)
    {
        if (have_pass) {
            // only allow using an explicit passphrase once
            if (used_pass) {
                handler.reject(id);
                return;
            }
            used_pass = true;
            handler.submitPassword(id, pass);
            return;
        }

        if (!allowPrompt) {
            if (!have_pass && !warned) {
                warned = true;
                fprintf(stderr, "Error: no passphrase specified (use '--pass=' for none).\n");
            }

            handler.reject(id);
            return;
        }

        if (e.type() == QCA::Event::Password) {
            QString type = QStringLiteral("password");
            if (e.passwordStyle() == QCA::Event::StylePassphrase)
                type = QStringLiteral("passphrase");
            else if (e.passwordStyle() == QCA::Event::StylePIN)
                type = QStringLiteral("PIN");

            QString str;
            if (e.source() == QCA::Event::KeyStore) {
                QString            name;
                QCA::KeyStoreEntry entry = e.keyStoreEntry();
                if (!entry.isNull()) {
                    name = entry.name();
                } else {
                    if (e.keyStoreInfo().type() == QCA::KeyStore::SmartCard)
                        name = QStringLiteral("the '") + e.keyStoreInfo().name() + QStringLiteral("' token");
                    else
                        name = e.keyStoreInfo().name();
                }
                str = QStringLiteral("Enter %1 for %2").arg(type, name);
            } else if (!e.fileName().isEmpty())
                str = QStringLiteral("Enter %1 for %2").arg(type, e.fileName());
            else
                str = QStringLiteral("Enter %1").arg(type);

            if (!prompt) {
                prompt = new QCA::ConsolePrompt(this);
                connect(prompt, &QCA::ConsolePrompt::finished, this, &PassphrasePrompt::prompt_finished);
                prompt_id    = id;
                prompt_event = e;
                prompt->getHidden(str);
            } else {
                Item i;
                i.promptStr = str;
                i.id        = id;
                i.event     = e;
                pending += i;
            }
        } else if (e.type() == QCA::Event::Token) {
            // even though we're being prompted for a missing token,
            //   we should still check if the token is present, due to
            //   a possible race between insert and token request.
            bool found = false;

            // token-only
            if (e.keyStoreEntry().isNull()) {
                foreach (QCA::KeyStore *ks, keyStores) {
                    if (ks->id() == e.keyStoreInfo().id()) {
                        found = true;
                        break;
                    }
                }
            }
            // token-entry
            else {
                QCA::KeyStoreEntry kse = e.keyStoreEntry();

                QCA::KeyStore *ks = nullptr;
                foreach (QCA::KeyStore *i, keyStores) {
                    if (i->id() == e.keyStoreInfo().id()) {
                        ks = i;
                        break;
                    }
                }
                if (ks) {
                    QList<QCA::KeyStoreEntry> list = ks->entryList();
                    foreach (const QCA::KeyStoreEntry &e, list) {
                        if (e.id() == kse.id() && kse.isAvailable()) {
                            found = true;
                            break;
                        }
                    }
                }
            }
            if (found) {
                // auto-accept
                handler.tokenOkay(id);
                return;
            }

            QCA::KeyStoreEntry entry = e.keyStoreEntry();
            QString            name;
            if (!entry.isNull()) {
                name = QStringLiteral("Please make ") + entry.name() + QStringLiteral(" (of ") + entry.storeName() +
                    QStringLiteral(") available");
            } else {
                name = QStringLiteral("Please insert the '") + e.keyStoreInfo().name() + QStringLiteral("' token");
            }

            QString str = QStringLiteral("%1 and press Enter (or 'q' to cancel) ...").arg(name);

            if (!prompt) {
                fprintf(stderr, "%s\n", qPrintable(str));
                prompt = new QCA::ConsolePrompt(this);
                connect(prompt, &QCA::ConsolePrompt::finished, this, &PassphrasePrompt::prompt_finished);
                prompt_id    = id;
                prompt_event = e;
                prompt->getChar();
            } else {
                Item i;
                i.promptStr = str;
                i.id        = id;
                i.event     = e;
                pending += i;
            }
        } else
            handler.reject(id);
    }

    void prompt_finished()
    {
        if (prompt_event.type() == QCA::Event::Password) {
            handler.submitPassword(prompt_id, prompt->result());
        } else {
            if (auto_accept) {
                auto_accept = false;
                handler.tokenOkay(prompt_id);
            } else {
                QChar c = prompt->resultChar();
                if (c == QLatin1Char('\r') || c == QLatin1Char('\n'))
                    handler.tokenOkay(prompt_id);
                else if (c == QLatin1Char('q') || c == QLatin1Char('Q'))
                    handler.reject(prompt_id);
                else {
                    // retry
                    prompt->getChar();
                    return;
                }
            }
        }

        if (!pending.isEmpty()) {
            Item i       = pending.takeFirst();
            prompt_id    = i.id;
            prompt_event = i.event;
            if (i.event.type() == QCA::Event::Password) {
                prompt->getHidden(i.promptStr);
            } else // Token
            {
                fprintf(stderr, "%s\n", qPrintable(i.promptStr));
                prompt->getChar();
            }
        } else {
            delete prompt;
            prompt = nullptr;
        }
    }

    void ks_available(const QString &keyStoreId)
    {
        QCA::KeyStore *ks = new QCA::KeyStore(keyStoreId, &ksm);
        connect(ks, &QCA::KeyStore::updated, this, &PassphrasePrompt::ks_updated);
        connect(ks, &QCA::KeyStore::unavailable, this, &PassphrasePrompt::ks_unavailable);
        keyStores += ks;
        ks->startAsynchronousMode();

        // are we currently in a token-only prompt?
        if (prompt && prompt_event.type() == QCA::Event::Token && prompt_event.keyStoreEntry().isNull()) {
            // was the token we're looking for just inserted?
            if (prompt_event.keyStoreInfo().id() == keyStoreId) {
                fprintf(stderr, "Token inserted!  Continuing...\n");

                // auto-accept
                auto_accept = true;
                prompt_finished();
            }
        }
    }

    void ks_unavailable()
    {
        QCA::KeyStore *ks = (QCA::KeyStore *)sender();
        keyStores.removeAll(ks);
        delete ks;
    }

    void ks_updated()
    {
        QCA::KeyStore *ks = (QCA::KeyStore *)sender();

        // are we currently in a token-entry prompt?
        if (prompt && prompt_event.type() == QCA::Event::Token && !prompt_event.keyStoreEntry().isNull()) {
            QCA::KeyStoreEntry kse = prompt_event.keyStoreEntry();

            // was the token of the entry we're looking for updated?
            if (prompt_event.keyStoreInfo().id() == ks->id()) {
                // is the entry available?
                bool                      avail = false;
                QList<QCA::KeyStoreEntry> list  = ks->entryList();
                foreach (const QCA::KeyStoreEntry &e, list) {
                    if (e.id() == kse.id()) {
                        avail = kse.isAvailable();
                        break;
                    }
                }
                if (avail) {
                    fprintf(stderr, "Entry available!  Continuing...\n");

                    // auto-accept
                    auto_accept = true;
                    prompt_finished();
                }
            }
        }
    }
};

class PassphrasePromptThread : public QCA::SyncThread
{
    Q_OBJECT
public:
    PassphrasePrompt *pp;

    PassphrasePromptThread()
    {
        start();
    }

    ~PassphrasePromptThread() override
    {
        stop();
    }

protected:
    void atStart() override
    {
        pp = new PassphrasePrompt;
    }

    void atEnd() override
    {
        delete pp;
    }
};

static bool promptForNewPassphrase(QCA::SecureArray *result)
{
    QCA::ConsolePrompt prompt;
    prompt.getHidden(QStringLiteral("Enter new passphrase"));
    prompt.waitForFinished();
    QCA::SecureArray out = prompt.result();

    prompt.getHidden(QStringLiteral("Confirm new passphrase"));
    prompt.waitForFinished();

    if (prompt.result() != out) {
        fprintf(stderr, "Error: confirmation does not match original entry.\n");
        return false;
    }
    *result = out;
    return true;
}

static void ksm_start_and_wait()
{
    // activate the KeyStoreManager and block until ready
    QCA::KeyStoreManager::start();
    {
        QCA::KeyStoreManager ksm;
        ksm.waitForBusyFinished();
    }
}

static QString line_encode(const QString &in)
{
    QString out;
    for (const QChar &c : in) {
        if (c == QLatin1Char('\\'))
            out += QStringLiteral("\\\\");
        else if (c == QLatin1Char('\n'))
            out += QStringLiteral("\\n");
        else
            out += c;
    }
    return out;
}

static QString line_decode(const QString &in)
{
    QString out;
    for (int n = 0; n < in.length(); ++n) {
        if (in[n] == QLatin1Char('\\')) {
            if (n + 1 < in.length()) {
                if (in[n + 1] == QLatin1Char('\\'))
                    out += QLatin1Char('\\');
                else if (in[n + 1] == QLatin1Char('n'))
                    out += QLatin1Char('\n');
                ++n;
            }
        } else
            out += in[n];
    }
    return out;
}

static QString make_ksentry_string(const QString &id)
{
    QString out;
    out += QStringLiteral("QCATOOL_KEYSTOREENTRY_1\n");
    out += line_encode(id) + QLatin1Char('\n');
    return out;
}

/*static bool write_ksentry_file(const QString &id, const QString &fileName)
{
    QFile f(fileName);
    if(!f.open(QFile::WriteOnly | QFile::Truncate))
        return false;
    f.write(make_ksentry_string(id).toUtf8());
    return true;
}*/

static QString read_ksentry_file(const QString &fileName)
{
    QString out;

    QFile f(fileName);
    if (!f.open(QFile::ReadOnly))
        return out;
    QTextStream ts(&f);
    int         linenum = 0;
    while (!ts.atEnd()) {
        QString line = ts.readLine();
        if (linenum == 0) {
            if (line != QLatin1String("QCATOOL_KEYSTOREENTRY_1"))
                return out;
        } else {
            out = line_decode(line);
            break;
        }
        ++linenum;
    }
    return out;
}

static bool is_pem_file(const QString &fileName)
{
    QFile f(fileName);
    if (!f.open(QFile::ReadOnly))
        return false;
    QTextStream ts(&f);
    if (!ts.atEnd()) {
        QString line = ts.readLine();
        if (line.startsWith(QLatin1String("-----BEGIN")))
            return true;
    }
    return false;
}

static QByteArray read_der_file(const QString &fileName)
{
    QFile f(fileName);
    if (!f.open(QFile::ReadOnly))
        return QByteArray();
    return f.readAll();
}

class InfoType
{
public:
    QCA::CertificateInfoType type;
    QString                  varname;
    QString                  shortname;
    QString                  name;
    QString                  desc;

    InfoType()
    {
    }

    InfoType(const QCA::CertificateInfoType &_type,
             const QString &                 _varname,
             const QString &                 _shortname,
             const QString &                 _name,
             const QString &                 _desc)
        : type(_type)
        , varname(_varname)
        , shortname(_shortname)
        , name(_name)
        , desc(_desc)
    {
    }
};

static QList<InfoType> makeInfoTypeList(bool legacyEmail = false)
{
    QList<InfoType> out;
    out += InfoType(QCA::CommonName,
                    QStringLiteral("CommonName"),
                    QStringLiteral("CN"),
                    QStringLiteral("Common Name (CN)"),
                    QStringLiteral("Full name, domain, anything"));
    out += InfoType(
        QCA::Email, QStringLiteral("Email"), QLatin1String(""), QStringLiteral("Email Address"), QLatin1String(""));
    if (legacyEmail)
        out += InfoType(QCA::EmailLegacy,
                        QStringLiteral("EmailLegacy"),
                        QLatin1String(""),
                        QStringLiteral("PKCS#9 Email Address"),
                        QLatin1String(""));
    out += InfoType(QCA::Organization,
                    QStringLiteral("Organization"),
                    QStringLiteral("O"),
                    QStringLiteral("Organization (O)"),
                    QStringLiteral("Company, group, etc"));
    out += InfoType(QCA::OrganizationalUnit,
                    QStringLiteral("OrganizationalUnit"),
                    QStringLiteral("OU"),
                    QStringLiteral("Organizational Unit (OU)"),
                    QStringLiteral("Division/branch of organization"));
    out += InfoType(QCA::Locality,
                    QStringLiteral("Locality"),
                    QLatin1String(""),
                    QStringLiteral("Locality (L)"),
                    QStringLiteral("City, shire, part of a state"));
    out += InfoType(QCA::State,
                    QStringLiteral("State"),
                    QLatin1String(""),
                    QStringLiteral("State (ST)"),
                    QStringLiteral("State within the country"));
    out += InfoType(QCA::Country,
                    QStringLiteral("Country"),
                    QStringLiteral("C"),
                    QStringLiteral("Country Code (C)"),
                    QStringLiteral("2-letter code"));
    out += InfoType(QCA::IncorporationLocality,
                    QStringLiteral("IncorporationLocality"),
                    QLatin1String(""),
                    QStringLiteral("Incorporation Locality"),
                    QStringLiteral("For EV certificates"));
    out += InfoType(QCA::IncorporationState,
                    QStringLiteral("IncorporationState"),
                    QLatin1String(""),
                    QStringLiteral("Incorporation State"),
                    QStringLiteral("For EV certificates"));
    out += InfoType(QCA::IncorporationCountry,
                    QStringLiteral("IncorporationCountry"),
                    QLatin1String(""),
                    QStringLiteral("Incorporation Country"),
                    QStringLiteral("For EV certificates"));
    out += InfoType(QCA::URI, QStringLiteral("URI"), QLatin1String(""), QStringLiteral("URI"), QLatin1String(""));
    out += InfoType(QCA::DNS,
                    QStringLiteral("DNS"),
                    QLatin1String(""),
                    QStringLiteral("Domain Name"),
                    QStringLiteral("Domain (dnsName)"));
    out += InfoType(QCA::IPAddress,
                    QStringLiteral("IPAddress"),
                    QLatin1String(""),
                    QStringLiteral("IP Adddress"),
                    QLatin1String(""));
    out += InfoType(QCA::XMPP,
                    QStringLiteral("XMPP"),
                    QLatin1String(""),
                    QStringLiteral("XMPP Address (JID)"),
                    QStringLiteral("From RFC 3920 (id-on-xmppAddr)"));
    return out;
}

class MyConstraintType
{
public:
    QCA::ConstraintType type;
    QString             varname;
    QString             name;
    QString             desc;

    MyConstraintType()
    {
    }

    MyConstraintType(const QCA::ConstraintType &_type,
                     const QString &            _varname,
                     const QString &            _name,
                     const QString &            _desc)
        : type(_type)
        , varname(_varname)
        , name(_name)
        , desc(_desc)
    {
    }
};

static QList<MyConstraintType> makeConstraintTypeList()
{
    QList<MyConstraintType> out;
    out += MyConstraintType(QCA::DigitalSignature,
                            QStringLiteral("DigitalSignature"),
                            QStringLiteral("Digital Signature"),
                            QStringLiteral("Can be used for signing"));
    out += MyConstraintType(QCA::NonRepudiation,
                            QStringLiteral("NonRepudiation"),
                            QStringLiteral("Non-Repudiation"),
                            QStringLiteral("Usage is legally binding"));
    out += MyConstraintType(QCA::KeyEncipherment,
                            QStringLiteral("KeyEncipherment"),
                            QStringLiteral("Key Encipherment"),
                            QStringLiteral("Can encrypt other keys"));
    out += MyConstraintType(QCA::DataEncipherment,
                            QStringLiteral("DataEncipherment"),
                            QStringLiteral("Data Encipherment"),
                            QStringLiteral("Can encrypt arbitrary data"));
    out += MyConstraintType(QCA::KeyAgreement,
                            QStringLiteral("KeyAgreement"),
                            QStringLiteral("Key Agreement"),
                            QStringLiteral("Can perform key agreement (DH)"));
    out += MyConstraintType(QCA::KeyCertificateSign,
                            QStringLiteral("KeyCertificateSign"),
                            QStringLiteral("Certificate Sign"),
                            QStringLiteral("Can sign other certificates"));
    out += MyConstraintType(
        QCA::CRLSign, QStringLiteral("CRLSign"), QStringLiteral("CRL Sign"), QStringLiteral("Can sign CRLs"));
    out += MyConstraintType(QCA::EncipherOnly,
                            QStringLiteral("EncipherOnly"),
                            QStringLiteral("Encipher Only"),
                            QStringLiteral("Can be used for encrypting"));
    out += MyConstraintType(QCA::DecipherOnly,
                            QStringLiteral("DecipherOnly"),
                            QStringLiteral("Decipher Only"),
                            QStringLiteral("Can be used for decrypting"));
    out += MyConstraintType(QCA::ServerAuth,
                            QStringLiteral("ServerAuth"),
                            QStringLiteral("Server Authentication"),
                            QStringLiteral("TLS Server"));
    out += MyConstraintType(QCA::ClientAuth,
                            QStringLiteral("ClientAuth"),
                            QStringLiteral("Client Authentication"),
                            QStringLiteral("TLS Client"));
    out += MyConstraintType(
        QCA::CodeSigning, QStringLiteral("CodeSigning"), QStringLiteral("Code Signing"), QLatin1String(""));
    out += MyConstraintType(QCA::EmailProtection,
                            QStringLiteral("EmailProtection"),
                            QStringLiteral("Email Protection"),
                            QStringLiteral("S/MIME"));
    out += MyConstraintType(
        QCA::IPSecEndSystem, QStringLiteral("IPSecEndSystem"), QStringLiteral("IPSec End-System"), QLatin1String(""));
    out += MyConstraintType(
        QCA::IPSecTunnel, QStringLiteral("IPSecTunnel"), QStringLiteral("IPSec Tunnel"), QLatin1String(""));
    out +=
        MyConstraintType(QCA::IPSecUser, QStringLiteral("IPSecUser"), QStringLiteral("IPSec User"), QLatin1String(""));
    out += MyConstraintType(
        QCA::TimeStamping, QStringLiteral("TimeStamping"), QStringLiteral("Time Stamping"), QLatin1String(""));
    out += MyConstraintType(
        QCA::OCSPSigning, QStringLiteral("OCSPSigning"), QStringLiteral("OCSP Signing"), QLatin1String(""));
    return out;
}

const char *crlEntryReasonToString(QCA::CRLEntry::Reason r)
{
    switch (r) {
    case QCA::CRLEntry::Unspecified:
        return "Unspecified";
    case QCA::CRLEntry::KeyCompromise:
        return "KeyCompromise";
    case QCA::CRLEntry::CACompromise:
        return "CACompromise";
    case QCA::CRLEntry::AffiliationChanged:
        return "AffiliationChanged";
    case QCA::CRLEntry::Superseded:
        return "Superseded";
    case QCA::CRLEntry::CessationOfOperation:
        return "CessationOfOperation";
    case QCA::CRLEntry::CertificateHold:
        return "CertificateHold";
    case QCA::CRLEntry::RemoveFromCRL:
        return "RemoveFromCRL";
    case QCA::CRLEntry::PrivilegeWithdrawn:
        return "PrivilegeWithdrawn";
    case QCA::CRLEntry::AACompromise:
        return "AACompromise";
    default:
        return "Unknown";
    }
}

static bool validOid(const QString &in)
{
    for (const QChar &c : in) {
        if (!c.isDigit() && c != QLatin1Char('.'))
            return false;
    }
    return true;
}

class ValidityLength
{
public:
    int years, months, days;
};

static int vl_getnext(const QString &in, int offset = 0)
{
    if (offset >= in.length())
        return in.length();

    int  n = offset;
    bool lookForNonDigit;

    if (in[n].isDigit())
        lookForNonDigit = true;
    else
        lookForNonDigit = false;

    for (++n; n < in.length(); ++n) {
        if (in[n].isDigit() != lookForNonDigit)
            break;
    }
    return n;
}

static QStringList vl_getparts(const QString &in)
{
    QStringList out;
    int         offset = 0;
    while (true) {
        int n = vl_getnext(in, offset);
        if (n == offset)
            break;
        out += in.mid(offset, n - offset);
        offset = n;
    }
    return out;
}

static bool parseValidityLength(const QString &in, ValidityLength *vl)
{
    vl->years  = -1;
    vl->months = -1;
    vl->days   = -1;

    QStringList parts = vl_getparts(in);
    while (true) {
        // first part should be a number
        if (parts.count() < 1)
            break;
        QString str = parts.takeFirst();
        bool    ok;
        int     x = str.toInt(&ok);
        if (!ok)
            return false;

        // next part should be 1 letter plus any amount of space
        if (parts.count() < 1)
            return false;
        str = parts.takeFirst();
        if (!str[0].isLetter())
            return false;
        str = str.trimmed(); // remove space

        if (str == QLatin1String("y")) {
            if (vl->years != -1)
                return false;
            vl->years = x;
        }
        if (str == QLatin1String("m")) {
            if (vl->months != -1)
                return false;
            vl->months = x;
        }
        if (str == QLatin1String("d")) {
            if (vl->days != -1)
                return false;
            vl->days = x;
        }
    }

    if (vl->years == -1)
        vl->years = 0;
    if (vl->months == -1)
        vl->months = 0;
    if (vl->days == -1)
        vl->days = 0;

    return true;
}

static QString prompt_for(const QString &prompt)
{
    printf("%s: ", prompt.toLatin1().data());
    fflush(stdout);
    QByteArray result(256, 0);
    if (fgets((char *)result.data(), result.size(), stdin))
        return QString::fromLocal8Bit(result).trimmed();
    else
        return QString();
}

static QCA::CertificateOptions promptForCertAttributes(bool advanced, bool req)
{
    QCA::CertificateOptions opts;

    if (advanced) {
        if (!req) {
            while (true) {
                QString str = prompt_for(
                    QStringLiteral("Create an end user ('user') certificate or a CA ('ca') certificate? [user]"));
                if (str.isEmpty())
                    str = QStringLiteral("user");
                if (str != QLatin1String("user") && str != QLatin1String("ca")) {
                    printf("'%s' is not a valid entry.\n", qPrintable(str));
                    continue;
                }

                if (str == QLatin1String("ca"))
                    opts.setAsCA();
                break;
            }
            printf("\n");

            while (true) {
                QString         str = prompt_for(QStringLiteral("Serial Number"));
                QCA::BigInteger num;
                if (str.isEmpty() || !num.fromString(str)) {
                    printf("'%s' is not a valid entry.\n", qPrintable(str));
                    continue;
                }

                opts.setSerialNumber(num);
                break;
            }
            printf("\n");
        }

        {
            QCA::CertificateInfoOrdered info;
            printf(
                "Choose the information attributes to add to the certificate.  They will be\n"
                "added in the order they are entered.\n\n");
            printf("Available information attributes:\n");
            QList<InfoType> list = makeInfoTypeList();
            for (int n = 0; n < list.count(); ++n) {
                const InfoType &i = list[n];
                char            c = 'a' + n;
                printf("  %c) %-32s        %s\n", c, qPrintable(i.name), qPrintable(i.desc));
            }
            printf("\n");
            while (true) {
                int index;
                while (true) {
                    QString str = prompt_for(QStringLiteral("Select an attribute to add, or enter to move on"));
                    if (str.isEmpty()) {
                        index = -1;
                        break;
                    }
                    if (str.length() == 1) {
                        index = str[0].toLatin1() - 'a';
                        if (index >= 0 && index < list.count())
                            break;
                    }
                    printf("'%s' is not a valid entry.\n", qPrintable(str));
                }
                if (index == -1)
                    break;

                QString val = prompt_for(list[index].name);
                info += QCA::CertificateInfoPair(list[index].type, val);
                printf("Added attribute.\n\n");
            }
            opts.setInfoOrdered(info);
        }

        {
            QCA::Constraints constraints;
            printf("\n");
            printf("Choose the constraint attributes to add to the certificate.\n\n");
            printf("Available attributes:\n");
            QList<MyConstraintType> list = makeConstraintTypeList();
            for (int n = 0; n < list.count(); ++n) {
                const MyConstraintType &i = list[n];
                char                    c = 'a' + n;
                printf("  %c) %-32s        %s\n", c, qPrintable(i.name), qPrintable(i.desc));
            }
            printf("\n");
            printf("If no constraints are added, then the certificate may be used for any purpose.\n\n");
            while (true) {
                int index;
                while (true) {
                    QString str = prompt_for(QStringLiteral("Select an attribute to add, or enter to move on"));
                    if (str.isEmpty()) {
                        index = -1;
                        break;
                    }
                    if (str.length() == 1) {
                        index = str[0].toLatin1() - 'a';
                        if (index >= 0 && index < list.count())
                            break;
                    }
                    printf("'%s' is not a valid entry.\n\n", qPrintable(str));
                }
                if (index == -1)
                    break;

                if (constraints.contains(list[index].type)) {
                    printf("You have already added '%s'.\n\n", qPrintable(list[index].name));
                    continue;
                }

                constraints += list[index].type;
                printf("Added attribute.\n\n");
            }
            opts.setConstraints(constraints);
        }

        {
            QStringList policies;
            printf("\n");
            printf(
                "Are there any policy OID attributes that you wish to add?  Use the dotted\n"
                "string format.\n\n");
            while (true) {
                QString str = prompt_for(QStringLiteral("Enter a policy OID to add, or enter to move on"));
                if (str.isEmpty())
                    break;
                if (!validOid(str)) {
                    printf("'%s' is not a valid entry.\n\n", qPrintable(str));
                    continue;
                }
                if (policies.contains(str)) {
                    printf("You have already added '%s'.\n\n", qPrintable(str));
                    continue;
                }

                policies += str;
                printf("Added attribute.\n\n");
            }
            opts.setPolicies(policies);
        }

        printf("\n");
    } else {
        QCA::CertificateInfo info;
        info.insert(QCA::CommonName, prompt_for(QStringLiteral("Common Name")));
        info.insert(QCA::Country, prompt_for(QStringLiteral("Country Code (2 letters)")));
        info.insert(QCA::Organization, prompt_for(QStringLiteral("Organization")));
        info.insert(QCA::Email, prompt_for(QStringLiteral("Email")));
        opts.setInfo(info);

        printf("\n");
    }

    if (!req) {
        while (true) {
            QString str = prompt_for(QStringLiteral("How long should the certificate be valid? (e.g. '1y2m3d')"));
            ValidityLength vl;
            if (!parseValidityLength(str, &vl)) {
                printf("'%s' is not a valid entry.\n\n", qPrintable(str));
                continue;
            }

            if (vl.years == 0 && vl.months == 0 && vl.days == 0) {
                printf("The certificate must be valid for at least one day.\n\n");
                continue;
            }

            QDateTime start = QDateTime::currentDateTimeUtc();
            QDateTime end   = start;
            if (vl.years > 0)
                end = end.addYears(vl.years);
            if (vl.months > 0)
                end = end.addMonths(vl.months);
            if (vl.days > 0)
                end = end.addDays(vl.days);
            opts.setValidityPeriod(start, end);

            QStringList parts;
            if (vl.years > 0)
                parts += QStringLiteral("%1 year(s)").arg(vl.years);
            if (vl.months > 0)
                parts += QStringLiteral("%1 month(s)").arg(vl.months);
            if (vl.days > 0)
                parts += QStringLiteral("%1 day(s)").arg(vl.days);
            QString out;
            if (parts.count() == 1)
                out = parts[0];
            else if (parts.count() == 2)
                out = parts[0] + QStringLiteral(" and ") + parts[1];
            else if (parts.count() == 3)
                out = parts[0] + QStringLiteral(", ") + parts[1] + QStringLiteral(", and ") + parts[2];
            printf("Certificate will be valid for %s.\n", qPrintable(out));
            break;
        }
        printf("\n");
    }

    return opts;
}

// qsettings seems to give us a string type for both bool and int (and
//   possibly others, but those are the only two we care about here).
//   in order to figure out what is actually a bool or an int, we need
//   to examine the string.  so for the functions below, we convert
//   the variant to a string, and then inspect it to see if it looks
//   like a bool or an int.

static bool string_is_bool(const QString &in)
{
    QString lc = in.toLower();
    if (lc == QLatin1String("true") || lc == QLatin1String("false"))
        return true;
    return false;
}

static bool string_is_int(const QString &in)
{
    bool ok;
    in.toInt(&ok);
    return ok;
}

static bool variant_is_bool(const QVariant &in)
{
    if (in.canConvert<QString>() && string_is_bool(in.toString()))
        return true;
    return false;
}

static bool variant_is_int(const QVariant &in)
{
    if (in.canConvert<QString>() && string_is_int(in.toString()))
        return true;
    return false;
}

static QString prompt_for_string(const QString &prompt, const QString &def = QString())
{
    printf("%s", prompt.toLatin1().data());
    fflush(stdout);
    QByteArray result(256, 0);
    if (!fgets((char *)result.data(), result.size(), stdin))
        return QString();
    if (result[result.length() - 1] == '\n')
        result.truncate(result.length() - 1);
    // empty input -> use default
    if (result.isEmpty())
        return def;
    // trimmed input could result in an empty value, but in that case
    //   it is treated as if the user wishes to submit an empty value.
    return QString::fromLocal8Bit(result).trimmed();
}

static int prompt_for_int(const QString &prompt, int def = 0)
{
    while (true) {
        QString str = prompt_for_string(prompt);
        if (str.isEmpty())
            return def;
        bool ok;
        int  x = str.toInt(&ok);
        if (ok)
            return x;
        printf("'%s' is not a valid entry.\n\n", qPrintable(str));
    }
}

static bool partial_compare_nocase(const QString &in, const QString &target, int min = 1)
{
    if (in.length() >= min && in.length() <= target.length() && target.mid(0, in.length()).toLower() == in.toLower())
        return true;
    return false;
}

static bool prompt_for_bool(const QString &prompt, bool def = false)
{
    while (true) {
        QString str = prompt_for_string(prompt);
        if (str.isEmpty())
            return def;
        if (partial_compare_nocase(str, QStringLiteral("true")))
            return true;
        else if (partial_compare_nocase(str, QStringLiteral("false")))
            return false;
        printf("'%s' is not a valid entry.\n\n", qPrintable(str));
    }
}

static bool prompt_for_yesno(const QString &prompt, bool def = false)
{
    while (true) {
        QString str = prompt_for_string(prompt);
        if (str.isEmpty())
            return def;
        if (partial_compare_nocase(str, QStringLiteral("yes")))
            return true;
        else if (partial_compare_nocase(str, QStringLiteral("no")))
            return false;
        printf("'%s' is not a valid entry.\n\n", qPrintable(str));
    }
}

static QString prompt_for_slotevent_method(const QString &prompt, const QString &def = QString())
{
    while (true) {
        QString str = prompt_for_string(prompt);
        if (str.isEmpty())
            return def;
        if (partial_compare_nocase(str, QStringLiteral("auto")))
            return QStringLiteral("auto");
        else if (partial_compare_nocase(str, QStringLiteral("trigger")))
            return QStringLiteral("trigger");
        else if (partial_compare_nocase(str, QStringLiteral("poll")))
            return QStringLiteral("poll");
        printf("'%s' is not a valid entry.\n\n", qPrintable(str));
    }
}

static QVariantMap provider_config_edit_generic(const QVariantMap &in)
{
    QVariantMap                            config = in;
    QMutableMapIterator<QString, QVariant> it(config);
    while (it.hasNext()) {
        it.next();
        QString var = it.key();
        if (var == QLatin1String("formtype"))
            continue;
        QVariant val = it.value();

        // fields must be bool, int, or string
        QVariant newval;
        QString  prompt = QStringLiteral("%1: [%2] ").arg(var, val.toString());
        if (variant_is_bool(val))
            newval = prompt_for_bool(QStringLiteral("bool   ") + prompt, val.toBool());
        else if (variant_is_int(val))
            newval = prompt_for_int(QStringLiteral("int    ") + prompt, val.toInt());
        else if (val.canConvert<QString>())
            newval = prompt_for_string(QStringLiteral("string ") + prompt, val.toString());
        else
            continue; // skip bogus fields

        it.setValue(newval);
    }

    return config;
}

class Pkcs11ProviderConfig
{
public:
    bool    allow_protected_authentication;
    bool    cert_private;
    bool    enabled;
    QString library;
    QString name;
    int     private_mask;
    QString slotevent_method;
    int     slotevent_timeout;

    Pkcs11ProviderConfig()
        : allow_protected_authentication(true)
        , cert_private(false)
        , enabled(false)
        , private_mask(0)
        , slotevent_method(QStringLiteral("auto"))
        , slotevent_timeout(0)
    {
    }

    QVariantMap toVariantMap() const
    {
        QVariantMap out;
        out[QStringLiteral("allow_protected_authentication")] = allow_protected_authentication;
        out[QStringLiteral("cert_private")]                   = cert_private;
        out[QStringLiteral("enabled")]                        = enabled;
        out[QStringLiteral("library")]                        = library;
        out[QStringLiteral("name")]                           = name;
        out[QStringLiteral("private_mask")]                   = private_mask;
        out[QStringLiteral("slotevent_method")]               = slotevent_method;
        out[QStringLiteral("slotevent_timeout")]              = slotevent_timeout;
        return out;
    }

    bool fromVariantMap(const QVariantMap &in)
    {
        allow_protected_authentication = in[QStringLiteral("allow_protected_authentication")].toBool();
        cert_private                   = in[QStringLiteral("cert_private")].toBool();
        enabled                        = in[QStringLiteral("enabled")].toBool();
        library                        = in[QStringLiteral("library")].toString();
        name                           = in[QStringLiteral("name")].toString();
        private_mask                   = in[QStringLiteral("private_mask")].toInt();
        slotevent_method               = in[QStringLiteral("slotevent_method")].toString();
        slotevent_timeout              = in[QStringLiteral("slotevent_timeout")].toInt();
        return true;
    }
};

class Pkcs11Config
{
public:
    bool                        allow_load_rootca;
    bool                        allow_protected_authentication;
    int                         log_level;
    int                         pin_cache;
    QList<Pkcs11ProviderConfig> providers;

    QVariantMap orig_config;

    Pkcs11Config()
        : allow_load_rootca(false)
        , allow_protected_authentication(true)
        , log_level(0)
        , pin_cache(-1)
    {
    }

    QVariantMap toVariantMap() const
    {
        QVariantMap out = orig_config;

        // form type
        out[QStringLiteral("formtype")] = QLatin1String("http://affinix.com/qca/forms/qca-pkcs11#1.0");

        // base settings
        out[QStringLiteral("allow_load_rootca")]              = allow_load_rootca;
        out[QStringLiteral("allow_protected_authentication")] = allow_protected_authentication;
        out[QStringLiteral("log_level")]                      = log_level;
        out[QStringLiteral("pin_cache")]                      = pin_cache;

        // provider settings (always write at least 10 providers)
        for (int n = 0; n < 10 || n < providers.count(); ++n) {
            QString prefix = QString::asprintf("provider_%02d_", n);

            Pkcs11ProviderConfig provider;
            if (n < providers.count())
                provider = providers[n];

            QVariantMap                     subconfig = provider.toVariantMap();
            QMapIterator<QString, QVariant> it(subconfig);
            while (it.hasNext()) {
                it.next();
                out.insert(prefix + it.key(), it.value());
            }
        }

        return out;
    }

    bool fromVariantMap(const QVariantMap &in)
    {
        if (in[QStringLiteral("formtype")] != QLatin1String("http://affinix.com/qca/forms/qca-pkcs11#1.0"))
            return false;

        allow_load_rootca              = in[QStringLiteral("allow_load_rootca")].toBool();
        allow_protected_authentication = in[QStringLiteral("allow_protected_authentication")].toBool();
        log_level                      = in[QStringLiteral("log_level")].toInt();
        pin_cache                      = in[QStringLiteral("pin_cache")].toInt();

        for (int n = 0;; ++n) {
            QString prefix = QString::asprintf("provider_%02d_", n);

            // collect all key/values with this prefix into a
            //   a separate container, leaving out the prefix
            //   from the keys.
            QVariantMap                     subconfig;
            QMapIterator<QString, QVariant> it(in);
            while (it.hasNext()) {
                it.next();
                if (it.key().startsWith(prefix))
                    subconfig.insert(it.key().mid(prefix.length()), it.value());
            }

            // if there are no config items with this prefix, we're done
            if (subconfig.isEmpty())
                break;

            Pkcs11ProviderConfig provider;
            if (!provider.fromVariantMap(subconfig))
                return false;

            // skip unnamed entries
            if (provider.name.isEmpty())
                continue;

            // skip duplicate entries
            bool have_name_already = false;
            foreach (const Pkcs11ProviderConfig &i, providers) {
                if (i.name == provider.name) {
                    have_name_already = true;
                    break;
                }
            }
            if (have_name_already)
                continue;

            providers += provider;
        }

        orig_config = in;
        return true;
    }
};

static QVariantMap provider_config_edit_pkcs11(const QVariantMap &in)
{
    Pkcs11Config config;
    if (!config.fromVariantMap(in)) {
        fprintf(stderr, "Error: unable to parse PKCS#11 provider configuration.\n");
        return QVariantMap();
    }

    while (true) {
        printf("\n");
        printf("Global settings:\n");
        printf("  Allow loading of root CAs: %s\n", config.allow_load_rootca ? "Yes" : "No");
        printf("  Allow protected authentication: %s\n", config.allow_protected_authentication ? "Yes" : "No");
        QString str;
        if (config.pin_cache == -1)
            str = QStringLiteral("No limit");
        else
            str = QStringLiteral("%1 seconds").arg(config.pin_cache);
        printf("  Maximum PIN cache time: %s\n", qPrintable(str));
        printf("  Log level: %d\n", config.log_level);
        printf("\n");
        printf("PKCS#11 modules:\n");
        if (!config.providers.isEmpty()) {
            foreach (const Pkcs11ProviderConfig &provider, config.providers)
                printf("  %s\n", qPrintable(provider.name));
        } else
            printf("  (None)\n");
        printf("\n");
        printf("Actions:\n");
        printf("  a) Edit global settings\n");
        printf("  b) Add PKCS#11 module\n");
        printf("  c) Edit PKCS#11 module\n");
        printf("  d) Remove PKCS#11 module\n");
        printf("\n");

        int index;
        while (true) {
            QString str = prompt_for(QStringLiteral("Select an action, or enter to quit"));
            if (str.isEmpty()) {
                index = -1;
                break;
            }
            if (str.length() == 1) {
                index = str[0].toLatin1() - 'a';
                if (index >= 0 && index < 4)
                    break;
            }
            printf("'%s' is not a valid entry.\n\n", qPrintable(str));
        }
        if (index == -1)
            break;

        if (index == 0) {
            printf("\n");

            QString prompt;
            prompt = QStringLiteral("Allow loading of root CAs: [%1] ")
                         .arg(config.allow_load_rootca ? QStringLiteral("Yes") : QStringLiteral("No"));
            config.allow_load_rootca = prompt_for_yesno(prompt, config.allow_load_rootca);
            prompt                   = QStringLiteral("Allow protected authentication: [%1] ")
                         .arg(config.allow_protected_authentication ? QStringLiteral("Yes") : QStringLiteral("No"));
            config.allow_protected_authentication = prompt_for_yesno(prompt, config.allow_protected_authentication);
            prompt = QStringLiteral("Maximum PIN cache time in seconds (-1 for no limit): [%1] ").arg(config.pin_cache);
            config.pin_cache = prompt_for_int(prompt, config.pin_cache);
            prompt           = QStringLiteral("Log level: [%1] ").arg(config.log_level);
            config.log_level = prompt_for_int(prompt, config.log_level);
        } else // 1, 2, 3
        {
            int at = -1;

            // for edit/remove, need to select provider
            if (index == 2 || index == 3) {
                printf("\nWhich PKCS#11 module?\n");
                for (int n = 0; n < config.providers.count(); ++n) {
                    const Pkcs11ProviderConfig &provider = config.providers[n];
                    char                        c        = 'a' + n;
                    printf("  %c) %s\n", c, qPrintable(provider.name));
                }
                printf("\n");

                int index;
                while (true) {
                    QString str = prompt_for(QStringLiteral("Select a module, or enter to go back"));
                    if (str.isEmpty()) {
                        index = -1;
                        break;
                    }
                    if (str.length() == 1) {
                        index = str[0].toLatin1() - 'a';
                        if (index >= 0 && index < config.providers.count())
                            break;
                    }
                    printf("'%s' is not a valid entry.\n", qPrintable(str));
                }

                // exit?
                if (index == -1)
                    continue;

                at = index;
            }

            // edit the entry
            if (index == 1 || index == 2) {
                Pkcs11ProviderConfig provider;
                if (index == 2) // edit
                    provider = config.providers[at];
                provider.enabled = true;
                printf("\n");

                QString prompt;

                // prompt for unique name
                while (true) {
                    if (index == 1)
                        prompt = QStringLiteral("Unique friendly name: ");
                    else
                        prompt = QStringLiteral("Unique friendly name: [%1] ").arg(provider.name);
                    provider.name = prompt_for_string(prompt, provider.name);

                    if (provider.name.isEmpty()) {
                        printf("The friendly name cannot be blank.\n\n");
                        continue;
                    }

                    bool have_name_already = false;
                    for (int n = 0; n < config.providers.count(); ++n) {
                        const Pkcs11ProviderConfig &i = config.providers[n];

                        // skip checking against the entry we are editing
                        if (at != -1 && n == at)
                            continue;

                        if (i.name == provider.name) {
                            have_name_already = true;
                            break;
                        }
                    }
                    if (have_name_already) {
                        printf("This name is already used by another module.\n\n");
                        continue;
                    }

                    break;
                }

                // prompt for library file
                QString last;
                while (true) {
                    if (index == 1)
                        prompt = QStringLiteral("Library filename: ");
                    else
                        prompt = QStringLiteral("Library filename: [%1] ").arg(provider.library);
                    provider.library = prompt_for_string(prompt, provider.library);

                    if (provider.library.isEmpty()) {
                        printf("The library filename cannot be blank.\n\n");
                        continue;
                    }

                    if (last != provider.library && !QFile::exists(provider.library)) {
                        last = provider.library;
                        printf("'%s' does not exist.\nPress enter again if you really want this.\n\n",
                               qPrintable(provider.library));
                        continue;
                    }

                    break;
                }

                prompt =
                    QStringLiteral("Allow protected authentication: [%1] ")
                        .arg(provider.allow_protected_authentication ? QStringLiteral("Yes") : QStringLiteral("No"));
                provider.allow_protected_authentication =
                    prompt_for_yesno(prompt, provider.allow_protected_authentication);
                prompt = QStringLiteral("Provider stores certificates as private objects: [%1] ")
                             .arg(provider.cert_private ? QStringLiteral("Yes") : QStringLiteral("No"));
                provider.cert_private = prompt_for_yesno(prompt, provider.cert_private);
                printf("\n");
                printf("Provider private key mask:\n");
                printf("    0        Determine automatically.\n");
                printf("    1        Use sign.\n");
                printf("    2        Use sign recover.\n");
                printf("    4        Use decrypt.\n");
                printf("    8        Use unwrap.\n");
                prompt                = QStringLiteral("Mask value: [%1] ").arg(provider.private_mask);
                provider.private_mask = prompt_for_int(prompt, provider.private_mask);
                printf("\n");
                printf("Slot event method:\n");
                printf("    auto     Determine automatically.\n");
                printf("    trigger  Use trigger.\n");
                printf("    poll     Use poll.\n");
                prompt                    = QStringLiteral("Method value: [%1] ").arg(provider.slotevent_method);
                provider.slotevent_method = prompt_for_slotevent_method(prompt, provider.slotevent_method);
                if (provider.slotevent_method == QLatin1String("poll")) {
                    prompt =
                        QStringLiteral("Poll timeout (0 for no preference): [%1] ").arg(provider.slotevent_timeout);
                    provider.slotevent_timeout = prompt_for_int(prompt, provider.slotevent_timeout);
                } else
                    provider.slotevent_timeout = 0;

                if (index == 1)
                    config.providers += provider;
                else // 2
                    config.providers[at] = provider;
            }
            // remove the entry
            else // 3
            {
                config.providers.removeAt(at);
            }
        }
    }

    return config.toVariantMap();
}

static QVariantMap provider_config_edit(const QVariantMap &in)
{
    // see if we have a configurator for a known form type
    if (in[QStringLiteral("formtype")] == QLatin1String("http://affinix.com/qca/forms/qca-pkcs11#1.0"))
        return provider_config_edit_pkcs11(in);

    // otherwise, use the generic configurator
    return provider_config_edit_generic(in);
}

static QString get_fingerprint(const QCA::Certificate &cert, const QString &hashType)
{
    QString hex = QCA::Hash(hashType).hashToString(cert.toDER());
    QString out;
    for (int n = 0; n < hex.count(); ++n) {
        if (n != 0 && n % 2 == 0)
            out += QLatin1Char(':');
        out += hex[n];
    }
    return out;
}

static QString kstype_to_string(QCA::KeyStore::Type _type)
{
    QString type;
    switch (_type) {
    case QCA::KeyStore::System:
        type = QStringLiteral("Sys ");
        break;
    case QCA::KeyStore::User:
        type = QStringLiteral("User");
        break;
    case QCA::KeyStore::Application:
        type = QStringLiteral("App ");
        break;
    case QCA::KeyStore::SmartCard:
        type = QStringLiteral("Card");
        break;
    case QCA::KeyStore::PGPKeyring:
        type = QStringLiteral("PGP ");
        break;
    default:
        type = QStringLiteral("XXXX");
        break;
    }
    return type;
}

static QString ksentrytype_to_string(QCA::KeyStoreEntry::Type _type)
{
    QString type;
    switch (_type) {
    case QCA::KeyStoreEntry::TypeKeyBundle:
        type = QStringLiteral("Key ");
        break;
    case QCA::KeyStoreEntry::TypeCertificate:
        type = QStringLiteral("Cert");
        break;
    case QCA::KeyStoreEntry::TypeCRL:
        type = QStringLiteral("CRL ");
        break;
    case QCA::KeyStoreEntry::TypePGPSecretKey:
        type = QStringLiteral("PSec");
        break;
    case QCA::KeyStoreEntry::TypePGPPublicKey:
        type = QStringLiteral("PPub");
        break;
    default:
        type = QStringLiteral("XXXX");
        break;
    }
    return type;
}

static void try_print_info(const char *name, const QStringList &values)
{
    if (!values.isEmpty()) {
        QString value = values.join(QStringLiteral(", "));
        printf("   %s: %s\n", name, value.toUtf8().data());
    }
}

static void print_info(const char *title, const QCA::CertificateInfo &info)
{
    QList<InfoType> list = makeInfoTypeList();
    printf("%s\n", title);
    foreach (const InfoType &t, list)
        try_print_info(qPrintable(t.name), info.values(t.type));
}

static void print_info_ordered(const char *title, const QCA::CertificateInfoOrdered &info)
{
    QList<InfoType> list = makeInfoTypeList(true);
    printf("%s\n", title);
    foreach (const QCA::CertificateInfoPair &pair, info) {
        QCA::CertificateInfoType type = pair.type();
        QString                  name;
        int                      at = -1;
        for (int n = 0; n < list.count(); ++n) {
            if (list[n].type == type) {
                at = n;
                break;
            }
        }

        // known type?
        if (at != -1) {
            name = list[at].name;
        } else {
            if (pair.type().section() == QCA::CertificateInfoType::DN)
                name = QStringLiteral("DN:") + pair.type().id();
            else
                name = QStringLiteral("AN:") + pair.type().id();
        }

        printf("   %s: %s\n", qPrintable(name), pair.value().toUtf8().data());
    }
}

static QString constraint_to_string(const QCA::ConstraintType &t)
{
    QList<MyConstraintType> list = makeConstraintTypeList();
    for (int n = 0; n < list.count(); ++n) {
        if (list[n].type == t)
            return list[n].name;
    }
    return t.id();
}

static QString sigalgo_to_string(QCA::SignatureAlgorithm algo)
{
    QString str;
    switch (algo) {
    case QCA::EMSA1_SHA1:
        str = QStringLiteral("EMSA1(SHA1)");
        break;
    case QCA::EMSA3_SHA1:
        str = QStringLiteral("EMSA3(SHA1)");
        break;
    case QCA::EMSA3_MD5:
        str = QStringLiteral("EMSA3(MD5)");
        break;
    case QCA::EMSA3_MD2:
        str = QStringLiteral("EMSA3(MD2)");
        break;
    case QCA::EMSA3_RIPEMD160:
        str = QStringLiteral("EMSA3(RIPEMD160)");
        break;
    case QCA::EMSA3_Raw:
        str = QStringLiteral("EMSA3(raw)");
        break;
    default:
        str = QStringLiteral("Unknown");
        break;
    }
    return str;
}

static void print_cert(const QCA::Certificate &cert, bool ordered = false)
{
    printf("Serial Number: %s\n", qPrintable(cert.serialNumber().toString()));

    if (ordered) {
        print_info_ordered("Subject", cert.subjectInfoOrdered());
        print_info_ordered("Issuer", cert.issuerInfoOrdered());
    } else {
        print_info("Subject", cert.subjectInfo());
        print_info("Issuer", cert.issuerInfo());
    }

    printf("Validity\n");
    printf("   Not before: %s\n", qPrintable(cert.notValidBefore().toString()));
    printf("   Not after:  %s\n", qPrintable(cert.notValidAfter().toString()));

    printf("Constraints\n");
    QCA::Constraints constraints = cert.constraints();
    int              n;
    if (!constraints.isEmpty()) {
        for (n = 0; n < constraints.count(); ++n)
            printf("   %s\n", qPrintable(constraint_to_string(constraints[n])));
    } else
        printf("   No constraints\n");

    printf("Policies\n");
    QStringList policies = cert.policies();
    if (!policies.isEmpty()) {
        for (n = 0; n < policies.count(); ++n)
            printf("   %s\n", qPrintable(policies[n]));
    } else
        printf("   No policies\n");

    QByteArray id;
    printf("Issuer Key ID: ");
    id = cert.issuerKeyId();
    if (!id.isEmpty())
        printf("%s\n", qPrintable(QCA::arrayToHex(id)));
    else
        printf("None\n");

    printf("Subject Key ID: ");
    id = cert.subjectKeyId();
    if (!id.isEmpty())
        printf("%s\n", qPrintable(QCA::arrayToHex(id)));
    else
        printf("None\n");

    printf("CA: %s\n", cert.isCA() ? "Yes" : "No");
    printf("Signature Algorithm: %s\n", qPrintable(sigalgo_to_string(cert.signatureAlgorithm())));

    QCA::PublicKey key = cert.subjectPublicKey();
    printf("Public Key:\n%s", key.toPEM().toLatin1().data());

    printf("SHA1 Fingerprint: %s\n", qPrintable(get_fingerprint(cert, QStringLiteral("sha1"))));
    printf("MD5 Fingerprint: %s\n", qPrintable(get_fingerprint(cert, QStringLiteral("md5"))));
}

static void print_certreq(const QCA::CertificateRequest &cert, bool ordered = false)
{
    if (ordered)
        print_info_ordered("Subject", cert.subjectInfoOrdered());
    else
        print_info("Subject", cert.subjectInfo());

    printf("Constraints\n");
    QCA::Constraints constraints = cert.constraints();
    int              n;
    if (!constraints.isEmpty()) {
        for (n = 0; n < constraints.count(); ++n)
            printf("   %s\n", qPrintable(constraint_to_string(constraints[n])));
    } else
        printf("   No constraints\n");

    printf("Policies\n");
    QStringList policies = cert.policies();
    if (!policies.isEmpty()) {
        for (n = 0; n < policies.count(); ++n)
            printf("   %s\n", qPrintable(policies[n]));
    } else
        printf("   No policies\n");

    printf("CA: %s\n", cert.isCA() ? "Yes" : "No");
    printf("Signature Algorithm: %s\n", qPrintable(sigalgo_to_string(cert.signatureAlgorithm())));

    QCA::PublicKey key = cert.subjectPublicKey();
    printf("Public Key:\n%s", key.toPEM().toLatin1().data());
}

static void print_crl(const QCA::CRL &crl, bool ordered = false)
{
    if (ordered)
        print_info_ordered("Issuer", crl.issuerInfoOrdered());
    else
        print_info("Issuer", crl.issuerInfo());

    int num = crl.number();
    if (num != -1)
        printf("Number: %d\n", num);

    printf("Validity\n");
    printf("   This update: %s\n", qPrintable(crl.thisUpdate().toString()));
    printf("   Next update: %s\n", qPrintable(crl.nextUpdate().toString()));

    QByteArray id;
    printf("Issuer Key ID: ");
    id = crl.issuerKeyId();
    if (!id.isEmpty())
        printf("%s\n", qPrintable(QCA::arrayToHex(id)));
    else
        printf("None\n");

    printf("Signature Algorithm: %s\n", qPrintable(sigalgo_to_string(crl.signatureAlgorithm())));

    QList<QCA::CRLEntry> revokedList = crl.revoked();
    foreach (const QCA::CRLEntry &entry, revokedList) {
        printf("   %s: %s, %s\n",
               qPrintable(entry.serialNumber().toString()),
               crlEntryReasonToString(entry.reason()),
               qPrintable(entry.time().toString()));
    }
}

static QString format_pgp_fingerprint(const QString &in)
{
    QString out;
    bool    first = true;
    for (int n = 0; n + 3 < in.length(); n += 4) {
        if (!first)
            out += QLatin1Char(' ');
        else
            first = false;
        out += in.mid(n, 4).toUpper();
    }
    return out;
}

static void print_pgp(const QCA::PGPKey &key)
{
    printf("Key ID: %s\n", qPrintable(key.keyId()));
    printf("User IDs:\n");
    foreach (const QString &s, key.userIds())
        printf("   %s\n", qPrintable(s));
    printf("Validity\n");
    printf("   Not before: %s\n", qPrintable(key.creationDate().toString()));
    if (!key.expirationDate().isNull())
        printf("   Not after:  %s\n", qPrintable(key.expirationDate().toString()));
    else
        printf("   Not after:  (no expiration)\n");
    printf("In Keyring: %s\n", key.inKeyring() ? "Yes" : "No");
    printf("Secret Key: %s\n", key.isSecret() ? "Yes" : "No");
    printf("Trusted:    %s\n", key.isTrusted() ? "Yes" : "No");
    printf("Fingerprint: %s\n", qPrintable(format_pgp_fingerprint(key.fingerprint())));
}

static QString validityToString(QCA::Validity v)
{
    QString s;
    switch (v) {
    case QCA::ValidityGood:
        s = QStringLiteral("Validated");
        break;
    case QCA::ErrorRejected:
        s = QStringLiteral("Root CA is marked to reject the specified purpose");
        break;
    case QCA::ErrorUntrusted:
        s = QStringLiteral("Certificate not trusted for the required purpose");
        break;
    case QCA::ErrorSignatureFailed:
        s = QStringLiteral("Invalid signature");
        break;
    case QCA::ErrorInvalidCA:
        s = QStringLiteral("Invalid CA certificate");
        break;
    case QCA::ErrorInvalidPurpose:
        s = QStringLiteral("Invalid certificate purpose");
        break;
    case QCA::ErrorSelfSigned:
        s = QStringLiteral("Certificate is self-signed");
        break;
    case QCA::ErrorRevoked:
        s = QStringLiteral("Certificate has been revoked");
        break;
    case QCA::ErrorPathLengthExceeded:
        s = QStringLiteral("Maximum certificate chain length exceeded");
        break;
    case QCA::ErrorExpired:
        s = QStringLiteral("Certificate has expired");
        break;
    case QCA::ErrorExpiredCA:
        s = QStringLiteral("CA has expired");
        break;
    case QCA::ErrorValidityUnknown:
    default:
        s = QStringLiteral("General certificate validation error");
        break;
    }
    return s;
}

static QString smIdentityResultToString(QCA::SecureMessageSignature::IdentityResult r)
{
    QString str;
    switch (r) {
    case QCA::SecureMessageSignature::Valid:
        str = QStringLiteral("Valid");
        break;
    case QCA::SecureMessageSignature::InvalidSignature:
        str = QStringLiteral("InvalidSignature");
        break;
    case QCA::SecureMessageSignature::InvalidKey:
        str = QStringLiteral("InvalidKey");
        break;
    case QCA::SecureMessageSignature::NoKey:
        str = QStringLiteral("NoKey");
        break;
    default:
        str = QStringLiteral("Unknown");
    }
    return str;
}

static QString smErrorToString(QCA::SecureMessage::Error e)
{
    QMap<QCA::SecureMessage::Error, QString> map;
    map[QCA::SecureMessage::ErrorPassphrase]       = QStringLiteral("ErrorPassphrase");
    map[QCA::SecureMessage::ErrorFormat]           = QStringLiteral("ErrorFormat");
    map[QCA::SecureMessage::ErrorSignerExpired]    = QStringLiteral("ErrorSignerExpired");
    map[QCA::SecureMessage::ErrorSignerInvalid]    = QStringLiteral("ErrorSignerInvalid");
    map[QCA::SecureMessage::ErrorEncryptExpired]   = QStringLiteral("ErrorEncryptExpired");
    map[QCA::SecureMessage::ErrorEncryptUntrusted] = QStringLiteral("ErrorEncryptUntrusted");
    map[QCA::SecureMessage::ErrorEncryptInvalid]   = QStringLiteral("ErrorEncryptInvalid");
    map[QCA::SecureMessage::ErrorNeedCard]         = QStringLiteral("ErrorNeedCard");
    map[QCA::SecureMessage::ErrorCertKeyMismatch]  = QStringLiteral("ErrorCertKeyMismatch");
    map[QCA::SecureMessage::ErrorUnknown]          = QStringLiteral("ErrorUnknown");
    return map[e];
}

static void smDisplaySignatures(const QList<QCA::SecureMessageSignature> &signers)
{
    foreach (const QCA::SecureMessageSignature &signer, signers) {
        QCA::SecureMessageSignature::IdentityResult r = signer.identityResult();
        fprintf(stderr, "IdentityResult: %s\n", qPrintable(smIdentityResultToString(r)));

        QCA::SecureMessageKey key = signer.key();
        if (!key.isNull()) {
            if (key.type() == QCA::SecureMessageKey::PGP) {
                QCA::PGPKey pub = key.pgpPublicKey();
                fprintf(stderr, "From: %s (%s)\n", qPrintable(pub.primaryUserId()), qPrintable(pub.keyId()));
            } else {
                QCA::Certificate     cert = key.x509CertificateChain().primary();
                QString              emailStr;
                QCA::CertificateInfo info = cert.subjectInfo();
                if (info.contains(QCA::Email))
                    emailStr = QStringLiteral(" (%1)").arg(info.value(QCA::Email));
                fprintf(stderr, "From: %s%s\n", qPrintable(cert.commonName()), qPrintable(emailStr));
            }
        }
    }
}

static const char *mime_signpart =
    "Content-Type: text/plain; charset=UTF-8\r\n"
    "Content-Transfer-Encoding: 8bit\r\n"
    "\r\n"
    "%1";

static const char *mime_signed =
    "Content-Type: multipart/signed;\r\n"
    "	micalg=%1;\r\n"
    "	boundary=QCATOOL-0001;\r\n"
    "	protocol=\"application/pkcs7-signature\"\r\n"
    "\r\n"
    "\r\n"
    "--QCATOOL-0001\r\n"
    "%2\r\n"
    "--QCATOOL-0001\r\n"
    "Content-Transfer-Encoding: base64\r\n"
    "Content-Type: application/pkcs7-signature;\r\n"
    "	name=smime.p7s\r\n"
    "Content-Disposition: attachment;\r\n"
    "	filename=smime.p7s\r\n"
    "\r\n"
    "%3\r\n"
    "\r\n"
    "--QCATOOL-0001--\r\n";

static const char *mime_enveloped =
    "Mime-Version: 1.0\r\n"
    "Content-Transfer-Encoding: base64\r\n"
    "Content-Type: application/pkcs7-mime;\r\n"
    "	name=smime.p7m;\r\n"
    "	smime-type=enveloped-data\r\n"
    "Content-Disposition: attachment;\r\n"
    "	filename=smime.p7m\r\n"
    "\r\n"
    "%1\r\n";

static QString add_cr(const QString &in)
{
    QString out = in;
    int     at  = 0;
    while (true) {
        at = out.indexOf(QLatin1Char('\n'), at);
        if (at == -1)
            break;
        if (at - 1 >= 0 && out[at - 1] != QLatin1Char('\r')) {
            out.insert(at, QLatin1Char('\r'));
            ++at;
        }
        ++at;
    }
    return out;
}

static QString rem_cr(const QString &in)
{
    QString out = in;
    out.replace(QLatin1String("\r\n"), QLatin1String("\n"));
    return out;
}

static int indexOf_newline(const QString &in, int offset = 0)
{
    for (int n = offset; n < in.length(); ++n) {
        if (n + 1 < in.length() && in[n] == QLatin1Char('\r') && in[n + 1] == QLatin1Char('\n'))
            return n;
        if (in[n] == QLatin1Char('\n'))
            return n;
    }
    return -1;
}

static int indexOf_doublenewline(const QString &in, int offset = 0)
{
    int at = -1;
    while (true) {
        int n = indexOf_newline(in, offset);
        if (n == -1)
            return -1;

        if (at != -1) {
            if (n == offset)
                break;
        }

        at = n;
        if (in[n] == QLatin1Char('\n'))
            offset = n + 1;
        else
            offset = n + 2;
    }
    return at;
}

// this is so gross
static int newline_len(const QString &in, int offset = 0)
{
    if (in[offset] == QLatin1Char('\r'))
        return 2;
    else
        return 1;
}

// all of this mime stuff is a total hack
static QString open_mime_envelope(const QString &in)
{
    int n = indexOf_doublenewline(in);
    if (n == -1)
        return QString();
    return in.mid(n + (newline_len(in, n) * 2)); // good lord
}

static bool open_mime_data_sig(const QString &in, QString *data, QString *sig)
{
    int n = in.indexOf(QLatin1String("boundary="));
    if (n == -1)
        return false;
    n += 9;
    int i = indexOf_newline(in, n);
    if (i == -1)
        return false;
    QString boundary;
    QString bregion = in.mid(n, i - n);
    n               = bregion.indexOf(QLatin1Char(';'));
    if (n != -1)
        boundary = bregion.mid(0, n);
    else
        boundary = bregion;

    if (boundary[0] == QLatin1Char('\"'))
        boundary.remove(0, 1);
    if (boundary[boundary.length() - 1] == QLatin1Char('\"'))
        boundary.remove(boundary.length() - 1, 1);
    // printf("boundary: [%s]\n", qPrintable(boundary));
    QString boundary_end = QStringLiteral("--") + boundary;
    boundary             = QStringLiteral("--") + boundary;

    QString work = open_mime_envelope(in);
    // printf("work: [%s]\n", qPrintable(work));

    n = work.indexOf(boundary);
    if (n == -1)
        return false;
    n += boundary.length();
    i = indexOf_newline(work, n);
    if (i == -1)
        return false;
    n += newline_len(work, i);
    int data_start = n;

    n = work.indexOf(boundary, data_start);
    if (n == -1)
        return false;
    int data_end = n;

    n = data_end + boundary.length();
    i = indexOf_newline(work, n);
    if (i == -1)
        return false;
    n += newline_len(work, i);
    int next = n;

    QString tmp_data = work.mid(data_start, data_end - data_start);
    n                = work.indexOf(boundary_end, next);
    if (n == -1)
        return false;
    QString tmp_sig = work.mid(next, n - next);

    // nuke some newlines
    if (tmp_data.right(2) == QLatin1String("\r\n"))
        tmp_data.truncate(tmp_data.length() - 2);
    else if (tmp_data.right(1) == QLatin1String("\n"))
        tmp_data.truncate(tmp_data.length() - 1);
    if (tmp_sig.right(2) == QLatin1String("\r\n"))
        tmp_sig.truncate(tmp_sig.length() - 2);
    else if (tmp_sig.right(1) == QLatin1String("\n"))
        tmp_sig.truncate(tmp_sig.length() - 1);

    tmp_sig = open_mime_envelope(tmp_sig);

    *data = tmp_data;
    *sig  = tmp_sig;
    return true;
}

static QString idHash(const QString &id)
{
    // hash the id and take the rightmost 4 hex characters
    return QCA::Hash(QStringLiteral("md5")).hashToString(id.toUtf8()).right(4);
}

// first = ids, second = names
static QPair<QStringList, QStringList> getKeyStoreStrings(const QStringList &list, QCA::KeyStoreManager *ksm)
{
    QPair<QStringList, QStringList> out;
    for (int n = 0; n < list.count(); ++n) {
        QCA::KeyStore ks(list[n], ksm);
        out.first.append(idHash(ks.id()));
        out.second.append(ks.name());
    }
    return out;
}

static QPair<QStringList, QStringList> getKeyStoreEntryStrings(const QList<QCA::KeyStoreEntry> &list)
{
    QPair<QStringList, QStringList> out;
    for (int n = 0; n < list.count(); ++n) {
        out.first.append(idHash(list[n].id()));
        out.second.append(list[n].name());
    }
    return out;
}

static QList<int> getPartialMatches(const QStringList &list, const QString &str)
{
    QList<int> out;
    for (int n = 0; n < list.count(); ++n) {
        if (list[n].contains(str, Qt::CaseInsensitive))
            out += n;
    }
    return out;
}

static int findByString(const QPair<QStringList, QStringList> &in, const QString &str)
{
    // exact id match
    int n = in.first.indexOf(str);
    if (n != -1)
        return n;

    // partial id match
    QList<int> ret = getPartialMatches(in.first, str);
    if (!ret.isEmpty())
        return ret.first();

    // partial name match
    ret = getPartialMatches(in.second, str);
    if (!ret.isEmpty())
        return ret.first();

    return -1;
}

static QString getKeyStore(const QString &name)
{
    QCA::KeyStoreManager ksm;
    QStringList          storeList = ksm.keyStores();
    int                  n         = findByString(getKeyStoreStrings(storeList, &ksm), name);
    if (n != -1)
        return storeList[n];
    return QString();
}

static QCA::KeyStoreEntry getKeyStoreEntry(QCA::KeyStore *store, const QString &name)
{
    QList<QCA::KeyStoreEntry> list = store->entryList();
    int                       n    = findByString(getKeyStoreEntryStrings(list), name);
    if (n != -1)
        return list[n];
    return QCA::KeyStoreEntry();
}

// here are a bunch of get_Foo functions for the various types

// E - generic entry
// K - private key
// C - cert
// X - keybundle
// P - pgp public key
// S - pgp secret key

// in all cases but K, the store:obj notation can be used.  if there
//   is no colon present, then we treat the input as a filename. we
//   try the file as an exported passive entry id, and if the type
//   is C or X, we'll fall back to regular files if necessary.

static QCA::KeyStoreEntry get_E(const QString &name, bool nopassiveerror = false)
{
    QCA::KeyStoreEntry entry;

    QCA::KeyStoreManager::start();

    int n = name.indexOf(QLatin1Char(':'));
    if (n != -1) {
        ksm_start_and_wait();

        // store:obj lookup
        QString storeName  = name.mid(0, n);
        QString objectName = name.mid(n + 1);

        QCA::KeyStoreManager ksm;
        QCA::KeyStore        store(getKeyStore(storeName), &ksm);
        if (!store.isValid()) {
            fprintf(stderr, "Error: no such store [%s].\n", qPrintable(storeName));
            return entry;
        }

        entry = getKeyStoreEntry(&store, objectName);
        if (entry.isNull()) {
            fprintf(stderr, "Error: no such object [%s].\n", qPrintable(objectName));
            return entry;
        }
    } else {
        // exported id
        QString serialized = read_ksentry_file(name);
        entry              = QCA::KeyStoreEntry(serialized);
        if (entry.isNull()) {
            if (!nopassiveerror)
                fprintf(stderr, "Error: invalid/unknown entry [%s].\n", qPrintable(name));
            return entry;
        }
    }

    return entry;
}

static QCA::PrivateKey get_K(const QString &name)
{
    QCA::PrivateKey key;

    int n = name.indexOf(QLatin1Char(':'));
    if (n != -1) {
        fprintf(stderr, "Error: cannot use store:obj notation for raw private keys.\n");
        return key;
    }

    if (is_pem_file(name))
        key = QCA::PrivateKey::fromPEMFile(name);
    else
        key = QCA::PrivateKey::fromDER(read_der_file(name));
    if (key.isNull()) {
        fprintf(stderr, "Error: unable to read/process private key file.\n");
        return key;
    }

    return key;
}

static QCA::Certificate get_C(const QString &name)
{
    QCA::KeyStoreEntry entry = get_E(name, true);
    if (!entry.isNull()) {
        if (entry.type() != QCA::KeyStoreEntry::TypeCertificate) {
            fprintf(stderr, "Error: entry is not a certificate.\n");
            return QCA::Certificate();
        }
        return entry.certificate();
    }

    if (!QCA::isSupported("cert")) {
        fprintf(stderr, "Error: need 'cert' feature.\n");
        return QCA::Certificate();
    }

    // try file
    QCA::Certificate cert;
    if (is_pem_file(name))
        cert = QCA::Certificate::fromPEMFile(name);
    else
        cert = QCA::Certificate::fromDER(read_der_file(name));
    if (cert.isNull()) {
        fprintf(stderr, "Error: unable to read/process certificate file.\n");
        return cert;
    }

    return cert;
}

static QCA::KeyBundle get_X(const QString &name)
{
    QCA::KeyStoreEntry entry = get_E(name, true);
    if (!entry.isNull()) {
        if (entry.type() != QCA::KeyStoreEntry::TypeKeyBundle) {
            fprintf(stderr, "Error: entry is not a keybundle.\n");
            return QCA::KeyBundle();
        }
        return entry.keyBundle();
    }

    if (!QCA::isSupported("pkcs12")) {
        fprintf(stderr, "Error: need 'pkcs12' feature.\n");
        return QCA::KeyBundle();
    }

    // try file
    QCA::KeyBundle key = QCA::KeyBundle::fromFile(name);
    if (key.isNull()) {
        fprintf(stderr, "Error: unable to read/process keybundle file.\n");
        return key;
    }

    return key;
}

static QCA::PGPKey get_P(const QString &name)
{
    QCA::KeyStoreEntry entry = get_E(name, true);
    if (!entry.isNull()) {
        if (entry.type() != QCA::KeyStoreEntry::TypePGPPublicKey &&
            entry.type() != QCA::KeyStoreEntry::TypePGPSecretKey) {
            fprintf(stderr, "Error: entry is not a pgp public key.\n");
            return QCA::PGPKey();
        }
        return entry.pgpPublicKey();
    }

    // try file
    QCA::PGPKey key = QCA::PGPKey::fromFile(name);
    if (key.isNull()) {
        fprintf(stderr, "Error: unable to read/process pgp key file.\n");
        return key;
    }

    return key;
}

static QPair<QCA::PGPKey, QCA::PGPKey> get_S(const QString &name, bool noerror = false)
{
    QPair<QCA::PGPKey, QCA::PGPKey> key;
    QCA::KeyStoreEntry              entry = get_E(name, true);
    if (!entry.isNull()) {
        if (entry.type() != QCA::KeyStoreEntry::TypePGPSecretKey) {
            if (!noerror)
                fprintf(stderr, "Error: entry is not a pgp secret key.\n");
            return key;
        }

        key.first  = entry.pgpSecretKey();
        key.second = entry.pgpPublicKey();
        return key;
    }
    return key;
}

static void usage()
{
    printf("%s: simple qca utility\n", APPNAME);
    printf("usage: %s (options) [command]\n", EXENAME);
    printf(" options: --pass=x, --newpass=x, --nonroots=x, --roots=x, --nosys,\n");
    printf("          --noprompt, --ordered, --debug, --log-file=x, --log-level=n,\n");
    printf("          --nobundle\n");
    printf("\n");
    printf(" help|--help|-h                        This help text\n");
    printf(" version|--version|-v                  Print version information\n");
    printf(" plugins                               List available plugins\n");
    printf(" config [command]\n");
    printf("   save [provider]                     Save default provider config\n");
    printf("   edit [provider]                     Edit provider config\n");
    printf(" key [command]\n");
    printf("   make rsa|dsa [bits]                 Create a key pair\n");
    printf("   changepass [K]                      Add/change/remove passphrase of a key\n");
    printf(" cert [command]\n");
    printf("   makereq [K]                         Create certificate request (CSR)\n");
    printf("   makeself [K]                        Create self-signed certificate\n");
    printf("   makereqadv [K]                      Advanced version of 'makereq'\n");
    printf("   makeselfadv [K]                     Advanced version of 'makeself'\n");
    printf("   validate [C]                        Validate certificate\n");
    printf(" keybundle [command]\n");
    printf("   make [K] [C]                        Create a keybundle\n");
    printf("   extract [X]                         Extract certificate(s) and key\n");
    printf("   changepass [X]                      Change passphrase of a keybundle\n");
    printf(" keystore [command]\n");
    printf("   list-stores                         List all available keystores\n");
    printf("   list [storeName]                    List content of a keystore\n");
    printf("   monitor                             Monitor for keystore availability\n");
    printf("   export [E]                          Export a keystore entry's content\n");
    printf("   exportref [E]                       Export a keystore entry reference\n");
    printf("   addkb [storeName] [cert.p12]        Add a keybundle into a keystore\n");
    printf("   addpgp [storeName] [key.asc]        Add a PGP key into a keystore\n");
    printf("   remove [E]                          Remove an object from a keystore\n");
    printf(" show [command]\n");
    printf("   cert [C]                            Examine a certificate\n");
    printf("   req [req.pem]                       Examine a certificate request (CSR)\n");
    printf("   crl [crl.pem]                       Examine a certificate revocation list\n");
    printf("   kb [X]                              Examine a keybundle\n");
    printf("   pgp [P|S]                           Examine a PGP key\n");
    printf(" message [command]\n");
    printf("   sign pgp|pgpdetach|smime [X|S]      Sign a message\n");
    printf("   encrypt pgp|smime [C|P]             Encrypt a message\n");
    printf("   signencrypt [S] [P]                 PGP sign & encrypt a message\n");
    printf("   verify pgp|smime                    Verify a message\n");
    printf("   decrypt pgp|smime ((X) ...)         Decrypt a message (S/MIME needs X)\n");
    printf("   exportcerts                         Export certs from S/MIME message\n");
    printf("\n");
    printf("Object types: K = private key, C = certificate, X = key bundle,\n");
    printf("  P = PGP public key, S = PGP secret key, E = generic entry\n");
    printf("\n");
    printf("An object must be either a filename or a keystore reference (\"store:obj\").\n");
    printf("\n");
    printf("Log level is from 0 (quiet) to 8 (debug)\n");
    printf("\n");
}

int main(int argc, char **argv)
{
    QCA::Initializer qcaInit;
    QCoreApplication app(argc, argv);
    QFile            logFile;
    QTextStream      logStream(stderr);
    StreamLogger     streamLogger(logStream);

    QStringList args;
    for (int n = 1; n < argc; ++n)
        args.append(QString::fromLocal8Bit(argv[n]));

    if (args.count() < 1) {
        usage();
        return 1;
    }

    bool             have_pass    = false;
    bool             have_newpass = false;
    QCA::SecureArray pass, newpass;
    bool             allowprompt = true;
    bool             ordered     = false;
    bool             debug       = false;
    bool             nosys       = false;
    bool             nobundle    = false;
    QString          rootsFile, nonRootsFile;

    for (int n = 0; n < args.count(); ++n) {
        QString s = args[n];
        if (!s.startsWith(QLatin1String("--")))
            continue;
        QString var;
        QString val;
        int     x = s.indexOf(QLatin1Char('='));
        if (x != -1) {
            var = s.mid(2, x - 2);
            val = s.mid(x + 1);
        } else {
            var = s.mid(2);
        }

        bool known = true;

        if (var == QLatin1String("pass")) {
            have_pass = true;
            pass      = val.toUtf8();
        } else if (var == QLatin1String("newpass")) {
            have_newpass = true;
            newpass      = val.toUtf8();
        } else if (var == QLatin1String("log-file")) {
            logFile.setFileName(val);
            logFile.open(QIODevice::Append | QIODevice::Text | QIODevice::Unbuffered);
            logStream.setDevice(&logFile);
        } else if (var == QLatin1String("log-level")) {
            QCA::logger()->setLevel((QCA::Logger::Severity)val.toInt());
        } else if (var == QLatin1String("noprompt"))
            allowprompt = false;
        else if (var == QLatin1String("ordered"))
            ordered = true;
        else if (var == QLatin1String("debug"))
            debug = true;
        else if (var == QLatin1String("roots"))
            rootsFile = val;
        else if (var == QLatin1String("nonroots"))
            nonRootsFile = val;
        else if (var == QLatin1String("nosys"))
            nosys = true;
        else if (var == QLatin1String("nobundle"))
            nobundle = true;
        else
            known = false;

        if (known) {
            args.removeAt(n);
            --n; // adjust position
        }
    }

    // help
    if (args.isEmpty() || args[0] == QLatin1String("help") || args[0] == QLatin1String("--help") ||
        args[0] == QLatin1String("-h")) {
        usage();
        return 0;
    }

    // version
    if (args[0] == QLatin1String("version") || args[0] == QLatin1String("--version") ||
        args[0] == QLatin1String("-v")) {
        int ver = qcaVersion();
        int maj = (ver >> 16) & 0xff;
        int min = (ver >> 8) & 0xff;
        int bug = ver & 0xff;
        printf("%s version %s by Justin Karneges\n", APPNAME, VERSION);
        printf("Using QCA version %d.%d.%d\n", maj, min, bug);
        return 0;
    }

    // show plugins
    if (args[0] == QLatin1String("plugins")) {
        QStringList paths = QCA::pluginPaths();
        if (!paths.isEmpty()) {
            for (int n = 0; n < paths.count(); ++n) {
                printf("  %s\n", qPrintable(QDir::toNativeSeparators(paths[n])));
            }
        } else
            printf("  (none)\n");

        QCA::ProviderList list = QCA::providers();

        if (debug)
            output_plugin_diagnostic_text();

        printf("Available Providers:\n");
        if (!list.isEmpty()) {
            for (int n = 0; n < list.count(); ++n) {
                printf("  %s\n", qPrintable(list[n]->name()));
                QString credit = list[n]->credit();
                if (!credit.isEmpty()) {
                    QStringList lines = wrapstring(credit, 74);
                    foreach (const QString &s, lines)
                        printf("    %s\n", qPrintable(s));
                }
                if (debug) {
                    QStringList capabilities = list[n]->features();
                    foreach (const QString &capability, capabilities) {
                        printf("    *%s", qPrintable(capability));
                        if (!QCA::isSupported(qPrintable(capability), list[n]->name())) {
                            printf("(NOT supported) - bug");
                        }
                        printf("\n");
                    }
                }
            }
        } else
            printf("  (none)\n");

        QCA::unloadAllPlugins();

        if (debug)
            output_plugin_diagnostic_text();

        return 0;
    }

    // config stuff
    if (args[0] == QLatin1String("config")) {
        if (args.count() < 2) {
            usage();
            return 1;
        }

        if (args[1] == QLatin1String("save")) {
            if (args.count() < 3) {
                usage();
                return 1;
            }

            QString        name = args[2];
            QCA::Provider *p    = QCA::findProvider(name);
            if (!p) {
                fprintf(stderr, "Error: no such provider '%s'.\n", qPrintable(name));
                return 1;
            }

            QVariantMap map1 = p->defaultConfig();
            if (map1.isEmpty()) {
                fprintf(stderr, "Error: provider does not support configuration.\n");
                return 1;
            }

            // set and save
            QCA::setProviderConfig(name, map1);
            QCA::saveProviderConfig(name);
            printf("Done.\n");
            return 0;
        } else if (args[1] == QLatin1String("edit")) {
            if (args.count() < 3) {
                usage();
                return 1;
            }

            QString name = args[2];
            if (!QCA::findProvider(name)) {
                fprintf(stderr, "Error: no such provider '%s'.\n", qPrintable(name));
                return 1;
            }

            QVariantMap map1 = QCA::getProviderConfig(name);
            if (map1.isEmpty()) {
                fprintf(stderr, "Error: provider does not support configuration.\n");
                return 1;
            }

            printf("Editing configuration for %s ...\n", qPrintable(name));
            printf("Note: to clear a string entry, type whitespace and press enter.\n");

            map1 = provider_config_edit(map1);
            if (map1.isEmpty())
                return 1;

            // set and save
            QCA::setProviderConfig(name, map1);
            QCA::saveProviderConfig(name);
            printf("Done.\n");
            return 0;
        } else {
            usage();
            return 1;
        }
    }

    // enable console passphrase prompt
    PassphrasePromptThread passphrasePrompt;
    if (!allowprompt)
        passphrasePrompt.pp->allowPrompt = false;
    if (have_pass)
        passphrasePrompt.pp->setExplicitPassword(pass);

    if (args[0] == QLatin1String("key")) {
        if (args.count() < 2) {
            usage();
            return 1;
        }

        if (args[1] == QLatin1String("make")) {
            if (args.count() < 4) {
                usage();
                return 1;
            }

            bool genrsa;
            int  bits;

            if (args[2] == QLatin1String("rsa")) {
                if (!QCA::isSupported("rsa")) {
                    fprintf(stderr, "Error: need 'rsa' feature.\n");
                    return 1;
                }

                genrsa = true;
                bits   = args[3].toInt();
                if (bits < 512) {
                    fprintf(stderr, "Error: RSA bits must be at least 512.\n");
                    return 1;
                }
            } else if (args[2] == QLatin1String("dsa")) {
                if (!QCA::isSupported("dsa")) {
                    fprintf(stderr, "Error: need 'dsa' feature.\n");
                    return 1;
                }

                if (!QCA::isSupported("dlgroup")) {
                    fprintf(stderr, "Error: need 'dlgroup' feature.\n");
                    return 1;
                }

                genrsa = false;
                bits   = args[3].toInt();
                if (bits != 512 && bits != 768 && bits != 1024) {
                    fprintf(stderr, "Error: DSA bits must be 512, 768, or 1024.\n");
                    return 1;
                }
            } else {
                usage();
                return 1;
            }

            if (!allowprompt && !have_newpass) {
                fprintf(stderr, "Error: no passphrase specified (use '--newpass=' for none).\n");
                return 1;
            }

            QCA::PrivateKey priv;
            QString         pubFileName, privFileName;

            if (genrsa) {
                // note: third arg is bogus, doesn't apply to RSA
                priv         = AnimatedKeyGen::makeKey(QCA::PKey::RSA, bits, QCA::DSA_512);
                pubFileName  = QStringLiteral("rsapub.pem");
                privFileName = QStringLiteral("rsapriv.pem");
            } else // dsa
            {
                QCA::DLGroupSet set;
                if (bits == 512)
                    set = QCA::DSA_512;
                else if (bits == 768)
                    set = QCA::DSA_768;
                else // 1024
                    set = QCA::DSA_1024;

                // note: second arg is bogus, doesn't apply to DSA
                priv         = AnimatedKeyGen::makeKey(QCA::PKey::DSA, 0, set);
                pubFileName  = QStringLiteral("dsapub.pem");
                privFileName = QStringLiteral("dsapriv.pem");
            }

            if (priv.isNull()) {
                fprintf(stderr, "Error: unable to generate key.\n");
                return 1;
            }

            QCA::PublicKey pub = priv.toPublicKey();

            // prompt for new passphrase if necessary
            if (!have_newpass) {
                while (!promptForNewPassphrase(&newpass)) { }
                have_newpass = true;
            }

            if (pub.toPEMFile(pubFileName))
                printf("Public key saved to %s\n", qPrintable(pubFileName));
            else {
                fprintf(stderr, "Error: can't encode/write %s\n", qPrintable(pubFileName));
                return 1;
            }

            bool ok;
            if (!newpass.isEmpty())
                ok = priv.toPEMFile(privFileName, newpass);
            else
                ok = priv.toPEMFile(privFileName);
            if (ok)
                printf("Private key saved to %s\n", qPrintable(privFileName));
            else {
                fprintf(stderr, "Error: can't encode/write %s\n", qPrintable(privFileName));
                return 1;
            }
        } else if (args[1] == QLatin1String("changepass")) {
            if (args.count() < 3) {
                usage();
                return 1;
            }

            QCA::PrivateKey priv = get_K(args[2]);
            if (priv.isNull())
                return 1;

            if (!allowprompt && !have_newpass) {
                fprintf(stderr, "Error: no passphrase specified (use '--newpass=' for none).\n");
                return 1;
            }

            // prompt for new passphrase if necessary
            if (!have_newpass) {
                while (!promptForNewPassphrase(&newpass)) { }
                have_newpass = true;
            }

            QString out;
            if (!newpass.isEmpty())
                out = priv.toPEM(newpass);
            else
                out = priv.toPEM();
            if (!out.isEmpty())
                printf("%s", qPrintable(out));
            else {
                fprintf(stderr, "Error: can't encode key.\n");
                return 1;
            }
        } else {
            usage();
            return 1;
        }
    } else if (args[0] == QLatin1String("cert")) {
        if (args.count() < 2) {
            usage();
            return 1;
        }

        if (args[1] == QLatin1String("makereq") || args[1] == QLatin1String("makereqadv")) {
            if (args.count() < 3) {
                usage();
                return 1;
            }

            if (!QCA::isSupported("csr")) {
                fprintf(stderr, "Error: need 'csr' feature.\n");
                return 1;
            }

            QCA::PrivateKey priv = get_K(args[2]);
            if (priv.isNull())
                return 1;

            printf("\n");

            bool advanced = (args[1] == QLatin1String("makereqadv")) ? true : false;

            QCA::CertificateOptions opts = promptForCertAttributes(advanced, true);
            QCA::CertificateRequest req(opts, priv);

            QString reqname = QStringLiteral("certreq.pem");
            if (req.toPEMFile(reqname))
                printf("Certificate request saved to %s\n", qPrintable(reqname));
            else {
                fprintf(stderr, "Error: can't encode/write %s\n", qPrintable(reqname));
                return 1;
            }
        } else if (args[1] == QLatin1String("makeself") || args[1] == QLatin1String("makeselfadv")) {
            if (args.count() < 3) {
                usage();
                return 1;
            }

            if (!QCA::isSupported("cert")) {
                fprintf(stderr, "Error: need 'cert' feature.\n");
                return 1;
            }

            QCA::PrivateKey priv = get_K(args[2]);
            if (priv.isNull())
                return 1;

            printf("\n");

            bool advanced = (args[1] == QLatin1String("makeselfadv")) ? true : false;

            QCA::CertificateOptions opts = promptForCertAttributes(advanced, false);
            QCA::Certificate        cert(opts, priv);

            QString certname = QStringLiteral("cert.pem");
            if (cert.toPEMFile(certname))
                printf("Certificate saved to %s\n", qPrintable(certname));
            else {
                fprintf(stderr, "Error: can't encode/write %s\n", qPrintable(certname));
                return 1;
            }
        } else if (args[1] == QLatin1String("validate")) {
            if (args.count() < 3) {
                usage();
                return 1;
            }

            QCA::Certificate target = get_C(args[2]);
            if (target.isNull())
                return 1;

            // get roots
            QCA::CertificateCollection roots;
            if (!nosys)
                roots += QCA::systemStore();
            if (!rootsFile.isEmpty())
                roots += QCA::CertificateCollection::fromFlatTextFile(rootsFile);

            // get nonroots
            QCA::CertificateCollection nonroots;
            if (!nonRootsFile.isEmpty())
                nonroots = QCA::CertificateCollection::fromFlatTextFile(nonRootsFile);

            QCA::Validity v = target.validate(roots, nonroots);
            if (v == QCA::ValidityGood)
                printf("Certificate is valid\n");
            else {
                printf("Certificate is NOT valid: %s\n", qPrintable(validityToString(v)));
                return 1;
            }
        } else {
            usage();
            return 1;
        }
    } else if (args[0] == QLatin1String("keybundle")) {
        if (args.count() < 2) {
            usage();
            return 1;
        }

        if (args[1] == QLatin1String("make")) {
            if (args.count() < 4) {
                usage();
                return 1;
            }

            if (!QCA::isSupported("pkcs12")) {
                fprintf(stderr, "Error: need 'pkcs12' feature.\n");
                return 1;
            }

            QCA::PrivateKey priv = get_K(args[2]);
            if (priv.isNull())
                return 1;

            QCA::Certificate cert = get_C(args[3]);
            if (cert.isNull())
                return 1;

            // get roots
            QCA::CertificateCollection roots;
            if (!nosys)
                roots += QCA::systemStore();
            if (!rootsFile.isEmpty())
                roots += QCA::CertificateCollection::fromFlatTextFile(rootsFile);

            // get nonroots
            QCA::CertificateCollection nonroots;
            if (!nonRootsFile.isEmpty())
                nonroots = QCA::CertificateCollection::fromFlatTextFile(nonRootsFile);

            QList<QCA::Certificate> issuer_pool = roots.certificates() + nonroots.certificates();

            QCA::CertificateChain chain;
            chain += cert;
            chain = chain.complete(issuer_pool);

            QCA::KeyBundle key;
            key.setName(chain.primary().commonName());
            key.setCertificateChainAndKey(chain, priv);

            if (!allowprompt && !have_newpass) {
                fprintf(stderr, "Error: no passphrase specified (use '--newpass=' for none).\n");
                return 1;
            }

            // prompt for new passphrase if necessary
            if (!have_newpass) {
                while (!promptForNewPassphrase(&newpass)) { }
                have_newpass = true;
            }

            if (newpass.isEmpty()) {
                fprintf(stderr, "Error: keybundles cannot have empty passphrases.\n");
                return 1;
            }

            QString newFileName = QStringLiteral("cert.p12");

            if (key.toFile(newFileName, newpass))
                printf("Keybundle saved to %s\n", qPrintable(newFileName));
            else {
                fprintf(stderr, "Error: can't encode keybundle.\n");
                return 1;
            }
        } else if (args[1] == QLatin1String("extract")) {
            if (args.count() < 3) {
                usage();
                return 1;
            }

            QCA::KeyBundle key = get_X(args[2]);
            if (key.isNull())
                return 1;

            QCA::PrivateKey priv        = key.privateKey();
            bool            export_priv = priv.canExport();

            if (export_priv) {
                fprintf(stderr, "You will need to create a passphrase for the extracted private key.\n");

                if (!allowprompt && !have_newpass) {
                    fprintf(stderr, "Error: no passphrase specified (use '--newpass=' for none).\n");
                    return 1;
                }

                // prompt for new passphrase if necessary
                if (!have_newpass) {
                    while (!promptForNewPassphrase(&newpass)) { }
                    have_newpass = true;
                }
            }

            printf("Certs: (first is primary)\n");
            QCA::CertificateChain chain = key.certificateChain();
            for (int n = 0; n < chain.count(); ++n)
                printf("%s", qPrintable(chain[n].toPEM()));
            printf("Private Key:\n");
            if (export_priv) {
                QString out;
                if (!newpass.isEmpty())
                    out = priv.toPEM(newpass);
                else
                    out = priv.toPEM();
                printf("%s", qPrintable(out));
            } else {
                printf("(Key is not exportable)\n");
            }
        } else if (args[1] == QLatin1String("changepass")) {
            if (args.count() < 3) {
                usage();
                return 1;
            }

            QCA::KeyBundle key = get_X(args[2]);
            if (key.isNull())
                return 1;

            if (!key.privateKey().canExport()) {
                fprintf(stderr, "Error: private key not exportable.\n");
                return 1;
            }

            if (!allowprompt && !have_newpass) {
                fprintf(stderr, "Error: no passphrase specified (use '--newpass=' for none).\n");
                return 1;
            }

            // prompt for new passphrase if necessary
            if (!have_newpass) {
                while (!promptForNewPassphrase(&newpass)) { }
                have_newpass = true;
            }

            if (newpass.isEmpty()) {
                fprintf(stderr, "Error: keybundles cannot have empty passphrases.\n");
                return 1;
            }

            QFileInfo fi(args[2]);
            QString   newFileName = fi.baseName() + QStringLiteral("_new.p12");

            if (key.toFile(newFileName, newpass))
                printf("Keybundle saved to %s\n", qPrintable(newFileName));
            else {
                fprintf(stderr, "Error: can't encode keybundle.\n");
                return 1;
            }
        } else {
            usage();
            return 1;
        }
    } else if (args[0] == QLatin1String("keystore")) {
        if (args.count() < 2) {
            usage();
            return 1;
        }

        if (args[1] == QLatin1String("list-stores")) {
            ksm_start_and_wait();

            QCA::KeyStoreManager ksm;
            QStringList          storeList = ksm.keyStores();

            for (int n = 0; n < storeList.count(); ++n) {
                QCA::KeyStore ks(storeList[n], &ksm);
                QString       type = kstype_to_string(ks.type());
                printf("%s %s [%s]\n", qPrintable(type), qPrintable(idHash(ks.id())), qPrintable(ks.name()));
            }

            if (debug)
                output_keystore_diagnostic_text();
        } else if (args[1] == QLatin1String("list")) {
            if (args.count() < 3) {
                usage();
                return 1;
            }

            ksm_start_and_wait();

            QCA::KeyStoreManager ksm;
            QCA::KeyStore        store(getKeyStore(args[2]), &ksm);
            if (!store.isValid()) {
                if (debug)
                    output_keystore_diagnostic_text();

                fprintf(stderr, "Error: no such store\n");
                return 1;
            }

            QList<QCA::KeyStoreEntry> list = store.entryList();
            for (int n = 0; n < list.count(); ++n) {
                QCA::KeyStoreEntry i    = list[n];
                QString            type = ksentrytype_to_string(i.type());
                printf("%s %s [%s]\n", qPrintable(type), qPrintable(idHash(i.id())), qPrintable(i.name()));
            }

            if (debug)
                output_keystore_diagnostic_text();
        } else if (args[1] == QLatin1String("monitor")) {
            KeyStoreMonitor::monitor();

            if (debug)
                output_keystore_diagnostic_text();
        } else if (args[1] == QLatin1String("export")) {
            if (args.count() < 3) {
                usage();
                return 1;
            }

            QCA::KeyStoreEntry entry = get_E(args[2]);
            if (entry.isNull())
                return 1;

            if (entry.type() == QCA::KeyStoreEntry::TypeCertificate)
                printf("%s", qPrintable(entry.certificate().toPEM()));
            else if (entry.type() == QCA::KeyStoreEntry::TypeCRL)
                printf("%s", qPrintable(entry.crl().toPEM()));
            else if (entry.type() == QCA::KeyStoreEntry::TypePGPPublicKey ||
                     entry.type() == QCA::KeyStoreEntry::TypePGPSecretKey)
                printf("%s", qPrintable(entry.pgpPublicKey().toString()));
            else if (entry.type() == QCA::KeyStoreEntry::TypeKeyBundle) {
                fprintf(stderr, "Error: use 'keybundle extract' command instead.\n");
                return 1;
            } else {
                fprintf(stderr, "Error: cannot export type '%d'.\n", entry.type());
                return 1;
            }
        } else if (args[1] == QLatin1String("exportref")) {
            if (args.count() < 3) {
                usage();
                return 1;
            }

            QCA::KeyStoreEntry entry = get_E(args[2]);
            if (entry.isNull())
                return 1;
            printf("%s", make_ksentry_string(entry.toString()).toUtf8().data());
        } else if (args[1] == QLatin1String("addkb")) {
            if (args.count() < 4) {
                usage();
                return 1;
            }

            ksm_start_and_wait();

            QCA::KeyStoreManager ksm;
            QCA::KeyStore        store(getKeyStore(args[2]), &ksm);
            if (!store.isValid()) {
                fprintf(stderr, "Error: no such store\n");
                return 1;
            }

            QCA::KeyBundle key = get_X(args[3]);
            if (key.isNull())
                return 1;

            if (!store.writeEntry(key).isEmpty())
                printf("Entry written.\n");
            else {
                fprintf(stderr, "Error: unable to write entry.\n");
                return 1;
            }
        } else if (args[1] == QLatin1String("addpgp")) {
            if (args.count() < 4) {
                usage();
                return 1;
            }

            if (!QCA::isSupported("openpgp")) {
                fprintf(stderr, "Error: need 'openpgp' feature.\n");
                return 1;
            }

            ksm_start_and_wait();

            QCA::KeyStoreManager ksm;
            QCA::KeyStore        store(getKeyStore(args[2]), &ksm);
            if (!store.isValid()) {
                fprintf(stderr, "Error: no such store\n");
                return 1;
            }

            QCA::PGPKey pub = QCA::PGPKey::fromFile(args[3]);
            if (pub.isNull())
                return 1;

            if (!store.writeEntry(pub).isEmpty())
                printf("Entry written.\n");
            else {
                fprintf(stderr, "Error: unable to write entry.\n");
                return 1;
            }
        } else if (args[1] == QLatin1String("remove")) {
            if (args.count() < 3) {
                usage();
                return 1;
            }

            QCA::KeyStoreEntry entry = get_E(args[2]);
            if (entry.isNull())
                return 1;

            QCA::KeyStoreManager ksm;
            QCA::KeyStore        store(entry.storeId(), &ksm);
            if (!store.isValid()) {
                fprintf(stderr, "Error: no such store\n");
                return 1;
            }

            if (store.removeEntry(entry.id()))
                printf("Entry removed.\n");
            else {
                fprintf(stderr, "Error: unable to remove entry.\n");
                return 1;
            }
        } else {
            usage();
            return 1;
        }
    } else if (args[0] == QLatin1String("show")) {
        if (args.count() < 2) {
            usage();
            return 1;
        }

        if (args[1] == QLatin1String("cert")) {
            if (args.count() < 3) {
                usage();
                return 1;
            }

            QCA::Certificate cert = get_C(args[2]);
            if (cert.isNull())
                return 1;

            print_cert(cert, ordered);
        } else if (args[1] == QLatin1String("req")) {
            if (args.count() < 3) {
                usage();
                return 1;
            }

            if (!QCA::isSupported("csr")) {
                fprintf(stderr, "Error: need 'csr' feature.\n");
                return 1;
            }

            QCA::CertificateRequest req(args[2]);
            if (req.isNull()) {
                fprintf(stderr, "Error: can't read/process certificate request file.\n");
                return 1;
            }

            print_certreq(req, ordered);
        } else if (args[1] == QLatin1String("crl")) {
            if (args.count() < 3) {
                usage();
                return 1;
            }

            if (!QCA::isSupported("crl")) {
                fprintf(stderr, "Error: need 'crl' feature.\n");
                return 1;
            }

            QCA::CRL crl;
            if (is_pem_file(args[2]))
                crl = QCA::CRL::fromPEMFile(args[2]);
            else
                crl = QCA::CRL::fromDER(read_der_file(args[2]));
            if (crl.isNull()) {
                fprintf(stderr, "Error: unable to read/process CRL file.\n");
                return 1;
            }

            print_crl(crl, ordered);
        } else if (args[1] == QLatin1String("kb")) {
            if (args.count() < 3) {
                usage();
                return 1;
            }

            QCA::KeyBundle key = get_X(args[2]);
            if (key.isNull())
                return 1;

            printf("Keybundle contains %d certificates.  Displaying primary:\n", int(key.certificateChain().count()));
            print_cert(key.certificateChain().primary(), ordered);
        } else if (args[1] == QLatin1String("pgp")) {
            if (args.count() < 3) {
                usage();
                return 1;
            }

            // try for secret key, then try public key
            QCA::PGPKey key = get_S(args[2], true).first;
            if (key.isNull()) {
                key = get_P(args[2]);
                if (key.isNull())
                    return 1;
            }

            print_pgp(key);
        } else {
            usage();
            return 1;
        }
    } else if (args[0] == QLatin1String("message")) {
        if (args.count() < 2) {
            usage();
            return 1;
        }

        if (args[1] == QLatin1String("sign")) {
            if (args.count() < 4) {
                usage();
                return 1;
            }

            QCA::SecureMessageSystem *   sms;
            QCA::SecureMessageKey        skey;
            QCA::SecureMessage::SignMode mode;
            bool                         pgp = false;

            if (args[2] == QLatin1String("pgp")) {
                if (!QCA::isSupported("openpgp")) {
                    fprintf(stderr, "Error: need 'openpgp' feature.\n");
                    return 1;
                }

                QPair<QCA::PGPKey, QCA::PGPKey> key = get_S(args[3]);
                if (key.first.isNull())
                    return 1;

                sms = new QCA::OpenPGP;
                skey.setPGPSecretKey(key.first);
                mode = QCA::SecureMessage::Clearsign;
                pgp  = true;
            } else if (args[2] == QLatin1String("pgpdetach")) {
                if (!QCA::isSupported("openpgp")) {
                    fprintf(stderr, "Error: need 'openpgp' feature.\n");
                    return 1;
                }

                QPair<QCA::PGPKey, QCA::PGPKey> key = get_S(args[3]);
                if (key.first.isNull())
                    return 1;

                sms = new QCA::OpenPGP;
                skey.setPGPSecretKey(key.first);
                mode = QCA::SecureMessage::Detached;
                pgp  = true;
            } else if (args[2] == QLatin1String("smime")) {
                if (!QCA::isSupported("cms")) {
                    fprintf(stderr, "Error: need 'cms' feature.\n");
                    return 1;
                }

                QCA::KeyBundle key = get_X(args[3]);
                if (key.isNull())
                    return 1;

                // get nonroots
                QCA::CertificateCollection nonroots;
                if (!nonRootsFile.isEmpty())
                    nonroots = QCA::CertificateCollection::fromFlatTextFile(nonRootsFile);

                QList<QCA::Certificate> issuer_pool = nonroots.certificates();

                QCA::CertificateChain chain = key.certificateChain();
                chain                       = chain.complete(issuer_pool);

                sms = new QCA::CMS;
                skey.setX509CertificateChain(chain);
                skey.setX509PrivateKey(key.privateKey());
                mode = QCA::SecureMessage::Detached;
            } else {
                usage();
                return 1;
            }

            // read input data from stdin all at once
            QByteArray plain;
            while (!feof(stdin)) {
                QByteArray block(1024, 0);
                int        n = fread(block.data(), 1, 1024, stdin);
                if (n < 0)
                    break;
                block.resize(n);
                plain += block;
            }

            // smime envelope
            if (!pgp) {
                QString text = add_cr(QString::fromUtf8(plain));
                plain        = QString::fromLatin1(mime_signpart).arg(text).toUtf8();
            }

            QCA::SecureMessage *msg = new QCA::SecureMessage(sms);
            msg->setSigner(skey);
            // pgp should always be ascii
            if (pgp)
                msg->setFormat(QCA::SecureMessage::Ascii);
            msg->setBundleSignerEnabled(!nobundle);
            msg->startSign(mode);
            msg->update(plain);
            msg->end();
            msg->waitForFinished(-1);

            if (debug) {
                output_keystore_diagnostic_text();
                output_message_diagnostic_text(msg);
            }

            if (!msg->success()) {
                QString errstr = smErrorToString(msg->errorCode());
                delete msg;
                delete sms;

                fprintf(stderr, "Error: unable to sign: %s\n", qPrintable(errstr));
                return 1;
            }

            QString hashName = msg->hashName();

            QByteArray output;
            if (mode == QCA::SecureMessage::Detached)
                output = msg->signature();
            else
                output = msg->read();

            delete msg;
            delete sms;

            // smime envelope
            if (!pgp) {
                QCA::Base64 enc;
                enc.setLineBreaksEnabled(true);
                enc.setLineBreaksColumn(76);
                QString sigtext = add_cr(enc.arrayToString(output));
                QString str     = QString::fromLatin1(mime_signed).arg(hashName, QString::fromUtf8(plain), sigtext);
                output          = str.toUtf8();
            }

            printf("%s", output.data());
        } else if (args[1] == QLatin1String("encrypt")) {
            if (args.count() < 4) {
                usage();
                return 1;
            }

            QCA::SecureMessageSystem *sms;
            QCA::SecureMessageKey     skey;
            bool                      pgp = false;

            if (args[2] == QLatin1String("pgp")) {
                if (!QCA::isSupported("openpgp")) {
                    fprintf(stderr, "Error: need 'openpgp' feature.\n");
                    return 1;
                }

                QCA::PGPKey key = get_P(args[3]);
                if (key.isNull())
                    return 1;

                sms = new QCA::OpenPGP;
                skey.setPGPPublicKey(key);
                pgp = true;
            } else if (args[2] == QLatin1String("smime")) {
                if (!QCA::isSupported("cms")) {
                    fprintf(stderr, "Error: need 'cms' feature.\n");
                    return 1;
                }

                QCA::Certificate cert = get_C(args[3]);
                if (cert.isNull())
                    return 1;

                sms = new QCA::CMS;
                skey.setX509CertificateChain(cert);
            } else {
                usage();
                return 1;
            }

            // read input data from stdin all at once
            QByteArray plain;
            while (!feof(stdin)) {
                QByteArray block(1024, 0);
                int        n = fread(block.data(), 1, 1024, stdin);
                if (n < 0)
                    break;
                block.resize(n);
                plain += block;
            }

            QCA::SecureMessage *msg = new QCA::SecureMessage(sms);
            msg->setRecipient(skey);
            // pgp should always be ascii
            if (pgp)
                msg->setFormat(QCA::SecureMessage::Ascii);
            msg->startEncrypt();
            msg->update(plain);
            msg->end();
            msg->waitForFinished(-1);

            if (debug) {
                output_keystore_diagnostic_text();
                output_message_diagnostic_text(msg);
            }

            if (!msg->success()) {
                QString errstr = smErrorToString(msg->errorCode());
                delete msg;
                delete sms;
                fprintf(stderr, "Error: unable to encrypt: %s\n", qPrintable(errstr));
                return 1;
            }

            QByteArray output = msg->read();
            delete msg;
            delete sms;

            // smime envelope
            if (!pgp) {
                QCA::Base64 enc;
                enc.setLineBreaksEnabled(true);
                enc.setLineBreaksColumn(76);
                QString enctext = add_cr(enc.arrayToString(output));
                QString str     = QString::fromLatin1(mime_enveloped).arg(enctext);
                output          = str.toUtf8();
            }

            printf("%s", output.data());
        } else if (args[1] == QLatin1String("signencrypt")) {
            if (args.count() < 4) {
                usage();
                return 1;
            }

            if (!QCA::isSupported("openpgp")) {
                fprintf(stderr, "Error: need 'openpgp' feature.\n");
                return 1;
            }

            QCA::SecureMessageSystem *sms;
            QCA::SecureMessageKey     skey;
            QCA::SecureMessageKey     rkey;

            {
                QPair<QCA::PGPKey, QCA::PGPKey> sec = get_S(args[2]);
                if (sec.first.isNull())
                    return 1;

                QCA::PGPKey pub = get_P(args[3]);
                if (pub.isNull())
                    return 1;

                sms = new QCA::OpenPGP;
                skey.setPGPSecretKey(sec.first);
                rkey.setPGPPublicKey(pub);
            }

            // read input data from stdin all at once
            QByteArray plain;
            while (!feof(stdin)) {
                QByteArray block(1024, 0);
                int        n = fread(block.data(), 1, 1024, stdin);
                if (n < 0)
                    break;
                block.resize(n);
                plain += block;
            }

            QCA::SecureMessage *msg = new QCA::SecureMessage(sms);
            if (!msg->canSignAndEncrypt()) {
                delete msg;
                delete sms;
                fprintf(stderr, "Error: cannot perform integrated sign and encrypt.\n");
                return 1;
            }

            msg->setSigner(skey);
            msg->setRecipient(rkey);
            msg->setFormat(QCA::SecureMessage::Ascii);
            msg->startSignAndEncrypt();
            msg->update(plain);
            msg->end();
            msg->waitForFinished(-1);

            if (debug) {
                output_keystore_diagnostic_text();
                output_message_diagnostic_text(msg);
            }

            if (!msg->success()) {
                QString errstr = smErrorToString(msg->errorCode());
                delete msg;
                delete sms;
                fprintf(stderr, "Error: unable to sign and encrypt: %s\n", qPrintable(errstr));
                return 1;
            }

            QByteArray output = msg->read();
            delete msg;
            delete sms;

            printf("%s", output.data());
        } else if (args[1] == QLatin1String("verify")) {
            if (args.count() < 3) {
                usage();
                return 1;
            }

            QCA::SecureMessageSystem *sms;
            bool                      pgp = false;

            if (args[2] == QLatin1String("pgp")) {
                if (!QCA::isSupported("openpgp")) {
                    fprintf(stderr, "Error: need 'openpgp' feature.\n");
                    return 1;
                }

                sms = new QCA::OpenPGP;
                pgp = true;
            } else if (args[2] == QLatin1String("smime")) {
                if (!QCA::isSupported("cms")) {
                    fprintf(stderr, "Error: need 'cms' feature.\n");
                    return 1;
                }

                // get roots
                QCA::CertificateCollection roots;
                if (!nosys)
                    roots += QCA::systemStore();
                if (!rootsFile.isEmpty())
                    roots += QCA::CertificateCollection::fromFlatTextFile(rootsFile);

                // get intermediates and possible signers, in case
                //   the message does not have them.
                QCA::CertificateCollection nonroots;
                if (!nonRootsFile.isEmpty())
                    nonroots += QCA::CertificateCollection::fromFlatTextFile(nonRootsFile);

                sms = new QCA::CMS;
                ((QCA::CMS *)sms)->setTrustedCertificates(roots);
                ((QCA::CMS *)sms)->setUntrustedCertificates(nonroots);
            } else {
                usage();
                return 1;
            }

            QByteArray data, sig;
            QString    smime_text;
            {
                // read input data from stdin all at once
                QByteArray plain;
                while (!feof(stdin)) {
                    QByteArray block(1024, 0);
                    int        n = fread(block.data(), 1, 1024, stdin);
                    if (n < 0)
                        break;
                    block.resize(n);
                    plain += block;
                }

                if (pgp) {
                    // pgp can be either a detached signature followed
                    //  by data, or an integrated message.

                    // detached signature?
                    if (plain.startsWith("-----BEGIN PGP SIGNATURE-----")) {
                        QByteArray footer = "-----END PGP SIGNATURE-----\n";
                        int        n      = plain.indexOf(footer);
                        if (n == -1) {
                            delete sms;
                            fprintf(stderr, "Error: pgp signature header, but no footer.\n");
                            return 1;
                        }

                        n += footer.length();
                        sig  = plain.mid(0, n);
                        data = plain.mid(n);
                    } else {
                        data = plain;
                    }
                } else {
                    // smime envelope
                    QString in = QString::fromUtf8(plain);
                    in         = add_cr(in); // change the line endings?!
                    QString str, sigtext;
                    if (!open_mime_data_sig(in, &str, &sigtext)) {
                        fprintf(stderr, "Error: can't parse message file.\n");
                        return 1;
                    }

                    data       = str.toUtf8();
                    smime_text = str;

                    QCA::Base64 dec;
                    dec.setLineBreaksEnabled(true);
                    sig = dec.stringToArray(rem_cr(sigtext)).toByteArray();
                }
            }

            QCA::SecureMessage *msg = new QCA::SecureMessage(sms);
            if (pgp)
                msg->setFormat(QCA::SecureMessage::Ascii);
            msg->startVerify(sig);
            msg->update(data);
            msg->end();
            msg->waitForFinished(-1);

            if (debug) {
                output_keystore_diagnostic_text();
                output_message_diagnostic_text(msg);
            }

            if (!msg->success()) {
                QString errstr = smErrorToString(msg->errorCode());
                delete msg;
                delete sms;
                fprintf(stderr, "Error: verify failed: %s\n", qPrintable(errstr));
                return 1;
            }

            QByteArray output;
            if (pgp && sig.isEmpty())
                output = msg->read();

            QList<QCA::SecureMessageSignature> signers = msg->signers();
            delete msg;
            delete sms;

            // for pgp clearsign, pgp signed (non-detached), and smime,
            //   the signed content was inside of the message.  we need
            //   to print that content now
            if (pgp) {
                printf("%s", output.data());
            } else {
                QString str = open_mime_envelope(smime_text);
                printf("%s", str.toUtf8().data());
            }

            smDisplaySignatures(signers);

            bool allgood = true;
            foreach (const QCA::SecureMessageSignature &signer, signers) {
                if (signer.identityResult() != QCA::SecureMessageSignature::Valid) {
                    allgood = false;
                    break;
                }
            }

            if (!allgood)
                return 1;
        } else if (args[1] == QLatin1String("decrypt")) {
            if (args.count() < 3) {
                usage();
                return 1;
            }

            QCA::SecureMessageSystem *sms;
            bool                      pgp = false;

            if (args[2] == QLatin1String("pgp")) {
                if (!QCA::isSupported("openpgp")) {
                    fprintf(stderr, "Error: need 'openpgp' feature.\n");
                    return 1;
                }

                sms = new QCA::OpenPGP;
                pgp = true;
            } else if (args[2] == QLatin1String("smime")) {
                if (args.count() < 4) {
                    usage();
                    return 1;
                }

                if (!QCA::isSupported("cms")) {
                    fprintf(stderr, "Error: need 'cms' feature.\n");
                    return 1;
                }

                // user can provide many possible decrypt keys
                QList<QCA::KeyBundle> keys;
                for (int n = 3; n < args.count(); ++n) {
                    QCA::KeyBundle key = get_X(args[n]);
                    if (key.isNull())
                        return 1;
                    keys += key;
                }

                sms = new QCA::CMS;

                QList<QCA::SecureMessageKey> skeys;
                foreach (const QCA::KeyBundle &key, keys) {
                    QCA::SecureMessageKey skey;
                    skey.setX509CertificateChain(key.certificateChain());
                    skey.setX509PrivateKey(key.privateKey());
                    skeys += skey;
                }

                ((QCA::CMS *)sms)->setPrivateKeys(skeys);
            } else {
                usage();
                return 1;
            }

            // read input data from stdin all at once
            QByteArray plain;
            while (!feof(stdin)) {
                QByteArray block(1024, 0);
                int        n = fread(block.data(), 1, 1024, stdin);
                if (n < 0)
                    break;
                block.resize(n);
                plain += block;
            }

            // smime envelope
            if (!pgp) {
                QString in  = QString::fromUtf8(plain);
                QString str = open_mime_envelope(in);
                if (str.isEmpty()) {
                    delete sms;
                    fprintf(stderr, "Error: can't parse message file.\n");
                    return 1;
                }

                QCA::Base64 dec;
                dec.setLineBreaksEnabled(true);
                plain = dec.stringToArray(rem_cr(str)).toByteArray();
            }

            QCA::SecureMessage *msg = new QCA::SecureMessage(sms);
            if (pgp)
                msg->setFormat(QCA::SecureMessage::Ascii);
            msg->startDecrypt();
            msg->update(plain);
            msg->end();
            msg->waitForFinished(-1);

            if (debug) {
                output_keystore_diagnostic_text();
                output_message_diagnostic_text(msg);
            }

            if (!msg->success()) {
                QString errstr = smErrorToString(msg->errorCode());
                delete msg;
                delete sms;
                fprintf(stderr, "Error: decrypt failed: %s\n", qPrintable(errstr));
                return 1;
            }

            QByteArray output = msg->read();

            QList<QCA::SecureMessageSignature> signers;
            bool                               wasSigned = false;
            if (msg->wasSigned()) {
                signers   = msg->signers();
                wasSigned = true;
            }
            delete msg;
            delete sms;

            printf("%s", output.data());

            if (wasSigned) {
                fprintf(stderr, "Message was also signed:\n");

                smDisplaySignatures(signers);

                bool allgood = true;
                foreach (const QCA::SecureMessageSignature &signer, signers) {
                    if (signer.identityResult() != QCA::SecureMessageSignature::Valid) {
                        allgood = false;
                        break;
                    }
                }

                if (!allgood)
                    return 1;
            }
        } else if (args[1] == QLatin1String("exportcerts")) {
            if (!QCA::isSupported("cms")) {
                fprintf(stderr, "Error: need 'cms' feature.\n");
                return 1;
            }

            QCA::SecureMessageSystem *sms = new QCA::CMS;

            QByteArray data, sig;
            QString    smime_text;
            {
                // read input data from stdin all at once
                QByteArray plain;
                while (!feof(stdin)) {
                    QByteArray block(1024, 0);
                    int        n = fread(block.data(), 1, 1024, stdin);
                    if (n < 0)
                        break;
                    block.resize(n);
                    plain += block;
                }

                // smime envelope
                QString in = QString::fromUtf8(plain);
                QString str, sigtext;
                if (!open_mime_data_sig(in, &str, &sigtext)) {
                    delete sms;
                    fprintf(stderr, "Error: can't parse message file.\n");
                    return 1;
                }

                data       = str.toUtf8();
                smime_text = str;

                QCA::Base64 dec;
                dec.setLineBreaksEnabled(true);
                sig = dec.stringToArray(rem_cr(sigtext)).toByteArray();
            }

            QCA::SecureMessage *msg = new QCA::SecureMessage(sms);
            msg->startVerify(sig);
            msg->update(data);
            msg->end();
            msg->waitForFinished(-1);

            if (debug)
                output_message_diagnostic_text(msg);

            if (!msg->success()) {
                QString errstr = smErrorToString(msg->errorCode());
                delete msg;
                delete sms;
                fprintf(stderr, "Error: export failed: %s\n", qPrintable(errstr));
                return 1;
            }

            QList<QCA::SecureMessageSignature> signers = msg->signers();
            delete msg;
            delete sms;

            // print out all certs of all signers
            foreach (const QCA::SecureMessageSignature &signer, signers) {
                QCA::SecureMessageKey key = signer.key();
                if (!key.isNull()) {
                    foreach (const QCA::Certificate &c, key.x509CertificateChain())
                        printf("%s", qPrintable(c.toPEM()));
                }
            }
        } else {
            usage();
            return 1;
        }
    } else {
        usage();
        return 1;
    }

    return 0;
}

#include "main.moc"
