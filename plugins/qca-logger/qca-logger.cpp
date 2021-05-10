/*
 * Copyright (C) 2007  Alon Bar-Lev <alon.barlev@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 *
 */

#include <QFile>
#include <QTextStream>
#include <QtCrypto>
#include <QtPlugin>
#include <qcaprovider.h>

#include <cstdlib>

using namespace QCA;

namespace loggerQCAPlugin {

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
        static const QString format = QStringLiteral("yyyy-MM-dd hh:mm:ss");
        return QDateTime::currentDateTime().toString(format);
    }

private:
    static const char *s_severityNames[];
    QTextStream &      _stream;
};

const char *StreamLogger::s_severityNames[] = {"Q", "M", "A", "C", "E", "W", "N", "I", "D", "U"};

}

using namespace loggerQCAPlugin;

class loggerProvider : public Provider
{
private:
    QFile         _logFile;
    QTextStream   _logStream;
    StreamLogger *_streamLogger;
    bool          _externalConfig;

public:
    loggerProvider()
    {
        _externalConfig = false;
        _streamLogger   = nullptr;

        const QByteArray level = qgetenv("QCALOGGER_LEVEL");
        const QByteArray file  = qgetenv("QCALOGGER_FILE");

        if (!level.isEmpty()) {
            printf("XXXX %s %s\n", level.data(), file.data());
            _externalConfig = true;
            createLogger(atoi(level.constData()), file.isEmpty() ? QString() : QString::fromUtf8(file));
        }
    }

    ~loggerProvider() override
    {
        delete _streamLogger;
        _streamLogger = nullptr;
    }

public:
    int qcaVersion() const override
    {
        return QCA_VERSION;
    }

    void init() override
    {
    }

    QString name() const override
    {
        return QStringLiteral("qca-logger");
    }

    QStringList features() const override
    {
        QStringList list;
        list += QStringLiteral("log");
        return list;
    }

    Context *createContext(const QString &type) override
    {
        Q_UNUSED(type);
        return nullptr;
    }

    QVariantMap defaultConfig() const override
    {
        QVariantMap mytemplate;

        mytemplate[QStringLiteral("formtype")] = QStringLiteral("http://affinix.com/qca/forms/qca-logger#1.0");
        mytemplate[QStringLiteral("enabled")]  = false;
        mytemplate[QStringLiteral("file")]     = QLatin1String("");
        mytemplate[QStringLiteral("level")]    = (int)Logger::Quiet;

        return mytemplate;
    }

    void configChanged(const QVariantMap &config) override
    {
        if (!_externalConfig) {
            delete _streamLogger;
            _streamLogger = nullptr;

            if (config[QStringLiteral("enabled")].toBool()) {
                createLogger(config[QStringLiteral("level")].toInt(), config[QStringLiteral("file")].toString());
            }
        }
    }

private:
    void createLogger(const int level, const QString &file)
    {
        bool success = false;
        if (file.isEmpty()) {
            success = _logFile.open(stderr, QIODevice::WriteOnly | QIODevice::Text | QIODevice::Unbuffered);
        } else {
            _logFile.setFileName(file);
            success = _logFile.open(QIODevice::Append | QIODevice::Text | QIODevice::Unbuffered);
        }

        if (success) {
            _logStream.setDevice(&_logFile);
            logger()->setLevel((Logger::Severity)level);
            _streamLogger = new StreamLogger(_logStream);
        }
    }
};

class loggerPlugin : public QObject, public QCAPlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "com.affinix.qca.Plugin/1.0")
    Q_INTERFACES(QCAPlugin)

public:
    Provider *createProvider() override
    {
        return new loggerProvider;
    }
};

#include "qca-logger.moc"
