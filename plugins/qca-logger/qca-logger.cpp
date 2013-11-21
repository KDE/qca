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

#include <QtCrypto>
#include <qcaprovider.h>
#include <QtPlugin>
#include <QTextStream>
#include <QFile>

#include <stdlib.h>

using namespace QCA;

namespace loggerQCAPlugin {

class StreamLogger : public QCA::AbstractLogDevice
{
public:
	StreamLogger(QTextStream &stream) : QCA::AbstractLogDevice( "Stream logger" ), _stream(stream)
	{
		QCA::logger()->registerLogDevice (this);
	}

	~StreamLogger()
	{
		QCA::logger()->unregisterLogDevice (name ());
	}

	void logTextMessage( const QString &message, enum QCA::Logger::Severity severity )
	{
		_stream << now () << " " << severityName (severity) << " " << message << endl;
	}

	void logBinaryMessage( const QByteArray &blob, enum QCA::Logger::Severity severity )
	{
		Q_UNUSED(blob);
		_stream << now () << " " << severityName (severity) << " " << "Binary blob not implemented yet" << endl;
	}

private:
	inline const char *severityName( enum QCA::Logger::Severity severity )
	{
		if (severity <= QCA::Logger::Debug) {
			return s_severityNames[severity];
		}
		else {
			return s_severityNames[QCA::Logger::Debug+1];
		}
	}

	inline QString now() {
		static QString format = "yyyy-MM-dd hh:mm:ss";
		return QDateTime::currentDateTime ().toString (format);
	}

private:
	static const char *s_severityNames[];
	QTextStream &_stream;
};

const char *StreamLogger::s_severityNames[] = {
	"Q",
	"M",
	"A",
	"C",
	"E",
	"W",
	"N",
	"I",
	"D",
	"U"
};

}

using namespace loggerQCAPlugin;

class loggerProvider : public Provider
{
private:
	QFile _logFile;
	QTextStream _logStream;
	StreamLogger *_streamLogger;
	bool _externalConfig;

public:
	loggerProvider () {
		_externalConfig = false;
		_streamLogger = NULL;

		QByteArray level = qgetenv ("QCALOGGER_LEVEL");
		QByteArray file = qgetenv ("QCALOGGER_FILE");

		if (!level.isEmpty ()) {
			printf ("XXXX %s %s\n", level.data (), file.data ());
			_externalConfig = true;
			createLogger (
				atoi (level),
				file.isEmpty () ? QString() : QString::fromUtf8 (file)
			);
		}
	}

	~loggerProvider () {
		delete _streamLogger;
		_streamLogger = NULL;
	}

public:
	virtual
	int
	qcaVersion() const {
		return QCA_VERSION;
	}

	virtual
	void
	init () {}

	virtual
	QString
	name () const {
		return "qca-logger";
	}

	virtual
	QStringList
	features () const {
		QStringList list;
		list += "log";
		return list;
	}

	virtual
	Context *
	createContext (
		const QString &type
	) {
		Q_UNUSED(type);
		return NULL;
	}

	virtual
	QVariantMap
	defaultConfig () const {
		QVariantMap mytemplate;

		mytemplate["formtype"] = "http://affinix.com/qca/forms/qca-logger#1.0";
		mytemplate["enabled"] = false;
		mytemplate["file"] = "";
		mytemplate["level"] = (int)Logger::Quiet;

		return mytemplate;
	}

	virtual
	void
	configChanged (const QVariantMap &config) {
		if (!_externalConfig) {
			delete _streamLogger;
			_streamLogger = NULL;

			if (config["enabled"].toBool ()) {
				createLogger (
					config["level"].toInt (),
					config["file"].toString ()
				);
			}
		}
	}

private:
	void
	createLogger (
		const int level,
		const QString &file
	) {
		bool success = false;
		if (file.isEmpty ()) {
			success = _logFile.open (stderr, QIODevice::WriteOnly | QIODevice::Text | QIODevice::Unbuffered);
		}
		else {
			_logFile.setFileName (file);
			success = _logFile.open (QIODevice::Append | QIODevice::Text | QIODevice::Unbuffered);
		}

		if (success) {
			_logStream.setDevice (&_logFile);
			logger ()->setLevel ((Logger::Severity)level);
			_streamLogger = new StreamLogger (_logStream);
		}
	}
};

class loggerPlugin : public QObject, public QCAPlugin
{
	Q_OBJECT
#if QT_VERSION >= 0x050000
	Q_PLUGIN_METADATA(IID "com.affinix.qca.Plugin/1.0")
#endif
	Q_INTERFACES(QCAPlugin)

public:
	virtual Provider *createProvider() { return new loggerProvider; }
};

#include "qca-logger.moc"

#if QT_VERSION < 0x050000
Q_EXPORT_PLUGIN2(qca_logger, loggerPlugin)
#endif
