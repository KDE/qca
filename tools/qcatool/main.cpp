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
#include <QFile>
#include <QFileInfo>
#include <QTextStream>
#include <QTimer>

#define VERSION "0.0.1"

static QStringList wrapstring(const QString &str, int width)
{
	QStringList out;
	QString simp = str.simplified();
	QString rest = simp;
	while(1)
	{
		int lastSpace = -1;
		int n;
		for(n = 0; n < rest.length(); ++n)
		{
			if(rest[n].isSpace())
				lastSpace = n;
			if(n == width)
				break;
		}
		if(n == rest.length())
		{
			out += rest;
			break;
		}

		QString line;
		if(lastSpace != -1)
		{
			line = rest.mid(0, lastSpace);
			rest = rest.mid(lastSpace + 1);
		}
		else
		{
			line = rest.mid(0, n);
			rest = rest.mid(n);
		}
		out += line;
	}
	return out;
}

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
	inline char *severityName( enum QCA::Logger::Severity severity )
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
	static char *s_severityNames[];
	QTextStream &_stream;
};

char *StreamLogger::s_severityNames[] = {
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

class AnimatedKeyGen : public QObject
{
	Q_OBJECT
public:
	static QCA::PrivateKey makeKey(QCA::PKey::Type type, int bits, QCA::DLGroupSet set)
	{
		AnimatedKeyGen kg;
		kg.type = type;
		kg.bits = bits;
		kg.set = set;
		QEventLoop eventLoop;
		kg.eventLoop = &eventLoop;
		QTimer::singleShot(0, &kg, SLOT(start()));
		eventLoop.exec();
		QCA::PrivateKey key = kg.key;
		return key;
	}

private:
	QCA::PKey::Type type;
	int bits;
	QCA::DLGroupSet set;
	QEventLoop *eventLoop;
	QCA::KeyGenerator gen;
	QCA::DLGroup group;
	QCA::PrivateKey key;
	QTimer t;
	int x;

	AnimatedKeyGen()
	{
		gen.setBlocking(false);
		connect(&gen, SIGNAL(finished()), SLOT(gen_finished()));
		connect(&t, SIGNAL(timeout()), SLOT(t_timeout()));
	}

private slots:
	void start()
	{
		printf("Generating Key ...  ");
		fflush(stdout);
		x = 0;
		t.start(125);

		if(type == QCA::PKey::RSA)
			gen.createRSA(bits);
		else
			gen.createDLGroup(set);
	}

	void gen_finished()
	{
		if(type == QCA::PKey::DSA || type == QCA::PKey::DH)
		{
			if(group.isNull())
			{
				group = gen.dlGroup();

				if(type == QCA::PKey::DSA)
					gen.createDSA(group);
				else
					gen.createDH(group);
				return;
			}
		}

		key = gen.key();

		printf("\b");
		if(!key.isNull())
			printf("Done\n");
		else
			printf("Error\n");

		eventLoop->exit();
	}

	void t_timeout()
	{
		if(x == 0)
			printf("\b/");
		else if(x == 1)
			printf("\b-");
		else if(x == 2)
			printf("\b\\");
		else if(x == 3)
			printf("\b|");
		fflush(stdout);

		++x;
		x %= 4;
	}
};

// TODO: support auto-discovering token during token request event
// TODO: add a special watching mode to qcatool to monitor keystore activity?

class PassphrasePrompt : public QObject
{
	Q_OBJECT
public:
	class Item
	{
	public:
		QString promptStr;
		int id;
		QCA::Event event;
	};

	QCA::EventHandler handler;
	bool allowPrompt;
	bool warned;
	bool have_pass;
	bool used_pass;
	QCA::SecureArray pass;
	QCA::ConsolePrompt *prompt;
	int prompt_id;
	QCA::Event prompt_event;
	QList<Item> pending;

	PassphrasePrompt()
	{
		allowPrompt = true;
		warned = false;
		have_pass = false;

		prompt = 0;

		connect(&handler, SIGNAL(eventReady(int, const QCA::Event &)), SLOT(ph_eventReady(int, const QCA::Event &)));
		handler.start();
	}

	~PassphrasePrompt()
	{
		if(prompt)
		{
			handler.reject(prompt_id);
			delete prompt;
		}

		while(!pending.isEmpty())
			handler.reject(pending.takeFirst().id);
	}

	void setExplicitPassword(const QCA::SecureArray &_pass)
	{
		have_pass = true;
		used_pass = false;
		pass = _pass;
	}

private slots:
	void ph_eventReady(int id, const QCA::Event &e)
	{
		if(have_pass)
		{
			// only allow using an explicit passphrase once
			if(used_pass)
			{
				handler.reject(id);
				return;
			}
			used_pass = true;
			handler.submitPassword(id, pass);
			return;
		}

		if(!allowPrompt)
		{
			if(!have_pass && !warned)
			{
				warned = true;
				fprintf(stderr, "Error: no passphrase specified (use '--pass=' for none).\n");
			}

			handler.reject(id);
			return;
		}

		if(e.type() == QCA::Event::Password)
		{
			QString type = "password";
			if(e.passwordStyle() == QCA::Event::StylePassphrase)
				type = "passphrase";
			else if(e.passwordStyle() == QCA::Event::StylePIN)
				type = "PIN";

			QString str;
			if(e.source() == QCA::Event::KeyStore)
			{
				QString name;
				QCA::KeyStoreEntry entry = e.keyStoreEntry();
				if(!entry.isNull())
				{
					name = entry.name();
				}
				else
				{
					if(e.keyStoreInfo().type() == QCA::KeyStore::SmartCard)
						name = QString("the '") + e.keyStoreInfo().name() + "' token";
					else
						name = e.keyStoreInfo().name();
				}
				str = QString("Enter %1 for %2").arg(type).arg(name);
			}
			else if(!e.fileName().isEmpty())
				str = QString("Enter %1 for %2").arg(type).arg(e.fileName());
			else
				str = QString("Enter %1").arg(type);

			if(!prompt)
			{
				prompt = new QCA::ConsolePrompt(this);
				connect(prompt, SIGNAL(finished()), SLOT(prompt_finished()));
				prompt_id = id;
				prompt_event = e;
				prompt->getHidden(str);
			}
			else
			{
				Item i;
				i.promptStr = str;
				i.id = id;
				i.event = e;
				pending += i;
			}
		}
		else if(e.type() == QCA::Event::Token)
		{
			QCA::KeyStoreEntry entry = e.keyStoreEntry();
			QString name;
			if(!entry.isNull())
			{
				name = QString("the '") + entry.storeName() + "' token for " + entry.name();
			}
			else
			{
				name = QString("the '") + e.keyStoreInfo().name() + "' token";
			}

			QString str = QString("Please insert %1 and press Enter ...").arg(name);

			if(!prompt)
			{
				printf("%s\n", qPrintable(str));
				prompt = new QCA::ConsolePrompt(this);
				connect(prompt, SIGNAL(finished()), SLOT(prompt_finished()));
				prompt_id = id;
				prompt_event = e;
				prompt->getEnter();
			}
			else
			{
				Item i;
				i.promptStr = str;
				i.id = id;
				i.event = e;
				pending += i;
			}
		}
		else
			handler.reject(id);
	}

	void prompt_finished()
	{
		if(prompt_event.type() == QCA::Event::Password)
			handler.submitPassword(prompt_id, prompt->result());
		else
			handler.tokenOkay(prompt_id);

		if(!pending.isEmpty())
		{
			Item i = pending.takeFirst();
			prompt_id = i.id;
			prompt_event = i.event;
			if(i.event.type() == QCA::Event::Password)
			{
				prompt->getHidden(i.promptStr);
			}
			else // Token
			{
				printf("%s\n", qPrintable(i.promptStr));
				prompt->getEnter();
			}
		}
		else
		{
			delete prompt;
			prompt = 0;
		}
	}
};

class PassphrasePromptThread : public QCA::SyncThread
{
public:
	PassphrasePrompt *pp;

	PassphrasePromptThread()
	{
		start();
	}

	~PassphrasePromptThread()
	{
		stop();
	}

protected:
	virtual void atStart()
	{
		pp = new PassphrasePrompt;
	}

	virtual void atEnd()
	{
		delete pp;
	}
};

static bool promptForNewPassphrase(QCA::SecureArray *result)
{
	QCA::ConsolePrompt prompt;
	prompt.getHidden("Enter new passphrase");
	prompt.waitForFinished();
	QCA::SecureArray out = prompt.result();

	prompt.getHidden("Confirm new passphrase");
	prompt.waitForFinished();

	if(prompt.result() != out)
	{
		fprintf(stderr, "Error: confirmation does not match original entry.\n");
		return false;
	}
	*result = out;
	return true;
}

static QString line_encode(const QString &in)
{
	QString out;
	for(int n = 0; n < in.length(); ++n)
	{
		if(in[n] == '\\')
			out += "\\\\";
		else if(in[n] == '\n')
			out += "\\n";
		else
			out += in[n];
	}
	return out;
}

static QString line_decode(const QString &in)
{
	QString out;
	for(int n = 0; n < in.length(); ++n)
	{
		if(in[n] == '\\')
		{
			if(n + 1 < in.length())
			{
				if(in[n + 1] == '\\')
					out += '\\';
				else if(in[n + 1] == 'n')
					out += '\n';
				++n;
			}
		}
		else
			out += in[n];
	}
	return out;
}

static QString make_ksentry_string(const QString &id)
{
	QString out;
	out += "QCATOOL_KEYSTOREENTRY_1\n";
	out += line_encode(id) + '\n';
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
	if(!f.open(QFile::ReadOnly))
		return out;
	QTextStream ts(&f);
	int linenum = 0;
	while(!ts.atEnd())
	{
		QString line = ts.readLine();
		if(linenum == 0)
		{
			if(line != "QCATOOL_KEYSTOREENTRY_1")
				return out;
		}
		else
		{
			out = line_decode(line);
			break;
		}
		++linenum;
	}
	return out;
}

static QByteArray read_der_file(const QString &fileName)
{
	QFile f(fileName);
	if(!f.open(QFile::ReadOnly))
		return QByteArray();
	return f.readAll();
}

class InfoType
{
public:
	QCA::CertificateInfoType type;
	QString varname;
	QString shortname;
	QString name;
	QString desc;

	InfoType()
	{
	}

	InfoType(QCA::CertificateInfoType _type, const QString &_varname, const QString &_shortname, const QString &_name, const QString &_desc)
	:type(_type), varname(_varname), shortname(_shortname), name(_name), desc(_desc)
	{
	}
};

static QList<InfoType> makeInfoTypeList(bool legacyEmail = false)
{
	QList<InfoType> out;
	out += InfoType(QCA::CommonName,             "CommonName",             "CN",  "Common Name (CN)",          "Full name, domain, anything");
	out += InfoType(QCA::Email,                  "Email",                  "",    "Email Address",             "");
	if(legacyEmail)
		out += InfoType(QCA::EmailLegacy,            "EmailLegacy",            "",    "PKCS#9 Email Address",      "");
	out += InfoType(QCA::Organization,           "Organization",           "O",   "Organization (O)",          "Company, group, etc");
	out += InfoType(QCA::OrganizationalUnit,     "OrganizationalUnit",     "OU",  "Organizational Unit (OU)",  "Division/branch of organization");
	out += InfoType(QCA::Locality,               "Locality",               "",    "Locality (L)",              "City, shire, part of a state");
	out += InfoType(QCA::State,                  "State",                  "",    "State (ST)",                "State within the country");
	out += InfoType(QCA::Country,                "Country",                "C",   "Country Code (C)",          "2-letter code");
	out += InfoType(QCA::IncorporationLocality,  "IncorporationLocality",  "",    "Incorporation Locality",    "For EV certificates");
	out += InfoType(QCA::IncorporationState,     "IncorporationState",     "",    "Incorporation State",       "For EV certificates");
	out += InfoType(QCA::IncorporationCountry,   "IncorporationCountry",   "",    "Incorporation Country",     "For EV certificates");
	out += InfoType(QCA::URI,                    "URI",                    "",    "URI",                       "");
	out += InfoType(QCA::DNS,                    "DNS",                    "",    "Domain Name",               "Domain (dnsName)");
	out += InfoType(QCA::IPAddress,              "IPAddress",              "",    "IP Adddress",               "");
	out += InfoType(QCA::XMPP,                   "XMPP",                   "",    "XMPP Address (JID)",        "From RFC 3920 (id-on-xmppAddr)");
	return out;
}

class MyConstraintType
{
public:
	QCA::ConstraintType type;
	QString varname;
	QString name;
	QString desc;

	MyConstraintType()
	{
	}

	MyConstraintType(QCA::ConstraintType _type, const QString &_varname, const QString &_name, const QString &_desc)
	:type(_type), varname(_varname), name(_name), desc(_desc)
	{
	}
};

static QList<MyConstraintType> makeConstraintTypeList()
{
	QList<MyConstraintType> out;
	out += MyConstraintType(QCA::DigitalSignature,    "DigitalSignature",    "Digital Signature",      "Can be used for signing");
	out += MyConstraintType(QCA::NonRepudiation,      "NonRepudiation",      "Non-Repudiation",        "Usage is legally binding");
	out += MyConstraintType(QCA::KeyEncipherment,     "KeyEncipherment",     "Key Encipherment",       "Can encrypt other keys");
	out += MyConstraintType(QCA::DataEncipherment,    "DataEncipherment",    "Data Encipherment",      "Can encrypt arbitrary data");
	out += MyConstraintType(QCA::KeyAgreement,        "KeyAgreement",        "Key Agreement",          "Can perform key agreement (DH)");
	out += MyConstraintType(QCA::KeyCertificateSign,  "KeyCertificateSign",  "Certificate Sign",       "Can sign other certificates");
	out += MyConstraintType(QCA::CRLSign,             "CRLSign",             "CRL Sign",               "Can sign CRLs");
	out += MyConstraintType(QCA::EncipherOnly,        "EncipherOnly",        "Encipher Only",          "Can be used for encrypting");
	out += MyConstraintType(QCA::DecipherOnly,        "DecipherOnly",        "Decipher Only",          "Can be used for decrypting");
	out += MyConstraintType(QCA::ServerAuth,          "ServerAuth",          "Server Authentication",  "TLS Server");
	out += MyConstraintType(QCA::ClientAuth,          "ClientAuth",          "Client Authentication",  "TLS Client");
	out += MyConstraintType(QCA::CodeSigning,         "CodeSigning",         "Code Signing",           "");
	out += MyConstraintType(QCA::EmailProtection,     "EmailProtection",     "Email Protection",       "S/MIME");
	out += MyConstraintType(QCA::IPSecEndSystem,      "IPSecEndSystem",      "IPSec End-System",       "");
	out += MyConstraintType(QCA::IPSecTunnel,         "IPSecTunnel",         "IPSec Tunnel",           "");
	out += MyConstraintType(QCA::IPSecUser,           "IPSecUser",           "IPSec User",             "");
	out += MyConstraintType(QCA::TimeStamping,        "TimeStamping",        "Time Stamping",          "");
	out += MyConstraintType(QCA::OCSPSigning,         "OCSPSigning",         "OCSP Signing",           "");
	return out;
}

static bool validOid(const QString &in)
{
	for(int n = 0; n < in.length(); ++n)
	{
		if(!in[n].isDigit() && in[n] != '.')
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
	if(offset >= in.length())
		return in.length();

	int n = offset;
	bool lookForNonDigit;

	if(in[n].isDigit())
		lookForNonDigit = true;
	else
		lookForNonDigit = false;

	for(++n; n < in.length(); ++n)
	{
		if(in[n].isDigit() != lookForNonDigit)
			break;
	}
	return n;
}

static QStringList vl_getparts(const QString &in)
{
	QStringList out;
	int offset = 0;
	while(1)
	{
		int n = vl_getnext(in, offset);
		if(n == offset)
			break;
		out += in.mid(offset, n - offset);
		offset = n;
	}
	return out;
}

static bool parseValidityLength(const QString &in, ValidityLength *vl)
{
	vl->years = -1;
	vl->months = -1;
	vl->days = -1;

	QStringList parts = vl_getparts(in);
	while(1)
	{
		// first part should be a number
		if(parts.count() < 1)
			break;
		QString str = parts.takeFirst();
		bool ok;
		int x = str.toInt(&ok);
		if(!ok)
			return false;

		// next part should be 1 letter plus any amount of space
		if(parts.count() < 1)
			return false;
		str = parts.takeFirst();
		if(!str[0].isLetter())
			return false;
		str = str.trimmed(); // remove space

		if(str == "y")
		{
			if(vl->years != -1)
				return false;
			vl->years = x;
		}
		if(str == "m")
		{
			if(vl->months != -1)
				return false;
			vl->months = x;
		}
		if(str == "d")
		{
			if(vl->days != -1)
				return false;
			vl->days = x;
		}
	}

	if(vl->years == -1)
		vl->years = 0;
	if(vl->months == -1)
		vl->months = 0;
	if(vl->days == -1)
		vl->days = 0;

	return true;
}

static QString prompt_for(const QString &prompt)
{
	printf("%s: ", prompt.toLatin1().data());
	fflush(stdout);
	QByteArray result(256, 0);
	fgets((char *)result.data(), result.size(), stdin);
	return QString::fromLocal8Bit(result).trimmed();
}

static QCA::CertificateOptions promptForCertAttributes(bool advanced, bool req)
{
	QCA::CertificateOptions opts;

	if(advanced)
	{
		if(!req)
		{
			while(1)
			{
				QString str = prompt_for("Create an end user ('user') certificate or a CA ('ca') certificate? [user]");
				if(str.isEmpty())
					str = "user";
				if(str != "user" && str != "ca")
				{
					printf("'%s' is not a valid entry.\n", qPrintable(str));
					continue;
				}

				if(str == "ca")
					opts.setAsCA();
				break;
			}
			printf("\n");

			while(1)
			{
				QString str = prompt_for("Serial Number");
				QCA::BigInteger num;
				if(str.isEmpty() || !num.fromString(str))
				{
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
			printf("Choose the information attributes to add to the certificate.  They will be\n"
				"added in the order they are entered.\n\n");
			printf("Available information attributes:\n");
			QList<InfoType> list = makeInfoTypeList();
			for(int n = 0; n < list.count(); ++n)
			{
				const InfoType &i = list[n];
				char c = 'a' + n;
				printf("  %c) %-32s        %s\n", c, qPrintable(i.name), qPrintable(i.desc));
			}
			printf("\n");
			while(1)
			{
				int index;
				while(1)
				{
					QString str = prompt_for("Select an attribute to add, or enter to move on");
					if(str.isEmpty())
					{
						index = -1;
						break;
					}
					if(str.length() == 1)
					{
						index = str[0].toLatin1() - 'a';
						if(index >= 0 && index < list.count())
							break;
					}
					printf("'%s' is not a valid entry.\n", qPrintable(str));
				}
				if(index == -1)
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
			for(int n = 0; n < list.count(); ++n)
			{
				const MyConstraintType &i = list[n];
				char c = 'a' + n;
				printf("  %c) %-32s        %s\n", c, qPrintable(i.name), qPrintable(i.desc));
			}
			printf("\n");
			printf("If no constraints are added, then the certificate may be used for any purpose.\n\n");
			while(1)
			{
				int index;
				while(1)
				{
					QString str = prompt_for("Select an attribute to add, or enter to move on");
					if(str.isEmpty())
					{
						index = -1;
						break;
					}
					if(str.length() == 1)
					{
						index = str[0].toLatin1() - 'a';
						if(index >= 0 && index < list.count())
							break;
					}
					printf("'%s' is not a valid entry.\n\n", qPrintable(str));
				}
				if(index == -1)
					break;

				if(constraints.contains(list[index].type))
				{
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
			printf("Are there any policy OID attributes that you wish to add?  Use the dotted\n"
				"string format.\n\n");
			while(1)
			{
				QString str = prompt_for("Enter a policy OID to add, or enter to move on");
				if(str.isEmpty())
					break;
				if(!validOid(str))
				{
					printf("'%s' is not a valid entry.\n\n", qPrintable(str));
					continue;
				}
				if(policies.contains(str))
				{
					printf("You have already added '%s'.\n\n", qPrintable(str));
					continue;
				}

				policies += str;
				printf("Added attribute.\n\n");
			}
			opts.setPolicies(policies);
		}

		printf("\n");
	}
	else
	{
		QCA::CertificateInfo info;
		info.insert(QCA::CommonName, prompt_for("Common Name"));
		info.insert(QCA::Country, prompt_for("Country Code (2 letters)"));
		info.insert(QCA::Organization, prompt_for("Organization"));
		info.insert(QCA::Email, prompt_for("Email"));
		opts.setInfo(info);

		printf("\n");
	}

	if(!req)
	{
		while(1)
		{
			QString str = prompt_for("How long should the certificate be valid? (e.g. '1y2m3d')");
			ValidityLength vl;
			if(!parseValidityLength(str, &vl))
			{
				printf("'%s' is not a valid entry.\n\n", qPrintable(str));
				continue;
			}

			if(vl.years == 0 && vl.months == 0 && vl.days == 0)
			{
				printf("The certificate must be valid for at least one day.\n\n");
				continue;
			}

			QDateTime start = QDateTime::currentDateTime().toUTC();
			QDateTime end = start;
			if(vl.years > 0)
				end = end.addYears(vl.years);
			if(vl.months > 0)
				end = end.addMonths(vl.months);
			if(vl.days > 0)
				end = end.addDays(vl.days);
			opts.setValidityPeriod(start, end);

			QStringList parts;
			if(vl.years > 0)
				parts += QString("%1 year(s)").arg(vl.years);
			if(vl.months > 0)
				parts += QString("%1 month(s)").arg(vl.months);
			if(vl.days > 0)
				parts += QString("%1 day(s)").arg(vl.days);
			QString out;
			if(parts.count() == 1)
				out = parts[0];
			else if(parts.count() == 2)
				out = parts[0] + " and " + parts[1];
			else if(parts.count() == 3)
				out = parts[0] + ", " + parts[1] + ", and " + parts[2];
			printf("Certificate will be valid for %s.\n", qPrintable(out));
			break;
		}
		printf("\n");
	}

	return opts;
}

static QString kstype_to_string(QCA::KeyStore::Type _type)
{
	QString type;
	switch(_type)
	{
		case QCA::KeyStore::System:      type = "Sys "; break;
		case QCA::KeyStore::User:        type = "User"; break;
		case QCA::KeyStore::Application: type = "App "; break;
		case QCA::KeyStore::SmartCard:   type = "Card"; break;
		case QCA::KeyStore::PGPKeyring:  type = "PGP "; break;
		default:                         type = "XXXX"; break;
	}
	return type;
}

static QString ksentrytype_to_string(QCA::KeyStoreEntry::Type _type)
{
	QString type;
	switch(_type)
	{
		case QCA::KeyStoreEntry::TypeKeyBundle:    type = "Key "; break;
		case QCA::KeyStoreEntry::TypeCertificate:  type = "Cert"; break;
		case QCA::KeyStoreEntry::TypeCRL:          type = "CRL "; break;
		case QCA::KeyStoreEntry::TypePGPSecretKey: type = "PSec"; break;
		case QCA::KeyStoreEntry::TypePGPPublicKey: type = "PPub"; break;
		default:                                   type = "XXXX"; break;
	}
	return type;
}

static void try_print_info(const QString &name, const QStringList &values)
{
	if(!values.isEmpty())
	{
		QString value = values.join(", ");
		printf("   %s: %s\n", qPrintable(name), value.toUtf8().data());
	}
}

static void print_info(const QString &title, const QCA::CertificateInfo &info)
{
	QList<InfoType> list = makeInfoTypeList();
	printf("%s\n", title.toLatin1().data());
	foreach(const InfoType &t, list)
		try_print_info(t.name, info.values(t.type));
}

static void print_info_ordered(const QString &title, const QCA::CertificateInfoOrdered &info)
{
	QList<InfoType> list = makeInfoTypeList(true);
	printf("%s\n", title.toLatin1().data());
	foreach(const QCA::CertificateInfoPair &pair, info)
	{
		QCA::CertificateInfoType type = pair.type();
		QString name;
		int at = -1;
		for(int n = 0; n < list.count(); ++n)
		{
			if(list[n].type == type)
			{
				at = n;
				break;
			}
		}

		// known type?
		if(at != -1)
		{
			name = list[at].name;
		}
		else
		{
			if(pair.section() == QCA::CertificateInfoPair::DN)
				name = QString("DN:") + pair.oid();
			else
				name = QString("AN:") + pair.oid();
		}

		printf("   %s: %s\n", qPrintable(name), pair.value().toUtf8().data());
	}
}

static QString constraint_to_string(QCA::ConstraintType t)
{
	QList<MyConstraintType> list = makeConstraintTypeList();
	for(int n = 0; n < list.count(); ++n)
	{
		if(list[n].type == t)
			return list[n].name;
	}
	return QString("Unknown Constraint");
}

static QString sigalgo_to_string(QCA::SignatureAlgorithm algo)
{
	QString str;
	switch(algo)
	{
		case QCA::EMSA1_SHA1:       str = "EMSA1(SHA1)"; break;
		case QCA::EMSA3_SHA1:       str = "EMSA3(SHA1)"; break;
		case QCA::EMSA3_MD5:        str = "EMSA3(MD5)"; break;
		case QCA::EMSA3_MD2:        str = "EMSA3(MD2)"; break;
		case QCA::EMSA3_RIPEMD160:  str = "EMSA3(RIPEMD160)"; break;
		case QCA::EMSA3_Raw:        str = "EMSA3(raw)"; break;
		default:                    str = "Unknown"; break;
	}
	return str;
}

static void print_cert(const QCA::Certificate &cert, bool ordered = false)
{
	printf("Serial Number: %s\n", qPrintable(cert.serialNumber().toString()));

	if(ordered)
	{
		print_info_ordered("Subject", cert.subjectInfoOrdered());
		print_info_ordered("Issuer", cert.issuerInfoOrdered());
	}
	else
	{
		print_info("Subject", cert.subjectInfo());
		print_info("Issuer", cert.issuerInfo());
	}

	printf("Validity\n");
	printf("   Not before: %s\n", qPrintable(cert.notValidBefore().toString()));
	printf("   Not after:  %s\n", qPrintable(cert.notValidAfter().toString()));

	printf("Constraints\n");
	QCA::Constraints constraints = cert.constraints();
	int n;
	if(!constraints.isEmpty())
	{
		for(n = 0; n < constraints.count(); ++n)
			printf("   %s\n", qPrintable(constraint_to_string(constraints[n])));
	}
	else
		printf("   No constraints\n");

	printf("Policies\n");
	QStringList policies = cert.policies();
	if(!policies.isEmpty())
	{
		for(n = 0; n < policies.count(); ++n)
			printf("   %s\n", qPrintable(policies[n]));
	}
	else
		printf("   No policies\n");

	QByteArray id;
	printf("Issuer Key ID: ");
	id = cert.issuerKeyId();
	if(!id.isEmpty())
		printf("%s\n", qPrintable(QCA::arrayToHex(id)));
	else
		printf("None\n");

	printf("Subject Key ID: ");
	id = cert.subjectKeyId();
	if(!id.isEmpty())
		printf("%s\n", qPrintable(QCA::arrayToHex(id)));
	else
		printf("None\n");

	printf("CA: %s\n", cert.isCA() ? "Yes": "No");
	printf("Signature Algorithm: %s\n", qPrintable(sigalgo_to_string(cert.signatureAlgorithm())));

	QCA::PublicKey key = cert.subjectPublicKey();
	printf("Public Key:\n%s", key.toPEM().toLatin1().data());
}

static void print_certreq(const QCA::CertificateRequest &cert, bool ordered = false)
{
	if(ordered)
		print_info_ordered("Subject", cert.subjectInfoOrdered());
	else
		print_info("Subject", cert.subjectInfo());

	printf("Constraints\n");
	QCA::Constraints constraints = cert.constraints();
	int n;
	if(!constraints.isEmpty())
	{
		for(n = 0; n < constraints.count(); ++n)
			printf("   %s\n", qPrintable(constraint_to_string(constraints[n])));
	}
	else
		printf("   No constraints\n");

	printf("Policies\n");
	QStringList policies = cert.policies();
	if(!policies.isEmpty())
	{
		for(n = 0; n < policies.count(); ++n)
			printf("   %s\n", qPrintable(policies[n]));
	}
	else
		printf("   No policies\n");

	printf("CA: %s\n", cert.isCA() ? "Yes": "No");
	printf("Signature Algorithm: %s\n", qPrintable(sigalgo_to_string(cert.signatureAlgorithm())));

	QCA::PublicKey key = cert.subjectPublicKey();
	printf("Public Key:\n%s", key.toPEM().toLatin1().data());
}

static void print_pgp(const QCA::PGPKey &key)
{
	printf("Key ID: %s\n", qPrintable(key.keyId()));
	printf("User IDs:\n");
	foreach(const QString &s, key.userIds())
		printf("   %s\n", qPrintable(s));
	printf("Validity\n");
	printf("   Not before: %s\n", qPrintable(key.creationDate().toString()));
	printf("   Not after:  %s\n", qPrintable(key.expirationDate().toString()));
	printf("In Keyring: %s\n", key.inKeyring() ? "Yes": "No");
	printf("Secret Key: %s\n", key.isSecret() ? "Yes": "No");
	printf("Trusted:    %s\n", key.isTrusted() ? "Yes": "No");
	printf("Fingerprint: %s\n", qPrintable(key.fingerprint()));
}

static QString validityToString(QCA::Validity v)
{
	QString s;
	switch(v)
	{
		case QCA::ValidityGood:
			s = "Validated";
			break;
		case QCA::ErrorRejected:
			s = "Root CA is marked to reject the specified purpose";
			break;
		case QCA::ErrorUntrusted:
			s = "Certificate not trusted for the required purpose";
			break;
		case QCA::ErrorSignatureFailed:
			s = "Invalid signature";
			break;
		case QCA::ErrorInvalidCA:
			s = "Invalid CA certificate";
			break;
		case QCA::ErrorInvalidPurpose:
			s = "Invalid certificate purpose";
			break;
		case QCA::ErrorSelfSigned:
			s = "Certificate is self-signed";
			break;
		case QCA::ErrorRevoked:
			s = "Certificate has been revoked";
			break;
		case QCA::ErrorPathLengthExceeded:
			s = "Maximum certificate chain length exceeded";
			break;
		case QCA::ErrorExpired:
			s = "Certificate has expired";
			break;
		case QCA::ErrorExpiredCA:
			s = "CA has expired";
			break;
		case QCA::ErrorValidityUnknown:
		default:
			s = "General certificate validation error";
			break;
	}
	return s;
}

static QString smErrorToString(QCA::SecureMessage::Error e)
{
	QMap<QCA::SecureMessage::Error,QString> map;
	map[QCA::SecureMessage::ErrorPassphrase] = "ErrorPassphrase";
	map[QCA::SecureMessage::ErrorFormat] = "ErrorFormat";
	map[QCA::SecureMessage::ErrorSignerExpired] = "ErrorSignerExpired";
	map[QCA::SecureMessage::ErrorSignerInvalid] = "ErrorSignerInvalid";
	map[QCA::SecureMessage::ErrorEncryptExpired] = "ErrorEncryptExpired";
	map[QCA::SecureMessage::ErrorEncryptUntrusted] = "ErrorEncryptUntrusted";
	map[QCA::SecureMessage::ErrorEncryptInvalid] = "ErrorEncryptInvalid";
	map[QCA::SecureMessage::ErrorNeedCard] = "ErrorNeedCard";
	map[QCA::SecureMessage::ErrorCertKeyMismatch] = "ErrorCertKeyMismatch";
	map[QCA::SecureMessage::ErrorUnknown] = "ErrorUnknown";
	return map[e];
}

const char *mime_signpart =
	"Content-Type: text/plain; charset=UTF-8\r\n"
	"Content-Transfer-Encoding: 8bit\r\n"
	"\r\n"
	"%1";

const char *mime_signed =
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

const char *mime_enveloped =
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
	int at = 0;
	while(1)
	{
		at = out.indexOf('\n', at);
		if(at == -1)
			break;
		if(at - 1 >= 0 && out[at - 1] != '\r')
		{
			out.insert(at, '\r');
			++at;
		}
		++at;
	}
	return out;
}

static QString rem_cr(const QString &in)
{
	QString out = in;
	out.replace("\r\n", "\n");
	return out;
}

static int indexOf_newline(const QString &in, int offset = 0)
{
	for(int n = offset; n < in.length(); ++n)
	{
		if(n + 1 < in.length() && in[n] == '\r' && in[n + 1] == '\n')
			return n;
		if(in[n] == '\n')
			return n;
	}
	return -1;
}

static int indexOf_doublenewline(const QString &in, int offset = 0)
{
	int at = -1;
	while(1)
	{
		int n = indexOf_newline(in, offset);
		if(n == -1)
			return -1;

		if(at != -1)
		{
			if(n == offset)
				break;
		}

		at = n;
		if(in[n] == '\n')
			offset = n + 1;
		else
			offset = n + 2;
	}
	return at;
}

// this is so gross
static int newline_len(const QString &in, int offset = 0)
{
	if(in[offset] == '\r')
		return 2;
	else
		return 1;
}

// FIXME: all of this mime stuff is a total hack
static QString open_mime_envelope(const QString &in)
{
	int n = indexOf_doublenewline(in);
	if(n == -1)
		return QString();
	return in.mid(n + (newline_len(in, n) * 2)); // good lord
}

static bool open_mime_data_sig(const QString &in, QString *data, QString *sig)
{
	int n = in.indexOf("boundary=");
	if(n == -1)
		return false;
	n += 9;
	int i = indexOf_newline(in, n);
	if(i == -1)
		return false;
	QString boundary;
	QString bregion = in.mid(n, i - n);
	n = bregion.indexOf(';');
	if(n != -1)
		boundary = bregion.mid(0, n);
	else
		boundary = bregion;

	if(boundary[0] == '\"')
		boundary.remove(0, 1);
	if(boundary[boundary.length() - 1] == '\"')
		boundary.remove(boundary.length() - 1, 1);
	//printf("boundary: [%s]\n", qPrintable(boundary));
	QString boundary_end = QString("--") + boundary;
	boundary = QString("--") + boundary;

	QString work = open_mime_envelope(in);
	//printf("work: [%s]\n", qPrintable(work));

	n = work.indexOf(boundary);
	if(n == -1)
		return false;
	n += boundary.length();
	i = indexOf_newline(work, n);
	if(i == -1)
		return false;
	n += newline_len(work, i);
	int data_start = n;

	n = work.indexOf(boundary, data_start);
	if(n == -1)
		return false;
	int data_end = n;

	n = data_end + boundary.length();
	i = indexOf_newline(work, n);
	if(i == -1)
		return false;
	n += newline_len(work, i);
	int next = n;

	QString tmp_data = work.mid(data_start, data_end - data_start);
	n = work.indexOf(boundary_end, next);
	if(n == -1)
		return false;
	QString tmp_sig = work.mid(next, n - next);

	// nuke some newlines
	if(tmp_data.right(2) == "\r\n")
		tmp_data.truncate(tmp_data.length() - 2);
	else if(tmp_data.right(1) == "\n")
		tmp_data.truncate(tmp_data.length() - 1);
	if(tmp_sig.right(2) == "\r\n")
		tmp_sig.truncate(tmp_sig.length() - 2);
	else if(tmp_sig.right(1) == "\n")
		tmp_sig.truncate(tmp_sig.length() - 1);

	tmp_sig = open_mime_envelope(tmp_sig);

	*data = tmp_data;
	*sig = tmp_sig;
	return true;
}

static QString idHash(const QString &id)
{
	// hash the id and take the rightmost 4 hex characters
	return QCA::Hash("md5").hashToString(id.toUtf8()).right(4);
}

// first = ids, second = names
static QPair<QStringList, QStringList> getKeyStoreStrings(const QStringList &list, QCA::KeyStoreManager *ksm)
{
	QPair<QStringList, QStringList> out;
	for(int n = 0; n < list.count(); ++n)
	{
		QCA::KeyStore ks(list[n], ksm);
		out.first.append(idHash(ks.id()));
		out.second.append(ks.name());
	}
	return out;
}

static QPair<QStringList, QStringList> getKeyStoreEntryStrings(const QList<QCA::KeyStoreEntry> &list)
{
	QPair<QStringList, QStringList> out;
	for(int n = 0; n < list.count(); ++n)
	{
		out.first.append(idHash(list[n].id()));
		out.second.append(list[n].name());
	}
	return out;
}

static QList<int> getPartialMatches(const QStringList &list, const QString &str)
{
	QList<int> out;
	for(int n = 0; n < list.count(); ++n)
	{
		if(list[n].contains(str, Qt::CaseInsensitive))
			out += n;
	}
	return out;
}

static int findByString(const QPair<QStringList, QStringList> &in, const QString &str)
{
	// exact id match
	int n = in.first.indexOf(str);
	if(n != -1)
		return n;

	// partial id match
	QList<int> ret = getPartialMatches(in.first, str);
	if(!ret.isEmpty())
		return ret.first();

	// partial name match
	ret = getPartialMatches(in.second, str);
	if(!ret.isEmpty())
		return ret.first();

	return -1;
}

static QString getKeyStore(const QString &name)
{
	QCA::KeyStoreManager ksm;
	QStringList storeList = ksm.keyStores();
	int n = findByString(getKeyStoreStrings(storeList, &ksm), name);
	if(n != -1)
		return storeList[n];
	return QString();
}

static QCA::KeyStoreEntry getKeyStoreEntry(QCA::KeyStore *store, const QString &name)
{
	QList<QCA::KeyStoreEntry> list = store->entryList();
	int n = findByString(getKeyStoreEntryStrings(list), name);
	if(n != -1)
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

	int n = name.indexOf(':');
	if(n != -1)
	{
		// store:obj lookup
		QString storeName = name.mid(0, n);
		QString objectName = name.mid(n + 1);

		QCA::KeyStoreManager ksm;
		QCA::KeyStore store(getKeyStore(storeName), &ksm);
		if(!store.isValid())
		{
			fprintf(stderr, "Error: no such store [%s].\n", qPrintable(storeName));
			return entry;
		}

		entry = getKeyStoreEntry(&store, objectName);
		if(entry.isNull())
		{
			fprintf(stderr, "Error: no such object [%s].\n", qPrintable(objectName));
			return entry;
		}
	}
	else
	{
		// TODO: users of this function assume objects will also exist

		// exported id
		QString serialized = read_ksentry_file(name);
		entry = QCA::KeyStoreEntry(serialized);
		if(entry.isNull())
		{
			if(!nopassiveerror)
				fprintf(stderr, "Error: invalid/unknown entry [%s].\n", qPrintable(name));
			return entry;
		}
	}

	return entry;
}

static QCA::PrivateKey get_K(const QString &name, const QCA::SecureArray &pass)
{
	QCA::PrivateKey key;

	int n = name.indexOf(':');
	if(n != -1)
	{
		fprintf(stderr, "Error: cannot use store:obj notation for raw private keys.\n");
		return key;
	}

	QCA::ConvertResult result;
	key = QCA::PrivateKey::fromPEMFile(name, pass, &result);
	if(result == QCA::ErrorDecode)
	{
		key = QCA::PrivateKey::fromDER(read_der_file(name), pass);
		if(key.isNull())
		{
			printf("Error: unable to read/process private key file.\n");
			return key;
		}
	}

	return key;
}

static QCA::Certificate get_C(const QString &name)
{
	QCA::KeyStoreEntry entry = get_E(name, true);
	if(!entry.isNull())
	{
		if(entry.type() != QCA::KeyStoreEntry::TypeCertificate)
		{
			printf("Error: entry is not a certificate.\n");
			return QCA::Certificate();
		}
		return entry.certificate();
	}

	// try file
	QCA::Certificate cert = QCA::Certificate::fromPEMFile(name);
	if(cert.isNull())
	{
		cert = QCA::Certificate::fromDER(read_der_file(name));
		if(cert.isNull())
		{
			printf("Error: unable to read/process certificate file.\n");
			return cert;
		}
	}

	return cert;
}

static QCA::KeyBundle get_X(const QString &name)
{
	QCA::KeyStoreEntry entry = get_E(name, true);
	if(!entry.isNull())
	{
		if(entry.type() != QCA::KeyStoreEntry::TypeKeyBundle)
		{
			printf("Error: entry is not a keybundle.\n");
			return QCA::KeyBundle();
		}
		return entry.keyBundle();
	}

	// try file
	// TODO: remove passphrase arg after api update
	QCA::KeyBundle key = QCA::KeyBundle::fromFile(name, QCA::SecureArray());
	if(key.isNull())
	{
		printf("Error: unable to read/process keybundle file.\n");
		return key;
	}

	return key;
}

static QCA::PGPKey get_P(const QString &name)
{
	QCA::PGPKey key;
	QCA::KeyStoreEntry entry = get_E(name);
	if(!entry.isNull())
	{
		if(entry.type() != QCA::KeyStoreEntry::TypePGPPublicKey && entry.type() != QCA::KeyStoreEntry::TypePGPSecretKey)
		{
			printf("Error: entry is not a pgp public key.\n");
			return key;
		}
		return entry.pgpPublicKey();
	}
	return key;
}

static QPair<QCA::PGPKey, QCA::PGPKey> get_S(const QString &name)
{
	QPair<QCA::PGPKey, QCA::PGPKey> key;
	QCA::KeyStoreEntry entry = get_E(name);
	if(!entry.isNull())
	{
		if(entry.type() != QCA::KeyStoreEntry::TypePGPSecretKey)
		{
			printf("Error: entry is not a pgp secret key.\n");
			return key;
		}

		key.first = entry.pgpSecretKey();
		key.second = entry.pgpPublicKey();
		return key;
	}
	return key;
}

static void usage()
{
	printf("qcatool: simple qca utility\n");
	printf("usage: qcatool (options) [command]\n");
	printf(" options: --pass=x, --newpass=x, --nonroots=x, --roots=x, --nosys,\n");
	printf("          --noprompt, --ordered, --debug\n");
	printf("          --log-file=x, --log-level=n\n");
	printf("\n");
	printf(" help|--help|-h                        This help text\n");
	printf(" version|--version|-v                  Print version information\n");
	printf(" plugins                               List available plugins\n");
	printf(" config [command]\n");
	printf("   save [provider]                     Save default provider config\n");
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
	printf("   export [E]                          Export a keystore entry's content\n");
	printf("   exportref [E]                       Export a keystore entry reference\n");
	printf("   addkb [storeName] [cert.p12]        Add a keybundle into a keystore\n");
	printf("   addpgp [storeName] [key.asc]        Add a PGP key into a keystore\n");
	printf("   remove [E]                          Remove an object from a keystore\n");
	printf(" show [command]\n");
	printf("   cert [C]                            Examine a certificate\n");
	printf("   req [req.pem]                       Examine a certificate request (CSR)\n");
	printf("   pgp [P|S]                           Examine a PGP key\n");
	printf(" message [command]\n");
	printf("   sign pgp|pgpdetach|smime [X|S]      Sign a message\n");
	printf("   encrypt pgp|smime [C|P]             Encrypt a message\n");
	printf("   signencrypt [S] [P]                 PGP sign & encrypt a message\n");
	printf("   verify pgp|smime                    Verify a message\n");
	printf("   decrypt pgp|smime (X)               Decrypt a message (S/MIME needs X)\n");
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
	QFile logFile;
	QTextStream logStream (stderr);
	StreamLogger streamLogger (logStream);

	QStringList args;
	for(int n = 1; n < argc; ++n)
		args.append(QString::fromLocal8Bit(argv[n]));

	if(args.count() < 1)
	{
		usage();
		return 1;
	}

	bool have_pass = false;
	bool have_newpass = false;
	QCA::SecureArray pass, newpass;
	bool allowprompt = true;
	bool ordered = false;
	bool debug = false;
	bool nosys = false;
	QString rootsFile, nonRootsFile;

	for(int n = 0; n < args.count(); ++n)
	{
		QString s = args[n];
		if(!s.startsWith("--"))
			continue;
		QString var;
		QString val;
		int x = s.indexOf('=');
		if(x != -1)
		{
			var = s.mid(2, x - 2);
			val = s.mid(x + 1);
		}
		else
		{
			var = s.mid(2);
		}

		bool known = true;

		if(var == "pass")
		{
			have_pass = true;
			pass = val.toUtf8();
		}
		else if(var == "newpass")
		{
			have_newpass = true;
			newpass = val.toUtf8();
		}
		else if(var == "log-file")
		{
			logFile.setFileName (val);
			logFile.open (QIODevice::Append | QIODevice::Text | QIODevice::Unbuffered);
			logStream.setDevice (&logFile);
		}
		else if(var == "log-level")
		{
			QCA::logger ()->setLevel ((QCA::Logger::Severity)val.toInt ());
		}
		else if(var == "noprompt")
			allowprompt = false;
		else if(var == "ordered")
			ordered = true;
		else if(var == "debug")
			debug = true;
		else if(var == "roots")
			rootsFile = val;
		else if(var == "nonroots")
			nonRootsFile = val;
		else if(var == "nosys")
			nosys = true;
		else
			known = false;

		if(known)
		{
			args.removeAt(n);
			--n; // adjust position
		}
	}

	// TODO: instead of printing full usage at every wrong turn, we might
	//       try to print something closer to the context.
	// TODO: use --debug for more stuff besides plugins
	// TODO: support for CRLs somewhere and somehow
	// TODO: ability to show .p12 files without having to extract first?

	// help
	if(args[0] == "help" || args[0] == "--help" || args[0] == "-h")
	{
		usage();
		return 0;
	}

	// version
	if(args[0] == "version" || args[0] == "--version" || args[0] == "-v")
	{
		int ver = qcaVersion();
		int maj = (ver >> 16) & 0xff;
		int min = (ver >> 8) & 0xff;
		int bug = ver & 0xff;
		printf("qcatool version %s by Justin Karneges\n", VERSION);
		printf("Using QCA version %d.%d.%d\n", maj, min, bug);
		return 0;
	}

	// show plugins
	if(args[0] == "plugins")
	{
		printf("Qt Library Paths:\n");
		QStringList paths = QCoreApplication::libraryPaths();
		if(!paths.isEmpty())
		{
			for(int n = 0; n < paths.count(); ++n)
			{
				printf("  %s\n", qPrintable(paths[n]));
			}
		}
		else
			printf("  (none)\n");

		QCA::ProviderList list = QCA::providers();

		if(debug)
		{
			QString str = QCA::pluginDiagnosticText();
			QCA::clearPluginDiagnosticText();
			QStringList lines = str.split('\n', QString::SkipEmptyParts);
			for(int n = 0; n < lines.count(); ++n)
				printf("qca: %s\n", qPrintable(lines[n]));
		}

		printf("Available Providers:\n");
		if(!list.isEmpty())
		{
			for(int n = 0; n < list.count(); ++n)
			{
				printf("  %s\n", qPrintable(list[n]->name()));
				QString credit = list[n]->credit();
				if(!credit.isEmpty())
				{
					QStringList lines = wrapstring(credit, 74);
					foreach(QString s, lines)
						printf("    %s\n", qPrintable(s));
				}
			}
		}
		else
			printf("  (none)\n");

		QCA::unloadAllPlugins();
		if(debug)
		{
			QString str = QCA::pluginDiagnosticText();
			QCA::clearPluginDiagnosticText();
			QStringList lines = str.split('\n', QString::SkipEmptyParts);
			for(int n = 0; n < lines.count(); ++n)
				printf("qca: %s\n", qPrintable(lines[n]));
		}

		return 0;
	}

	// config stuff
	if(args[0] == "config")
	{
		if(args.count() < 2)
		{
			usage();
			return 1;
		}

		if(args[1] == "save")
		{
			if(args.count() < 3)
			{
				usage();
				return 1;
			}

			QString name = args[2];
			if(!QCA::findProvider(name))
			{
				fprintf(stderr, "Error: no such provider '%s'.\n", qPrintable(name));
				return 1;
			}

			QVariantMap map1 = QCA::getProviderConfig(name);
			if(map1.isEmpty())
			{
				fprintf(stderr, "Error: provider does not support configuration.\n");
				return 1;
			}

			// set and save
			QCA::setProviderConfig(name, map1);
			QCA::saveProviderConfig(name);
			printf("Done.\n");
			return 0;
		}
		else
		{
			usage();
			return 1;
		}
	}

	// for all other commands, we set up keystore/prompter:

	// enable console passphrase prompt
	PassphrasePromptThread passphrasePrompt;
	if(!allowprompt)
		passphrasePrompt.pp->allowPrompt = false;
	if(have_pass)
		passphrasePrompt.pp->setExplicitPassword(pass);

	// TODO: don't start the keystores, or at least don't wait
	//   for busy finished for operations that don't need it.  lagggg.

	// activate the KeyStoreManager and block until ready
	QCA::KeyStoreManager::start();
	{
		QCA::KeyStoreManager ksm;
		ksm.waitForBusyFinished();
	}

	// TODO: for each kind of operation, we need to check for support first!!
	if(args[0] == "key")
	{
		if(args.count() < 2)
		{
			usage();
			return 1;
		}

		if(args[1] == "make")
		{
			if(args.count() < 4)
			{
				usage();
				return 1;
			}

			bool genrsa;
			int bits;

			if(args[2] == "rsa")
			{
				genrsa = true;
				bits = args[3].toInt();
				if(bits < 512)
				{
					fprintf(stderr, "Error: RSA bits must be at least 512.\n");
					return 1;
				}
			}
			else if(args[2] == "dsa")
			{
				genrsa = false;
				bits = args[3].toInt();
				if(bits != 512 && bits != 768 && bits != 1024)
				{
					fprintf(stderr, "Error: DSA bits must be 512, 768, or 1024.\n");
					return 1;
				}
			}
			else
			{
				usage();
				return 1;
			}

			if(!allowprompt && !have_newpass)
			{
				fprintf(stderr, "Error: no passphrase specified (use '--newpass=' for none).\n");
				return 1;
			}

			QCA::PrivateKey priv;
			QString pubFileName, privFileName;

			if(genrsa)
			{
				// note: third arg is bogus, doesn't apply to RSA
				priv = AnimatedKeyGen::makeKey(QCA::PKey::RSA, bits, QCA::DSA_512);
				pubFileName = "rsapub.pem";
				privFileName = "rsapriv.pem";
			}
			else // dsa
			{
				QCA::DLGroupSet set;
				if(bits == 512)
					set = QCA::DSA_512;
				else if(bits == 768)
					set = QCA::DSA_768;
				else // 1024
					set = QCA::DSA_1024;

				// note: second arg is bogus, doesn't apply to DSA
				priv = AnimatedKeyGen::makeKey(QCA::PKey::DSA, 0, set);
				pubFileName = "dsapub.pem";
				privFileName = "dsapriv.pem";
			}

			if(priv.isNull())
			{
				fprintf(stderr, "Error: unable to generate key.\n");
				return 1;
			}

			QCA::PublicKey pub = priv.toPublicKey();

			// prompt for new passphrase if necessary
			if(!have_newpass)
			{
				while(!promptForNewPassphrase(&newpass))
				{
				}
				have_newpass = true;
			}

			if(pub.toPEMFile(pubFileName))
				printf("Public key saved to %s\n", qPrintable(pubFileName));
			else
			{
				fprintf(stderr, "Error: can't encode/write %s\n", qPrintable(pubFileName));
				return 1;
			}

			bool ok;
			if(!newpass.isEmpty())
				ok = priv.toPEMFile(privFileName, newpass);
			else
				ok = priv.toPEMFile(privFileName);
			if(ok)
				printf("Private key saved to %s\n", qPrintable(privFileName));
			else
			{
				fprintf(stderr, "Error: can't encode/write %s\n", qPrintable(privFileName));
				return 1;
			}
		}
		else if(args[1] == "changepass")
		{
			if(args.count() < 3)
			{
				usage();
				return 1;
			}

			// TODO: is it weird passing 'pass' here?
			QCA::PrivateKey priv = get_K(args[2], pass);
			if(priv.isNull())
				return 1;

			if(!allowprompt && !have_newpass)
			{
				fprintf(stderr, "Error: no passphrase specified (use '--newpass=' for none).\n");
				return 1;
			}

			// prompt for new passphrase if necessary
			if(!have_newpass)
			{
				while(!promptForNewPassphrase(&newpass))
				{
				}
				have_newpass = true;
			}

			QString out;
			if(!newpass.isEmpty())
				out = priv.toPEM(newpass);
			else
				out = priv.toPEM();
			if(!out.isEmpty())
				printf("%s", qPrintable(out));
			else
			{
				fprintf(stderr, "Error: can't encode key.\n");
				return 1;
			}
		}
		else
		{
			usage();
			return 1;
		}
	}
	else if(args[0] == "cert")
	{
		if(args.count() < 2)
		{
			usage();
			return 1;
		}

		if(args[1] == "makereq" || args[1] == "makereqadv")
		{
			if(args.count() < 3)
			{
				usage();
				return 1;
			}

			// TODO: same as before
			QCA::PrivateKey priv = get_K(args[2], pass);
			if(priv.isNull())
				return 1;

			printf("\n");

			bool advanced = (args[1] == "makereqadv") ? true: false;

			QCA::CertificateOptions opts = promptForCertAttributes(advanced, true);
			QCA::CertificateRequest req(opts, priv);

			QString reqname = "certreq.pem";
			if(req.toPEMFile(reqname))
				printf("Certificate request saved to %s\n", qPrintable(reqname));
			else
			{
				fprintf(stderr, "Error: can't encode/write %s\n", qPrintable(reqname));
				return 1;
			}
		}
		else if(args[1] == "makeself" || args[1] == "makeselfadv")
		{
			if(args.count() < 3)
			{
				usage();
				return 1;
			}

			// TODO: same as before
			QCA::PrivateKey priv = get_K(args[2], pass);
			if(priv.isNull())
				return 1;

			printf("\n");

			bool advanced = (args[1] == "makeselfadv") ? true: false;

			QCA::CertificateOptions opts = promptForCertAttributes(advanced, false);
			QCA::Certificate cert(opts, priv);

			QString certname = "cert.pem";
			if(cert.toPEMFile(certname))
				printf("Certificate saved to %s\n", qPrintable(certname));
			else
			{
				fprintf(stderr, "Error: can't encode/write %s\n", qPrintable(certname));
				return 1;
			}
		}
		else if(args[1] == "validate")
		{
			if(args.count() < 3)
			{
				usage();
				return 1;
			}

			QCA::Certificate target = get_C(args[2]);
			if(target.isNull())
				return 1;

			// get roots
			QCA::CertificateCollection roots;
			if(!nosys)
				roots += QCA::systemStore();
			if(!rootsFile.isEmpty())
				roots += QCA::CertificateCollection::fromFlatTextFile(rootsFile);

			// get nonroots
			QCA::CertificateCollection nonroots;
			if(!nonRootsFile.isEmpty())
				nonroots = QCA::CertificateCollection::fromFlatTextFile(nonRootsFile);

			QCA::Validity v = target.validate(roots, nonroots);
			if(v == QCA::ValidityGood)
				printf("Certificate is valid\n");
			else
			{
				printf("Certificate is NOT valid: %s\n", qPrintable(validityToString(v)));
				return 1;
			}
		}
		else
		{
			usage();
			return 1;
		}
	}
	else if(args[0] == "keybundle")
	{
		if(args.count() < 2)
		{
			usage();
			return 1;
		}

		if(args[1] == "make")
		{
			if(args.count() < 4)
			{
				usage();
				return 1;
			}

			// TODO: same as before
			QCA::PrivateKey priv = get_K(args[2], pass);
			if(priv.isNull())
				return 1;

			QCA::Certificate cert = get_C(args[3]);
			if(cert.isNull())
				return 1;

			// get roots
			QCA::CertificateCollection roots;
			if(!nosys)
				roots += QCA::systemStore();
			if(!rootsFile.isEmpty())
				roots += QCA::CertificateCollection::fromFlatTextFile(rootsFile);

			// get nonroots
			QCA::CertificateCollection nonroots;
			if(!nonRootsFile.isEmpty())
				nonroots = QCA::CertificateCollection::fromFlatTextFile(nonRootsFile);

			QList<QCA::Certificate> issuer_pool = roots.certificates() + nonroots.certificates();

			QCA::CertificateChain chain;
			chain += cert;
			chain = chain.complete(issuer_pool);

			QCA::KeyBundle key;
			key.setName(chain.primary().commonName());
			key.setCertificateChainAndKey(chain, priv);

			if(!allowprompt && !have_newpass)
			{
				fprintf(stderr, "Error: no passphrase specified (use '--newpass=' for none).\n");
				return 1;
			}

			// prompt for new passphrase if necessary
			if(!have_newpass)
			{
				while(!promptForNewPassphrase(&newpass))
				{
				}
				have_newpass = true;
			}

			if(newpass.isEmpty())
			{
				fprintf(stderr, "Error: keybundles cannot have empty passphrases.\n");
				return 1;
			}

			QString newFileName = "cert.p12";

			if(key.toFile(newFileName, newpass))
				printf("Keybundle saved to %s\n", qPrintable(newFileName));
			else
			{
				fprintf(stderr, "Error: can't encode keybundle.\n");
				return 1;
			}
		}
		else if(args[1] == "extract")
		{
			if(args.count() < 3)
			{
				usage();
				return 1;
			}

			QCA::KeyBundle key = get_X(args[2]);
			if(key.isNull())
				return 1;

			QCA::PrivateKey priv = key.privateKey();
			bool export_priv = priv.canExport();

			if(export_priv)
			{
				fprintf(stderr, "You will need to create a passphrase for the extracted private key.\n");

				if(!allowprompt && !have_newpass)
				{
					fprintf(stderr, "Error: no passphrase specified (use '--newpass=' for none).\n");
					return 1;
				}

				// prompt for new passphrase if necessary
				if(!have_newpass)
				{
					while(!promptForNewPassphrase(&newpass))
					{
					}
					have_newpass = true;
				}
			}

			printf("Certs: (first is primary)\n");
			QCA::CertificateChain chain = key.certificateChain();
			for(int n = 0; n < chain.count(); ++n)
				printf("%s", qPrintable(chain[n].toPEM()));
			printf("Private Key:\n");
			if(export_priv)
			{
				QString out;
				if(!newpass.isEmpty())
					out = priv.toPEM(newpass);
				else
					out = priv.toPEM();
				printf("%s", qPrintable(out));
			}
			else
			{
				printf("(Key is not exportable)\n");
			}
		}
		else if(args[1] == "changepass")
		{
			if(args.count() < 3)
			{
				usage();
				return 1;
			}

			QCA::KeyBundle key = get_X(args[2]);
			if(key.isNull())
				return 1;

			if(!key.privateKey().canExport())
			{
				fprintf(stderr, "Error: private key not exportable.\n");
				return 1;
			}

			if(!allowprompt && !have_newpass)
			{
				fprintf(stderr, "Error: no passphrase specified (use '--newpass=' for none).\n");
				return 1;
			}

			// prompt for new passphrase if necessary
			if(!have_newpass)
			{
				while(!promptForNewPassphrase(&newpass))
				{
				}
				have_newpass = true;
			}

			if(newpass.isEmpty())
			{
				fprintf(stderr, "Error: keybundles cannot have empty passphrases.\n");
				return 1;
			}

			QFileInfo fi(args[2]);
			QString newFileName = fi.baseName() + "_new.p12";

			if(key.toFile(newFileName, newpass))
				printf("Keybundle saved to %s\n", qPrintable(newFileName));
			else
			{
				fprintf(stderr, "Error: can't encode keybundle.\n");
				return 1;
			}
		}
		else
		{
			usage();
			return 1;
		}
	}
	else if(args[0] == "keystore")
	{
		if(args.count() < 2)
		{
			usage();
			return 1;
		}

		if(args[1] == "list-stores")
		{
			QCA::KeyStoreManager ksm;
			QStringList storeList = ksm.keyStores();

			// find longest id
			int longest_id = -1;
			for(int n = 0; n < storeList.count(); ++n)
			{
				if(longest_id == -1 || storeList[n].length() > longest_id)
					longest_id = storeList[n].length();
			}

			for(int n = 0; n < storeList.count(); ++n)
			{
				QCA::KeyStore ks(storeList[n], &ksm);
				QString type = kstype_to_string(ks.type());

				// give all ids the same width
				/*QString id = ks.id();
				QString str;
				str.fill(' ', longest_id);
				str.replace(0, id.length(), id);*/

				printf("%s %s [%s]\n", qPrintable(type), qPrintable(idHash(ks.id())), qPrintable(ks.name()));
			}
		}
		else if(args[1] == "list")
		{
			if(args.count() < 3)
			{
				usage();
				return 1;
			}

			QCA::KeyStoreManager ksm;
			QCA::KeyStore store(getKeyStore(args[2]), &ksm);
			if(!store.isValid())
			{
				fprintf(stderr, "Error: no such store\n");
				return 1;
			}

			QList<QCA::KeyStoreEntry> list = store.entryList();
			for(int n = 0; n < list.count(); ++n)
			{
				QCA::KeyStoreEntry i = list[n];
				QString type = ksentrytype_to_string(i.type());
				printf("%s %s [%s]\n", qPrintable(type), qPrintable(idHash(i.id())), qPrintable(i.name()));
			}
		}
		else if(args[1] == "export")
		{
			if(args.count() < 3)
			{
				usage();
				return 1;
			}

			QCA::KeyStoreEntry entry = get_E(args[2]);
			if(entry.isNull())
				return 1;

			if(entry.type() == QCA::KeyStoreEntry::TypeCertificate)
				printf("%s", qPrintable(entry.certificate().toPEM()));
			else if(entry.type() == QCA::KeyStoreEntry::TypeCRL)
				printf("%s", qPrintable(entry.crl().toPEM()));
			else if(entry.type() == QCA::KeyStoreEntry::TypePGPPublicKey || entry.type() == QCA::KeyStoreEntry::TypePGPSecretKey)
				printf("%s", qPrintable(entry.pgpPublicKey().toString()));
			else if(entry.type() == QCA::KeyStoreEntry::TypeKeyBundle)
				fprintf(stderr, "Error: use 'keybundle extract' command instead.\n");
			else
				fprintf(stderr, "Error: cannot export type '%d'.\n", entry.type());
		}
		else if(args[1] == "exportref")
		{
			if(args.count() < 3)
			{
				usage();
				return 1;
			}

			QCA::KeyStoreEntry entry = get_E(args[2]);
			if(entry.isNull())
				return 1;
			printf("%s", make_ksentry_string(entry.toString()).toUtf8().data());
		}
		else if(args[1] == "addkb")
		{
			if(args.count() < 4)
			{
				usage();
				return 1;
			}

			QCA::KeyStoreManager ksm;
			QCA::KeyStore store(getKeyStore(args[2]), &ksm);
			if(!store.isValid())
			{
				fprintf(stderr, "Error: no such store\n");
				return 1;
			}

			QCA::Certificate cert = get_C(args[3]);
			if(cert.isNull())
				return 1;

			if(!store.writeEntry(cert).isEmpty())
				printf("Entry written.\n");
			else
			{
				fprintf(stderr, "Error: unable to write entry.\n");
				return 1;
			}
		}
		else if(args[1] == "addpgp")
		{
			if(args.count() < 4)
			{
				usage();
				return 1;
			}

			QCA::KeyStoreManager ksm;
			QCA::KeyStore store(getKeyStore(args[2]), &ksm);
			if(!store.isValid())
			{
				fprintf(stderr, "Error: no such store\n");
				return 1;
			}

			QCA::PGPKey pub = QCA::PGPKey::fromFile(args[3]);
			if(pub.isNull())
				return 1;

			if(!store.writeEntry(pub).isEmpty())
				printf("Entry written.\n");
			else
			{
				fprintf(stderr, "Error: unable to write entry.\n");
				return 1;
			}
		}
		else if(args[1] == "remove")
		{
			if(args.count() < 3)
			{
				usage();
				return 1;
			}

			QCA::KeyStoreEntry entry = get_E(args[2]);
			if(entry.isNull())
				return 1;

			QCA::KeyStoreManager ksm;
			QCA::KeyStore store(entry.storeId(), &ksm);
			if(!store.isValid())
			{
				fprintf(stderr, "Error: no such store\n");
				return 1;
			}

			if(store.removeEntry(entry.id()))
				printf("Entry removed.\n");
			else
			{
				fprintf(stderr, "Error: unable to remove entry.\n");
				return 1;
			}
		}
		else
		{
			usage();
			return 1;
		}
	}
	else if(args[0] == "show")
	{
		if(args.count() < 2)
		{
			usage();
			return 1;
		}

		if(args[1] == "cert")
		{
			if(args.count() < 3)
			{
				usage();
				return 1;
			}

			QCA::Certificate cert = get_C(args[2]);
			if(cert.isNull())
				return 1;

			print_cert(cert, ordered);
		}
		else if(args[1] == "req")
		{
			if(args.count() < 3)
			{
				usage();
				return 1;
			}

			QCA::CertificateRequest req(args[2]);
			if(req.isNull())
			{
				fprintf(stderr, "Error: can't read/decode certificate request file.\n");
				return 1;
			}

			print_certreq(req, ordered);
		}
		else if(args[1] == "pgp")
		{
			if(args.count() < 3)
			{
				usage();
				return 1;
			}

			// FIXME: isSecret will always print false here
			QCA::PGPKey pub = get_P(args[2]);
			if(pub.isNull())
				return 1;

			print_pgp(pub);
		}
		else
		{
			usage();
			return 1;
		}
	}
	else if(args[0] == "message")
	{
		if(args.count() < 2)
		{
			usage();
			return 1;
		}

		if(args[1] == "sign")
		{
			if(args.count() < 4)
			{
				usage();
				return 1;
			}

			QCA::SecureMessageSystem *sms;
			QCA::SecureMessageKey skey;
			QCA::SecureMessage::SignMode mode;
			bool pgp = false;

			if(args[2] == "pgp")
			{
				QPair<QCA::PGPKey, QCA::PGPKey> key = get_S(args[3]);
				if(key.first.isNull())
					return 1;

				sms = new QCA::OpenPGP;
				skey.setPGPSecretKey(key.first);
				mode = QCA::SecureMessage::Clearsign;
				pgp = true;
			}
			else if(args[2] == "pgpdetach")
			{
				QPair<QCA::PGPKey, QCA::PGPKey> key = get_S(args[3]);
				if(key.first.isNull())
					return 1;

				sms = new QCA::OpenPGP;
				skey.setPGPSecretKey(key.first);
				mode = QCA::SecureMessage::Detached;
				pgp = true;
			}
			else if(args[2] == "smime")
			{
				QCA::KeyBundle key = get_X(args[3]);
				if(key.isNull())
					return 1;

				// get nonroots
				QCA::CertificateCollection nonroots;
				if(!nonRootsFile.isEmpty())
					nonroots = QCA::CertificateCollection::fromFlatTextFile(nonRootsFile);

				QList<QCA::Certificate> issuer_pool = nonroots.certificates();

				QCA::CertificateChain chain = key.certificateChain();
				chain = chain.complete(issuer_pool);

				sms = new QCA::CMS;
				skey.setX509CertificateChain(chain);
				skey.setX509PrivateKey(key.privateKey());
				mode = QCA::SecureMessage::Detached;
			}
			else
			{
				usage();
				return 1;
			}

			// TODO: support streaming someday ?  we need support in
			//   the provider as well as our smime envelope stuff

			// read input data from stdin all at once
			QByteArray plain;
			while(!feof(stdin))
			{
				QByteArray block(1024, 0);
				int n = fread(block.data(), 1, 1024, stdin);
				if(n < 0)
					break;
				block.resize(n);
				plain += block;
			}

			// smime envelope
			if(!pgp)
			{
				QString text = add_cr(QString::fromUtf8(plain));
				plain = QString(mime_signpart).arg(text).toUtf8();
			}

			QCA::SecureMessage *msg = new QCA::SecureMessage(sms);
			msg->setSigner(skey);
			// pgp should always be ascii
			if(pgp)
				msg->setFormat(QCA::SecureMessage::Ascii);
			msg->startSign(mode);
			msg->update(plain);
			msg->end();
			msg->waitForFinished(-1);

			if(!msg->success())
			{
				QString errstr = smErrorToString(msg->errorCode());
				delete msg;
				delete sms;
				fprintf(stderr, "Error: unable to sign: %s\n", qPrintable(errstr));
				return 1;
			}

			QString hashName = msg->hashName();

			QByteArray output;
			if(mode == QCA::SecureMessage::Detached)
				output = msg->signature();
			else
				output = msg->read();

			delete msg;
			delete sms;

			// smime envelope
			if(!pgp)
			{
				QCA::Base64 enc;
				enc.setLineBreaksEnabled(true);
				enc.setLineBreaksColumn(76);
				QString sigtext = add_cr(enc.arrayToString(output));
				QString str = QString(mime_signed).arg(hashName).arg(QString::fromUtf8(plain)).arg(sigtext);
				output = str.toUtf8();
			}

			printf("%s", output.data());
		}
		else if(args[1] == "encrypt")
		{
			if(args.count() < 4)
			{
				usage();
				return 1;
			}

			QCA::SecureMessageSystem *sms;
			QCA::SecureMessageKey skey;
			bool pgp = false;

			if(args[2] == "pgp")
			{
				QCA::PGPKey key = get_P(args[3]);
				if(key.isNull())
					return 1;

				sms = new QCA::OpenPGP;
				skey.setPGPPublicKey(key);
				pgp = true;
			}
			else if(args[2] == "smime")
			{
				QCA::Certificate cert = get_C(args[3]);
				if(cert.isNull())
					return 1;

				sms = new QCA::CMS;
				skey.setX509CertificateChain(cert);
			}
			else
			{
				usage();
				return 1;
			}

			// read input data from stdin all at once
			QByteArray plain;
			while(!feof(stdin))
			{
				QByteArray block(1024, 0);
				int n = fread(block.data(), 1, 1024, stdin);
				if(n < 0)
					break;
				block.resize(n);
				plain += block;
			}

			QCA::SecureMessage *msg = new QCA::SecureMessage(sms);
			msg->setRecipient(skey);
			// pgp should always be ascii
			if(pgp)
				msg->setFormat(QCA::SecureMessage::Ascii);
			msg->startEncrypt();
			msg->update(plain);
			msg->end();
			msg->waitForFinished(-1);

			if(!msg->success())
			{
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
			if(!pgp)
			{
				QCA::Base64 enc;
				enc.setLineBreaksEnabled(true);
				enc.setLineBreaksColumn(76);
				QString enctext = add_cr(enc.arrayToString(output));
				QString str = QString(mime_enveloped).arg(enctext);
				output = str.toUtf8();
			}

			printf("%s", output.data());
		}
		else if(args[1] == "signencrypt")
		{
			if(args.count() < 4)
			{
				usage();
				return 1;
			}

			QCA::SecureMessageSystem *sms;
			QCA::SecureMessageKey skey;
			QCA::SecureMessageKey rkey;

			{
				QPair<QCA::PGPKey,QCA::PGPKey> sec = get_S(args[2]);
				if(sec.first.isNull())
					return 1;

				QCA::PGPKey pub = get_P(args[3]);
				if(pub.isNull())
					return 1;

				sms = new QCA::OpenPGP;
				skey.setPGPSecretKey(sec.first);
				rkey.setPGPPublicKey(pub);
			}

			// read input data from stdin all at once
			QByteArray plain;
			while(!feof(stdin))
			{
				QByteArray block(1024, 0);
				int n = fread(block.data(), 1, 1024, stdin);
				if(n < 0)
					break;
				block.resize(n);
				plain += block;
			}

			QCA::SecureMessage *msg = new QCA::SecureMessage(sms);
			if(!msg->canSignAndEncrypt())
			{
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

			if(!msg->success())
			{
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
		}
		else if(args[1] == "verify")
		{
			if(args.count() < 3)
			{
				usage();
				return 1;
			}

			// TODO: CMS: allow verifying with --nonroots, in case the message
			//       doesn't have the issuers in it. (also allow verifying if
			//       if there is no cert at all (have to specify possible certs then)).

			QCA::SecureMessageSystem *sms;
			bool pgp = false;

			if(args[2] == "pgp")
			{
				sms = new QCA::OpenPGP;
				pgp = true;
			}
			else if(args[2] == "smime")
			{
				// get roots
				QCA::CertificateCollection roots;
				if(!nosys)
					roots += QCA::systemStore();
				if(!rootsFile.isEmpty())
					roots += QCA::CertificateCollection::fromFlatTextFile(rootsFile);

				sms = new QCA::CMS;
				((QCA::CMS *)sms)->setTrustedCertificates(roots);
			}
			else
			{
				usage();
				return 1;
			}

			QByteArray data, sig;
			QString smime_text;
			{
				// read input data from stdin all at once
				QByteArray plain;
				while(!feof(stdin))
				{
					QByteArray block(1024, 0);
					int n = fread(block.data(), 1, 1024, stdin);
					if(n < 0)
						break;
					block.resize(n);
					plain += block;
				}

				if(pgp)
				{
					// TODO: ensure the plugin actually outputs the signed data

					// pgp can be either a detached signature followed
					//  by data, or an integrated message.

					// detached signature?
					if(plain.startsWith("-----BEGIN PGP SIGNATURE-----"))
					{
						QString footer = "-----END PGP SIGNATURE-----\n";
						int n = plain.indexOf(footer);
						if(n == -1)
						{
							delete sms;
							fprintf(stderr, "Error: pgp signature header, but no footer.\n");
							return 1;
						}

						n += footer.length();
						sig = plain.mid(0, n);
						data = plain.mid(n);
					}
					else
					{
						data = plain;
					}
				}
				else
				{
					// smime envelope
					QString in = QString::fromUtf8(plain);
					in = add_cr(in); // change the line endings?!
					QString str, sigtext;
					if(!open_mime_data_sig(in, &str, &sigtext))
					{
						fprintf(stderr, "Error: can't parse message file.\n");
						return 1;
					}

					data = str.toUtf8();
					smime_text = str;

					QCA::Base64 dec;
					dec.setLineBreaksEnabled(true);
					sig = dec.stringToArray(rem_cr(sigtext)).toByteArray();
				}
			}

			QCA::SecureMessage *msg = new QCA::SecureMessage(sms);
			if(pgp)
				msg->setFormat(QCA::SecureMessage::Ascii);
			msg->startVerify(sig);
			msg->update(data);
			msg->end();
			msg->waitForFinished(-1);

			if(!msg->success())
			{
				QString errstr = smErrorToString(msg->errorCode());
				delete msg;
				delete sms;
				fprintf(stderr, "Error: verify failed: %s\n", qPrintable(errstr));
				return 1;
			}

			QByteArray output;
			if(pgp && sig.isEmpty())
				output = msg->read();

			// TODO: support multiple signers?

			QCA::SecureMessageSignature signer = msg->signer();
			QCA::SecureMessageSignature::IdentityResult r = signer.identityResult();
			delete msg;
			delete sms;

			// for pgp clearsign, pgp signed (non-detached), and smime,
			//   the signed content was inside of the message.  we need
			//   to print that content now
			if(pgp)
			{
				printf("%s", output.data());
			}
			else
			{
				QString str = open_mime_envelope(smime_text);
				printf("%s", str.toUtf8().data());
			}

			QString rs;
			if(r == QCA::SecureMessageSignature::Valid)
				rs = "Valid";
			else if(r == QCA::SecureMessageSignature::InvalidSignature)
				rs = "InvalidSignature";
			else if(r == QCA::SecureMessageSignature::InvalidKey)
				rs = "InvalidKey";
			else if(r == QCA::SecureMessageSignature::NoKey)
				rs = "NoKey";
			fprintf(stderr, "IdentityResult: %s\n", qPrintable(rs));

			QCA::SecureMessageKey key = signer.key();
			if(!key.isNull())
			{
				if(pgp)
				{
					QCA::PGPKey pub = key.pgpPublicKey();
					fprintf(stderr, "From: %s (%s)\n", qPrintable(pub.primaryUserId()), qPrintable(pub.keyId()));
				}
				else
				{
					QCA::Certificate cert = key.x509CertificateChain().primary();
					QString emailStr;
					QCA::CertificateInfo info = cert.subjectInfo();
					if(info.contains(QCA::Email))
						emailStr = QString(" (%1)").arg(info.value(QCA::Email));
					fprintf(stderr, "From: %s%s\n", qPrintable(cert.commonName()), qPrintable(emailStr));
				}
			}
		}
		else if(args[1] == "decrypt")
		{
			if(args.count() < 3)
			{
				usage();
				return 1;
			}

			QCA::SecureMessageSystem *sms;
			QCA::SecureMessageKey skey;
			bool pgp = false;

			if(args[2] == "pgp")
			{
				sms = new QCA::OpenPGP;
				pgp = true;
			}
			else if(args[2] == "smime")
			{
				if(args.count() < 4)
				{
					usage();
					return 1;
				}

				QCA::KeyBundle key = get_X(args[3]);
				if(key.isNull())
					return 1;

				sms = new QCA::CMS;
				skey.setX509CertificateChain(key.certificateChain());
				skey.setX509PrivateKey(key.privateKey());

				// TODO: support more than one decrypt key
				((QCA::CMS*)sms)->setPrivateKeys(QCA::SecureMessageKeyList() << skey);
			}
			else
			{
				usage();
				return 1;
			}

			// read input data from stdin all at once
			QByteArray plain;
			while(!feof(stdin))
			{
				QByteArray block(1024, 0);
				int n = fread(block.data(), 1, 1024, stdin);
				if(n < 0)
					break;
				block.resize(n);
				plain += block;
			}

			// smime envelope
			if(!pgp)
			{
				QString in = QString::fromUtf8(plain);
				QString str = open_mime_envelope(in);
				if(str.isEmpty())
				{
					delete sms;
					fprintf(stderr, "Error: can't parse message file.\n");
					return 1;
				}

				QCA::Base64 dec;
				dec.setLineBreaksEnabled(true);
				plain = dec.stringToArray(rem_cr(str)).toByteArray();
			}

			QCA::SecureMessage *msg = new QCA::SecureMessage(sms);
			if(pgp)
				msg->setFormat(QCA::SecureMessage::Ascii);
			msg->startDecrypt();
			msg->update(plain);
			msg->end();
			msg->waitForFinished(-1);

			if(!msg->success())
			{
				QString errstr = smErrorToString(msg->errorCode());
				delete msg;
				delete sms;
				fprintf(stderr, "Error: decrypt failed: %s\n", qPrintable(errstr));
				return 1;
			}

			QByteArray output = msg->read();

			// TODO: support multiple signers?

			QCA::SecureMessageSignature signer;
			bool wasSigned = false;
			if(msg->wasSigned())
			{
				signer = msg->signer();
				wasSigned = true;
			}
			delete msg;
			delete sms;

			printf("%s", output.data());

			if(wasSigned)
			{
				fprintf(stderr, "Message was also signed:\n");

				QCA::SecureMessageSignature::IdentityResult r = signer.identityResult();
				QString rs;
				if(r == QCA::SecureMessageSignature::Valid)
					rs = "Valid";
				else if(r == QCA::SecureMessageSignature::InvalidSignature)
					rs = "InvalidSignature";
				else if(r == QCA::SecureMessageSignature::InvalidKey)
					rs = "InvalidKey";
				else if(r == QCA::SecureMessageSignature::NoKey)
					rs = "NoKey";
				fprintf(stderr, "IdentityResult: %s\n", qPrintable(rs));

				QCA::SecureMessageKey key = signer.key();
				if(!key.isNull())
				{
					QCA::PGPKey pub = key.pgpPublicKey();
					fprintf(stderr, "From: %s (%s)\n", qPrintable(pub.primaryUserId()), qPrintable(pub.keyId()));
				}
			}
		}
		else if(args[1] == "exportcerts")
		{
			// TODO: can we do this with PKCS7 (certcollection) rather than smime verify?
			QCA::SecureMessageSystem *sms;

			// get roots
			QCA::CertificateCollection roots;
			if(!nosys)
				roots += QCA::systemStore();
			if(!rootsFile.isEmpty())
				roots += QCA::CertificateCollection::fromFlatTextFile(rootsFile);

			sms = new QCA::CMS;
			((QCA::CMS *)sms)->setTrustedCertificates(roots);

			QByteArray data, sig;
			QString smime_text;
			{
				// read input data from stdin all at once
				QByteArray plain;
				while(!feof(stdin))
				{
					QByteArray block(1024, 0);
					int n = fread(block.data(), 1, 1024, stdin);
					if(n < 0)
						break;
					block.resize(n);
					plain += block;
				}

				// smime envelope
				QString in = QString::fromUtf8(plain);
				QString str, sigtext;
				if(!open_mime_data_sig(in, &str, &sigtext))
				{
					delete sms;
					fprintf(stderr, "Error: can't parse message file.\n");
					return 1;
				}

				data = str.toUtf8();
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

			if(!msg->success())
			{
				QString errstr = smErrorToString(msg->errorCode());
				delete msg;
				delete sms;
				// TODO: wrong error message for export
				fprintf(stderr, "Error: verify failed: %s\n", qPrintable(errstr));
				return 1;
			}

			// TODO: support multiple signers?

			QCA::SecureMessageSignature signer = msg->signer();
			delete msg;
			delete sms;

			QCA::SecureMessageKey key = signer.key();
			if(!key.isNull())
			{
				foreach(const QCA::Certificate &c, key.x509CertificateChain())
					printf("%s", qPrintable(c.toPEM()));
			}
		}
		else
		{
			usage();
			return 1;
		}
	}
	else
	{
		usage();
		return 1;
	}

	return 0;
}

#include "main.moc"
