/*
 Copyright (C) 2007 Justin Karneges <justin@affinix.com>

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
 AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "certviewdlg.h"

#include <QtCore>
#include <QtGui>
#include <QtCrypto>
#include "ui_certview.h"

// from qcatool
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

	InfoType(QCA::CertificateInfoType _type, const QString &_varname, const QString &_shortname, const QString &_name, const QString &_desc) :
		type(_type),
		varname(_varname),
		shortname(_shortname),
		name(_name),
		desc(_desc)
	{
	}
};

static QList<InfoType> makeInfoTypeList(bool legacyEmail = false)
{
	QList<InfoType> out;
	out += InfoType(QCA::CommonName,             "CommonName",             "CN",  CertViewDlg::tr("Common Name (CN)"),          "Full name, domain, anything");
	out += InfoType(QCA::Email,                  "Email",                  "",    CertViewDlg::tr("Email Address"),             "");
	if(legacyEmail)
		out += InfoType(QCA::EmailLegacy,            "EmailLegacy",       "",    CertViewDlg::tr("PKCS#9 Email Address"),      "");
	out += InfoType(QCA::Organization,           "Organization",           "O",   CertViewDlg::tr("Organization (O)"),          "Company, group, etc");
	out += InfoType(QCA::OrganizationalUnit,     "OrganizationalUnit",     "OU",  CertViewDlg::tr("Organizational Unit (OU)"),  "Division/branch of organization");
	out += InfoType(QCA::Locality,               "Locality",               "",    CertViewDlg::tr("Locality (L)"),              "City, shire, part of a state");
	out += InfoType(QCA::State,                  "State",                  "",    CertViewDlg::tr("State (ST)"),                "State within the country");
	out += InfoType(QCA::Country,                "Country",                "C",   CertViewDlg::tr("Country Code (C)"),          "2-letter code");
	out += InfoType(QCA::IncorporationLocality,  "IncorporationLocality",  "",    CertViewDlg::tr("Incorporation Locality"),    "For EV certificates");
	out += InfoType(QCA::IncorporationState,     "IncorporationState",     "",    CertViewDlg::tr("Incorporation State"),       "For EV certificates");
	out += InfoType(QCA::IncorporationCountry,   "IncorporationCountry",   "",    CertViewDlg::tr("Incorporation Country"),     "For EV certificates");
	out += InfoType(QCA::URI,                    "URI",                    "",    CertViewDlg::tr("URI"),                       "");
	out += InfoType(QCA::DNS,                    "DNS",                    "",    CertViewDlg::tr("Domain Name"),               "Domain (dnsName)");
	out += InfoType(QCA::IPAddress,              "IPAddress",              "",    CertViewDlg::tr("IP Adddress"),               "");
	out += InfoType(QCA::XMPP,                   "XMPP",                   "",    CertViewDlg::tr("XMPP Address (JID)"),        "From RFC 3920 (id-on-xmppAddr)");
	return out;
}

static QString try_print_info(const QString &name, const QStringList &values)
{
	QString out;
	if(!values.isEmpty())
	{
		QString value = values.join(", ");
		out = QString("   ") + CertViewDlg::tr("%1: %2").arg(name, value) + '\n';
	}
	return out;
}

static QString print_info(const QString &title, const QCA::CertificateInfo &info)
{
	QString out;
	QList<InfoType> list = makeInfoTypeList();
	out += title + '\n';
	foreach(const InfoType &t, list)
		out += try_print_info(t.name, info.values(t.type));
	return out;
}

static QString cert_info_string(const QCA::Certificate &cert)
{
	QString out;
	out += CertViewDlg::tr("Serial Number: %1").arg(cert.serialNumber().toString()) + '\n';
	out += print_info(CertViewDlg::tr("Subject"), cert.subjectInfo());
	out += print_info(CertViewDlg::tr("Issuer"), cert.issuerInfo());
	out += CertViewDlg::tr("Validity") + '\n';
	out += QString("   ") + CertViewDlg::tr("Not before: %1").arg(cert.notValidBefore().toString()) + '\n';
	out += QString("   ") + CertViewDlg::tr("Not after:  %1").arg(cert.notValidAfter().toString()) + '\n';
	return out;
}

class CertViewDlg::Private : public QObject
{
	Q_OBJECT
public:
	CertViewDlg *q;
	Ui_CertView ui;
	QCA::CertificateChain chain;

	Private(CertViewDlg *_q) :
		QObject(_q),
		q(_q)
	{
		ui.setupUi(q);
		connect(ui.cb_chain, SIGNAL(activated(int)), SLOT(cb_activated(int)));
		ui.lb_info->setTextInteractionFlags(Qt::TextSelectableByMouse);
	}

	void update()
	{
		QStringList names = QCA::makeFriendlyNames(chain);
		ui.cb_chain->clear();
		foreach(const QString &s, names)
			ui.cb_chain->insertItem(ui.cb_chain->count(), s);
		updateInfo();
	}

	void updateInfo()
	{
		int x = ui.cb_chain->currentIndex();
		if(x == -1)
		{
			ui.lb_info->setText("");
			return;
		}

		ui.lb_info->setText(cert_info_string(chain[x]));
	}

private slots:
	void cb_activated(int)
	{
		updateInfo();
	}
};

CertViewDlg::CertViewDlg(const QCA::CertificateChain &chain, QWidget *parent) :
	QDialog(parent)
{
	d = new Private(this);
	d->chain = chain;
	d->update();
}

CertViewDlg::~CertViewDlg()
{
	delete d;
}

#include "certviewdlg.moc"
