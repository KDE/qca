/*
 * qca_cert.cpp - Qt Cryptographic Architecture
 * Copyright (C) 2003-2005  Justin Karneges <justin@affinix.com>
 * Copyright (C) 2004,2005  Brad Hards <bradh@frogmouth.net>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "qca_cert.h"

#include <QtCore>
#include "qca_publickey.h"
#include "qcaprovider.h"

namespace QCA {

Provider::Context *getContext(const QString &type, const QString &provider);

static bool stringToFile(const QString &fileName, const QString &content)
{
	QFile f(fileName);
	if(!f.open(QFile::WriteOnly))
		return false;
	QTextStream ts(&f);
	ts << content;
	return true;
}

static bool stringFromFile(const QString &fileName, QString *s)
{
	QFile f(fileName);
	if(!f.open(QFile::ReadOnly))
		return false;
	QTextStream ts(&f);
	*s = ts.readAll();
	return true;
}

static bool arrayToFile(const QString &fileName, const QByteArray &content)
{
	QFile f(fileName);
	if(!f.open(QFile::WriteOnly))
		return false;
	f.write(content.data(), content.size());
	return true;
}

static bool arrayFromFile(const QString &fileName, QByteArray *a)
{
	QFile f(fileName);
	if(!f.open(QFile::ReadOnly))
		return false;
	*a = f.readAll();
	return true;
}

//----------------------------------------------------------------------------
// CertificateOptions
//----------------------------------------------------------------------------
class CertificateOptions::Private
{
public:
	CertificateRequestFormat format;

	QString challenge;
	CertificateInfo info;
	Constraints constraints;
	QStringList policies;
	bool isCA;
	int pathLimit;
	QBigInteger serial;
	QDateTime start, end;

	Private() : isCA(false), pathLimit(-1)
	{
	}
};

CertificateOptions::CertificateOptions(CertificateRequestFormat f)
{
	d = new Private;
	d->format = f;
}

CertificateOptions::CertificateOptions(const CertificateOptions &from)
{
	d = new Private(*from.d);
}

CertificateOptions::~CertificateOptions()
{
	delete d;
}

CertificateOptions & CertificateOptions::operator=(const CertificateOptions &from)
{
	*d = *from.d;
	return *this;
}

CertificateRequestFormat CertificateOptions::format() const
{
	return d->format;
}

void CertificateOptions::setFormat(CertificateRequestFormat f)
{
	d->format = f;
}

bool CertificateOptions::isValid() const
{
	// TODO: check the content
	return false;
}

QString CertificateOptions::challenge() const
{
	return d->challenge;
}

CertificateInfo CertificateOptions::info() const
{
	return d->info;
}

Constraints CertificateOptions::constraints() const
{
	return d->constraints;
}

QStringList CertificateOptions::policies() const
{
	return d->policies;
}

bool CertificateOptions::isCA() const
{
	return d->isCA;
}

int CertificateOptions::pathLimit() const
{
	return d->pathLimit;
}

QBigInteger CertificateOptions::serialNumber() const
{
	return d->serial;
}

QDateTime CertificateOptions::notValidBefore() const
{
	return d->start;
}

QDateTime CertificateOptions::notValidAfter() const
{
	return d->end;
}

void CertificateOptions::setChallenge(const QString &s)
{
	d->challenge = s;
}

void CertificateOptions::setInfo(const CertificateInfo &info)
{
	d->info = info;
}

void CertificateOptions::setConstraints(const Constraints &constraints)
{
	d->constraints = constraints;
}

void CertificateOptions::setPolicies(const QStringList &policies)
{
	d->policies = policies;
}

void CertificateOptions::setAsCA(int pathLimit)
{
	d->isCA = true;
	d->pathLimit = pathLimit;
}

void CertificateOptions::setSerialNumber(const QBigInteger &i)
{
	d->serial = i;
}

void CertificateOptions::setValidityPeriod(const QDateTime &start, const QDateTime &end)
{
	d->start = start;
	d->end = end;
}

//----------------------------------------------------------------------------
// Certificate
//----------------------------------------------------------------------------
// (adapted from kdelibs) -- Justin
static bool cnMatchesAddress(const QString &_cn, const QString &peerHost)
{
	QString cn = _cn.trimmed().toLower();
	QRegExp rx;

	// Check for invalid characters
	if(QRegExp("[^a-zA-Z0-9\\.\\*\\-]").indexIn(cn) >= 0)
		return false;

	// Domains can legally end with '.'s.  We don't need them though.
	while(cn.endsWith("."))
		cn.truncate(cn.length()-1);

	// Do not let empty CN's get by!!
	if(cn.isEmpty())
		return false;

	// Check for IPv4 address
	rx.setPattern("[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}");
	if(rx.exactMatch(peerHost))
		return peerHost == cn;

	// Check for IPv6 address here...
	rx.setPattern("^\\[.*\\]$");
	if(rx.exactMatch(peerHost))
		return peerHost == cn;

	if(cn.contains('*'))
	{
		// First make sure that there are at least two valid parts
		// after the wildcard (*).
		QStringList parts = cn.split('.', QString::SkipEmptyParts);

		while(parts.count() > 2)
			parts.removeFirst();

		if(parts.count() != 2)
			return false;  // we don't allow *.root - that's bad

		if(parts[0].contains('*') || parts[1].contains('*'))
			return false;

		// RFC2818 says that *.example.com should match against
		// foo.example.com but not bar.foo.example.com
		// (ie. they must have the same number of parts)
		if(QRegExp(cn, Qt::CaseInsensitive, QRegExp::Wildcard).exactMatch(peerHost) &&
			cn.split('.', QString::SkipEmptyParts).count() ==
			peerHost.split('.', QString::SkipEmptyParts).count())
			return true;

		return false;
	}

	// We must have an exact match in this case (insensitive though)
	// (note we already did .lower())
	if(cn == peerHost)
		return true;
	return false;
}

Certificate::Certificate()
{
}

Certificate::Certificate(const QString &fileName)
{
	*this = fromPEMFile(fileName, 0, QString());
}

Certificate::Certificate(const CertificateOptions &opts, const PrivateKey &key, const QString &provider)
{
	CertContext *c = static_cast<CertContext *>(getContext("cert", provider));
	if(c->createSelfSigned(opts, *(static_cast<const PKeyContext *>(key.context()))))
		change(c);
	else
		delete c;
}

bool Certificate::isNull() const
{
	return (!context() ? true : false);
}

QDateTime Certificate::notValidBefore() const
{
	return static_cast<const CertContext *>(context())->props()->start;
}

QDateTime Certificate::notValidAfter() const
{
	return static_cast<const CertContext *>(context())->props()->end;
}

CertificateInfo Certificate::subjectInfo() const
{
	return static_cast<const CertContext *>(context())->props()->subject;
}

CertificateInfo Certificate::issuerInfo() const
{
	return static_cast<const CertContext *>(context())->props()->issuer;
}

Constraints Certificate::constraints() const
{
	return static_cast<const CertContext *>(context())->props()->constraints;
}

QStringList Certificate::policies() const
{
	return static_cast<const CertContext *>(context())->props()->policies;
}

QString Certificate::commonName() const
{
	return static_cast<const CertContext *>(context())->props()->subject[CommonName];
}

QBigInteger Certificate::serialNumber() const
{
	return static_cast<const CertContext *>(context())->props()->serial;
}

PublicKey Certificate::subjectPublicKey() const
{
	PKeyContext *c = static_cast<const CertContext *>(context())->subjectPublicKey();
	PublicKey key;
	key.change(c);
	return key;
}

bool Certificate::isCA() const
{
	return static_cast<const CertContext *>(context())->props()->isCA;
}

bool Certificate::isSelfSigned() const
{
	return static_cast<const CertContext *>(context())->props()->isSelfSigned;
}

int Certificate::pathLimit() const
{
	return static_cast<const CertContext *>(context())->props()->pathLimit;
}

SignatureAlgorithm Certificate::signatureAlgorithm() const
{
	return static_cast<const CertContext *>(context())->props()->sigalgo;
}

QSecureArray Certificate::toDER() const
{
	return static_cast<const CertContext *>(context())->toDER();
}

QString Certificate::toPEM() const
{
	return static_cast<const CertContext *>(context())->toPEM();
}

bool Certificate::toPEMFile(const QString &fileName) const
{
	return stringToFile(fileName, toPEM());
}

Certificate Certificate::fromDER(const QSecureArray &a, ConvertResult *result, const QString &provider)
{
	Certificate c;
	CertContext *cc = static_cast<CertContext *>(getContext("cert", provider));
	ConvertResult r = cc->fromDER(a);
	if(result)
		*result = r;
	if(r == ConvertGood)
		c.change(cc);
	return c;
}

Certificate Certificate::fromPEM(const QString &s, ConvertResult *result, const QString &provider)
{
	Certificate c;
	CertContext *cc = static_cast<CertContext *>(getContext("cert", provider));
	ConvertResult r = cc->fromPEM(s);
	if(result)
		*result = r;
	if(r == ConvertGood)
		c.change(cc);
	return c;
}

Certificate Certificate::fromPEMFile(const QString &fileName, ConvertResult *result, const QString &provider)
{
	QString pem;
	if(!stringFromFile(fileName, &pem))
	{
		if(result)
			*result = ErrorFile;
		return Certificate();
	}
	return fromPEM(pem, result, provider);
}

bool Certificate::matchesHostname(const QString &realHost) const
{
	// TODO
	QString peerHost = realHost.trimmed();
	while(peerHost.endsWith("."))
		peerHost.truncate(peerHost.length()-1);
	peerHost = peerHost.toLower();

	if(cnMatchesAddress(commonName(), peerHost))
		return true;
	return false;
}

bool Certificate::operator==(const Certificate &) const
{
	// TODO
	return false;
}

bool Certificate::operator!=(const Certificate &a) const
{
	return !(*this == a);
}

//----------------------------------------------------------------------------
// CertificateChain
//----------------------------------------------------------------------------
CertificateChain::CertificateChain()
{
}

CertificateChain::CertificateChain(const Certificate &primary)
{
	append(primary);
}

const Certificate & CertificateChain::primary() const
{
	return first();
}

//----------------------------------------------------------------------------
// CertificateRequest
//----------------------------------------------------------------------------
CertificateRequest::CertificateRequest()
{
}

CertificateRequest::CertificateRequest(const QString &fileName)
{
	*this = fromPEMFile(fileName, 0, QString());
}

CertificateRequest::CertificateRequest(const CertificateOptions &opts, const PrivateKey &key, const QString &provider)
{
	CSRContext *c = static_cast<CSRContext *>(getContext("csr", provider));
	if(c->createRequest(opts, *(static_cast<const PKeyContext *>(key.context()))))
		change(c);
	else
		delete c;
}

bool CertificateRequest::isNull() const
{
	return (!context() ? true : false);
}

bool CertificateRequest::canUseFormat(CertificateRequestFormat f, const QString &provider)
{
	CSRContext *c = static_cast<CSRContext *>(getContext("csr", provider));
	bool ok = c->canUseFormat(f);
	delete c;
	return ok;
}

CertificateRequestFormat CertificateRequest::format() const
{
	if(isNull())
		return PKCS10; // some default so we don't explode
	return static_cast<const CSRContext *>(context())->props()->format;
}

CertificateInfo CertificateRequest::subjectInfo() const
{
	return static_cast<const CSRContext *>(context())->props()->subject;
}

Constraints CertificateRequest::constraints() const
{
	return static_cast<const CSRContext *>(context())->props()->constraints;
}

QStringList CertificateRequest::policies() const
{
	return static_cast<const CSRContext *>(context())->props()->policies;
}

PublicKey CertificateRequest::subjectPublicKey() const
{
	PKeyContext *c = static_cast<const CSRContext *>(context())->subjectPublicKey();
	PublicKey key;
	key.change(c);
	return key;
}

bool CertificateRequest::isCA() const
{
	return static_cast<const CSRContext *>(context())->props()->isCA;
}

int CertificateRequest::pathLimit() const
{
	return static_cast<const CSRContext *>(context())->props()->pathLimit;
}

QString CertificateRequest::challenge() const
{
	return static_cast<const CSRContext *>(context())->props()->challenge;
}

SignatureAlgorithm CertificateRequest::signatureAlgorithm() const
{
	return static_cast<const CSRContext *>(context())->props()->sigalgo;
}

QSecureArray CertificateRequest::toDER() const
{
	return static_cast<const CSRContext *>(context())->toDER();
}

QString CertificateRequest::toPEM() const
{
	return static_cast<const CSRContext *>(context())->toPEM();
}

bool CertificateRequest::toPEMFile(const QString &fileName) const
{
	return stringToFile(fileName, toPEM());
}

CertificateRequest CertificateRequest::fromDER(const QSecureArray &a, ConvertResult *result, const QString &provider)
{
	CertificateRequest c;
	CSRContext *csr = static_cast<CSRContext *>(getContext("csr", provider));
	ConvertResult r = csr->fromDER(a);
	if(result)
		*result = r;
	if(r == ConvertGood)
		c.change(csr);
	return c;
}

CertificateRequest CertificateRequest::fromPEM(const QString &s, ConvertResult *result, const QString &provider)
{
	CertificateRequest c;
	CSRContext *csr = static_cast<CSRContext *>(getContext("csr", provider));
	ConvertResult r = csr->fromPEM(s);
	if(result)
		*result = r;
	if(r == ConvertGood)
		c.change(csr);
	return c;
}

CertificateRequest CertificateRequest::fromPEMFile(const QString &fileName, ConvertResult *result, const QString &provider)
{
	QString pem;
	if(!stringFromFile(fileName, &pem))
	{
		if(result)
			*result = ErrorFile;
		return CertificateRequest();
	}
	return fromPEM(pem, result, provider);
}

QString CertificateRequest::toString() const
{
	return static_cast<const CSRContext *>(context())->toSPKAC();
}

CertificateRequest CertificateRequest::fromString(const QString &s, ConvertResult *result, const QString &provider)
{
	CertificateRequest c;
	CSRContext *csr = static_cast<CSRContext *>(getContext("csr", provider));
	ConvertResult r = csr->fromSPKAC(s);
	if(result)
		*result = r;
	if(r == ConvertGood)
		c.change(csr);
	return c;
}

//----------------------------------------------------------------------------
// CRLEntry
//----------------------------------------------------------------------------
CRLEntry::CRLEntry()
{
	_reason = Unspecified;
}

CRLEntry::CRLEntry(const Certificate &c, Reason r)
{
	_serial = c.serialNumber();
	_time = QDateTime::currentDateTime();
	_reason = r;
}

QBigInteger CRLEntry::serialNumber() const
{
	return _serial;
}

QDateTime CRLEntry::time() const
{
	return _time;
}

CRLEntry::Reason CRLEntry::reason() const
{
	return _reason;
}

//----------------------------------------------------------------------------
// CRL
//----------------------------------------------------------------------------
CRL::CRL()
{
}

bool CRL::isNull() const
{
	return (!context() ? true : false);
}

CertificateInfo CRL::issuerInfo() const
{
	return static_cast<const CRLContext *>(context())->props()->issuer;
}

int CRL::number() const
{
	return static_cast<const CRLContext *>(context())->props()->number;
}

QDateTime CRL::thisUpdate() const
{
	return static_cast<const CRLContext *>(context())->props()->thisUpdate;
}

QDateTime CRL::nextUpdate() const
{
	return static_cast<const CRLContext *>(context())->props()->nextUpdate;
}

QList<CRLEntry> CRL::revoked() const
{
	return static_cast<const CRLContext *>(context())->props()->revoked;
}

SignatureAlgorithm CRL::signatureAlgorithm() const
{
	return static_cast<const CRLContext *>(context())->props()->sigalgo;
}

QSecureArray CRL::toDER() const
{
	return static_cast<const CRLContext *>(context())->toDER();
}

QString CRL::toPEM() const
{
	return static_cast<const CRLContext *>(context())->toPEM();
}

CRL CRL::fromDER(const QSecureArray &a, ConvertResult *result, const QString &provider)
{
	CRL c;
	CRLContext *cc = static_cast<CRLContext *>(getContext("crl", provider));
	ConvertResult r = cc->fromDER(a);
	if(result)
		*result = r;
	if(r == ConvertGood)
		c.change(cc);
	return c;
}

CRL CRL::fromPEM(const QString &s, ConvertResult *result, const QString &provider)
{
	CRL c;
	CRLContext *cc = static_cast<CRLContext *>(getContext("crl", provider));
	ConvertResult r = cc->fromPEM(s);
	if(result)
		*result = r;
	if(r == ConvertGood)
		c.change(cc);
	return c;
}

//----------------------------------------------------------------------------
// Store
//----------------------------------------------------------------------------
static QString readNextPem(QTextStream *ts)
{
	QString pem;
	bool found = false;
	bool done = false;
	while(!ts->atEnd())
	{
		QString line = ts->readLine();
		if(!found)
		{
			if(line == "-----BEGIN CERTIFICATE-----")
			{
				found = true;
				pem += line + '\n';
			}
		}
		else
		{
			pem += line + '\n';
			if(line == "-----END CERTIFICATE-----")
			{
				done = true;
				break;
			}
		}
	}
	if(!done)
		return QString::null;
	return pem;
}

Store::Store(const QString &provider)
:Algorithm("store", provider)
{
}

void Store::addCertificate(const Certificate &cert, bool trusted)
{
	static_cast<StoreContext *>(context())->addCertificate(*(static_cast<const CertContext *>(cert.context())), trusted);
}

void Store::addCRL(const CRL &crl)
{
	static_cast<StoreContext *>(context())->addCRL(*(static_cast<const CRLContext *>(crl.context())));
}

Validity Store::validate(const Certificate &cert, UsageMode u) const
{
	return static_cast<const StoreContext *>(context())->validate(*(static_cast<const CertContext *>(cert.context())), u);
}

QList<Certificate> Store::certificates() const
{
	QList<CertContext *> in = static_cast<const StoreContext *>(context())->certificates();
	QList<Certificate> out;
	for(int n = 0; n < in.count(); ++n)
	{
		Certificate cert;
		cert.change(in[n]);
		out.append(cert);
	}
	return out;
}

QList<CRL> Store::crls() const
{
	QList<CRLContext *> in = static_cast<const StoreContext *>(context())->crls();
	QList<CRL> out;
	for(int n = 0; n < in.count(); ++n)
	{
		CRL crl;
		crl.change(in[n]);
		out.append(crl);
	}
	return out;
}

bool Store::canUsePKCS7(const QString &provider)
{
	StoreContext *c = static_cast<StoreContext *>(getContext("store", provider));
	bool ok = c->canUsePKCS7();
	delete c;
	return ok;
}

bool Store::toPKCS7File(const QString &fileName) const
{
	return arrayToFile(fileName, static_cast<const StoreContext *>(context())->toPKCS7());
}

bool Store::toFlatTextFile(const QString &fileName) const
{
	QFile f(fileName);
	if(!f.open(QFile::WriteOnly))
		return false;

	QList<CertContext *> in = static_cast<const StoreContext *>(context())->certificates();
	QTextStream ts(&f);
	for(int n = 0; n < in.count(); ++n)
		ts << in[n]->toPEM();
	return true;
}

Store Store::fromPKCS7File(const QString &fileName, ConvertResult *result, const QString &provider)
{
	QByteArray der;
	if(!arrayFromFile(fileName, &der))
	{
		if(result)
			*result = ErrorFile;
		return Store();
	}

	Store store;
	StoreContext *c = static_cast<StoreContext *>(getContext("store", provider));
	ConvertResult r = c->fromPKCS7(der);
	if(result)
		*result = r;
	if(r == ConvertGood)
		store.change(c);
	return store;
}

Store Store::fromFlatTextFile(const QString &fileName, ConvertResult *result, const QString &provider)
{
	QFile f(fileName);
	if(!f.open(QFile::ReadOnly))
	{
		if(result)
			*result = ErrorFile;
		return Store();
	}

	Store store(provider);
	QTextStream ts(&f);
	while(1)
	{
		QString pem = readNextPem(&ts);
		if(pem.isNull())
			break;
		Certificate cert = Certificate::fromPEM(pem, 0, store.provider()->name());
		if(!cert.isNull())
			store.addCertificate(cert, true);
	}
	return store;
}

void Store::append(const Store &a)
{
	static_cast<StoreContext *>(context())->append(*(static_cast<const StoreContext *>(a.context())));
}

Store Store::operator+(const Store &a) const
{
	Store s = *this;
	s.append(a);
	return s;
}

Store & Store::operator+=(const Store &a)
{
	append(a);
	return *this;
}

//----------------------------------------------------------------------------
// CertificateAuthority
//----------------------------------------------------------------------------
CertificateAuthority::CertificateAuthority(const Certificate &cert, const PrivateKey &key, const QString &provider)
{
	Q_UNUSED(cert);
	Q_UNUSED(key);
	Q_UNUSED(provider);
}

Certificate CertificateAuthority::certificate() const
{
	return Certificate();
}

Certificate CertificateAuthority::signRequest(const CertificateRequest &req, const QDateTime &notValidAfter) const
{
	Q_UNUSED(req);
	Q_UNUSED(notValidAfter);
	return Certificate();
}

CRL CertificateAuthority::createCRL(const QDateTime &nextUpdate) const
{
	Q_UNUSED(nextUpdate);
	return CRL();
}

CRL CertificateAuthority::updateCRL(const CRL &crl, const QList<CRLEntry> &entries, const QDateTime &nextUpdate) const
{
	Q_UNUSED(crl);
	Q_UNUSED(entries);
	Q_UNUSED(nextUpdate);
	return CRL();
}

//----------------------------------------------------------------------------
// PersonalBundle
//----------------------------------------------------------------------------
PersonalBundle::PersonalBundle(const QString &provider)
{
	Q_UNUSED(provider);
}

bool PersonalBundle::isNull() const
{
	return false;
}

CertificateChain PersonalBundle::certificateChain() const
{
	return CertificateChain();
}

PrivateKey PersonalBundle::privateKey() const
{
	return PrivateKey();
}

void PersonalBundle::setCertificateChainAndKey(const CertificateChain &c, const PrivateKey &key)
{
	Q_UNUSED(c);
	Q_UNUSED(key);
}

QSecureArray PersonalBundle::toArray(const QString &name, const QSecureArray &passphrase) const
{
	Q_UNUSED(name);
	Q_UNUSED(passphrase);
	return QSecureArray();
}

PersonalBundle PersonalBundle::fromArray(const QSecureArray &a, const QSecureArray &passphrase, const QString &provider)
{
	Q_UNUSED(a);
	Q_UNUSED(passphrase);
	Q_UNUSED(provider);
	return PersonalBundle();
}

}
