/*
 * Copyright (C) 2005  Justin Karneges <justin@affinix.com>
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

#include <QtCore>
#include <QtCrypto>

//Q_IMPORT_PLUGIN(opensslPlugin);
//Q_IMPORT_PLUGIN(gnupgPlugin);

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

class PassphrasePrompt : public QObject
{
	Q_OBJECT
public:
	QList<QCA::KeyStore*> list;

	PassphrasePrompt()
	{
		QCA::KeyStoreManager *ksm = QCA::keyStoreManager();
		QStringList storeList = ksm->keyStores();
		for(int n = 0; n < storeList.count(); ++n)
		{
			QCA::KeyStore *ks = new QCA::KeyStore(storeList[n]);
			connect(ks, SIGNAL(needPassphrase(int, const QString &)), SLOT(ks_needPassphrase(int, const QString &)));
			list += ks;
		}
	}

	~PassphrasePrompt()
	{
		qDeleteAll(list);
	}

private slots:
	void ks_needPassphrase(int requestId, const QString &entryId)
	{
		Q_UNUSED(entryId);

		QCA::KeyStore *ks = static_cast<QCA::KeyStore *>(sender());
		QString name = ks->name();
		/*if(!entryId.isEmpty())
		{
			QList<QCA::KeyStoreEntry> list = ks->entryList();
			QCA::KeyStoreEntry entry;
			for(int n = 0; n < list.count(); ++n)
			{
				QCA::KeyStoreEntry &e = list[n];
				if(e.id() == entryId)
				{
					entry = e;
					break;
				}
			}
			if(entry.type() == QCA::KeyStoreEntry::TypePGPSecretKey)
				name = entry.pgpSecretKey().primaryUserId();
		}*/
		printf("Enter passphrase for %s (not hidden!) : ", qPrintable(name));
		fflush(stdout);
		QSecureArray result(256);
		fgets((char *)result.data(), result.size(), stdin);
		result.resize(qstrlen(result.data()));
		if(result[result.size() - 1] == '\n')
			result.resize(result.size() - 1);
		ks->submitPassphrase(requestId, result);
	}
};

#include "main.moc"

static bool write_dhprivatekey_file(const QCA::PrivateKey &priv, const QString &fileName)
{
	QCA::DHPrivateKey key = priv.toDH();
	QFile f(fileName);
	if(!f.open(QFile::WriteOnly | QFile::Truncate))
		return false;
	QTextStream ts(&f);
	ts << "P:" << QCA::arrayToHex(key.domain().p().toArray()).toLatin1() << endl;
	ts << "G:" << QCA::arrayToHex(key.domain().g().toArray()).toLatin1() << endl;
	ts << "Y:" << QCA::arrayToHex(key.y().toArray()).toLatin1() << endl;
	ts << "X:" << QCA::arrayToHex(key.x().toArray()).toLatin1() << endl;
	return true;
}

static bool write_dhpublickey_file(const QCA::PublicKey &pub, const QString &fileName)
{
	QCA::DHPublicKey key = pub.toDH();
	QFile f(fileName);
	if(!f.open(QFile::WriteOnly | QFile::Truncate))
		return false;
	QTextStream ts(&f);
	ts << "P:" << QCA::arrayToHex(key.domain().p().toArray()).toLatin1() << endl;
	ts << "G:" << QCA::arrayToHex(key.domain().g().toArray()).toLatin1() << endl;
	ts << "Y:" << QCA::arrayToHex(key.y().toArray()).toLatin1() << endl;
	return true;
}

static QMap<QString, QBigInteger> read_map_file(const QString &fileName)
{
	QMap<QString, QBigInteger> map;

	QFile f(fileName);
	if(!f.open(QFile::ReadOnly))
		return map;
	QTextStream ts(&f);
	while(!ts.atEnd())
	{
		QString line = ts.readLine();
		QStringList pair = line.split(':');
		QSecureArray bin = QCA::hexToArray(pair[1]);
		map[pair[0]] = QBigInteger(bin);
	}
	return map;
}

static QCA::PrivateKey read_dhprivatekey_file(const QString &fileName)
{
	QCA::PrivateKey key;
	QMap<QString, QBigInteger> map;
	map = read_map_file(fileName);
	if(map.isEmpty())
		return key;
	return QCA::DHPrivateKey(QCA::DLGroup(map["P"], map["G"]), map["Y"], map["X"]);
}

static QCA::PublicKey read_dhpublickey_file(const QString &fileName)
{
	QCA::PublicKey key;
	QMap<QString, QBigInteger> map;
	map = read_map_file(fileName);
	if(map.isEmpty())
		return key;
	return QCA::DHPublicKey(QCA::DLGroup(map["P"], map["G"]), map["Y"]);
}

static QString prompt_for(const QString &prompt)
{
	printf("%s: ", prompt.toLatin1().data());
	fflush(stdout);
	QByteArray result(256, 0);
	fgets((char *)result.data(), result.size(), stdin);
	return QString::fromLatin1(result).trimmed();
}

static void try_print_info(const QString &name, const QString &value)
{
	if(!value.isEmpty())
		printf("   %s: %s\n", name.toLatin1().data(), value.toLatin1().data());
}

static void print_info(const QString &title, const QCA::CertificateInfo &info)
{
	printf("%s\n", title.toLatin1().data());
	try_print_info("Name", info.value(QCA::CommonName));
	try_print_info("Email", info.value(QCA::Email));
	try_print_info("Organization", info.value(QCA::Organization));
	try_print_info("Organizational Unit", info.value(QCA::OrganizationalUnit));
	try_print_info("Locality", info.value(QCA::Locality));
	try_print_info("State", info.value(QCA::State));
	try_print_info("Country", info.value(QCA::Country));
	try_print_info("URI", info.value(QCA::URI));
	try_print_info("DNS", info.value(QCA::DNS));
	try_print_info("IP Address", info.value(QCA::IPAddress));
	try_print_info("JID", info.value(QCA::XMPP));
}

static QString constraint_to_string(QCA::ConstraintType t)
{
	QString str;
	switch(t)
	{
		case QCA::DigitalSignature:   str = "Digital Signature"; break;
		case QCA::NonRepudiation:     str = "Non-Repudiation"; break;
		case QCA::KeyEncipherment:    str = "Key Encipherment"; break;
		case QCA::DataEncipherment:   str = "Data Encipherment"; break;
		case QCA::KeyAgreement:       str = "Key Agreement"; break;
		case QCA::KeyCertificateSign: str = "Certificate Sign"; break;
		case QCA::CRLSign:            str = "CRL Sign"; break;
		case QCA::EncipherOnly:       str = "Encipher Only"; break;
		case QCA::DecipherOnly:       str = "Decipher Only"; break;
		case QCA::ServerAuth:         str = "TLS Server Authentication"; break;
		case QCA::ClientAuth:         str = "TLS Client Authentication"; break;
		case QCA::CodeSigning:        str = "Code Signing"; break;
		case QCA::EmailProtection:    str = "Email Protection"; break;
		case QCA::IPSecEndSystem:     str = "IPSec End System"; break;
		case QCA::IPSecTunnel:        str = "IPSec Tunnel"; break;
		case QCA::IPSecUser:          str = "IPSec User"; break;
		case QCA::TimeStamping:       str = "Time Stamping"; break;
		case QCA::OCSPSigning:        str = "OCSP Signing"; break;
	}
	return str;
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

char *mime_signpart =
	"Content-Type: text/plain; charset=ISO-8859-1\r\n"
	"Content-Transfer-Encoding: 7bit\r\n"
	"\r\n"
	"%1";

char *mime_signed =
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

char *mime_enveloped =
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

// FIXME: all of this mime stuff is a total hack
static QString open_mime_envelope(const QString &in)
{
	int n = in.indexOf("\r\n\r\n");
	if(n == -1)
		return QString();
	return in.mid(n + 4);
}

static bool open_mime_data_sig(const QString &in, QString *data, QString *sig)
{
	int n = in.indexOf("boundary=");
	if(n == -1)
		return false;
	n += 9;
	int i = in.indexOf("\r\n", n);
	if(n == -1)
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
	boundary = QString("--") + boundary + "\r\n";

	QString work = open_mime_envelope(in);
	n = work.indexOf(boundary);
	if(n == -1)
		return false;
	n += boundary.length();
	i = work.indexOf(boundary, n);
	if(n == -1)
		return false;
	QString tmp_data = work.mid(n, i - n);
	n = i + boundary.length();
	i = work.indexOf(boundary_end, n);
	if(i == -1)
		return false;
	QString tmp_sig = work.mid(n, i - n);

	// nuke some newlines
	if(tmp_data.right(2) == "\r\n")
		tmp_data.truncate(tmp_data.length() - 2);
	if(tmp_sig.right(2) == "\r\n")
		tmp_sig.truncate(tmp_sig.length() - 2);
	tmp_sig = open_mime_envelope(tmp_sig);

	*data = tmp_data;
	*sig = tmp_sig;
	return true;
}

// first = ids, second = names
static QPair<QStringList, QStringList> getKeyStoreStrings(const QStringList &list)
{
	QPair<QStringList, QStringList> out;
	for(int n = 0; n < list.count(); ++n)
	{
		QCA::KeyStore ks(list[n]);
		out.first.append(ks.id());
		out.second.append(ks.name());
	}
	return out;
}

static QPair<QStringList, QStringList> getKeyStoreEntryStrings(const QList<QCA::KeyStoreEntry> &list)
{
	QPair<QStringList, QStringList> out;
	for(int n = 0; n < list.count(); ++n)
	{
		out.first.append(list[n].id());
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
	QCA::KeyStoreManager *ksm = QCA::keyStoreManager();
	QStringList storeList = ksm->keyStores();
	int n = findByString(getKeyStoreStrings(storeList), name);
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

static QPair<QCA::PGPKey, QCA::PGPKey> getPGPSecretKey(const QString &name)
{
	QPair<QCA::PGPKey, QCA::PGPKey> key;
	int n = name.indexOf(':');
	if(n == -1)
	{
		printf("missing colon\n");
		return key;
	}
	QString storeName = name.mid(0, n);
	QString objectName = name.mid(n + 1);

	QCA::KeyStore store(getKeyStore(storeName));
	if(!store.isValid())
	{
		printf("no such store\n");
		return key;
	}

	QCA::KeyStoreEntry e = getKeyStoreEntry(&store, objectName);
	if(e.isNull())
	{
		printf("no such object\n");
		return key;
	}

	if(e.type() != QCA::KeyStoreEntry::TypePGPSecretKey)
	{
		printf("not a PGPSecretKey\n");
		return key;
	}

	key.first = e.pgpSecretKey();
	key.second = e.pgpPublicKey();
	return key;
}

static QCA::Certificate getCertificate(const QString &name)
{
	QCA::Certificate cert;

	int n = name.indexOf(':');
	if(n == -1)
	{
		cert = QCA::Certificate::fromPEMFile(name);
		if(cert.isNull())
			printf("Error reading cert file\n");

		return cert;
	}

	QString storeName = name.mid(0, n);
	QString objectName = name.mid(n + 1);

	QCA::KeyStore store(getKeyStore(storeName));
	if(!store.isValid())
	{
		printf("no such store\n");
		return cert;
	}

	QCA::KeyStoreEntry e = getKeyStoreEntry(&store, objectName);
	if(e.isNull())
	{
		printf("no such object\n");
		return cert;
	}

	if(e.type() != QCA::KeyStoreEntry::TypeCertificate)
	{
		printf("not a certificate\n");
		return cert;
	}

	cert = e.certificate();
	return cert;
}

static QCA::PrivateKey getPrivateKey(const QString &name)
{
	QCA::PrivateKey key;

	int n = name.indexOf(':');
	if(n == -1)
	{
		key = QCA::PrivateKey::fromPEMFile(name);
		if(key.isNull())
			printf("Error reading private key file\n");

		return key;
	}

	QString storeName = name.mid(0, n);
	QString objectName = name.mid(n + 1);

	QCA::KeyStore store(getKeyStore(storeName));
	if(!store.isValid())
	{
		printf("no such store\n");
		return key;
	}

	QCA::KeyStoreEntry e = getKeyStoreEntry(&store, objectName);
	if(e.isNull())
	{
		printf("no such object\n");
		return key;
	}

	if(e.type() != QCA::KeyStoreEntry::TypeKeyBundle)
	{
		printf("not a keybundle\n");
		return key;
	}

	QCA::KeyBundle kb = e.keyBundle();
	return kb.privateKey();
}

static void usage()
{
	printf("qcatool: simple qca testing tool\n");
	printf("usage: qcatool [--command] (options)\n");
	printf("commands:\n");
	printf("  --help\n");
	printf("  --plugins [-d]\n");
	printf("\n");
	printf("  --genrsa [bits] (passphrase)\n");
	printf("  --gendsa [512|768|1024] (passphrase)\n");
	printf("  --gendh [1024|2048|4096]\n");
	printf("\n");
	printf("  --encrypt [pub.pem] [messagefile]\n");
	printf("  --decrypt [priv.pem] [encryptedfile] (passphrase)\n");
	printf("  --sign [priv.pem] [messagefile] (passphrase)\n");
	printf("  --verify [pub.pem] [messagefile] [sigfile]\n");
	printf("  --derivekey [priv.txt] [peerpub.txt]\n");
	printf("\n");
	printf("  --makeselfcert [priv.pem] [ca|user] (passphrase)\n");
	printf("  --makereq [priv.pem] (passphrase)\n");
	printf("  --showcert [cert.pem]\n");
	printf("  --showreq [certreq.pem]\n");
	printf("  --validate [cert.pem] (nonroots.pem)\n");
	printf("\n");
	printf("  --extract-keybundle [cert.p12] [passphrase]\n");
	printf("\n");
	printf("  --list-keystores\n");
	printf("  --list-keystore [storeName]\n");
	printf("\n");
	printf("  --smime sign [priv.pem|X] [messagefile] [cert.pem] [nonroots.pem] (passphrase)\n");
	printf("  --smime verify [messagefile]\n");
	printf("  --smime encrypt [cert.pem] [messagefile]\n");
	printf("  --smime decrypt [priv.pem] [messagefile] [cert.pem] (passphrase)\n");
	printf("\n");
	printf("  --pgp clearsign [S] [messagefile]\n");
	printf("\n");

	/*printf("qcatool: simple qca utility\n");
	printf("usage: qcatool (--pass, --noprompt) [command]\n");
	printf("\n");
	printf(" key [command]\n");
	printf("   make rsa|dsa [bits]                Create a key pair\n");
	printf("   changepass (--newpass) [priv.pem]  Add/change passphrase of a key\n");
	printf("   removepass [priv.pem]              Remove passphrase of a key\n");
	printf(" cert [command]\n");
	printf("   makereq [K]                        Create certificate request (CSR)\n");
	printf("   makeself [K] ca|user               Create self-signed certificate\n");
	printf("   validate [C] (nonroots.pem)        Validate certificate\n");
	printf(" keybundle [command]\n");
	printf("   make [K] [C] (nonroots.pem)        Create a keybundle\n");
	printf("   extract                            Extract certificate(s) and key\n");
	printf("   changepass (--newpass)             Change passphrase of a keybundle\n");
	printf(" keystore [command]\n");
	printf("   list-stores                        List all available keystores\n");
	printf("   list [storeName]                   List content of a keystore\n");
	printf("   addcert [storeName] [cert.p12]     Add a keybundle into a keystore\n");
	printf("   addpgp [storeName] [key.asc]       Add a PGP key into a keystore\n");
	printf("   remove [storeName] [objectName]    Remove an object from a keystore\n");
	printf(" show [command]\n");
	printf("   cert [C]                           Examine a certificate\n");
	printf("   req [req.pem]                      Examine a certificate request (CSR)\n");
	printf("   pgp [P|S]                          Examine a PGP key\n");
	printf(" message [command]\n");
	printf("   sign pgp|pgpdetach|smime [X|S]     Sign a message\n");
	printf("   encrypt pgp|smime [C|P]            Encrypt a message\n");
	printf("   signencrypt [S] [P]                PGP sign & encrypt a message\n");
	printf("   verify pgp|smime                   Verify a message\n");
	printf("   decrypt pgp|smime [X|S]            Decrypt a message\n");
	printf("\n");
	printf("Object types: K = private key, C = certificate, X = key bundle,\n");
	printf("  P = PGP public key, S = PGP secret key\n");
	printf("\n");
	printf("An object must be either a filename or a keystore reference (\"store:obj\").\n");
	printf("\n");*/
}

int main(int argc, char **argv)
{
	QCA::Initializer qcaInit;
	QCoreApplication app(argc, argv);

	/*if(!QCA::isSupported("pkey") || !QCA::PKey::supportedTypes().contains(QCA::PKey::RSA) || !QCA::PKey::supportedIOTypes().contains(QCA::PKey::RSA))
	{
		printf("Error: no RSA support\n");
		return 1;
	}

	if(!QCA::PKey::supportedTypes().contains(QCA::PKey::DSA) || !QCA::PKey::supportedIOTypes().contains(QCA::PKey::DSA))
	{
		printf("Error: no DSA support\n");
		return 1;
	}

	if(!QCA::PKey::supportedTypes().contains(QCA::PKey::DH))
	{
		printf("Error: no DH support\n");
		return 1;
	}

	if(!QCA::isSupported("cert"))
	{
		printf("Error: no cert support\n");
		return 1;
	}*/

	QStringList args;
	for(int n = 1; n < argc; ++n)
		args.append(QString(argv[n]));

	if(args.count() < 1)
	{
		usage();
		return 1;
	}

	if(args[0] == "--help")
	{
		usage();
		return 1;
	}

	if(args[0] == "--plugins")
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

		QCA::scanForPlugins();
		QCA::ProviderList list = QCA::providers();

		bool debug = false;
		for(int n = 1; n < args.count(); ++n)
		{
			if(args[n] == "-d")
			{
				debug = true;
				break;
			}
		}
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

	// activate the KeyStoreManager and block until ready
	QCA::keyStoreManager()->start();
	QCA::keyStoreManager()->waitForBusyFinished();

	// hook a passphrase prompt onto all the KeyStores
	PassphrasePrompt passphrasePrompt;

	bool genrsa = false;
	bool gendsa = false;
	bool gendh = false;

	if(args[0] == "--genrsa")
	{
		if(args.count() < 2)
		{
			usage();
			return 1;
		}

		genrsa = true;
	}
	if(args[0] == "--gendsa")
	{
		if(args.count() < 2)
		{
			usage();
			return 1;
		}

		gendsa = true;
	}
	else if(args[0] == "--gendh")
	{
		if(args.count() < 2)
		{
			usage();
			return 1;
		}

		gendh = true;
	}

	if(genrsa || gendsa || gendh)
	{
		QCA::PrivateKey priv;
		QString pubname, privname;

		if(genrsa)
		{
			int bits = args[1].toInt();

			// note: last arg here is bogus
			priv = AnimatedKeyGen::makeKey(QCA::PKey::RSA, bits, QCA::DSA_512);
			pubname = "rsapub.pem";
			privname = "rsapriv.pem";
		}
		else if(gendsa)
		{
			QCA::DLGroupSet set;
			if(args[1] == "512")
				set = QCA::DSA_512;
			else if(args[1] == "768")
				set = QCA::DSA_768;
			else if(args[1] == "1024")
				set = QCA::DSA_1024;
			else
			{
				usage();
				return 1;
			}

			priv = AnimatedKeyGen::makeKey(QCA::PKey::DSA, 0, set);
			pubname = "dsapub.pem";
			privname = "dsapriv.pem";
		}
		else if(gendh)
		{
			QCA::DLGroupSet set;
			if(args[1] == "1024")
				set = QCA::IETF_1024;
			else if(args[1] == "2048")
				set = QCA::IETF_2048;
			else if(args[1] == "4096")
				set = QCA::IETF_4096;
			else
			{
				usage();
				return 1;
			}

			priv = AnimatedKeyGen::makeKey(QCA::PKey::DH, 0, set);
			pubname = "dhpub.txt";
			privname = "dhpriv.txt";
		}

		if(priv.isNull())
		{
			printf("Error: unable to generate key\n");
			return 1;
		}

		QCA::PublicKey pub = priv.toPublicKey();

		if(genrsa || gendsa)
		{
			QSecureArray passphrase;
			if(args.count() >= 3)
			 	passphrase = args[2].toLatin1();

			if(pub.toPEMFile(pubname))
				printf("Public key saved to %s\n", pubname.toLatin1().data());
			else
			{
				printf("Error writing %s\n", pubname.toLatin1().data());
				return 1;
			}

			bool ok;
			if(!passphrase.isEmpty())
				ok = priv.toPEMFile(privname, passphrase);
			else
				ok = priv.toPEMFile(privname);
			if(ok)
				printf("Private key saved to %s\n", privname.toLatin1().data());
			else
			{
				printf("Error writing %s\n", privname.toLatin1().data());
				return 1;
			}
		}
		else
		{
			if(write_dhpublickey_file(pub, pubname))
				printf("Public key saved to %s\n", pubname.toLatin1().data());
			else
			{
				printf("Error writing %s\n", pubname.toLatin1().data());
				return 1;
			}

			if(write_dhprivatekey_file(priv, privname))
				printf("Private key saved to %s\n", privname.toLatin1().data());
			else
			{
				printf("Error writing %s\n", privname.toLatin1().data());
				return 1;
			}
		}
	}
	else if(args[0] == "--encrypt")
	{
		if(args.count() < 3)
		{
			usage();
			return 1;
		}

		QCA::PublicKey key(args[1]);
		if(key.isNull())
		{
			printf("Error reading key file\n");
			return 1;
		}

		if(!key.canEncrypt())
		{
			printf("Error: this kind of key cannot encrypt\n");
			return 1;
		}

		QCA::EncryptionAlgorithm alg = QCA::EME_PKCS1_OAEP;
		int max = key.maximumEncryptSize(alg);

		QByteArray buf;
		{
			QFile infile(args[2]);
			if(!infile.open(QFile::ReadOnly))
			{
				printf("Error opening message file\n");
				return 1;
			}

			if(infile.size() > max)
				fprintf(stderr, "Warning: input size is greater than key maximum, result will be truncated\n");

			buf = infile.read(max);
		}

		QFile outfile("rsaenc.txt");
		if(!outfile.open(QFile::WriteOnly | QFile::Truncate))
		{
			printf("Error opening output file\n");
			return 1;
		}

		QSecureArray result = key.encrypt(buf, alg);

		QString str = QCA::Base64().arrayToString(result);
		QTextStream ts(&outfile);
		ts << str << endl;

		printf("Wrote %s\n", outfile.fileName().toLatin1().data());
	}
	else if(args[0] == "--decrypt")
	{
		if(args.count() < 3)
		{
			usage();
			return 1;
		}

		QSecureArray passphrase;
		if(args.count() >= 4)
			passphrase = args[3].toLatin1();

		QCA::PrivateKey key;
		if(!passphrase.isEmpty())
			key = QCA::PrivateKey(args[1], passphrase);
		else
			key = QCA::PrivateKey(args[1]);
		if(key.isNull())
		{
			printf("Error reading key file\n");
			return 1;
		}

		if(!key.canDecrypt())
		{
			printf("Error: this kind of key cannot create decrypt\n");
			return 1;
		}

		QCA::EncryptionAlgorithm alg = QCA::EME_PKCS1_OAEP;

		QSecureArray buf;
		{
			QFile infile(args[2]);
			if(!infile.open(QFile::ReadOnly))
			{
				printf("Error opening input file\n");
				return 1;
			}
			QTextStream ts(&infile);
			QString str = ts.readLine();
			buf = QCA::Base64().stringToArray(str);
		}

		QSecureArray result;
		if(!key.decrypt(buf, &result, alg))
		{
			printf("Error decrypting\n");
			return 1;
		}

		printf("%s\n", result.data());
	}
	else if(args[0] == "--sign")
	{
		if(args.count() < 3)
		{
			usage();
			return 1;
		}

		QSecureArray passphrase;
		if(args.count() >= 4)
			passphrase = args[3].toLatin1();

		QCA::PrivateKey key;
		if(!passphrase.isEmpty())
			key = QCA::PrivateKey(args[1], passphrase);
		else
			key = QCA::PrivateKey(args[1]);
		if(key.isNull())
		{
			printf("Error reading key file\n");
			return 1;
		}

		if(!key.canSign())
		{
			printf("Error: this kind of key cannot create signatures\n");
			return 1;
		}

		QFile infile(args[2]);
		QFile outfile(infile.fileName() + ".sig");
		if(!infile.open(QFile::ReadOnly) || !outfile.open(QFile::WriteOnly | QFile::Truncate))
		{
			printf("Error opening message or signature files\n");
			return 1;
		}

		if(key.isRSA())
			key.startSign(QCA::EMSA3_MD5);
		else
			key.startSign(QCA::EMSA1_SHA1);
		while(!infile.atEnd())
			key.update(infile.read(16384));
		QSecureArray sig = key.signature();

		QString str = QCA::Base64().arrayToString(sig);
		QTextStream ts(&outfile);
		ts << str << endl;

		printf("Wrote %s\n", outfile.fileName().toLatin1().data());
	}
	else if(args[0] == "--verify")
	{
		if(args.count() < 4)
		{
			usage();
			return 1;
		}

		QCA::PublicKey key(args[1]);
		if(key.isNull())
		{
			printf("Error reading key file\n");
			return 1;
		}

		if(!key.canVerify())
		{
			printf("Error: this kind of key cannot verify signatures\n");
			return 1;
		}

		QSecureArray sig;
		{
			QFile sigfile(args[3]);
			if(!sigfile.open(QFile::ReadOnly))
			{
				printf("Error opening signature file\n");
				return 1;
			}
			QTextStream ts(&sigfile);
			QString str = ts.readLine();
			sig = QCA::Base64().stringToArray(str);
		}

		QFile infile(args[2]);
		if(!infile.open(QFile::ReadOnly))
		{
			printf("Error opening message file\n");
			return 1;
		}

		if(key.isRSA())
			key.startVerify(QCA::EMSA3_MD5);
		else
			key.startVerify(QCA::EMSA1_SHA1);
		while(!infile.atEnd())
			key.update(infile.read(16384));
		if(key.validSignature(sig))
			printf("Signature verified\n");
		else
		{
			printf("Signature did NOT verify\n");
			return 1;
		}
	}
	else if(args[0] == "--derivekey")
	{
		if(args.count() < 3)
		{
			usage();
			return 1;
		}

		QCA::PrivateKey priv = read_dhprivatekey_file(args[1]);
		if(priv.isNull())
		{
			printf("Error reading private key file\n");
			return 1;
		}

		if(!priv.canKeyAgree())
		{
			printf("Error: the private key cannot be used to derive shared keys\n");
			return 1;
		}

		QCA::PublicKey pub = read_dhpublickey_file(args[2]);
		if(pub.isNull())
		{
			printf("Error reading public key file\n");
			return 1;
		}

		if(!pub.canKeyAgree())
		{
			printf("Error: the public key cannot be used to derive shared keys\n");
			return 1;
		}

		QCA::SymmetricKey key = priv.deriveKey(pub);
		if(!key.isEmpty())
			printf("%s\n", QCA::Base64().arrayToString(key).toLatin1().data());
		else
		{
			printf("Error deriving key\n");
			return 1;
		}
	}
	else if(args[0] == "--makeselfcert")
	{
		if(args.count() < 3)
		{
			usage();
			return 1;
		}

		QSecureArray passphrase;
		if(args.count() >= 4)
			passphrase = args[3].toLatin1();

		QCA::PrivateKey key;
		if(!passphrase.isEmpty())
			key = QCA::PrivateKey(args[1], passphrase);
		else
			key = QCA::PrivateKey(args[1]);
		if(key.isNull())
		{
			printf("Error reading key file\n");
			return 1;
		}

		bool do_ca;
		if(args[2] == "ca")
			do_ca = true;
		else if(args[2] == "user")
			do_ca = false;
		else
		{
			printf("Must specify 'ca' or 'user' as type\n");
			return 1;
		}

		QCA::CertificateOptions opts;
		//opts.setSerialNumber(QBigInteger("1000000000000"));
		QCA::CertificateInfo info;
		info.insert(QCA::CommonName, prompt_for("Common Name"));
		info.insert(QCA::Country, prompt_for("Country Code (2 letters)"));
		info.insert(QCA::Organization, prompt_for("Organization"));
		info.insert(QCA::Email, prompt_for("Email"));

		//info[QCA::URI] = "http://psi.affinix.com/";
		//info[QCA::DNS] = "psi.affinix.com";
		//info[QCA::IPAddress] = "192.168.0.1";
		//info.insert(QCA::XMPP, "justin@andbit.net");

		opts.setInfo(info);
		if(do_ca)
			opts.setAsCA();

		//QCA::Constraints constraints;
		//constraints += QCA::ServerAuth;
		//constraints += QCA::CodeSigning;
		//opts.setConstraints(constraints);

		//QStringList policies;
		//policies += "1.2.3.4";
		//policies += "1.6.7.8";
		//opts.setPolicies(policies);

		QDateTime t = QDateTime::currentDateTime().toUTC();
		opts.setValidityPeriod(t, t.addMonths(1));

		QCA::Certificate cert(opts, key);

		QString certname = "cert.pem";
		if(cert.toPEMFile(certname))
			printf("Certificate saved to %s\n", certname.toLatin1().data());
		else
		{
			printf("Error writing %s\n", certname.toLatin1().data());
			return 1;
		}
	}
	else if(args[0] == "--makereq")
	{
		if(args.count() < 2)
		{
			usage();
			return 1;
		}

		QSecureArray passphrase;
		if(args.count() >= 3)
			passphrase = args[2].toLatin1();

		QCA::PrivateKey key;
		if(!passphrase.isEmpty())
			key = QCA::PrivateKey(args[1], passphrase);
		else
			key = QCA::PrivateKey(args[1]);
		if(key.isNull())
		{
			printf("Error reading key file\n");
			return 1;
		}

		QCA::CertificateOptions opts;
		QCA::CertificateInfo info;
		info.insert(QCA::CommonName, prompt_for("Common Name"));
		info.insert(QCA::Country, prompt_for("Country Code (2 letters)"));
		info.insert(QCA::Organization, prompt_for("Organization"));
		info.insert(QCA::Email, prompt_for("Email"));

		opts.setInfo(info);

		//if(do_ca)
		//	opts.setAsCA();

		//QCA::Constraints constraints;
		//constraints += QCA::ServerAuth;
		//constraints += QCA::CodeSigning;
		//opts.setConstraints(constraints);

		//QStringList policies;
		//policies += "1.2.3.4";
		//policies += "1.6.7.8";
		//opts.setPolicies(policies);

		QDateTime t = QDateTime::currentDateTime().toUTC();
		opts.setValidityPeriod(t, t.addMonths(1));

		QCA::CertificateRequest req(opts, key);

		QString reqname = "certreq.pem";
		if(req.toPEMFile(reqname))
			printf("Certificate request saved to %s\n", reqname.toLatin1().data());
		else
		{
			printf("Error writing %s\n", reqname.toLatin1().data());
			return 1;
		}
	}
	else if(args[0] == "--showcert")
	{
		if(args.count() < 2)
		{
			usage();
			return 1;
		}

		QCA::Certificate cert = getCertificate(args[1]);
		if(cert.isNull())
			return 1;

		printf("Serial Number: %s\n", cert.serialNumber().toString().toLatin1().data());

		print_info("Subject", cert.subjectInfo());
		print_info("Issuer", cert.issuerInfo());

		printf("Validity\n");
		printf("   Not before: %s\n", cert.notValidBefore().toString().toLatin1().data());
		printf("   Not after: %s\n", cert.notValidAfter().toString().toLatin1().data());

		printf("Constraints\n");
		QCA::Constraints constraints = cert.constraints();
		int n;
		if(!constraints.isEmpty())
		{
			for(n = 0; n < constraints.count(); ++n)
				printf("   %s\n", constraint_to_string(constraints[n]).toLatin1().data());
		}
		else
			printf("   No constraints\n");

		printf("Policies\n");
		QStringList policies = cert.policies();
		if(!policies.isEmpty())
		{
			for(n = 0; n < policies.count(); ++n)
				printf("   %s\n", policies[n].toLatin1().data());
		}
		else
			printf("   No policies\n");

		// TODO: printf("Signature algorithm: %s\n");

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

		QCA::PublicKey key = cert.subjectPublicKey();
		printf("Public Key:\n%s", key.toPEM().toLatin1().data());
	}
	else if(args[0] == "--showreq")
	{
		if(args.count() < 2)
		{
			usage();
			return 1;
		}

		QCA::CertificateRequest req(args[1]);
		if(req.isNull())
		{
			printf("Error reading cert request file\n");
			return 1;
		}

		print_info("Subject", req.subjectInfo());

		printf("Constraints\n");
		QCA::Constraints constraints = req.constraints();
		int n;
		for(n = 0; n < constraints.count(); ++n)
			printf("   %s\n", constraint_to_string(constraints[n]).toLatin1().data());

		printf("Policies\n");
		QStringList policies = req.policies();
		for(n = 0; n < policies.count(); ++n)
			printf("   %s\n", policies[n].toLatin1().data());

		QCA::PublicKey key = req.subjectPublicKey();
		printf("Public Key:\n%s", key.toPEM().toLatin1().data());
	}
	else if(args[0] == "--validate")
	{
		if(args.count() < 2)
		{
			usage();
			return 1;
		}

		QCA::Certificate target(args[1]);
		if(target.isNull())
		{
			printf("Error reading cert file\n");
			return 1;
		}

		if(!QCA::haveSystemStore())
		{
			printf("Error: no system store\n");
			return 1;
		}

		// get roots
		QCA::CertificateCollection roots = QCA::systemStore();

		// get nonroots
		QCA::CertificateCollection nonroots;
		if(args.count() >= 3)
			nonroots = QCA::CertificateCollection::fromFlatTextFile(args[2]);

		QCA::Validity v = target.validate(roots, nonroots);
		if(v == QCA::ValidityGood)
			printf("Certificate is valid\n");
		else
		{
			printf("Certificate is NOT valid: %s\n", validityToString(v).toLatin1().data());
			return 1;
		}
	}
	else if(args[0] == "--smime")
	{
		if(args.count() < 2)
		{
			usage();
			return 1;
		}

		if(args[1] == "sign")
		{
			if(args.count() < 6)
			{
				usage();
				return 1;
			}

			QSecureArray passphrase;
			if(args.count() >= 7)
				passphrase = args[6].toLatin1();

			QCA::PrivateKey key;
			if(!passphrase.isEmpty())
				key = QCA::PrivateKey(args[2], passphrase);
			else
				key = getPrivateKey(args[2]);
			if(key.isNull())
			{
				printf("Error reading key file\n");
				return 1;
			}

			QCA::Certificate cert(args[4]);
			if(cert.isNull())
			{
				printf("Error reading cert file\n");
				return 1;
			}

			QCA::CertificateCollection nonroots = QCA::CertificateCollection::fromFlatTextFile(args[5]);

			QFile infile(args[3]);
			if(!infile.open(QFile::ReadOnly))
			{
				printf("Error opening message file\n");
				return 1;
			}

			QCA::SecureMessageKey skey;
			{
				QCA::CertificateChain chain;
				chain += cert;
				chain += nonroots.certificates();
				skey.setX509CertificateChain(chain);
				skey.setX509PrivateKey(key);
			}

			QString text = add_cr(QString::fromLatin1(infile.readAll()));
			QByteArray plain = QString(mime_signpart).arg(text).toLatin1();

			QCA::CMS cms;
			QCA::SecureMessage msg(&cms);
			msg.setSigner(skey);
			msg.startSign(QCA::SecureMessage::Detached);
			msg.update(plain);
			msg.end();
			msg.waitForFinished(-1);

			if(!msg.success())
			{
				printf("Error signing: [%d]\n", msg.errorCode());
				return 1;
			}

			QFileInfo fi(infile.fileName());

			QFile outfile(fi.baseName() + "_signed.txt");
			if(!outfile.open(QFile::WriteOnly | QFile::Truncate))
			{
				printf("Error opening sig file\n");
				return 1;
			}

			QSecureArray sig = msg.signature();

			QCA::Base64 enc;
			enc.setLineBreaksEnabled(true);
			enc.setLineBreaksColumn(76);
			QString sigtext = add_cr(enc.arrayToString(sig));

			QString str = QString(mime_signed).arg(msg.hashName()).arg(QString(plain)).arg(sigtext);
			QTextStream ts(&outfile);
			ts << str;

			printf("Wrote %s\n", qPrintable(outfile.fileName()));
		}
		else if(args[1] == "encrypt")
		{
			if(args.count() < 4)
			{
				usage();
				return 1;
			}

			QCA::Certificate cert(args[2]);
			if(cert.isNull())
			{
				printf("Error reading cert file\n");
				return 1;
			}

			QFile infile(args[3]);
			if(!infile.open(QFile::ReadOnly))
			{
				printf("Error opening message file\n");
				return 1;
			}

			QCA::SecureMessageKey skey;
			{
				QCA::CertificateChain chain;
				chain += cert;
				skey.setX509CertificateChain(chain);
			}

			QByteArray plain = infile.readAll();

			QCA::CMS cms;
			QCA::SecureMessage msg(&cms);
			msg.setRecipient(skey);
			msg.startEncrypt();
			msg.update(plain);
			msg.end();
			msg.waitForFinished(-1);

			if(!msg.success())
			{
				printf("Error encrypting: [%d]\n", msg.errorCode());
				return 1;
			}

			QFileInfo fi(infile.fileName());

			QFile outfile(fi.baseName() + "_encrypted.txt");
			if(!outfile.open(QFile::WriteOnly | QFile::Truncate))
			{
				printf("Error opening output file\n");
				return 1;
			}

			QSecureArray result = msg.read();

			QCA::Base64 enc;
			enc.setLineBreaksEnabled(true);
			enc.setLineBreaksColumn(76);
			QString enctext = add_cr(enc.arrayToString(result));

			QString str = QString(mime_enveloped).arg(enctext);
			QTextStream ts(&outfile);
			ts << str;

			printf("Wrote %s\n", qPrintable(outfile.fileName()));
		}
		else if(args[1] == "decrypt")
		{
			if(args.count() < 5)
			{
				usage();
				return 1;
			}

			QSecureArray passphrase;
			if(args.count() >= 6)
				passphrase = args[5].toLatin1();

			QCA::PrivateKey key;
			if(!passphrase.isEmpty())
				key = QCA::PrivateKey(args[2], passphrase);
			else
				key = QCA::PrivateKey(args[2]);
			if(key.isNull())
			{
				printf("Error reading key file\n");
				return 1;
			}

			QCA::Certificate cert(args[4]);
			if(cert.isNull())
			{
				printf("Error reading cert file\n");
				return 1;
			}

			QFile infile(args[3]);
			if(!infile.open(QFile::ReadOnly))
			{
				printf("Error opening message file\n");
				return 1;
			}

			QString in = QString::fromUtf8(infile.readAll());
			QString str = open_mime_envelope(in);
			if(str.isEmpty())
			{
				printf("Error parsing message file\n");
				return 1;
			}

			QCA::Base64 dec;
			dec.setLineBreaksEnabled(true);
			QByteArray crypted = dec.stringToArray(rem_cr(str)).toByteArray();

			QCA::SecureMessageKey skey;
			{
				QCA::CertificateChain chain;
				chain += cert;
				skey.setX509CertificateChain(chain);
				skey.setX509PrivateKey(key);
			}

			QCA::CMS cms;
			cms.setPrivateKeys(QCA::SecureMessageKeyList() << skey);
			QCA::SecureMessage msg(&cms);
			msg.startDecrypt();
			msg.update(crypted);
			msg.end();
			msg.waitForFinished(-1);

			if(!msg.success())
			{
				printf("Error decrypting: [%d]\n", msg.errorCode());
				return 1;
			}

			QByteArray result = msg.read();

			QFileInfo fi(infile.fileName());

			QFile outfile(fi.baseName() + "_decrypted.txt");
			if(!outfile.open(QFile::WriteOnly | QFile::Truncate))
			{
				printf("Error opening output file\n");
				return 1;
			}

			QTextStream ts(&outfile);
			ts << QString::fromUtf8(result);

			printf("Wrote %s\n", qPrintable(outfile.fileName()));
		}
		else if(args[1] == "verify")
		{
			if(args.count() < 3)
			{
				usage();
				return 1;
			}

			QFile infile(args[2]);
			if(!infile.open(QFile::ReadOnly))
			{
				printf("Error opening message file\n");
				return 1;
			}

			QString in = QString::fromUtf8(infile.readAll());
			QString str, sigtext;
			if(!open_mime_data_sig(in, &str, &sigtext))
			{
				printf("Error parsing message file\n");
				return 1;
			}

			QByteArray plain = str.toLatin1();

			//printf("parsed: data=[%s], sig=[%s]\n", qPrintable(str), qPrintable(sigtext));

			QCA::Base64 dec;
			dec.setLineBreaksEnabled(true);
			QByteArray sig = dec.stringToArray(rem_cr(sigtext)).toByteArray();

			QCA::CMS cms;
			cms.setTrustedCertificates(QCA::systemStore());
			QCA::SecureMessage msg(&cms);
			msg.startVerify(sig);
			msg.update(plain);
			msg.end();
			msg.waitForFinished(-1);

			if(!msg.success())
			{
				printf("Error verifying: [%d]\n", msg.errorCode());
				return 1;
			}

			QCA::SecureMessageSignature signer = msg.signer();
			QCA::SecureMessageSignature::IdentityResult r = signer.identityResult();

			str = open_mime_envelope(str);
			printf("%s", qPrintable(str));
			QString rs;
			if(r == QCA::SecureMessageSignature::Valid)
				rs = "Valid";
			else if(r == QCA::SecureMessageSignature::InvalidSignature)
				rs = "InvalidSignature";
			else if(r == QCA::SecureMessageSignature::InvalidKey)
				rs = "InvalidKey";
			else if(r == QCA::SecureMessageSignature::NoKey)
				rs = "NoKey";
			printf("IdentityResult: %s\n", qPrintable(rs));
			QCA::SecureMessageKey key = signer.key();
			if(!key.isNull())
			{
				QCA::Certificate cert = key.x509CertificateChain().primary();
				printf("From: %s (%s)\n", qPrintable(cert.commonName()), qPrintable(cert.subjectInfo().value(QCA::Email)));
			}
		}
		else
		{
			usage();
			return 1;
		}
	}
	else if(args[0] == "--extract-keybundle")
	{
		if(args.count() < 3)
		{
			usage();
			return 1;
		}

		QCA::KeyBundle key = QCA::KeyBundle::fromFile(args[1], args[2].toLatin1());
		if(key.isNull())
		{
			printf("Error reading key file\n");
			return 1;
		}

		printf("Certs: (first is primary)\n");
		QCA::CertificateChain chain = key.certificateChain();
		for(int n = 0; n < chain.count(); ++n)
			printf("%s", qPrintable(chain[n].toPEM()));
		printf("Private Key:\n");
			printf("%s", qPrintable(key.privateKey().toPEM()));
	}
	else if(args[0] == "--list-keystores")
	{
		QCA::KeyStoreManager *ksm = QCA::keyStoreManager();
		QStringList storeList = ksm->keyStores();
		for(int n = 0; n < storeList.count(); ++n)
		{
			QCA::KeyStore ks(storeList[n]);
			QString type;
			switch(ks.type())
			{
				case QCA::KeyStore::System:      type = "Sys "; break;
				case QCA::KeyStore::User:        type = "User"; break;
				case QCA::KeyStore::Application: type = "App "; break;
				case QCA::KeyStore::SmartCard:   type = "Card"; break;
				case QCA::KeyStore::PGPKeyring:  type = "PGP "; break;
			}
			// TODO: id field length should be uniform based on all entries
			printf("%s %s [%s]\n", qPrintable(type), qPrintable(ks.id()), qPrintable(ks.name()));
		}
	}
	else if(args[0] == "--list-keystore")
	{
		if(args.count() < 2)
		{
			usage();
			return 1;
		}

		QCA::KeyStore store(getKeyStore(args[1]));
		if(!store.isValid())
		{
			printf("no such store\n");
			return 1;
		}

		QList<QCA::KeyStoreEntry> list = store.entryList();
		for(int n = 0; n < list.count(); ++n)
		{
			QCA::KeyStoreEntry i = list[n];
			QString type;
			switch(i.type())
			{
				case QCA::KeyStoreEntry::TypeKeyBundle:    type = "Key "; break;
				case QCA::KeyStoreEntry::TypeCertificate:  type = "Cert"; break;
				case QCA::KeyStoreEntry::TypeCRL:          type = "CRL "; break;
				case QCA::KeyStoreEntry::TypePGPSecretKey: type = "PSec"; break;
				case QCA::KeyStoreEntry::TypePGPPublicKey: type = "PPub"; break;
			}
			// TODO: id field length should be uniform based on all entries
			printf("%s %-2s [%s]\n", qPrintable(type), qPrintable(i.id()), qPrintable(i.name()));
		}
	}
	else if(args[0] == "--pgp")
	{
		if(args.count() < 2)
		{
			usage();
			return 1;
		}

		if(args[1] == "clearsign")
		{
			if(args.count() < 4)
			{
				usage();
				return 1;
			}

			QPair<QCA::PGPKey, QCA::PGPKey> key = getPGPSecretKey(args[2]);
			if(key.first.isNull())
				return 1;

			QFile infile(args[3]);
			if(!infile.open(QFile::ReadOnly))
			{
				printf("Error opening message file\n");
				return 1;
			}

			QCA::SecureMessageKey skey;
			skey.setPGPSecretKey(key.first);

			QByteArray plain = infile.readAll();

			QCA::OpenPGP pgp;
			QCA::SecureMessage msg(&pgp);
			msg.setSigner(skey);
			msg.startSign(QCA::SecureMessage::Clearsign);
			msg.update(plain);
			msg.end();
			msg.waitForFinished(-1);

			if(!msg.success())
			{
				printf("Error signing: [%d]\n", msg.errorCode());
				return 1;
			}

			QSecureArray result = msg.read();

			printf("Result:\n%s\n", result.data());
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
