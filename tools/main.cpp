#include <QtCore>
#include <QtCrypto>

Q_IMPORT_PLUGIN(opensslPlugin);

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

static void usage()
{
	printf("qcatool: simple qca testing tool\n");
	printf("usage: qcatool [--command] (options)\n");
	printf("commands:\n");
	printf("  --help\n");
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
	printf("  --validate [cert.pem] (nonrootstore.pem)\n");
	printf("\n");
}

int main(int argc, char **argv)
{
	QCA::Initializer qcaInit;

	QCoreApplication app(argc, argv);

	QCA::scanForPlugins();

	if(!QCA::isSupported("pkey") || !QCA::PKey::supportedTypes().contains(QCA::PKey::RSA) || !QCA::PKey::supportedIOTypes().contains(QCA::PKey::RSA))
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
		info[QCA::CommonName] = prompt_for("Common Name");
		info[QCA::Country] = prompt_for("Country Code (2 letters)");
		info[QCA::Organization] = prompt_for("Organization");
		info[QCA::Email] = prompt_for("Email");

		//info[QCA::URI] = "http://psi.affinix.com/";
		//info[QCA::DNS] = "psi.affinix.com";
		//info[QCA::IPAddress] = "192.168.0.1";
		//info[QCA::XMPP] = "justin@andbit.net";

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
		info[QCA::CommonName] = prompt_for("Common Name");
		info[QCA::Country] = prompt_for("Country Code (2 letters)");
		info[QCA::Organization] = prompt_for("Organization");
		info[QCA::Email] = prompt_for("Email");

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

		QCA::Certificate cert(args[1]);
		if(cert.isNull())
		{
			printf("Error reading cert file\n");
			return 1;
		}

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
		QCA::Store store = QCA::systemStore();

		// get nonroots
		if(args.count() >= 3)
			store += QCA::Store::fromFlatTextFile(args[2]);

		QCA::Validity v = store.validate(target);
		if(v == QCA::ValidityGood)
			printf("Certificate is valid\n");
		else
		{
			printf("Certificate is NOT valid: %s\n", validityToString(v).toLatin1().data());
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
