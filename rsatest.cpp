#include<qfile.h>
#include"qca.h"
#include<stdio.h>

static QCA::RSAKey readKeyFile(const QString &name, bool sec=false)
{
	QCA::RSAKey k;
	QFile f(name);
	if(!f.open(IO_ReadOnly)) {
		printf("Unable to open %s\n", name.latin1());
		return k;
	}
	QByteArray der = f.readAll();
	f.close();
	printf("Read %s [%d bytes]\n", name.latin1(), der.size());

	if(!k.fromDER(der, sec)) {
		printf("%s: Error importing DER format.\n", name.latin1());
		return k;
	}
	printf("Successfully imported %s\n", name.latin1());
	return k;
}

int main(int argc, char **argv)
{
	QCA::init();
	QCString cs = (argc >= 2) ? argv[1] : "hello";

	if(!QCA::isSupported(QCA::CAP_RSA))
		printf("RSA not supported!\n");
	else {
		QCA::RSAKey pubkey = readKeyFile("keypublic.der");
		if(pubkey.isNull())
			return 1;
		QCA::RSAKey seckey = readKeyFile("keyprivate.der", true);
		if(seckey.isNull())
			return 1;

		// encrypt some data
		QByteArray a(cs.length());
		memcpy(a.data(), cs.data(), a.size());

		QCA::RSA op;
		op.setKey(pubkey);
		QByteArray result;
		if(!op.encrypt(a, &result)) {
			printf("Error encrypting.\n");
			return 1;
		}
		QString rstr = QCA::arrayToHex(result);
		printf(">rsa(\"%s\") = [%s]\n", cs.data(), rstr.latin1());

		// now decrypt it
		op.setKey(seckey);
		QByteArray dec;
		if(!op.decrypt(result, &dec)) {
			printf("Error decrypting.\n");
			return 1;
		}
		QCString dstr;
		dstr.resize(dec.size()+1);
		memcpy(dstr.data(), dec.data(), dec.size());
		printf("<rsa(\"%s\") = [%s]\n", rstr.latin1(), dstr.data());
	}

	return 0;
}

