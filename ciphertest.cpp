#include"qca.h"
#include<stdio.h>

static QCString arrayToCString(const QByteArray &);
static QByteArray cstringToArray(const QCString &);

int main(int argc, char **argv)
{
	QCA::init();
	QCString cs = (argc >= 2) ? argv[1] : "hello";

	if(!QCA::isSupported(QCA::CAP_TripleDES))
		printf("TripleDES not supported!\n");
	else {
		// encrypt
		QByteArray key = QCA::TripleDES::generateKey();
		QByteArray iv = QCA::TripleDES::generateIV();
		printf("3des:key:%s\n", QCA::arrayToHex(key).latin1());
		printf("3des:iv:%s\n", QCA::arrayToHex(iv).latin1());
		QCA::TripleDES c(QCA::Encrypt, key, iv);
		c.update(cstringToArray(cs));
		QByteArray f = c.final();
		QString result = QCA::arrayToHex(f);
		printf(">3des(\"%s\") = [%s]\n", cs.data(), result.latin1());

		// decrypt
		QCA::TripleDES d(QCA::Decrypt, key, iv);
		d.update(f);
		QCString dec = arrayToCString(d.final());
		printf("<3des(\"%s\") = [%s]\n", result.latin1(), dec.data());
	}

	if(!QCA::isSupported(QCA::CAP_AES128))
		printf("AES128 not supported!\n");
	else {
		// encrypt
		QByteArray key = QCA::AES128::generateKey();
		QByteArray iv = QCA::AES128::generateIV();
		QCA::AES128 c(QCA::Encrypt, key, iv);
		c.update(cstringToArray(cs));
		QByteArray f = c.final();
		QString result = QCA::arrayToHex(f);
		printf(">aes128(\"%s\") = [%s]\n", cs.data(), result.latin1());

		// decrypt
		QCA::AES128 d(QCA::Decrypt, key, iv);
		d.update(f);
		QCString dec = arrayToCString(d.final());
		printf("<aes128(\"%s\") = [%s]\n", result.latin1(), dec.data());
	}

	return 0;
}

QCString arrayToCString(const QByteArray &a)
{
	QCString cs;
	cs.resize(a.size()+1);
	memcpy(cs.data(), a.data(), a.size());
	return cs;
}

QByteArray cstringToArray(const QCString &cs)
{
	QByteArray a(cs.length());
	memcpy(a.data(), cs.data(), a.size());
	return a;
}

