#include"qca.h"
#include<stdio.h>

static QCString arrayToCString(const QByteArray &);
static QByteArray cstringToArray(const QCString &);
static void doDynTest(QCA::Cipher *c, const QString &name, const QCString &cs);

int main(int argc, char **argv)
{
	QCA::init();
	QCString cs = (argc >= 2) ? argv[1] : "hello";

	// AES128 test
	if(!QCA::isSupported(QCA::CAP_AES128))
		printf("AES128 not supported!\n");
	else {
		// encrypt
		QByteArray key = QCA::AES128::generateKey();
		QByteArray iv = QCA::AES128::generateIV();
		printf("aes128:key:%s\n", QCA::arrayToHex(key).latin1());
		printf("aes128:iv:%s\n", QCA::arrayToHex(iv).latin1());
		QCA::AES128 c(QCA::Encrypt, QCA::CBC, key, iv);
		c.update(cstringToArray(cs));
		QByteArray f = c.final();
		QString result = QCA::arrayToHex(f);
		printf(">aes128(\"%s\") = [%s]\n", cs.data(), result.latin1());

		// decrypt
		QCA::AES128 d(QCA::Decrypt, QCA::CBC, key, iv);
		d.update(f);
		QCString dec = arrayToCString(d.final());
		printf("<aes128(\"%s\") = [%s]\n", result.latin1(), dec.data());
	}

	// BlowFish, TripleDES, and AES256 tested dynamically
	if(!QCA::isSupported(QCA::CAP_BlowFish))
		printf("BlowFish not supported!\n");
	else
		doDynTest(new QCA::BlowFish, "bfish", cs);

	if(!QCA::isSupported(QCA::CAP_TripleDES))
		printf("TripleDES not supported!\n");
	else
		doDynTest(new QCA::TripleDES, "3des", cs);

	if(!QCA::isSupported(QCA::CAP_AES256))
		printf("AES256 not supported!\n");
	else
		doDynTest(new QCA::AES256, "aes256", cs);

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

void doDynTest(QCA::Cipher *c, const QString &name, const QCString &cs)
{
	// encrypt
	QByteArray key = c->dyn_generateKey();
	QByteArray iv = c->dyn_generateIV();
	printf("%s:key:%s\n", name.latin1(), QCA::arrayToHex(key).latin1());
	printf("%s:iv:%s\n", name.latin1(), QCA::arrayToHex(iv).latin1());
	c->reset(QCA::Encrypt, QCA::CBC, key, iv);
	c->update(cstringToArray(cs));
	QByteArray f = c->final();
	QString result = QCA::arrayToHex(f);
	printf(">%s(\"%s\") = [%s]\n", name.latin1(), cs.data(), result.latin1());

	// decrypt
	c->reset(QCA::Decrypt, QCA::CBC, key, iv);
	c->update(f);
	QCString dec = arrayToCString(c->final());
	printf("<%s(\"%s\") = [%s]\n", name.latin1(), result.latin1(), dec.data());
	delete c;
}

