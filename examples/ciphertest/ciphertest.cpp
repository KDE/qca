/*
 Copyright (C) 2003 Justin Karneges

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

// TODO: this code needs to be updated for QCA2
#include"qca.h"
#include<stdio.h>

int main(int argc, char **argv)
{
	QCA::Initializer init;
	QCString cs = (argc >= 2) ? argv[1] : "hello";

	// AES128 test
	if(!QCA::isSupported("aes128"))
		printf("AES128 not supported!\n");
	else {
#if 0
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
#endif
	}

	// BlowFish, TripleDES, and AES256 tested dynamically
	if(!QCA::isSupported("blowfish"))
		printf("BlowFish not supported!\n");
//	else
//		doDynTest(new QCA::BlowFish, "bfish", cs);

	if(!QCA::isSupported("tripledes"))
		printf("TripleDES not supported!\n");
//	else
//		doDynTest(new QCA::TripleDES, "3des", cs);

	if(!QCA::isSupported("aes256"))
		printf("AES256 not supported!\n");
//	else
//		doDynTest(new QCA::AES256, "aes256", cs);

	return 0;
}

#if 0
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
#endif
