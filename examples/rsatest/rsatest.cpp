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
#include<qfile.h>
#include<qfileinfo.h>
#include"qca.h"
#include<stdio.h>

//#define USE_FILE

QCA::RSAKey readKeyFile(const QString &name)
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

	if(!k.fromDER(der)) {
		printf("%s: Error importing DER format.\n", name.latin1());
		return k;
	}
	char *yes = "yes";
	char *no = "no";
	printf("Successfully imported %s (enc=%s, dec=%s)\n",
		name.latin1(),
		k.havePublic() ? yes : no,
		k.havePrivate() ? yes : no);

	printf("Converting to DER: %d bytes\n", k.toDER().size());
	printf("Converting to PEM:\n%s\n", k.toPEM().latin1());
	return k;
}

int main(int argc, char **argv)
{
	QCA::init();
	QCString cs = (argc >= 2) ? argv[1] : "hello";

	if(!QCA::isSupported(QCA::CAP_RSA))
		printf("RSA not supported!\n");
	else {
#ifdef USE_FILE
		QCA::RSAKey pubkey = readKeyFile("keypublic.der");
		if(pubkey.isNull())
			return 1;
		QCA::RSAKey seckey = readKeyFile("keyprivate.der");
		if(seckey.isNull())
			return 1;
#else
		QCA::RSAKey seckey = QCA::RSA::generateKey(1024);
		if(seckey.isNull())
			return 1;
		QCA::RSAKey pubkey = seckey;
#endif
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

