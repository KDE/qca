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
#include<qdom.h>
#include<qfile.h>
#include"base64.h"
#include"qca.h"

QCA::Cert readCertXml(const QDomElement &e)
{
	QCA::Cert cert;
	// there should be one child data tag
	QDomElement data = e.elementsByTagName("data").item(0).toElement();
	if(!data.isNull())
		cert.fromDER(Base64::stringToArray(data.text()));
	return cert;
}

void showCertInfo(const QCA::Cert &cert)
{
	printf(" CN: %s\n", cert.subject()["CN"].latin1());
	printf(" Valid from: %s, until %s\n",
		cert.notBefore().toString().latin1(),
		cert.notAfter().toString().latin1());
	printf(" PEM:\n%s\n", cert.toPEM().latin1());
}

int main()
{
	if(!QCA::isSupported(QCA::CAP_X509)) {
		printf("X509 not supported!\n");
		return 1;
	}

	// open the Psi rootcerts file
	QFile f("/usr/local/share/psi/certs/rootcert.xml");
	if(!f.open(IO_ReadOnly)) {
		printf("unable to open %s\n", f.name().latin1());
		return 1;
	}
	QDomDocument doc;
	doc.setContent(&f);
	f.close();

	QDomElement base = doc.documentElement();
	if(base.tagName() != "store") {
		printf("wrong format of %s\n", f.name().latin1());
		return 1;
	}
	QDomNodeList cl = base.elementsByTagName("certificate");
	if(cl.count() == 0) {
		printf("no certs found in %s\n", f.name().latin1());
		return 1;
	}

	for(int n = 0; n < (int)cl.count(); ++n) {
		printf("-- Cert %d --\n", n);
		QCA::Cert cert = readCertXml(cl.item(n).toElement());
		if(cert.isNull()) {
			printf("error reading cert\n");
			continue;
		}
		showCertInfo(cert);
	}

	return 0;
}

