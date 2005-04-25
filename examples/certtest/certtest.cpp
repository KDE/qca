/*
 Copyright (C) 2003 Justin Karneges
 Copyright (C) 2005 Brad Hards <bradh@frogmouth.net>

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


#include <QtCore>

#include <QtCrypto>

#include <iostream>

static void dumpCertificateInfo( QCA::CertificateInfo subject)
{
    std::cout << "  Common Name: " << std::endl;
    QList<QString> commonNameList = subject.values(QCA::CommonName);
    QString commonName;
    foreach( commonName, commonNameList ) {
	std::cout << "    " << qPrintable(commonName) << std::endl;
    }

    std::cout << "  Organization: " << std::endl;
    QList<QString> orgInfo = subject.values(QCA::Organization);
    QString organization;
    foreach( organization, orgInfo ) {
	std::cout << "    " << qPrintable(organization) << std::endl;
    }

    std::cout << "  Country: " << std::endl;
    QList<QString> countryList = subject.values(QCA::Country);
    QString country;
    foreach( country, countryList ) {
	std::cout << "    " << qPrintable(country) << std::endl;
    }
}

static void dumpSubjectInfo( QCA::CertificateInfo subject)
{
    std::cout << "Subject: " << std::endl;

    dumpCertificateInfo( subject );
}

static void dumpIssuerInfo( QCA::CertificateInfo subject)
{
    std::cout << "Issuer: " << std::endl;

    dumpCertificateInfo( subject );
}


int main(int argc, char** argv)
{
    // the Initializer object sets things up, and 
    // also does cleanup when it goes out of scope
    QCA::Initializer init;

    QCoreApplication app(argc, argv);

    // get all the available providers loaded.
    QCA::scanForPlugins();

    if ( !QCA::isSupported( "cert" ) ) {
	std::cout << "Sorry, no PKI certificate support" << std::endl;
    	return 1;
    }

    QList<QCA::Certificate> certlist;

    if (argc >= 2) {
	std::cout << "Reading certificates from : " << argv[1] << std::endl;
	QCA::CertificateCollection filecerts;
	QCA::ConvertResult importResult;
	filecerts = QCA::CertificateCollection::fromPKCS7File( argv[1], &importResult );
	if ( QCA::ConvertGood == importResult) {
	    std::cout << "Import succeeded" << std::endl;
	    certlist == filecerts.certificates();
	} else {
	    std::cout << "Import failed" << std::endl;
	}

    } else {
	if ( !QCA::haveSystemStore() ) {
	    std::cout << "System certificates not available" << std::endl;
	    return 2;
	}

	QCA::CertificateCollection systemcerts = QCA::systemStore();

	certlist = systemcerts.certificates();
    }

    QCA::Certificate cert;
    foreach (cert, certlist) {
	std::cout << "Serial Number:";
	std::cout << qPrintable(cert.serialNumber().toString()) << std::endl;

	dumpSubjectInfo( cert.subjectInfo() );

	dumpIssuerInfo( cert.issuerInfo() );

	if ( cert.isCA() ) {
	    std::cout << "Is certificate authority" << std::endl;
	} else {
	    std::cout << "Is not a certificate authority" << std::endl;
	}

	if (cert.isSelfSigned() ) {
	    std::cout << "Self signed" << std::endl;
	} else {
	    std::cout << "Is not self-signed!!!" << std::endl;
	}

	std::cout << "Valid from " << qPrintable(cert.notValidBefore().toString());
	std::cout << ", until " << qPrintable(cert.notValidAfter().toString());
	//std::cout << std::endl;
	//std::cout << "PEM:" << std::endl;
	//std::cout << qPrintable(cert.toPEM());
	std::cout << std::endl << std::endl;
   }

    return 0;
}

