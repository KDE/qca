/*
 Copyright (C) 2003 Justin Karneges <justin@affinix.com>
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


#include <QtCrypto>

#include <QCoreApplication>

#include <iostream>

#ifdef QT_STATICPLUGIN
#include "import_plugins.h"
#endif

// dump out information about some part of the certificate
// we use this same approach for information about the subject
// of the certificate, and also about the issuer of the certificate
static void dumpCertificateInfo( QCA::CertificateInfo info)
{
    std::cout << "  Organization: " << std::endl;

    // Note that a single certificate can apply to more than one
    // organisation. QCA::Certificate is a multimap, so when you
    // ask for the values associated with a parameter, it returns
    // a list.
    QList<QString> orgInfoList = info.values(QCA::Organization);

    // foreach() interates over each value in the list, and we dump
    // out each value. Note that is uncommon for a certificate to
    // actually contain multiple values for a single parameter.
    QString organization;
    foreach( organization, orgInfoList ) {
	std::cout << "    " << qPrintable(organization) << std::endl;
    }

    std::cout << "  Country: " << std::endl;
    // As above, however this shows a more compact way to represent
    // the iteration and output.
    foreach( QString country, info.values(QCA::Country) ) {
	std::cout << "    " << qPrintable(country) << std::endl;
    }
}

// This is just a convenience routine
static void dumpSubjectInfo( QCA::CertificateInfo subject)
{
    std::cout << "Subject: " << std::endl;

    dumpCertificateInfo( subject );
}


// This is just a convenience routine
static void dumpIssuerInfo( QCA::CertificateInfo issuer)
{
    std::cout << "Issuer: " << std::endl;

    dumpCertificateInfo( issuer );
}


int main(int argc, char** argv)
{
    // the Initializer object sets things up, and
    // also does cleanup when it goes out of scope
    QCA::Initializer init;

    QCoreApplication app(argc, argv);

    // We need to ensure that we have certificate handling support
    if ( !QCA::isSupported( "cert" ) ) {
	std::cout << "Sorry, no PKI certificate support" << std::endl;
    	return 1;
    }

    // We are going to work with a number of certificates, and a
    // QList is a great template class for that
    QList<QCA::Certificate> certlist;

    // We do two different cases - if we provide an argument, it is taken
    // as a filename to read the keys from. If there is no argument, we just
    // read from the system store certificates.
    if (argc >= 2) {
	// we are going to read the certificates in using a single call
	// which requires a CertificateCollection.
	QCA::CertificateCollection filecerts;
	// The conversion can be tested (although you don't have to) to find out if it
	// worked.
	QCA::ConvertResult importResult;
	// This imports all the PEM encoded certificates from the file specified as the argument
	// Note that you pass in a pointer to the result argument.
	filecerts = QCA::CertificateCollection::fromFlatTextFile( argv[1], &importResult );
	if ( QCA::ConvertGood == importResult) {
	    std::cout << "Import succeeded" << std::endl;
	    // this turns the CertificateCollection into a QList of Certificate objects
	    certlist = filecerts.certificates();
	}
    } else {
	// we have no arguments, so just use the system certificates
	if ( !QCA::haveSystemStore() ) {
	    std::cout << "System certificates not available" << std::endl;
	    return 2;
	}

	// Similar to above, except we just want the system certificates
	QCA::CertificateCollection systemcerts = QCA::systemStore();

	// this turns the CertificateCollection into a QList of Certificate objects
	certlist = systemcerts.certificates();
    }

    std::cout << "Number of certificates: " << certlist.count() << std::endl;

    QCA::Certificate cert;
    foreach (cert, certlist) {
	std::cout << "Serial Number:";
	// the serial number of the certificate is a QCA::BigInteger, but we can
	// just convert it to a string, and then output it.
	std::cout << qPrintable(cert.serialNumber().toString()) << std::endl;

	// The subject information shows properties of who the certificate
	// applies to. See the convenience routines above.
	dumpSubjectInfo( cert.subjectInfo() );

	// The issuer information shows properties of who the certificate
	// was signed by. See the convenience routines above.
	dumpIssuerInfo( cert.issuerInfo() );

	// Test if the certificate can be used as a certificate authority
	if ( cert.isCA() ) {
	    std::cout << "Is certificate authority" << std::endl;
	} else {
	    std::cout << "Is not a certificate authority" << std::endl;
	}

	// Test if the certificate is self-signed.
	if (cert.isSelfSigned() ) {
	    std::cout << "Self signed" << std::endl;
	} else {
	    std::cout << "Is not self-signed!!!" << std::endl;
	}

	// Certificate are only valid between specific dates. We can get the dates
	// (as a QDateTime) using a couple of calls
	std::cout << "Valid from " << qPrintable(cert.notValidBefore().toString());
	std::cout << ", until " << qPrintable(cert.notValidAfter().toString());
	std::cout << std::endl;

	// You can get the certificate in PEM encoding with a simple toPEM() call
	std::cout << "PEM:" << std::endl;
	std::cout << qPrintable(cert.toPEM());
	std::cout << std::endl << std::endl;
   }

    return 0;
}

