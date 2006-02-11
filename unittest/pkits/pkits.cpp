/**
 * Copyright (C)  2006  Brad Hards <bradh@frogmouth.net>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "pkits.h"

void Pkits::initTestCase()
{
    m_init = new QCA::Initializer;
#include "../fixpaths.include"
}

void Pkits::cleanupTestCase()
{
    delete m_init;
}

static QCA::Certificate certFromDERFile(const QString &fileName, const QString &provider)
{
    QFile certFile(fileName);
    certFile.open(QFile::ReadOnly);
    QByteArray certArray = certFile.readAll();
    QCA::ConvertResult resultCert;
    QCA::Certificate cert = QCA::Certificate::fromDER( certArray, &resultCert, provider);
    return cert;
}

static QCA::CRL crlFromDERFile(const QString &fileName, const QString &provider)
{
    QFile crlFile(fileName);
    crlFile.open(QFile::ReadOnly);
    QByteArray crlArray = crlFile.readAll();
    QCA::ConvertResult crlResult;
    QCA::CRL crl = QCA::CRL::fromDER( crlArray, &crlResult, provider);
    return crl;
}

void Pkits::pkits4_1_1()
{
    QStringList providersToTest;
    providersToTest.append("qca-openssl");
    providersToTest.append("qca-gcrypt");
    providersToTest.append("qca-botan");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::Certificate cert = certFromDERFile("certs/ValidCertificatePathTest1EE.crt", provider);
	    QCOMPARE( cert.isNull(), false );

	    QCOMPARE( cert.policies().count(), 1 );
	    
	    QCA::CertificateCollection trusted;
	    QCA::CertificateCollection untrusted;
	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ErrorInvalidCA );
	    
	    QCA::Certificate root = certFromDERFile("certs/TrustAnchorRootCertificate.crt", provider);
	    QCOMPARE( root.isNull(), false );
	    trusted.addCertificate( root );
	    QCA::CRL rootCRL = crlFromDERFile("certs/TrustAnchorRootCRL.crl", provider);
	    QCOMPARE( rootCRL.isNull(), false );
	    trusted.addCRL( rootCRL );

	    QCA::Certificate ca = certFromDERFile("certs/GoodCACert.crt", provider);
	    QCOMPARE( ca.isNull(), false );
	    trusted.addCertificate( ca );
	    QCA::CRL caCRL = crlFromDERFile("certs/GoodCACRL.crl", provider);
	    QCOMPARE( caCRL.isNull(), false );
	    trusted.addCRL( caCRL );

	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ValidityGood );
	}
    }
}

void Pkits::pkits4_1_2()
{
    QStringList providersToTest;
    providersToTest.append("qca-openssl");
    providersToTest.append("qca-gcrypt");
    providersToTest.append("qca-botan");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::Certificate cert = certFromDERFile("certs/InvalidCASignatureTest2EE.crt", provider);
	    QCOMPARE( cert.isNull(), false );

	    QCOMPARE( cert.policies().count(), 1 );
	    
	    QCA::CertificateCollection trusted;
	    QCA::CertificateCollection untrusted;
	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ErrorInvalidCA );
	    
	    QCA::Certificate root = certFromDERFile("certs/TrustAnchorRootCertificate.crt", provider);
	    QCOMPARE( root.isNull(), false );
	    trusted.addCertificate( root );
	    QCA::CRL rootCRL = crlFromDERFile("certs/TrustAnchorRootCRL.crl", provider);
	    QCOMPARE( rootCRL.isNull(), false );
	    trusted.addCRL( rootCRL );

	    QCA::Certificate ca = certFromDERFile("certs/BadSignedCACert.crt", provider);
	    QCOMPARE( ca.isNull(), false );
	    trusted.addCertificate( ca );
	    QCA::CRL caCRL = crlFromDERFile("certs/BadSignedCACRL.crl", provider);
	    QCOMPARE( caCRL.isNull(), false );
	    trusted.addCRL( caCRL );

	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ErrorSignatureFailed );
	}
    }
}

void Pkits::pkits4_1_3()
{
    QStringList providersToTest;
    providersToTest.append("qca-openssl");
    providersToTest.append("qca-gcrypt");
    providersToTest.append("qca-botan");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::Certificate cert = certFromDERFile("certs/InvalidEESignatureTest3EE.crt", provider);
	    QCOMPARE( cert.isNull(), false );

	    QCOMPARE( cert.policies().count(), 1 );
	    
	    QCA::CertificateCollection trusted;
	    QCA::CertificateCollection untrusted;
	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ErrorInvalidCA );
	    
	    QCA::Certificate root = certFromDERFile("certs/TrustAnchorRootCertificate.crt", provider);
	    QCOMPARE( root.isNull(), false );
	    trusted.addCertificate( root );
	    QCA::CRL rootCRL = crlFromDERFile("certs/TrustAnchorRootCRL.crl", provider);
	    QCOMPARE( rootCRL.isNull(), false );
	    trusted.addCRL( rootCRL );

	    QCA::Certificate ca = certFromDERFile("certs/GoodCACert.crt", provider);
	    QCOMPARE( ca.isNull(), false );
	    trusted.addCertificate( ca );
	    QCA::CRL caCRL = crlFromDERFile("certs/GoodCACRL.crl", provider);
	    QCOMPARE( caCRL.isNull(), false );
	    trusted.addCRL( caCRL );

	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ErrorSignatureFailed );
	}
    }
}

void Pkits::pkits4_1_4()
{
    QStringList providersToTest;
    providersToTest.append("qca-openssl");
    providersToTest.append("qca-gcrypt");
    providersToTest.append("qca-botan");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::Certificate cert = certFromDERFile("certs/ValidDSASignaturesTest4EE.crt", provider);
	    QCOMPARE( cert.isNull(), false );

	    QCOMPARE( cert.policies().count(), 1 );
	    
	    QCA::CertificateCollection trusted;
	    QCA::CertificateCollection untrusted;
	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ErrorInvalidCA );
	    
	    QCA::Certificate root = certFromDERFile("certs/TrustAnchorRootCertificate.crt", provider);
	    QCOMPARE( root.isNull(), false );
	    trusted.addCertificate( root );
	    QCA::CRL rootCRL = crlFromDERFile("certs/TrustAnchorRootCRL.crl", provider);
	    QCOMPARE( rootCRL.isNull(), false );
	    trusted.addCRL( rootCRL );

	    QCA::Certificate ca = certFromDERFile("certs/DSACACert.crt", provider);
	    QCOMPARE( ca.isNull(), false );
	    trusted.addCertificate( ca );
	    QCA::CRL caCRL = crlFromDERFile("certs/DSACACRL.crl", provider);
	    QCOMPARE( caCRL.isNull(), false );
	    trusted.addCRL( caCRL );

	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ValidityGood );
	}
    }
}

void Pkits::pkits4_1_5()
{
    QStringList providersToTest;
    providersToTest.append("qca-openssl");
    providersToTest.append("qca-gcrypt");
    providersToTest.append("qca-botan");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::Certificate cert = certFromDERFile("certs/ValidDSAParameterInheritanceTest5EE.crt", provider);
	    QCOMPARE( cert.isNull(), false );

	    QCOMPARE( cert.policies().count(), 1 );
	    
	    QCA::CertificateCollection trusted;
	    QCA::CertificateCollection untrusted;
	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ErrorInvalidCA );
	    
	    QCA::Certificate root = certFromDERFile("certs/TrustAnchorRootCertificate.crt", provider);
	    QCOMPARE( root.isNull(), false );
	    trusted.addCertificate( root );
	    QCA::CRL rootCRL = crlFromDERFile("certs/TrustAnchorRootCRL.crl", provider);
	    QCOMPARE( rootCRL.isNull(), false );
	    trusted.addCRL( rootCRL );

	    QCA::Certificate ca = certFromDERFile("certs/DSACACert.crt", provider);
	    QCOMPARE( ca.isNull(), false );
	    trusted.addCertificate( ca );
	    QCA::CRL caCRL = crlFromDERFile("certs/DSACACRL.crl", provider);
	    QCOMPARE( caCRL.isNull(), false );
	    trusted.addCRL( caCRL );

	    QCA::Certificate params = certFromDERFile("certs/DSAParametersInheritedCACert.crt", provider);
	    QCOMPARE( params.isNull(), false );
	    trusted.addCertificate( params );
	    QCA::CRL paramsCRL = crlFromDERFile("certs/DSAParametersInheritedCACRL.crl", provider);
	    QCOMPARE( paramsCRL.isNull(), false );
	    trusted.addCRL( paramsCRL );

	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ValidityGood );
	}
    }
}

void Pkits::pkits4_1_6()
{
    QStringList providersToTest;
    providersToTest.append("qca-openssl");
    providersToTest.append("qca-gcrypt");
    providersToTest.append("qca-botan");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::Certificate cert = certFromDERFile("certs/InvalidDSASignatureTest6EE.crt", provider);
	    QCOMPARE( cert.isNull(), false );

	    QCOMPARE( cert.policies().count(), 1 );
	    
	    QCA::CertificateCollection trusted;
	    QCA::CertificateCollection untrusted;
	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ErrorInvalidCA );
	    
	    QCA::Certificate root = certFromDERFile("certs/TrustAnchorRootCertificate.crt", provider);
	    QCOMPARE( root.isNull(), false );
	    trusted.addCertificate( root );
	    QCA::CRL rootCRL = crlFromDERFile("certs/TrustAnchorRootCRL.crl", provider);
	    QCOMPARE( rootCRL.isNull(), false );
	    trusted.addCRL( rootCRL );

	    QCA::Certificate ca = certFromDERFile("certs/DSACACert.crt", provider);
	    QCOMPARE( ca.isNull(), false );
	    trusted.addCertificate( ca );
	    QCA::CRL caCRL = crlFromDERFile("certs/DSACACRL.crl", provider);
	    QCOMPARE( caCRL.isNull(), false );
	    trusted.addCRL( caCRL );

	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ValidityGood );
	}
    }
}

QTEST_MAIN(Pkits)
