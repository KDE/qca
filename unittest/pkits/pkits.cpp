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

#include <QtCrypto>
#include <QtTest/QtTest>

class Pkits : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();

    void pkits4_1_1();
    void pkits4_1_2();
    void pkits4_1_3();
    void pkits4_1_4();
    void pkits4_1_5();
    void pkits4_1_6();

    void pkits4_2_1();
    void pkits4_2_2();
    void pkits4_2_3();
    void pkits4_2_4();
    void pkits4_2_5();
    void pkits4_2_6();
    void pkits4_2_7();
    void pkits4_2_8();

    void pkits4_3_1();
    void pkits4_3_2();
    void pkits4_3_3();
    void pkits4_3_4();
    void pkits4_3_5();
    void pkits4_3_6();
    void pkits4_3_9();
#ifdef ALL_PKITS_TESTS
    void pkits4_3_7();
    void pkits4_3_8();
    void pkits4_3_10();
    void pkits4_3_11();
#endif
    void pkits4_4_1();
    void pkits4_4_2();
    void pkits4_4_3();

    void cleanupTestCase();
private:
    QCA::Initializer* m_init;
};

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
    providersToTest.append("qca-ossl");

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
	    untrusted.addCertificate( ca );
	    QCA::CRL caCRL = crlFromDERFile("certs/GoodCACRL.crl", provider);
	    QCOMPARE( caCRL.isNull(), false );
	    untrusted.addCRL( caCRL );

	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ValidityGood );
	}
    }
}

void Pkits::pkits4_1_2()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");

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
	    untrusted.addCertificate( ca );
	    QCA::CRL caCRL = crlFromDERFile("certs/BadSignedCACRL.crl", provider);
	    QCOMPARE( caCRL.isNull(), false );
	    untrusted.addCRL( caCRL );

	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ErrorSignatureFailed );
	}
    }
}

void Pkits::pkits4_1_3()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");

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
	    untrusted.addCertificate( ca );
	    QCA::CRL caCRL = crlFromDERFile("certs/GoodCACRL.crl", provider);
	    QCOMPARE( caCRL.isNull(), false );
	    untrusted.addCRL( caCRL );

	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ErrorSignatureFailed );
	}
    }
}

void Pkits::pkits4_1_4()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");

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
	    untrusted.addCertificate( ca );
	    QCA::CRL caCRL = crlFromDERFile("certs/DSACACRL.crl", provider);
	    QCOMPARE( caCRL.isNull(), false );
	    untrusted.addCRL( caCRL );

	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ValidityGood );
	}
    }
}

void Pkits::pkits4_1_5()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::Certificate cert = certFromDERFile("certs/ValidDSAParameterInheritanceTest5EE.crt", provider);
	    QCOMPARE( cert.isNull(), false );

	    // QCOMPARE( cert.policies().count(), 1 );

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
	    untrusted.addCertificate( ca );
	    QCA::CRL caCRL = crlFromDERFile("certs/DSACACRL.crl", provider);
	    QCOMPARE( caCRL.isNull(), false );
	    untrusted.addCRL( caCRL );

	    QCA::Certificate params = certFromDERFile("certs/DSAParametersInheritedCACert.crt", provider);
	    QCOMPARE( params.isNull(), false );
	    untrusted.addCertificate( params );
	    QCA::CRL paramsCRL = crlFromDERFile("certs/DSAParametersInheritedCACRL.crl", provider);
	    QCOMPARE( paramsCRL.isNull(), false );
	    untrusted.addCRL( paramsCRL );

	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ValidityGood );
	}
    }
}

void Pkits::pkits4_1_6()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::Certificate cert = certFromDERFile("certs/InvalidDSASignatureTest6EE.crt", provider);
	    QCOMPARE( cert.isNull(), false );

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
	    untrusted.addCertificate( ca );
	    QCA::CRL caCRL = crlFromDERFile("certs/DSACACRL.crl", provider);
	    QCOMPARE( caCRL.isNull(), false );
	    untrusted.addCRL( caCRL );

	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ErrorSignatureFailed );
	}
    }
}

void Pkits::pkits4_2_1()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::Certificate cert = certFromDERFile("certs/InvalidCAnotBeforeDateTest1EE.crt", provider);
	    QCOMPARE( cert.isNull(), false );

	    QCA::CertificateCollection trusted;
	    QCA::CertificateCollection untrusted;
	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ErrorInvalidCA );

	    QCA::Certificate root = certFromDERFile("certs/TrustAnchorRootCertificate.crt", provider);
	    QCOMPARE( root.isNull(), false );
	    trusted.addCertificate( root );
	    QCA::CRL rootCRL = crlFromDERFile("certs/TrustAnchorRootCRL.crl", provider);
	    QCOMPARE( rootCRL.isNull(), false );
	    trusted.addCRL( rootCRL );

	    QCA::Certificate ca = certFromDERFile("certs/BadnotBeforeDateCACert.crt", provider);
	    QCOMPARE( ca.isNull(), false );
	    untrusted.addCertificate( ca );
	    QCA::CRL caCRL = crlFromDERFile("certs/BadnotBeforeDateCACRL.crl", provider);
	    QCOMPARE( caCRL.isNull(), false );
	    untrusted.addCRL( caCRL );

	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ErrorExpired );
	}
    }
}

void Pkits::pkits4_2_2()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::Certificate cert = certFromDERFile("certs/InvalidEEnotBeforeDateTest2EE.crt", provider);
	    QCOMPARE( cert.isNull(), false );

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
	    untrusted.addCertificate( ca );
	    QCA::CRL caCRL = crlFromDERFile("certs/GoodCACRL.crl", provider);
	    QCOMPARE( caCRL.isNull(), false );
	    untrusted.addCRL( caCRL );

	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ErrorExpired );
	}
    }
}

void Pkits::pkits4_2_3()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::Certificate cert = certFromDERFile("certs/Validpre2000UTCnotBeforeDateTest3EE.crt", provider);
	    QCOMPARE( cert.isNull(), false );

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
	    untrusted.addCertificate( ca );
	    QCA::CRL caCRL = crlFromDERFile("certs/GoodCACRL.crl", provider);
	    QCOMPARE( caCRL.isNull(), false );
	    untrusted.addCRL( caCRL );

	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ValidityGood );
	}
    }
}

void Pkits::pkits4_2_4()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::Certificate cert = certFromDERFile("certs/ValidGeneralizedTimenotBeforeDateTest4EE.crt", provider);
	    QCOMPARE( cert.isNull(), false );

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
	    untrusted.addCertificate( ca );
	    QCA::CRL caCRL = crlFromDERFile("certs/GoodCACRL.crl", provider);
	    QCOMPARE( caCRL.isNull(), false );
	    untrusted.addCRL( caCRL );

	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ValidityGood );
	}
    }
}


void Pkits::pkits4_2_5()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::Certificate cert = certFromDERFile("certs/InvalidCAnotAfterDateTest5EE.crt", provider);
	    QCOMPARE( cert.isNull(), false );

	    QCA::CertificateCollection trusted;
	    QCA::CertificateCollection untrusted;
	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ErrorInvalidCA );

	    QCA::Certificate root = certFromDERFile("certs/TrustAnchorRootCertificate.crt", provider);
	    QCOMPARE( root.isNull(), false );
	    trusted.addCertificate( root );
	    QCA::CRL rootCRL = crlFromDERFile("certs/TrustAnchorRootCRL.crl", provider);
	    QCOMPARE( rootCRL.isNull(), false );
	    trusted.addCRL( rootCRL );

	    QCA::Certificate ca = certFromDERFile("certs/BadnotAfterDateCACert.crt", provider);
	    QCOMPARE( ca.isNull(), false );
	    untrusted.addCertificate( ca );
	    QCA::CRL caCRL = crlFromDERFile("certs/BadnotAfterDateCACRL.crl", provider);
	    QCOMPARE( caCRL.isNull(), false );
	    untrusted.addCRL( caCRL );

	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ErrorExpired );
	}
    }
}

void Pkits::pkits4_2_6()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::Certificate cert = certFromDERFile("certs/InvalidEEnotAfterDateTest6EE.crt", provider);
	    QCOMPARE( cert.isNull(), false );

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
	    untrusted.addCertificate( ca );
	    QCA::CRL caCRL = crlFromDERFile("certs/GoodCACRL.crl", provider);
	    QCOMPARE( caCRL.isNull(), false );
	    untrusted.addCRL( caCRL );

	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ErrorExpired );
	}
    }
}

void Pkits::pkits4_2_7()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::Certificate cert = certFromDERFile("certs/Invalidpre2000UTCEEnotAfterDateTest7EE.crt", provider);
	    QCOMPARE( cert.isNull(), false );

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
	    untrusted.addCertificate( ca );
	    QCA::CRL caCRL = crlFromDERFile("certs/GoodCACRL.crl", provider);
	    QCOMPARE( caCRL.isNull(), false );
	    untrusted.addCRL( caCRL );

	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ErrorExpired );
	}
    }
}

void Pkits::pkits4_2_8()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::Certificate cert = certFromDERFile("certs/ValidGeneralizedTimenotAfterDateTest8EE.crt", provider);
	    QCOMPARE( cert.isNull(), false );

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
	    untrusted.addCertificate( ca );
	    QCA::CRL caCRL = crlFromDERFile("certs/GoodCACRL.crl", provider);
	    QCOMPARE( caCRL.isNull(), false );
	    untrusted.addCRL( caCRL );

	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ValidityGood );
	}
    }
}

void Pkits::pkits4_3_1()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::Certificate cert = certFromDERFile("certs/InvalidNameChainingTest1EE.crt", provider);
	    QCOMPARE( cert.isNull(), false );

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
	    untrusted.addCertificate( ca );
	    QCA::CRL caCRL = crlFromDERFile("certs/GoodCACRL.crl", provider);
	    QCOMPARE( caCRL.isNull(), false );
	    untrusted.addCRL( caCRL );

	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ErrorInvalidCA );
	}
    }
}

void Pkits::pkits4_3_2()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::Certificate cert = certFromDERFile("certs/InvalidNameChainingOrderTest2EE.crt", provider);
	    QCOMPARE( cert.isNull(), false );

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
	    untrusted.addCertificate( ca );
	    QCA::CRL caCRL = crlFromDERFile("certs/GoodCACRL.crl", provider);
	    QCOMPARE( caCRL.isNull(), false );
	    untrusted.addCRL( caCRL );

	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ErrorInvalidCA );
	}
    }
}

void Pkits::pkits4_3_3()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::Certificate cert = certFromDERFile("certs/ValidNameChainingWhitespaceTest3EE.crt", provider);
	    QCOMPARE( cert.isNull(), false );

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
	    untrusted.addCertificate( ca );
	    QCA::CRL caCRL = crlFromDERFile("certs/GoodCACRL.crl", provider);
	    QCOMPARE( caCRL.isNull(), false );
	    untrusted.addCRL( caCRL );

	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ValidityGood );
	}
    }
}


void Pkits::pkits4_3_4()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::Certificate cert = certFromDERFile("certs/ValidNameChainingWhitespaceTest4EE.crt", provider);
	    QCOMPARE( cert.isNull(), false );

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
	    untrusted.addCertificate( ca );
	    QCA::CRL caCRL = crlFromDERFile("certs/GoodCACRL.crl", provider);
	    QCOMPARE( caCRL.isNull(), false );
	    untrusted.addCRL( caCRL );

	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ValidityGood );
	}
    }
}

void Pkits::pkits4_3_5()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::Certificate cert = certFromDERFile("certs/ValidNameChainingCapitalizationTest5EE.crt", provider);
	    QCOMPARE( cert.isNull(), false );

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
	    untrusted.addCertificate( ca );
	    QCA::CRL caCRL = crlFromDERFile("certs/GoodCACRL.crl", provider);
	    QCOMPARE( caCRL.isNull(), false );
	    untrusted.addCRL( caCRL );

	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ValidityGood );
	}
    }
}

void Pkits::pkits4_3_6()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::Certificate cert = certFromDERFile("certs/ValidNameUIDsTest6EE.crt", provider);
	    QCOMPARE( cert.isNull(), false );

	    QCA::CertificateCollection trusted;
	    QCA::CertificateCollection untrusted;
	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ErrorInvalidCA );

	    QCA::Certificate root = certFromDERFile("certs/TrustAnchorRootCertificate.crt", provider);
	    QCOMPARE( root.isNull(), false );
	    trusted.addCertificate( root );
	    QCA::CRL rootCRL = crlFromDERFile("certs/TrustAnchorRootCRL.crl", provider);
	    QCOMPARE( rootCRL.isNull(), false );
	    trusted.addCRL( rootCRL );

	    QCA::Certificate ca = certFromDERFile("certs/UIDCACert.crt", provider);
	    QCOMPARE( ca.isNull(), false );
	    untrusted.addCertificate( ca );
	    QCA::CRL caCRL = crlFromDERFile("certs/UIDCACRL.crl", provider);
	    QCOMPARE( caCRL.isNull(), false );
	    untrusted.addCRL( caCRL );

	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ValidityGood );
	}
    }
}

#ifdef ALL_PKITS_TESTS
void Pkits::pkits4_3_7()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::Certificate cert = certFromDERFile("certs/ValidRFC3280MandatoryAttributeTypesTest7EE.crt", provider);
	    QCOMPARE( cert.isNull(), false );

	    QCA::CertificateCollection trusted;
	    QCA::CertificateCollection untrusted;
	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ErrorInvalidCA );

	    QCA::Certificate root = certFromDERFile("certs/TrustAnchorRootCertificate.crt", provider);
	    QCOMPARE( root.isNull(), false );
	    trusted.addCertificate( root );
	    QCA::CRL rootCRL = crlFromDERFile("certs/TrustAnchorRootCRL.crl", provider);
	    QCOMPARE( rootCRL.isNull(), false );
	    trusted.addCRL( rootCRL );

	    QCA::Certificate ca = certFromDERFile("certs/RFC3280MandatoryAttributeTypesCACert.crt", provider);
	    QCOMPARE( ca.isNull(), false );
	    untrusted.addCertificate( ca );
	    QCA::CRL caCRL = crlFromDERFile("certs/RFC3280MandatoryAttributeTypesCACRL.crl", provider);
	    QCOMPARE( caCRL.isNull(), false );
	    untrusted.addCRL( caCRL );

	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ValidityGood );
	}
    }
}
#endif

#ifdef ALL_PKITS_TESTS
void Pkits::pkits4_3_8()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::Certificate cert = certFromDERFile("certs/ValidRFC3280OptionalAttributeTypesTest8EE.crt", provider);
	    QCOMPARE( cert.isNull(), false );

	    QCA::CertificateCollection trusted;
	    QCA::CertificateCollection untrusted;
	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ErrorInvalidCA );

	    QCA::Certificate root = certFromDERFile("certs/TrustAnchorRootCertificate.crt", provider);
	    QCOMPARE( root.isNull(), false );
	    trusted.addCertificate( root );
	    QCA::CRL rootCRL = crlFromDERFile("certs/TrustAnchorRootCRL.crl", provider);
	    QCOMPARE( rootCRL.isNull(), false );
	    trusted.addCRL( rootCRL );

	    QCA::Certificate ca = certFromDERFile("certs/RFC3280OptionalAttributeTypesCACert.crt", provider);
	    QCOMPARE( ca.isNull(), false );
	    untrusted.addCertificate( ca );
	    QCA::CRL caCRL = crlFromDERFile("certs/RFC3280OptionalAttributeTypesCACRL.crl", provider);
	    QCOMPARE( caCRL.isNull(), false );
	    untrusted.addCRL( caCRL );

	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ValidityGood );
	}
    }
}
#endif

void Pkits::pkits4_3_9()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::Certificate cert = certFromDERFile("certs/ValidUTF8StringEncodedNamesTest9EE.crt", provider);
	    QCOMPARE( cert.isNull(), false );

	    QCA::CertificateCollection trusted;
	    QCA::CertificateCollection untrusted;
	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ErrorInvalidCA );

	    QCA::Certificate root = certFromDERFile("certs/TrustAnchorRootCertificate.crt", provider);
	    QCOMPARE( root.isNull(), false );
	    trusted.addCertificate( root );
	    QCA::CRL rootCRL = crlFromDERFile("certs/TrustAnchorRootCRL.crl", provider);
	    QCOMPARE( rootCRL.isNull(), false );
	    trusted.addCRL( rootCRL );

	    QCA::Certificate ca = certFromDERFile("certs/UTF8StringEncodedNamesCACert.crt", provider);
	    QCOMPARE( ca.isNull(), false );
	    untrusted.addCertificate( ca );
	    QCA::CRL caCRL = crlFromDERFile("certs/UTF8StringEncodedNamesCACRL.crl", provider);
	    QCOMPARE( caCRL.isNull(), false );
	    untrusted.addCRL( caCRL );

	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ValidityGood );
	}
    }
}

#ifdef ALL_PKITS_TESTS
void Pkits::pkits4_3_10()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::Certificate cert = certFromDERFile("certs/ValidRolloverfromPrintableStringtoUTF8StringTest10EE.crt", provider);
	    QCOMPARE( cert.isNull(), false );

	    QCA::CertificateCollection trusted;
	    QCA::CertificateCollection untrusted;
	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ErrorInvalidCA );

	    QCA::Certificate root = certFromDERFile("certs/TrustAnchorRootCertificate.crt", provider);
	    QCOMPARE( root.isNull(), false );
	    trusted.addCertificate( root );
	    QCA::CRL rootCRL = crlFromDERFile("certs/TrustAnchorRootCRL.crl", provider);
	    QCOMPARE( rootCRL.isNull(), false );
	    trusted.addCRL( rootCRL );

	    QCA::Certificate ca = certFromDERFile("certs/RolloverfromPrintableStringtoUTF8StringCACert.crt", provider);
	    QCOMPARE( ca.isNull(), false );
	    untrusted.addCertificate( ca );
	    QCA::CRL caCRL = crlFromDERFile("certs/RolloverfromPrintableStringtoUTF8StringCACRL.crl", provider);
	    QCOMPARE( caCRL.isNull(), false );
	    untrusted.addCRL( caCRL );

	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ValidityGood );
	}
    }
}
#endif

#ifdef ALL_PKITS_TESTS
void Pkits::pkits4_3_11()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::Certificate cert = certFromDERFile("certs/ValidUTF8StringCaseInsensitiveMatchTest11EE.crt", provider);
	    QCOMPARE( cert.isNull(), false );

	    QCA::CertificateCollection trusted;
	    QCA::CertificateCollection untrusted;
	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ErrorInvalidCA );

	    QCA::Certificate root = certFromDERFile("certs/TrustAnchorRootCertificate.crt", provider);
	    QCOMPARE( root.isNull(), false );
	    trusted.addCertificate( root );
	    QCA::CRL rootCRL = crlFromDERFile("certs/TrustAnchorRootCRL.crl", provider);
	    QCOMPARE( rootCRL.isNull(), false );
	    trusted.addCRL( rootCRL );

	    QCA::Certificate ca = certFromDERFile("certs/UTF8StringCaseInsensitiveMatchCACert.crt", provider);
	    QCOMPARE( ca.isNull(), false );
	    untrusted.addCertificate( ca );
	    QCA::CRL caCRL = crlFromDERFile("certs/UTF8StringCaseInsensitiveMatchCACRL.crl", provider);
	    QCOMPARE( caCRL.isNull(), false );
	    untrusted.addCRL( caCRL );

	    qDebug() << "validity: " << cert.validate( trusted, untrusted );

	    QEXPECT_FAIL("", "This should validate, but it doesn't (QCA::ErrorInvalidCA)", Continue);
	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ValidityGood );
	}
    }
}
#endif

void Pkits::pkits4_4_1()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::Certificate cert = certFromDERFile("certs/InvalidMissingCRLTest1EE.crt", provider);
	    QCOMPARE( cert.isNull(), false );

	    QCA::CertificateCollection trusted;
	    QCA::CertificateCollection untrusted;
	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ErrorInvalidCA );

	    QCA::Certificate root = certFromDERFile("certs/TrustAnchorRootCertificate.crt", provider);
	    QCOMPARE( root.isNull(), false );
	    trusted.addCertificate( root );
	    QCA::CRL rootCRL = crlFromDERFile("certs/TrustAnchorRootCRL.crl", provider);
	    QCOMPARE( rootCRL.isNull(), false );
	    trusted.addCRL( rootCRL );

	    QCA::Certificate ca = certFromDERFile("certs/NoCRLCACert.crt", provider);
	    QCOMPARE( ca.isNull(), false );
	    untrusted.addCertificate( ca );

	    qDebug() << "validity: " << cert.validate( trusted, untrusted );

	    QEXPECT_FAIL("", "This should not validate, but it does", Continue);
	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ErrorInvalidCA );
	}
    }
}

void Pkits::pkits4_4_2()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::Certificate cert = certFromDERFile("certs/InvalidRevokedCATest2EE.crt", provider);
	    QCOMPARE( cert.isNull(), false );

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
	    untrusted.addCertificate( ca );
	    QCA::CRL caCRL = crlFromDERFile("certs/GoodCACRL.crl", provider);
	    QCOMPARE( caCRL.isNull(), false );
	    untrusted.addCRL( caCRL );

	    QCA::Certificate subca = certFromDERFile("certs/RevokedsubCACert.crt", provider);
	    QCOMPARE( subca.isNull(), false );
	    untrusted.addCertificate( subca );
	    QCA::CRL subcaCRL = crlFromDERFile("certs/RevokedsubCACRL.crl", provider);
	    QCOMPARE( subcaCRL.isNull(), false );
	    untrusted.addCRL( subcaCRL );

	    qDebug() << "validity: " << cert.validate( trusted, untrusted );

	    QEXPECT_FAIL("", "This should not validate, but it does", Continue);
	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ErrorInvalidCA );
	}
    }
}

void Pkits::pkits4_4_3()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::Certificate cert = certFromDERFile("certs/InvalidRevokedEETest3EE.crt", provider);
	    QCOMPARE( cert.isNull(), false );

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
	    untrusted.addCertificate( ca );
	    QCA::CRL caCRL = crlFromDERFile("certs/GoodCACRL.crl", provider);
	    QCOMPARE( caCRL.isNull(), false );
	    untrusted.addCRL( caCRL );

	    qDebug() << "validity: " << cert.validate( trusted, untrusted );

	    QEXPECT_FAIL("", "This should not validate, but it does", Continue);
	    QCOMPARE( cert.validate( trusted, untrusted ), QCA::ErrorUntrusted );
	}
    }
}

QTEST_MAIN(Pkits)

#include "pkits.moc"

