/**
 * Copyright (C)  2004-2006  Brad Hards <bradh@frogmouth.net>
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

#ifdef QT_STATICPLUGIN
#include "import_plugins.h"
#endif

class CertUnitTest : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void checkSystemStore();
    void nullCert();
    void noSuchFile();
    void CAcertstest();
    void derCAcertstest();
    void qualitysslcatest();
    void checkExpiredClientCerts();
    void checkClientCerts();
    void altName();
    void extXMPP();
    void checkExpiredServerCerts();
    void checkServerCerts();
    void altNames76();
    void sha256cert();
    void crl();
    void crl2();
    void csr();
    void csr2();
    void cleanupTestCase();
private:
    QCA::Initializer* m_init;
};

void CertUnitTest::initTestCase()
{
    m_init = new QCA::Initializer;
}

void CertUnitTest::cleanupTestCase()
{
    delete m_init;
}

void CertUnitTest::nullCert()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");
    // providersToTest.append("qca-botan");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::Certificate nullCert;
	    QVERIFY(nullCert.isNull());
	    QCA::Certificate anotherNullCert = nullCert;
	    QVERIFY( anotherNullCert.isNull() );
	    QCOMPARE( nullCert, anotherNullCert );
	}
    }
}

void CertUnitTest::noSuchFile()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");
    // providersToTest.append("qca-botan");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::ConvertResult resultNoFile;
	    QCA::Certificate cert = QCA::Certificate::fromPEMFile( "thisIsJustaFileNameThatWeDontHave", &resultNoFile, provider);
	    QCOMPARE( resultNoFile, QCA::ErrorFile );
            QVERIFY(  cert.isNull() );
        }
    }
}

void CertUnitTest::CAcertstest()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");
    // providersToTest.append("qca-botan");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::ConvertResult resultca1;
	    QCA::Certificate ca1 = QCA::Certificate::fromPEMFile( "certs/RootCAcert.pem", &resultca1, provider);

	    QCOMPARE( resultca1, QCA::ConvertGood );
	    QCOMPARE( ca1.isNull(), false );
	    QCOMPARE( ca1.pathLimit(), 0 );
	    QCOMPARE( ca1.isCA(), true );
	    QCOMPARE( ca1.isSelfSigned(), true );

	    QCOMPARE( ca1.serialNumber(), QCA::BigInteger(0) );

	    QCOMPARE( ca1.commonName(), QString("For Tests Only") );

	    QCOMPARE( ca1.notValidBefore().toString(), QDateTime( QDate( 2001, 8, 17 ), QTime( 8, 30, 39 ), Qt::UTC ).toString() );
	    QCOMPARE( ca1.notValidAfter().toString(), QDateTime( QDate( 2011, 8, 15 ), QTime( 8, 30, 39 ), Qt::UTC ).toString() );

	    QCOMPARE( ca1.constraints().contains(QCA::DigitalSignature) == true, true );
	    QCOMPARE( ca1.constraints().contains(QCA::NonRepudiation) == true, true );
	    QCOMPARE( ca1.constraints().contains(QCA::KeyEncipherment) == true, true );
	    QCOMPARE( ca1.constraints().contains(QCA::DataEncipherment) == true, false );
	    QCOMPARE( ca1.constraints().contains(QCA::KeyAgreement) == true, false );
	    QCOMPARE( ca1.constraints().contains(QCA::KeyCertificateSign) == true, true );
	    QCOMPARE( ca1.constraints().contains(QCA::CRLSign) == true, true );
	    QCOMPARE( ca1.constraints().contains(QCA::EncipherOnly) == true, false );
	    QCOMPARE( ca1.constraints().contains(QCA::DecipherOnly) == true, false );
	    QCOMPARE( ca1.constraints().contains(QCA::ServerAuth) == true, false );
	    QCOMPARE( ca1.constraints().contains(QCA::ClientAuth) == true, false );
	    QCOMPARE( ca1.constraints().contains(QCA::CodeSigning) == true, false );
	    QCOMPARE( ca1.constraints().contains(QCA::EmailProtection) == true, false );
	    QCOMPARE( ca1.constraints().contains(QCA::IPSecEndSystem) == true, false );
	    QCOMPARE( ca1.constraints().contains(QCA::IPSecTunnel) == true, false);
	    QCOMPARE( ca1.constraints().contains(QCA::IPSecUser) == true, false );
	    QCOMPARE( ca1.constraints().contains(QCA::TimeStamping) == true, false );
	    QCOMPARE( ca1.constraints().contains(QCA::OCSPSigning) == true, false );

	    // no policies on this cert
	    QCOMPARE( ca1.policies().count(), 0 );
	}
    }
}

void CertUnitTest::qualitysslcatest()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");
    // providersToTest.append("qca-botan");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::ConvertResult resultca1;
	    QCA::Certificate ca1 = QCA::Certificate::fromPEMFile( "certs/QualitySSLIntermediateCA.crt", &resultca1, provider);

	    QCOMPARE( resultca1, QCA::ConvertGood );
	    QCOMPARE( ca1.isNull(), false );
	    QCOMPARE( ca1.isCA(), true );
	    QCOMPARE( ca1.isSelfSigned(), false );

	    QCOMPARE( ca1.signatureAlgorithm(), QCA::EMSA3_SHA1 );

	    QCOMPARE( ca1.serialNumber(), QCA::BigInteger("33555098") );

	    QCOMPARE( ca1.commonName(), QString("Comodo Class 3 Security Services CA") );

	    QCOMPARE( ca1.notValidBefore().toString(), QDateTime( QDate( 2002, 8, 27 ), QTime( 19, 02, 00 ), Qt::UTC ).toString() );
	    QCOMPARE( ca1.notValidAfter().toString(), QDateTime( QDate( 2012, 8, 27 ), QTime( 23, 59, 00 ), Qt::UTC ).toString() );


	    QCOMPARE( ca1.pathLimit(), 0 );

	    QCOMPARE( ca1.constraints().contains(QCA::DigitalSignature) == true, true );
	    QCOMPARE( ca1.constraints().contains(QCA::NonRepudiation) == true, true );
	    QCOMPARE( ca1.constraints().contains(QCA::KeyEncipherment) == true, true );
	    QCOMPARE( ca1.constraints().contains(QCA::DataEncipherment) == true, false );
	    QCOMPARE( ca1.constraints().contains(QCA::KeyAgreement) == true, false );
	    QCOMPARE( ca1.constraints().contains(QCA::KeyCertificateSign) == true, true );
	    QCOMPARE( ca1.constraints().contains(QCA::CRLSign) == true, true );
	    QCOMPARE( ca1.constraints().contains(QCA::EncipherOnly) == true, false );
	    QCOMPARE( ca1.constraints().contains(QCA::DecipherOnly) == true, false );
	    QCOMPARE( ca1.constraints().contains(QCA::ServerAuth) == true, false );
	    QCOMPARE( ca1.constraints().contains(QCA::ClientAuth) == true, false );
	    QCOMPARE( ca1.constraints().contains(QCA::CodeSigning) == true, false );
	    QCOMPARE( ca1.constraints().contains(QCA::EmailProtection) == true, false );
	    QCOMPARE( ca1.constraints().contains(QCA::IPSecEndSystem) == true, false );
	    QCOMPARE( ca1.constraints().contains(QCA::IPSecTunnel) == true, false);
	    QCOMPARE( ca1.constraints().contains(QCA::IPSecUser) == true, false );
	    QCOMPARE( ca1.constraints().contains(QCA::TimeStamping) == true, false );
	    QCOMPARE( ca1.constraints().contains(QCA::OCSPSigning) == true, false );
	}
    }
}

void CertUnitTest::checkExpiredClientCerts()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");
    // providersToTest.append("qca-botan");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::ConvertResult resultClient1;
	    QCA::Certificate client1 = QCA::Certificate::fromPEMFile( "certs/User.pem", &resultClient1, provider);
	    QCOMPARE( resultClient1, QCA::ConvertGood );
	    QCOMPARE( client1.isNull(), false );
	    QCOMPARE( client1.isCA(), false );
	    QCOMPARE( client1.isSelfSigned(), false );

	    QCOMPARE( client1.serialNumber(), QCA::BigInteger(2) );

	    QCOMPARE( client1.commonName(), QString("Insecure User Test Cert") );

	    QCOMPARE( client1.notValidBefore().toString(), QDateTime( QDate( 2001, 8, 17 ), QTime( 8, 32, 38 ), Qt::UTC ).toString() );
	    QCOMPARE( client1.notValidAfter().toString(), QDateTime( QDate( 2006, 8, 16 ), QTime( 8, 32, 38 ), Qt::UTC ).toString() );

	    QCOMPARE( client1.constraints().contains(QCA::DigitalSignature) == true, true );
	    QCOMPARE( client1.constraints().contains(QCA::NonRepudiation) == true, true );
	    QCOMPARE( client1.constraints().contains(QCA::KeyEncipherment) == true, true );
	    QCOMPARE( client1.constraints().contains(QCA::DataEncipherment) == true, true );
	    QCOMPARE( client1.constraints().contains(QCA::KeyAgreement) == true, false );
	    QCOMPARE( client1.constraints().contains(QCA::KeyCertificateSign) == true, false );
	    QCOMPARE( client1.constraints().contains(QCA::CRLSign) == true, false );
	    QCOMPARE( client1.constraints().contains(QCA::EncipherOnly) == true, false );
	    QCOMPARE( client1.constraints().contains(QCA::DecipherOnly) == true, false );
	    QCOMPARE( client1.constraints().contains(QCA::ServerAuth) == true, false );
	    QCOMPARE( client1.constraints().contains(QCA::ClientAuth) == true, true );
	    QCOMPARE( client1.constraints().contains(QCA::CodeSigning) == true, false );
	    QCOMPARE( client1.constraints().contains(QCA::EmailProtection) == true, true );
	    QCOMPARE( client1.constraints().contains(QCA::IPSecEndSystem) == true, false );
	    QCOMPARE( client1.constraints().contains(QCA::IPSecTunnel) == true, false);
	    QCOMPARE( client1.constraints().contains(QCA::IPSecUser) == true, false );
	    QCOMPARE( client1.constraints().contains(QCA::TimeStamping) == true, false );
	    QCOMPARE( client1.constraints().contains(QCA::OCSPSigning) == true, false );

	    // no policies on this cert
	    QCOMPARE( client1.policies().count(), 0 );

	    QCA::CertificateInfo subject1 = client1.subjectInfo();
	    QCOMPARE( subject1.isEmpty(), false );
	    QCOMPARE( subject1.values(QCA::Country).contains("de") == true, true );
	    QCOMPARE( subject1.values(QCA::Organization).contains("InsecureTestCertificate") == true, true );
	    QCOMPARE( subject1.values(QCA::CommonName).contains("Insecure User Test Cert") == true, true );

	    QCA::CertificateInfo issuer1 = client1.issuerInfo();
	    QCOMPARE( issuer1.isEmpty(), false );
	    QCOMPARE( issuer1.values(QCA::Country).contains("de") == true, true );
	    QCOMPARE( issuer1.values(QCA::Organization).contains("InsecureTestCertificate") == true, true );
	    QCOMPARE( issuer1.values(QCA::CommonName).contains("For Tests Only") == true, true );

	    QByteArray subjectKeyID = QCA::Hex().stringToArray("889E7EF729719D7B280F361AAE6D00D39DE1AADB").toByteArray();
	    QCOMPARE( client1.subjectKeyId(), subjectKeyID );
	    QCOMPARE( QCA::Hex().arrayToString(client1.issuerKeyId()), QString("bf53438278d09ec380e51b67ca0500dfb94883a5") );

	    QCA::PublicKey pubkey1 = client1.subjectPublicKey();
	    QCOMPARE( pubkey1.isNull(), false );
	    QCOMPARE( pubkey1.isRSA(), true );
	    QCOMPARE( pubkey1.isDSA(), false );
	    QCOMPARE( pubkey1.isDH(), false );
	    QCOMPARE( pubkey1.isPublic(), true );
	    QCOMPARE( pubkey1.isPrivate(), false );
	    QCOMPARE( pubkey1.bitSize(), 1024 );

	    QCOMPARE( client1.pathLimit(), 0 );

	    QCOMPARE( client1.signatureAlgorithm(), QCA::EMSA3_MD5 );

	    QCA::CertificateCollection trusted;
	    QCA::CertificateCollection untrusted;
	    QCOMPARE( client1.validate( trusted, untrusted ), QCA::ErrorInvalidCA );

	    QCA::ConvertResult resultca1;
	    QCA::Certificate ca1 = QCA::Certificate::fromPEMFile( "certs/RootCAcert.pem", &resultca1, provider);
	    QCOMPARE( resultca1, QCA::ConvertGood );
	    trusted.addCertificate( ca1 );

	    QCOMPARE( client1.validate( trusted, untrusted ), QCA::ErrorExpired );
	    QCOMPARE( client1.validate( trusted, untrusted, QCA::UsageAny ), QCA::ErrorExpired );
	    QCOMPARE( client1.validate( trusted, untrusted, QCA::UsageTLSServer ), QCA::ErrorExpired );
	    QCOMPARE( client1.validate( trusted, untrusted, QCA::UsageTLSClient ), QCA::ErrorExpired );
	    QCOMPARE( client1.validate( trusted, untrusted, QCA::UsageCodeSigning ), QCA::ErrorExpired );
	    QCOMPARE( client1.validate( trusted, untrusted, QCA::UsageTimeStamping ), QCA::ErrorExpired );
	    QCOMPARE( client1.validate( trusted, untrusted, QCA::UsageEmailProtection ), QCA::ErrorExpired );
	    QCOMPARE( client1.validate( trusted, untrusted, QCA::UsageCRLSigning ), QCA::ErrorExpired );
	    QByteArray derClient1 = client1.toDER();
	    QCOMPARE( derClient1.isEmpty(), false );
	    QCA::Certificate fromDer1 = QCA::Certificate::fromDER( derClient1, &resultClient1, provider );
	    QCOMPARE( resultClient1, QCA::ConvertGood );
	    QVERIFY( fromDer1 == client1 );

	    QString pemClient1 = client1.toPEM();
	    QCOMPARE( pemClient1.isEmpty(), false );
	    QCA::Certificate fromPem1 = QCA::Certificate::fromPEM( pemClient1, &resultClient1, provider);
	    QCOMPARE( resultClient1, QCA::ConvertGood );
	    QVERIFY( fromPem1 == client1);
	    QCOMPARE( fromPem1 != fromDer1, false );
	}
    }
}

void CertUnitTest::checkClientCerts()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");
    // providersToTest.append("qca-botan");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::ConvertResult resultClient2;
	    QCA::Certificate client2 = QCA::Certificate::fromPEMFile( "certs/QcaTestClientCert.pem", &resultClient2, provider);
	    QCOMPARE( resultClient2, QCA::ConvertGood );
	    QCOMPARE( client2.isNull(), false );
	    QCOMPARE( client2.isCA(), false );
	    QCOMPARE( client2.isSelfSigned(), false );

	    QCOMPARE( client2.serialNumber(), QCA::BigInteger("13149359243510447488") );

	    QCOMPARE( client2.commonName(), QString("Qca Test Client Certificate") );

	    QCOMPARE( client2.notValidBefore().toString(), QDateTime( QDate( 2013, 7, 31 ), QTime( 15, 14, 28 ), Qt::UTC ).toString() );
	    QCOMPARE( client2.notValidAfter().toString(), QDateTime( QDate( 2033, 7, 26 ), QTime( 15, 14, 28 ), Qt::UTC ).toString() );

	    QCOMPARE( client2.constraints().contains(QCA::DigitalSignature) == true, true );
	    QCOMPARE( client2.constraints().contains(QCA::NonRepudiation) == true, true );
	    QCOMPARE( client2.constraints().contains(QCA::KeyEncipherment) == true, true );
	    QCOMPARE( client2.constraints().contains(QCA::DataEncipherment) == true, true );
	    QCOMPARE( client2.constraints().contains(QCA::KeyAgreement) == true, false );
	    QCOMPARE( client2.constraints().contains(QCA::KeyCertificateSign) == true, false );
	    QCOMPARE( client2.constraints().contains(QCA::CRLSign) == true, false );
	    QCOMPARE( client2.constraints().contains(QCA::EncipherOnly) == true, false );
	    QCOMPARE( client2.constraints().contains(QCA::DecipherOnly) == true, false );
	    QCOMPARE( client2.constraints().contains(QCA::ServerAuth) == true, false );
	    QCOMPARE( client2.constraints().contains(QCA::ClientAuth) == true, true );
	    QCOMPARE( client2.constraints().contains(QCA::CodeSigning) == true, false );
	    QCOMPARE( client2.constraints().contains(QCA::EmailProtection) == true, true );
	    QCOMPARE( client2.constraints().contains(QCA::IPSecEndSystem) == true, false );
	    QCOMPARE( client2.constraints().contains(QCA::IPSecTunnel) == true, false);
	    QCOMPARE( client2.constraints().contains(QCA::IPSecUser) == true, false );
	    QCOMPARE( client2.constraints().contains(QCA::TimeStamping) == true, false );
	    QCOMPARE( client2.constraints().contains(QCA::OCSPSigning) == true, false );

	    // no policies on this cert
	    QCOMPARE( client2.policies().count(), 0 );

	    QCA::CertificateInfo subject2 = client2.subjectInfo();
	    QCOMPARE( subject2.isEmpty(), false );
	    QVERIFY( subject2.values(QCA::Country).contains("US") );
	    QVERIFY( subject2.values(QCA::Organization).contains("Qca Development and Test") );
	    QVERIFY( subject2.values(QCA::OrganizationalUnit).contains("Certificate Generation Section") );
	    QVERIFY( subject2.values(QCA::CommonName).contains("Qca Test Client Certificate") );

	    QCA::CertificateInfo issuer2 = client2.issuerInfo();
	    QCOMPARE( issuer2.isEmpty(), false );
	    QVERIFY( issuer2.values(QCA::Country).contains("AU") );
	    QVERIFY( issuer2.values(QCA::Organization).contains("Qca Development and Test") );
	    QVERIFY( issuer2.values(QCA::CommonName).contains("Qca Test Root Certificate") );

	    QByteArray subjectKeyID = QCA::Hex().stringToArray("1e604e03127d287ba40427a961b428a2d09b50d1").toByteArray();
	    QCOMPARE( client2.subjectKeyId(), subjectKeyID );
	    QCOMPARE( QCA::Hex().arrayToString(client2.issuerKeyId()), QString("f61c451de1b0458138c60568c1a7cb0f7ade0363") );

	    QCA::PublicKey pubkey2 = client2.subjectPublicKey();
	    QCOMPARE( pubkey2.isNull(), false );
	    QCOMPARE( pubkey2.isRSA(), true );
	    QCOMPARE( pubkey2.isDSA(), false );
	    QCOMPARE( pubkey2.isDH(), false );
	    QCOMPARE( pubkey2.isPublic(), true );
	    QCOMPARE( pubkey2.isPrivate(), false );
	    QCOMPARE( pubkey2.bitSize(), 1024 );

	    QCOMPARE( client2.pathLimit(), 0 );

	    QCOMPARE( client2.signatureAlgorithm(), QCA::EMSA3_SHA1 );

	    QCA::CertificateCollection trusted;
	    QCA::CertificateCollection untrusted;
	    QCOMPARE( client2.validate( trusted, untrusted ), QCA::ErrorInvalidCA );

	    QCA::ConvertResult resultca2;
	    QCA::Certificate ca2 = QCA::Certificate::fromPEMFile( "certs/QcaTestRootCert.pem", &resultca2, provider);
	    QCOMPARE( resultca2, QCA::ConvertGood );
	    trusted.addCertificate( ca2 );

	    QCOMPARE( client2.validate( trusted, untrusted ), QCA::ValidityGood );
	    QCOMPARE( client2.validate( trusted, untrusted, QCA::UsageAny ), QCA::ValidityGood );
	    QCOMPARE( client2.validate( trusted, untrusted, QCA::UsageTLSServer ), QCA::ErrorInvalidPurpose );
	    QCOMPARE( client2.validate( trusted, untrusted, QCA::UsageTLSClient ), QCA::ValidityGood );
	    QCOMPARE( client2.validate( trusted, untrusted, QCA::UsageCodeSigning ), QCA::ErrorInvalidPurpose );
	    QCOMPARE( client2.validate( trusted, untrusted, QCA::UsageTimeStamping ), QCA::ErrorInvalidPurpose );
	    QCOMPARE( client2.validate( trusted, untrusted, QCA::UsageEmailProtection ), QCA::ValidityGood );
	    QCOMPARE( client2.validate( trusted, untrusted, QCA::UsageCRLSigning ), QCA::ErrorInvalidPurpose );
	    QByteArray derClient2 = client2.toDER();
	    QCOMPARE( derClient2.isEmpty(), false );
	    QCA::Certificate fromDer2 = QCA::Certificate::fromDER( derClient2, &resultClient2, provider );
	    QCOMPARE( resultClient2, QCA::ConvertGood );
	    QVERIFY( fromDer2 == client2 );

	    QString pemClient2 = client2.toPEM();
	    QCOMPARE( pemClient2.isEmpty(), false );
	    QCA::Certificate fromPem2 = QCA::Certificate::fromPEM( pemClient2, &resultClient2, provider);
	    QCOMPARE( resultClient2, QCA::ConvertGood );
	    QVERIFY( fromPem2 == client2);
	    QCOMPARE( fromPem2 != fromDer2, false );
	}
    }
}


void CertUnitTest::derCAcertstest()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
            QFile f("certs/ov-root-ca-cert.crt");
            QVERIFY(f.open(QFile::ReadOnly));
            QByteArray der = f.readAll();
            QCA::ConvertResult resultca1;
            QCA::Certificate ca1 = QCA::Certificate::fromDER(der,
                                                              &resultca1,
                                                              provider);

            QCOMPARE( resultca1, QCA::ConvertGood );

            QCOMPARE( ca1.pathLimit(), 0 );

            QCOMPARE( ca1.isNull(), false );
            QCOMPARE( ca1.isCA(), true );

            QCOMPARE( ca1.isSelfSigned(), true );

            QCOMPARE( ca1.serialNumber(), QCA::BigInteger(0) );

            QCOMPARE( ca1.commonName(), QString("For Tests Only") );

            QCA::CertificateInfo si = ca1.subjectInfo();
            QCOMPARE( si.isEmpty(), false );
            QCOMPARE( si.value(QCA::CommonName), QString("For Tests Only") );
            QCOMPARE( si.value(QCA::Organization), QString("InsecureTestCertificate") );
            QCOMPARE( si.value(QCA::Country), QString("de") );


            QCA::CertificateInfo ii = ca1.issuerInfo();
            QCOMPARE( ii.isEmpty(), false );
            QCOMPARE( ii.value(QCA::CommonName), QString("For Tests Only") );
            QCOMPARE( ii.value(QCA::Organization), QString("InsecureTestCertificate") );
            QCOMPARE( ii.value(QCA::Country), QString("de") );

            QCOMPARE( ca1.notValidBefore().toString(), QDateTime( QDate( 2001, 8, 17 ), QTime( 8, 30, 39 ), Qt::UTC ).toString() );
            QCOMPARE( ca1.notValidAfter().toString(), QDateTime( QDate( 2011, 8, 15 ), QTime( 8, 30, 39 ), Qt::UTC ).toString() );

            QCOMPARE( ca1.constraints().contains(QCA::DigitalSignature) == true, true );
            QCOMPARE( ca1.constraints().contains(QCA::NonRepudiation) == true, true );
            QCOMPARE( ca1.constraints().contains(QCA::KeyEncipherment) == true, true );
            QCOMPARE( ca1.constraints().contains(QCA::DataEncipherment) == true, false );
            QCOMPARE( ca1.constraints().contains(QCA::KeyAgreement) == true, false );
            QCOMPARE( ca1.constraints().contains(QCA::KeyCertificateSign) == true, true );
            QCOMPARE( ca1.constraints().contains(QCA::CRLSign) == true, true );
            QCOMPARE( ca1.constraints().contains(QCA::EncipherOnly) == true, false );
            QCOMPARE( ca1.constraints().contains(QCA::DecipherOnly) == true, false );
            QCOMPARE( ca1.constraints().contains(QCA::ServerAuth) == true, false );
            QCOMPARE( ca1.constraints().contains(QCA::ClientAuth) == true, false );
            QCOMPARE( ca1.constraints().contains(QCA::CodeSigning) == true, false );
            QCOMPARE( ca1.constraints().contains(QCA::EmailProtection) == true, false );
            QCOMPARE( ca1.constraints().contains(QCA::IPSecEndSystem) == true, false );
            QCOMPARE( ca1.constraints().contains(QCA::IPSecTunnel) == true, false);
            QCOMPARE( ca1.constraints().contains(QCA::IPSecUser) == true, false );
            QCOMPARE( ca1.constraints().contains(QCA::TimeStamping) == true, false );
            QCOMPARE( ca1.constraints().contains(QCA::OCSPSigning) == true, false );

            // no policies on this cert
            QCOMPARE( ca1.policies().count(), 0 );

            QCOMPARE( ca1.signatureAlgorithm(), QCA::EMSA3_MD5 );
        }
    }
}

void CertUnitTest::altName()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");
    // providersToTest.append("qca-botan");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::ConvertResult resultClient1;
	    QCA::Certificate client1 = QCA::Certificate::fromPEMFile( "certs/altname.pem", &resultClient1, provider);
	    QCOMPARE( resultClient1, QCA::ConvertGood );
	    QCOMPARE( client1.isNull(), false );
	    QCOMPARE( client1.isCA(), false );
	    QCOMPARE( client1.isSelfSigned(), false );

	    QCOMPARE( client1.serialNumber(), QCA::BigInteger(1) );

	    QCOMPARE( client1.commonName(), QString("Valid RFC822 nameConstraints EE Certificate Test21") );

	    QCOMPARE( client1.constraints().contains(QCA::DigitalSignature) == true, true );
	    QCOMPARE( client1.constraints().contains(QCA::NonRepudiation) == true, true );
	    QCOMPARE( client1.constraints().contains(QCA::KeyEncipherment) == true, true );
	    QCOMPARE( client1.constraints().contains(QCA::DataEncipherment) == true, true );
	    QCOMPARE( client1.constraints().contains(QCA::KeyAgreement) == true, false );
	    QCOMPARE( client1.constraints().contains(QCA::KeyCertificateSign) == true, false );
	    QCOMPARE( client1.constraints().contains(QCA::CRLSign) == true, false );
	    QCOMPARE( client1.constraints().contains(QCA::EncipherOnly) == true, false );
	    QCOMPARE( client1.constraints().contains(QCA::DecipherOnly) == true, false );
	    QCOMPARE( client1.constraints().contains(QCA::ServerAuth) == true, false );
	    QCOMPARE( client1.constraints().contains(QCA::ClientAuth) == true, false );
	    QCOMPARE( client1.constraints().contains(QCA::CodeSigning) == true, false );
	    QCOMPARE( client1.constraints().contains(QCA::EmailProtection) == true, false );
	    QCOMPARE( client1.constraints().contains(QCA::IPSecEndSystem) == true, false );
	    QCOMPARE( client1.constraints().contains(QCA::IPSecTunnel) == true, false);
	    QCOMPARE( client1.constraints().contains(QCA::IPSecUser) == true, false );
	    QCOMPARE( client1.constraints().contains(QCA::TimeStamping) == true, false );
	    QCOMPARE( client1.constraints().contains(QCA::OCSPSigning) == true, false );

	    QCOMPARE( client1.policies().count(), 1 );
	    QCOMPARE( client1.policies().at(0), QString("2.16.840.1.101.3.2.1.48.1") );

	    QCA::CertificateInfo subject1 = client1.subjectInfo();
	    QCOMPARE( subject1.isEmpty(), false );
	    QVERIFY( subject1.values(QCA::Country).contains("US") );
	    QVERIFY( subject1.values(QCA::Organization).contains("Test Certificates") );
	    QVERIFY( subject1.values(QCA::CommonName).contains("Valid RFC822 nameConstraints EE Certificate Test21") );
	    QVERIFY( subject1.values(QCA::Email).contains("Test21EE@mailserver.testcertificates.gov") );

	    QCA::CertificateInfo issuer1 = client1.issuerInfo();
	    QCOMPARE( issuer1.isEmpty(), false );
	    QVERIFY( issuer1.values(QCA::Country).contains("US") );
	    QVERIFY( issuer1.values(QCA::Organization).contains("Test Certificates") );
	    QVERIFY( issuer1.values(QCA::CommonName).contains("nameConstraints RFC822 CA1") );

	    QByteArray subjectKeyID = QCA::Hex().stringToArray("b4200d42cd95ea87d463d54f0ed6d10fe5b73bfb").toByteArray();
	    QCOMPARE( client1.subjectKeyId(), subjectKeyID );
	    QCOMPARE( QCA::Hex().arrayToString(client1.issuerKeyId()), QString("e37f857a8ea23b9eeeb8121d7913aac4bd2e59ad") );

	    QCA::PublicKey pubkey1 = client1.subjectPublicKey();
	    QCOMPARE( pubkey1.isNull(), false );
	    QCOMPARE( pubkey1.isRSA(), true );
	    QCOMPARE( pubkey1.isDSA(), false );
	    QCOMPARE( pubkey1.isDH(), false );
	    QCOMPARE( pubkey1.isPublic(), true );
	    QCOMPARE( pubkey1.isPrivate(), false );
	    QCOMPARE( pubkey1.bitSize(), 1024 );

	    QCOMPARE( client1.pathLimit(), 0 );

	    QCOMPARE( client1.signatureAlgorithm(), QCA::EMSA3_SHA1 );
	}
    }
}

void CertUnitTest::extXMPP()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");
    // providersToTest.append("qca-botan");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::ConvertResult resultClient1;
	    QCA::Certificate client1 = QCA::Certificate::fromPEMFile( "certs/xmppcert.pem", &resultClient1, provider);
	    QCOMPARE( resultClient1, QCA::ConvertGood );
	    QCOMPARE( client1.isNull(), false );
	    QCOMPARE( client1.isCA(), false );
	    QCOMPARE( client1.isSelfSigned(), true );

	    QCOMPARE( client1.serialNumber(), QCA::BigInteger("9635301556349760241") );

	    QCOMPARE( client1.commonName(), QString("demo.jabber.com") );

	    QCA::CertificateInfo subject1 = client1.subjectInfo();
	    QCOMPARE( subject1.isEmpty(), false );
	    QVERIFY( subject1.values(QCA::Country).contains("US") );
	    QVERIFY( subject1.values(QCA::Organization).contains("Jabber, Inc.") );
	    QVERIFY( subject1.values(QCA::Locality).contains("Denver") );
	    QVERIFY( subject1.values(QCA::State).contains("Colorado") );
	    QVERIFY( subject1.values(QCA::CommonName).contains("demo.jabber.com") );
	    QVERIFY( subject1.values(QCA::DNS).contains("demo.jabber.com") );
	    QVERIFY( subject1.values(QCA::XMPP).contains("demo.jabber.com") );

	    QCA::CertificateInfo issuer1 = client1.issuerInfo();
	    QCOMPARE( issuer1.isEmpty(), false );
	    QVERIFY( issuer1.values(QCA::Country).contains("US") );
	    QVERIFY( issuer1.values(QCA::Organization).contains("Jabber, Inc.") );
	    QVERIFY( issuer1.values(QCA::Locality).contains("Denver") );
	    QVERIFY( issuer1.values(QCA::State).contains("Colorado") );
	    QVERIFY( issuer1.values(QCA::CommonName).contains("demo.jabber.com") );
	}
    }
}

void CertUnitTest::altNames76()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");
    // providersToTest.append("qca-botan");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
            QCA::ConvertResult resultClient1;
            QCA::Certificate client1 = QCA::Certificate::fromPEMFile( "certs/76.pem", &resultClient1, provider);
            QCOMPARE( resultClient1, QCA::ConvertGood );
            QCOMPARE( client1.isNull(), false );
            QCOMPARE( client1.isCA(), false );
            QCOMPARE( client1.isSelfSigned(), false );

            QCOMPARE( client1.serialNumber(), QCA::BigInteger(118) );

            QCOMPARE( client1.commonName(), QString("sip1.su.se") );

            QCOMPARE( client1.constraints().contains(QCA::DigitalSignature) == true, true );
            QCOMPARE( client1.constraints().contains(QCA::NonRepudiation) == true, true );
            QCOMPARE( client1.constraints().contains(QCA::KeyEncipherment) == true, true );
            QCOMPARE( client1.constraints().contains(QCA::DataEncipherment) == true, false );
            QCOMPARE( client1.constraints().contains(QCA::KeyAgreement) == true, false );
            QCOMPARE( client1.constraints().contains(QCA::KeyCertificateSign) == true, false );
            QCOMPARE( client1.constraints().contains(QCA::CRLSign) == true, false );
            QCOMPARE( client1.constraints().contains(QCA::EncipherOnly) == true, false );
            QCOMPARE( client1.constraints().contains(QCA::DecipherOnly) == true, false );
            QCOMPARE( client1.constraints().contains(QCA::ServerAuth) == true, true );
            QCOMPARE( client1.constraints().contains(QCA::ClientAuth) == true, true );
            QCOMPARE( client1.constraints().contains(QCA::CodeSigning) == true, false );
            QCOMPARE( client1.constraints().contains(QCA::EmailProtection) == true, false );
            QCOMPARE( client1.constraints().contains(QCA::IPSecEndSystem) == true, false );
            QCOMPARE( client1.constraints().contains(QCA::IPSecTunnel) == true, false);
            QCOMPARE( client1.constraints().contains(QCA::IPSecUser) == true, false );
            QCOMPARE( client1.constraints().contains(QCA::TimeStamping) == true, false );
            QCOMPARE( client1.constraints().contains(QCA::OCSPSigning) == true, false );

            QCOMPARE( client1.policies().count(), 1 );

            QCA::CertificateInfo subject1 = client1.subjectInfo();
            QCOMPARE( subject1.isEmpty(), false );
            QVERIFY( subject1.values(QCA::Country).contains("SE") );
            QVERIFY( subject1.values(QCA::Organization).contains("Stockholms universitet") );
            QVERIFY( subject1.values(QCA::CommonName).contains("sip1.su.se") );
            QCOMPARE( subject1.values(QCA::Email).count(), 0 );
            QCOMPARE( subject1.values(QCA::DNS).count(), 8 );
            QVERIFY( subject1.values(QCA::DNS).contains("incomingproxy.sip.su.se") );
            QVERIFY( subject1.values(QCA::DNS).contains("incomingproxy1.sip.su.se") );
            QVERIFY( subject1.values(QCA::DNS).contains("outgoingproxy.sip.su.se") );
            QVERIFY( subject1.values(QCA::DNS).contains("outgoingproxy1.sip.su.se") );
            QVERIFY( subject1.values(QCA::DNS).contains("out.sip.su.se") );
            QVERIFY( subject1.values(QCA::DNS).contains("appserver.sip.su.se") );
            QVERIFY( subject1.values(QCA::DNS).contains("appserver1.sip.su.se") );
            QVERIFY( subject1.values(QCA::DNS).contains("sip1.su.se") );

            QVERIFY( client1.matchesHostName("incomingproxy.sip.su.se") );
            QVERIFY( client1.matchesHostName("incomingproxy1.sip.su.se") );
            QVERIFY( client1.matchesHostName("outgoingproxy.sip.su.se") );
            QVERIFY( client1.matchesHostName("outgoingproxy1.sip.su.se") );
            QVERIFY( client1.matchesHostName("out.sip.su.se") );
            QVERIFY( client1.matchesHostName("appserver.sip.su.se") );
            QVERIFY( client1.matchesHostName("appserver1.sip.su.se") );
            QVERIFY( client1.matchesHostName("sip1.su.se") );

            QCA::CertificateInfo issuer1 = client1.issuerInfo();
            QCOMPARE( issuer1.isEmpty(), false );
            QVERIFY( issuer1.values(QCA::Country).contains("SE") );
            QVERIFY( issuer1.values(QCA::Organization).contains("Stockholms universitet") );
            QVERIFY( issuer1.values(QCA::CommonName).contains("Stockholm University CA") );
            QVERIFY( issuer1.values(QCA::URI).contains("http://ca.su.se") );
            QVERIFY( issuer1.values(QCA::Email).contains("ca@su.se") );

            QByteArray subjectKeyID = QCA::Hex().stringToArray("3a5c5cd1cc2c9edf73f73bd81b59b1eab83035c5").toByteArray();
            QCOMPARE( client1.subjectKeyId(), subjectKeyID );
            QCOMPARE( QCA::Hex().arrayToString(client1.issuerKeyId()), QString("9e2e30ba37d95144c99dbf1821f1bd7eeeb58648") );

            QCA::PublicKey pubkey1 = client1.subjectPublicKey();
            QCOMPARE( pubkey1.isNull(), false );
            QCOMPARE( pubkey1.isRSA(), true );
            QCOMPARE( pubkey1.isDSA(), false );
            QCOMPARE( pubkey1.isDH(), false );
            QCOMPARE( pubkey1.isPublic(), true );
            QCOMPARE( pubkey1.isPrivate(), false );
            QCOMPARE( pubkey1.bitSize(), 1024 );

            QCOMPARE( client1.pathLimit(), 0 );

            QCOMPARE( client1.signatureAlgorithm(), QCA::EMSA3_SHA1 );
        }
    }
}

void CertUnitTest::sha256cert()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");
    // providersToTest.append("qca-botan");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
            QFile f("certs/RAIZ2007_CERTIFICATE_AND_CRL_SIGNING_SHA256.crt");
            QVERIFY(f.open(QFile::ReadOnly));
            QByteArray der = f.readAll();
            QCA::ConvertResult resultcert;
            QCA::Certificate cert = QCA::Certificate::fromDER(der,
                                                              &resultcert,
                                                              provider);

            QCOMPARE( resultcert, QCA::ConvertGood );
            QCOMPARE( cert.isNull(), false );
            QCOMPARE( cert.isCA(), true );
            QCOMPARE( cert.isSelfSigned(), true );

            QCA::PublicKey pubkey = cert.subjectPublicKey();
            QCOMPARE( pubkey.isNull(), false );
            QCOMPARE( pubkey.isRSA(), true );
            QCOMPARE( pubkey.isDSA(), false );
            QCOMPARE( pubkey.isDH(), false );
            QCOMPARE( pubkey.isPublic(), true );
            QCOMPARE( pubkey.isPrivate(), false );
            QCOMPARE( pubkey.bitSize(), 4096 );

            QCOMPARE( cert.pathLimit(), 0 );

            QCOMPARE( cert.signatureAlgorithm(), QCA::EMSA3_SHA256 );
        }
    }
}

void CertUnitTest::checkExpiredServerCerts()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");
    // providersToTest.append("qca-botan");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::ConvertResult resultServer1;
	    QCA::Certificate server1 = QCA::Certificate::fromPEMFile( "certs/Server.pem", &resultServer1, provider);
	    QCOMPARE( resultServer1, QCA::ConvertGood );
	    QCOMPARE( server1.isNull(), false );
	    QCOMPARE( server1.isCA(), false );
	    QCOMPARE( server1.isSelfSigned(), false );

	    QCOMPARE( server1.serialNumber(), QCA::BigInteger(4) );

	    QCOMPARE( server1.commonName(), QString("Insecure Server Cert") );

	    QCOMPARE( server1.notValidBefore().toString(), QDateTime( QDate( 2001, 8, 17 ), QTime( 8, 46, 24 ), Qt::UTC ).toString() );
	    QCOMPARE( server1.notValidAfter().toString(), QDateTime( QDate( 2006, 8, 16 ), QTime( 8, 46, 24 ), Qt::UTC ).toString() );

	    QCOMPARE( server1.constraints().contains(QCA::DigitalSignature) == true, true );
	    QCOMPARE( server1.constraints().contains(QCA::NonRepudiation) == true, false );
	    QCOMPARE( server1.constraints().contains(QCA::KeyEncipherment) == true, true );
	    QCOMPARE( server1.constraints().contains(QCA::DataEncipherment) == true, false );
	    QCOMPARE( server1.constraints().contains(QCA::KeyAgreement) == true, true );
	    QCOMPARE( server1.constraints().contains(QCA::KeyCertificateSign) == true, false );
	    QCOMPARE( server1.constraints().contains(QCA::CRLSign) == true, false );
	    QCOMPARE( server1.constraints().contains(QCA::EncipherOnly) == true, false );
	    QCOMPARE( server1.constraints().contains(QCA::DecipherOnly) == true, false );
	    QCOMPARE( server1.constraints().contains(QCA::ServerAuth) == true, true );
	    QCOMPARE( server1.constraints().contains(QCA::ClientAuth) == true, false );
	    QCOMPARE( server1.constraints().contains(QCA::CodeSigning) == true, false );
	    QCOMPARE( server1.constraints().contains(QCA::EmailProtection) == true, false );
	    QCOMPARE( server1.constraints().contains(QCA::IPSecEndSystem) == true, false );
	    QCOMPARE( server1.constraints().contains(QCA::IPSecTunnel) == true, false);
	    QCOMPARE( server1.constraints().contains(QCA::IPSecUser) == true, false );
	    QCOMPARE( server1.constraints().contains(QCA::TimeStamping) == true, false );
	    QCOMPARE( server1.constraints().contains(QCA::OCSPSigning) == true, false );

	    // no policies on this cert
	    QCOMPARE( server1.policies().count(), 0 );

	    QCA::CertificateInfo subject1 = server1.subjectInfo();
	    QCOMPARE( subject1.isEmpty(), false );
	    QCOMPARE( subject1.values(QCA::Country).contains("de") == true, true );
	    QCOMPARE( subject1.values(QCA::Organization).contains("InsecureTestCertificate") == true, true );
	    QCOMPARE( subject1.values(QCA::CommonName).contains("Insecure Server Cert") == true, true );

	    QCA::CertificateInfo issuer1 = server1.issuerInfo();
	    QCOMPARE( issuer1.isEmpty(), false );
	    QCOMPARE( issuer1.values(QCA::Country).contains("de") == true, true );
	    QCOMPARE( issuer1.values(QCA::Organization).contains("InsecureTestCertificate") == true, true );
	    QCOMPARE( issuer1.values(QCA::CommonName).contains("For Tests Only") == true, true );

	    QByteArray subjectKeyID = QCA::Hex().stringToArray("0234E2C906F6E0B44253BE04C0CBA7823A6DB509").toByteArray();
	    QCOMPARE( server1.subjectKeyId(), subjectKeyID );
	    QByteArray authorityKeyID = QCA::Hex().stringToArray("BF53438278D09EC380E51B67CA0500DFB94883A5").toByteArray();
	    QCOMPARE( server1.issuerKeyId(), authorityKeyID );

	    QCA::PublicKey pubkey1 = server1.subjectPublicKey();
	    QCOMPARE( pubkey1.isNull(), false );
	    QCOMPARE( pubkey1.isRSA(), true );
	    QCOMPARE( pubkey1.isDSA(), false );
	    QCOMPARE( pubkey1.isDH(), false );
	    QCOMPARE( pubkey1.isPublic(), true );
	    QCOMPARE( pubkey1.isPrivate(), false );
	    QCOMPARE( pubkey1.bitSize(), 1024 );

	    QCOMPARE( server1.pathLimit(), 0 );

	    QCOMPARE( server1.signatureAlgorithm(), QCA::EMSA3_MD5 );

	    QCA::CertificateCollection trusted;
	    QCA::CertificateCollection untrusted;
	    QCOMPARE( server1.validate( trusted, untrusted ), QCA::ErrorInvalidCA );

	    QCA::ConvertResult resultca1;
	    QCA::Certificate ca1 = QCA::Certificate::fromPEMFile( "certs/RootCAcert.pem", &resultca1, provider);
	    QCOMPARE( resultca1, QCA::ConvertGood );
	    trusted.addCertificate( ca1 );
	    QCOMPARE( server1.validate( trusted, untrusted ), QCA::ErrorExpired );
	    QCOMPARE( server1.validate( trusted, untrusted, QCA::UsageAny ), QCA::ErrorExpired );
	    QCOMPARE( server1.validate( trusted, untrusted, QCA::UsageTLSServer ), QCA::ErrorExpired );
	    QCOMPARE( server1.validate( trusted, untrusted, QCA::UsageTLSClient ), QCA::ErrorExpired );
	    QCOMPARE( server1.validate( trusted, untrusted, QCA::UsageCodeSigning ), QCA::ErrorExpired );
	    QCOMPARE( server1.validate( trusted, untrusted, QCA::UsageTimeStamping ), QCA::ErrorExpired );
	    QCOMPARE( server1.validate( trusted, untrusted, QCA::UsageEmailProtection ), QCA::ErrorExpired );
	    QCOMPARE( server1.validate( trusted, untrusted, QCA::UsageCRLSigning ), QCA::ErrorExpired );

	    QByteArray derServer1 = server1.toDER();
	    QCOMPARE( derServer1.isEmpty(), false );
	    QCA::Certificate fromDer1 = QCA::Certificate::fromDER( derServer1, &resultServer1, provider );
	    QCOMPARE( resultServer1, QCA::ConvertGood );
	    QCOMPARE( fromDer1 == server1, true );
	}
    }
}


void CertUnitTest::checkServerCerts()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");
    // providersToTest.append("qca-botan");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::ConvertResult resultServer1;
	    QCA::Certificate server1 = QCA::Certificate::fromPEMFile( "certs/QcaTestServerCert.pem", &resultServer1, provider);
	    QCOMPARE( resultServer1, QCA::ConvertGood );
	    QCOMPARE( server1.isNull(), false );
	    QCOMPARE( server1.isCA(), false );
	    QCOMPARE( server1.isSelfSigned(), false );

	    QCOMPARE( server1.serialNumber(), QCA::BigInteger("13149359243510447489") );

	    QCOMPARE( server1.commonName(), QString("Qca Server Test certificate") );

	    QCOMPARE( server1.notValidBefore().toString(), QDateTime( QDate( 2013, 7, 31 ), QTime( 15, 23, 25 ), Qt::UTC ).toString() );
	    QCOMPARE( server1.notValidAfter().toString(), QDateTime( QDate( 2033, 7, 26 ), QTime( 15, 23, 25 ), Qt::UTC ).toString() );

	    QCOMPARE( server1.constraints().contains(QCA::DigitalSignature) == true, true );
	    QCOMPARE( server1.constraints().contains(QCA::NonRepudiation) == true, true );
	    QCOMPARE( server1.constraints().contains(QCA::KeyEncipherment) == true, true );
	    QCOMPARE( server1.constraints().contains(QCA::DataEncipherment) == true, false );
	    QCOMPARE( server1.constraints().contains(QCA::KeyAgreement) == true, false );
	    QCOMPARE( server1.constraints().contains(QCA::KeyCertificateSign) == true, false );
	    QCOMPARE( server1.constraints().contains(QCA::CRLSign) == true, false );
	    QCOMPARE( server1.constraints().contains(QCA::EncipherOnly) == true, false );
	    QCOMPARE( server1.constraints().contains(QCA::DecipherOnly) == true, false );
	    QCOMPARE( server1.constraints().contains(QCA::ServerAuth) == true, true );
	    QCOMPARE( server1.constraints().contains(QCA::ClientAuth) == true, false );
	    QCOMPARE( server1.constraints().contains(QCA::CodeSigning) == true, false );
	    QCOMPARE( server1.constraints().contains(QCA::EmailProtection) == true, false );
	    QCOMPARE( server1.constraints().contains(QCA::IPSecEndSystem) == true, false );
	    QCOMPARE( server1.constraints().contains(QCA::IPSecTunnel) == true, false);
	    QCOMPARE( server1.constraints().contains(QCA::IPSecUser) == true, false );
	    QCOMPARE( server1.constraints().contains(QCA::TimeStamping) == true, false );
	    QCOMPARE( server1.constraints().contains(QCA::OCSPSigning) == true, false );

	    // no policies on this cert
	    QCOMPARE( server1.policies().count(), 0 );

	    QCA::CertificateInfo subject1 = server1.subjectInfo();
	    QCOMPARE( subject1.isEmpty(), false );
	    QVERIFY( subject1.values(QCA::Country).contains("IL") );
	    QVERIFY( subject1.values(QCA::Organization).contains("Qca Development and Test") );
	    QVERIFY( subject1.values(QCA::OrganizationalUnit).contains("Server Management Section") );
	    QVERIFY( subject1.values(QCA::CommonName).contains("Qca Server Test certificate") );

	    QCA::CertificateInfo issuer1 = server1.issuerInfo();
	    QCOMPARE( issuer1.isEmpty(), false );
	    QVERIFY( issuer1.values(QCA::Country).contains("AU") );
	    QVERIFY( issuer1.values(QCA::Organization).contains("Qca Development and Test") );
	    QVERIFY( issuer1.values(QCA::OrganizationalUnit).contains("Certificate Generation Section") );
	    QVERIFY( issuer1.values(QCA::CommonName).contains("Qca Test Root Certificate") );

	    QByteArray subjectKeyID = QCA::Hex().stringToArray("819870c8b81eab53e72d0446b65790aa0d3eab1a").toByteArray();
	    QCOMPARE( server1.subjectKeyId(), subjectKeyID );
	    QByteArray authorityKeyID = QCA::Hex().stringToArray("f61c451de1b0458138c60568c1a7cb0f7ade0363").toByteArray();
	    QCOMPARE( server1.issuerKeyId(), authorityKeyID );

	    QCA::PublicKey pubkey1 = server1.subjectPublicKey();
	    QCOMPARE( pubkey1.isNull(), false );
	    QCOMPARE( pubkey1.isRSA(), true );
	    QCOMPARE( pubkey1.isDSA(), false );
	    QCOMPARE( pubkey1.isDH(), false );
	    QCOMPARE( pubkey1.isPublic(), true );
	    QCOMPARE( pubkey1.isPrivate(), false );
	    QCOMPARE( pubkey1.bitSize(), 1024 );

	    QCOMPARE( server1.pathLimit(), 0 );

	    QCOMPARE( server1.signatureAlgorithm(), QCA::EMSA3_SHA1 );

	    QCA::CertificateCollection trusted;
	    QCA::CertificateCollection untrusted;
	    QCOMPARE( server1.validate( trusted, untrusted ), QCA::ErrorInvalidCA );

	    QCA::ConvertResult resultca1;
	    QCA::Certificate ca1 = QCA::Certificate::fromPEMFile( "certs/QcaTestRootCert.pem", &resultca1, provider);
	    QCOMPARE( resultca1, QCA::ConvertGood );
	    trusted.addCertificate( ca1 );
	    QCOMPARE( server1.validate( trusted, untrusted ), QCA::ValidityGood );
	    QCOMPARE( server1.validate( trusted, untrusted, QCA::UsageAny ),  QCA::ValidityGood );
	    QCOMPARE( server1.validate( trusted, untrusted, QCA::UsageTLSServer ), QCA::ValidityGood );
	    QCOMPARE( server1.validate( trusted, untrusted, QCA::UsageTLSClient ), QCA::ErrorInvalidPurpose );
	    QCOMPARE( server1.validate( trusted, untrusted, QCA::UsageCodeSigning ), QCA::ErrorInvalidPurpose );
	    QCOMPARE( server1.validate( trusted, untrusted, QCA::UsageTimeStamping ), QCA::ErrorInvalidPurpose );
	    QCOMPARE( server1.validate( trusted, untrusted, QCA::UsageEmailProtection ), QCA::ErrorInvalidPurpose );
	    QCOMPARE( server1.validate( trusted, untrusted, QCA::UsageCRLSigning ), QCA::ErrorInvalidPurpose );

	    QByteArray derServer1 = server1.toDER();
	    QCOMPARE( derServer1.isEmpty(), false );
	    QCA::Certificate fromDer1 = QCA::Certificate::fromDER( derServer1, &resultServer1, provider );
	    QCOMPARE( resultServer1, QCA::ConvertGood );
	    QCOMPARE( fromDer1 == server1, true );
	}
    }
}


void CertUnitTest::checkSystemStore()
{
    if ( QCA::isSupported("cert") && QCA::isSupported("crl") ) {
        QCOMPARE( QCA::haveSystemStore(), true );

	QCA::CertificateCollection collection1;
	collection1 = QCA::systemStore();
	// Do we have any certs?
	QVERIFY( collection1.certificates().count() > 0);
    } else {
      QCOMPARE( QCA::haveSystemStore(), false );
    }
}

void CertUnitTest::crl()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");
    // providersToTest.append("qca-botan");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "crl", provider ) )
            QWARN( QString( "Certificate revocation not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::CRL emptyCRL;
	    QVERIFY( emptyCRL.isNull() );

	    QCA::ConvertResult resultCrl;
	    QCA::CRL crl1 = QCA::CRL::fromPEMFile( "certs/Test_CRL.crl", &resultCrl, provider);
	    QCOMPARE( resultCrl, QCA::ConvertGood );
	    QCOMPARE( crl1.isNull(), false );

	    QCA::CertificateInfo issuer = crl1.issuerInfo();
	    QCOMPARE( issuer.isEmpty(), false );
	    QVERIFY( issuer.values(QCA::Country).contains("de") );
	    QVERIFY( issuer.values(QCA::Organization).contains("InsecureTestCertificate") );
	    QVERIFY( issuer.values(QCA::CommonName).contains("For Tests Only") );

	    // No keyid extension on this crl
	    QCOMPARE( QCA::arrayToHex( crl1.issuerKeyId() ), QString("") );

	    QCOMPARE( crl1.thisUpdate(), QDateTime(QDate(2001, 8, 17), QTime(11, 12, 03), Qt::UTC) );
	    QCOMPARE( crl1.nextUpdate(), QDateTime(QDate(2006, 8, 16), QTime(11, 12, 03), Qt::UTC) );

	    QCOMPARE( crl1.signatureAlgorithm(), QCA::EMSA3_MD5 );

	    QCOMPARE( crl1.issuerKeyId(), QByteArray("") );
	    QCOMPARE( crl1, QCA::CRL(crl1) );
	    QCOMPARE( crl1 == QCA::CRL(), false );
	    QCOMPARE( crl1.number(), -1 );

	    QList<QCA::CRLEntry> revokedList = crl1.revoked();
	    QCOMPARE( revokedList.size(), 2 );
	    qSort(revokedList);
	    QCOMPARE( revokedList[0].serialNumber(), QCA::BigInteger("3") );
	    QCOMPARE( revokedList[1].serialNumber(), QCA::BigInteger("5") );
	    QCOMPARE( revokedList[0].reason(), QCA::CRLEntry::Unspecified );
	    QCOMPARE( revokedList[1].reason(), QCA::CRLEntry::Unspecified );
	    QCOMPARE( revokedList[0].time(), QDateTime(QDate(2001, 8, 17), QTime(11, 10, 39), Qt::UTC) );
	    QCOMPARE( revokedList[1].time(), QDateTime(QDate(2001, 8, 17), QTime(11, 11, 59), Qt::UTC) );

	    // convert to DER
	    QByteArray derCRL1 = crl1.toDER();
	    // check we got something, at least
	    QCOMPARE( derCRL1.isEmpty(), false );
	    // convert back from DER
	    QCA::CRL fromDer1 = QCA::CRL::fromDER( derCRL1, &resultCrl, provider );
	    // check the conversion at least appeared to work
	    QCOMPARE( resultCrl, QCA::ConvertGood );
	    // check the result is the same as what we started with
	    QCOMPARE( fromDer1, crl1 );
	}
    }
}

void CertUnitTest::crl2()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");
    // providersToTest.append("qca-botan");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "crl", provider ) )
            QWARN( QString( "Certificate revocation not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::ConvertResult resultCrl;
	    QCA::CRL crl1 = QCA::CRL::fromPEMFile( "certs/GoodCACRL.pem", &resultCrl, provider);
	    QCOMPARE( resultCrl, QCA::ConvertGood );
	    QCOMPARE( crl1.isNull(), false );
	    QCOMPARE( crl1.provider()->name(), provider );

	    QCA::CertificateInfo issuer = crl1.issuerInfo();
	    QCOMPARE( issuer.isEmpty(), false );
	    QVERIFY( issuer.values(QCA::Country).contains("US") );
	    QVERIFY( issuer.values(QCA::Organization).contains("Test Certificates") );
	    QVERIFY( issuer.values(QCA::CommonName).contains("Good CA") );

	    QCOMPARE( crl1.thisUpdate(), QDateTime(QDate(2001, 4, 19), QTime(14, 57, 20), Qt::UTC) );
	    QCOMPARE( crl1.nextUpdate(), QDateTime(QDate(2011, 4, 19), QTime(14, 57, 20), Qt::UTC) );

	    QCOMPARE( crl1.signatureAlgorithm(), QCA::EMSA3_SHA1 );

	    QCOMPARE( QCA::arrayToHex( crl1.issuerKeyId() ), QString("b72ea682cbc2c8bca87b2744d73533df9a1594c7") );
	    QCOMPARE( crl1.number(), 1 );
	    QCOMPARE( crl1, QCA::CRL(crl1) );
	    QCOMPARE( crl1 == QCA::CRL(), false );

	    QList<QCA::CRLEntry> revokedList = crl1.revoked();
	    QCOMPARE( revokedList.size(), 2 );
	    qSort(revokedList);
	    QCOMPARE( revokedList[0].serialNumber(), QCA::BigInteger("14") );
	    QCOMPARE( revokedList[1].serialNumber(), QCA::BigInteger("15") );
	    QCOMPARE( revokedList[0].reason(), QCA::CRLEntry::KeyCompromise );
	    QCOMPARE( revokedList[1].reason(), QCA::CRLEntry::KeyCompromise );
	    QCOMPARE( revokedList[0].time(), QDateTime(QDate(2001, 4, 19), QTime(14, 57, 20), Qt::UTC) );
	    QCOMPARE( revokedList[1].time(), QDateTime(QDate(2001, 4, 19), QTime(14, 57, 20), Qt::UTC) );

	    // convert to DER
	    QByteArray derCRL1 = crl1.toDER();
	    // check we got something, at least
	    QCOMPARE( derCRL1.isEmpty(), false );
	    // convert back from DER
	    QCA::CRL fromDer1 = QCA::CRL::fromDER( derCRL1, &resultCrl, provider );
	    // check the conversion at least appeared to work
	    QCOMPARE( resultCrl, QCA::ConvertGood );
	    // check the result is the same as what we started with
	    QCOMPARE( fromDer1, crl1 );

	    // convert to PEM
	    QString pemCRL1 = crl1.toPEM();
	    // check we got something, at least
	    QCOMPARE( pemCRL1.isEmpty(), false );
	    // convert back from PEM
	    QCA::CRL fromPEM1 = QCA::CRL::fromPEM( pemCRL1, &resultCrl, provider );
	    // check the conversion at least appeared to work
	    QCOMPARE( resultCrl, QCA::ConvertGood );
	    // check the result is the same as what we started with
	    QCOMPARE( fromPEM1, crl1 );
	}
    }
}

void CertUnitTest::csr()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");
    // providersToTest.append("qca-botan");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "csr", provider ) )
            QWARN( QString( "Certificate signing requests not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::CertificateRequest nullCSR;
	    QVERIFY( nullCSR.isNull() );
	    QCA::CertificateRequest anotherNullCSR = nullCSR;
	    QVERIFY( anotherNullCSR.isNull() );
	    QCOMPARE( nullCSR, anotherNullCSR);

	    QCA::ConvertResult resultCsr;
	    QCA::CertificateRequest csr1 = QCA::CertificateRequest::fromPEMFile( "certs/csr1.pem", &resultCsr, provider);
	    QCOMPARE( resultCsr, QCA::ConvertGood );
	    QCOMPARE( csr1.isNull(), false );
	    QCOMPARE( csr1.provider()->name(), provider );
	    QCA::CertificateInfo subject = csr1.subjectInfo();
	    QCOMPARE( subject.isEmpty(), false );
	    QVERIFY( subject.values(QCA::Country).contains("AU") );
	    QVERIFY( subject.values(QCA::State).contains("Victoria") );
	    QVERIFY( subject.values(QCA::Locality).contains("Mitcham") );
	    QVERIFY( subject.values(QCA::Organization).contains("GE Interlogix") );
	    QVERIFY( subject.values(QCA::OrganizationalUnit).contains("Engineering") );
	    QVERIFY( subject.values(QCA::CommonName).contains("coldfire") );

	    QCA::PublicKey pkey = csr1.subjectPublicKey();
	    QCOMPARE( pkey.isNull(), false );
	    QVERIFY( pkey.isRSA() );

	    QCA::RSAPublicKey rsaPkey = pkey.toRSA();
	    QCOMPARE( rsaPkey.isNull(), false );
	    QCOMPARE( rsaPkey.e(), QCA::BigInteger(65537) );
	    QCOMPARE( rsaPkey.n(), QCA::BigInteger("104853561647822232509211983664549572246855698961210758585652966258891659217901732470712446421431206166165309547771124747713609923038218156616083520796442797276676074122658684367500665423564881889504308700315044585826841844654287577169905826705891670004942854611681809539126326134927995969418712881512819058439") );

	    QCOMPARE( csr1.signatureAlgorithm(), QCA::EMSA3_MD5 );
	}
    }
}

void CertUnitTest::csr2()
{
    QStringList providersToTest;
    providersToTest.append("qca-ossl");
    // providersToTest.append("qca-botan");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "csr", provider ) )
            QWARN( QString( "Certificate signing requests not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::ConvertResult resultCsr;
	    QCA::CertificateRequest csr1 = QCA::CertificateRequest::fromPEMFile( "certs/newreq.pem", &resultCsr, provider);
	    QCOMPARE( resultCsr, QCA::ConvertGood );
	    QCOMPARE( csr1.isNull(), false );
	    QCOMPARE( csr1.provider()->name(), provider );
	    QCA::CertificateInfo subject = csr1.subjectInfo();
	    QCOMPARE( subject.isEmpty(), false );
	    QVERIFY( subject.values(QCA::Country).contains("AI") );
	    QVERIFY( subject.values(QCA::State).contains("Hutt River Province") );
	    QVERIFY( subject.values(QCA::Locality).contains("Lesser Internet") );
	    QVERIFY( subject.values(QCA::Organization).contains("My Company Ltd") );
	    QVERIFY( subject.values(QCA::OrganizationalUnit).contains("Backwater Branch Office") );
	    QVERIFY( subject.values(QCA::CommonName).contains("FirstName Surname") );

	    QCA::PublicKey pkey = csr1.subjectPublicKey();
	    QCOMPARE( pkey.isNull(), false );
	    QVERIFY( pkey.isRSA() );

	    QCA::RSAPublicKey rsaPkey = pkey.toRSA();
	    QCOMPARE( rsaPkey.isNull(), false );
	    QCOMPARE( rsaPkey.e(), QCA::BigInteger(65537) );
	    QCOMPARE( rsaPkey.n(), QCA::BigInteger("151872780463004414908584891835397365176526767139347372444365914360701714510188717169754430290680734981291754624394094502297070722505032645306680495915914243593438796635264236530526146243919417744996366836534380790370421346490191416041004278161146551997010463199760480957900518811859984176646089981367745961681" ) );

	    QCOMPARE( csr1.signatureAlgorithm(), QCA::EMSA3_MD5 );

	    // convert to DER
	    QByteArray derCSR1 = csr1.toDER();
	    // check we got something, at least
	    QCOMPARE( derCSR1.isEmpty(), false );
	    // convert back from DER
	    QCA::CertificateRequest fromDer1 = QCA::CertificateRequest::fromDER( derCSR1, &resultCsr, provider );
	    // check the conversion at least appeared to work
	    QCOMPARE( resultCsr, QCA::ConvertGood );
	    // check the result is the same as what we started with
	    QCOMPARE( fromDer1, csr1 );

	    // convert to PEM
	    QString pemCSR1 = csr1.toPEM();
	    // check we got something, at least
	    QCOMPARE( pemCSR1.isEmpty(), false );
	    // convert back from PEM
	    QCA::CertificateRequest fromPEM1 = QCA::CertificateRequest::fromPEM( pemCSR1, &resultCsr, provider );
	    // check the conversion at least appeared to work
	    QCOMPARE( resultCsr, QCA::ConvertGood );
	    // check the result is the same as what we started with
	    QCOMPARE( fromPEM1, csr1 );
	}
    }
}
QTEST_MAIN(CertUnitTest)

#include "certunittest.moc"
