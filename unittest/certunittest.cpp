/**
 * Copyright (C)  2004-2005  Brad Hards <bradh@frogmouth.net>
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
#include "certunittest.h"
#include <QtCrypto>

#include <iostream>
CertUnitTest::CertUnitTest()
    : Tester()
{

}

void CertUnitTest::checkCAcerts(const QString &provider)
{
    QCA::ConvertResult resultca1;
    QCA::Certificate ca1 = QCA::Certificate::fromPEMFile( "certs/RootCAcert.pem", &resultca1, provider);

    CHECK( resultca1, QCA::ConvertGood );
    CHECK( ca1.isNull(), false );
    CHECK( ca1.isCA(), true );
    CHECK( ca1.isSelfSigned(), true );

    CHECK( ca1.serialNumber(), QBigInteger(0) );

    CHECK( ca1.commonName(), QString("For Tests Only") );

    CHECK( ca1.notValidBefore().toString(), QDateTime( QDate( 2001, 8, 17 ), QTime( 8, 30, 39 ), Qt::UTC ).toString() );
    CHECK( ca1.notValidAfter().toString(), QDateTime( QDate( 2011, 8, 15 ), QTime( 8, 30, 39 ), Qt::UTC ).toString() );

    CHECK( ca1.constraints().contains(QCA::DigitalSignature), (QBool)true );
    CHECK( ca1.constraints().contains(QCA::NonRepudiation), (QBool)true );
    CHECK( ca1.constraints().contains(QCA::KeyEncipherment), (QBool)true );
    CHECK( ca1.constraints().contains(QCA::DataEncipherment), (QBool)false );
    CHECK( ca1.constraints().contains(QCA::KeyAgreement), (QBool)false );
    CHECK( ca1.constraints().contains(QCA::KeyCertificateSign), (QBool)true );
    CHECK( ca1.constraints().contains(QCA::CRLSign), (QBool)true );
    CHECK( ca1.constraints().contains(QCA::EncipherOnly), (QBool)false );
    CHECK( ca1.constraints().contains(QCA::DecipherOnly), (QBool)false );
    CHECK( ca1.constraints().contains(QCA::ServerAuth), (QBool)false );
    CHECK( ca1.constraints().contains(QCA::ClientAuth), (QBool)false );
    CHECK( ca1.constraints().contains(QCA::CodeSigning), (QBool)false );
    CHECK( ca1.constraints().contains(QCA::EmailProtection), (QBool)false );
    CHECK( ca1.constraints().contains(QCA::IPSecEndSystem), (QBool)false );
    CHECK( ca1.constraints().contains(QCA::IPSecTunnel), (QBool)false);
    CHECK( ca1.constraints().contains(QCA::IPSecUser), (QBool)false );
    CHECK( ca1.constraints().contains(QCA::TimeStamping), (QBool)false );
    CHECK( ca1.constraints().contains(QCA::OCSPSigning), (QBool)false );

    // no policies on this cert
    CHECK( ca1.policies().count(), 0 );
}

void CertUnitTest::checkClientCerts(const QString &provider)
{
    QCA::ConvertResult resultClient1;
    QCA::Certificate client1 = QCA::Certificate::fromPEMFile( "certs/User.pem", &resultClient1, provider);
    CHECK( resultClient1, QCA::ConvertGood );
    CHECK( client1.isNull(), false );
    CHECK( client1.isCA(), false );
    CHECK( client1.isSelfSigned(), false );

    CHECK( client1.serialNumber(), QBigInteger(2) );

    CHECK( client1.commonName(), QString("Insecure User Test Cert") );

    CHECK( client1.notValidBefore().toString(), QDateTime( QDate( 2001, 8, 17 ), QTime( 8, 32, 38 ), Qt::UTC ).toString() );
    CHECK( client1.notValidAfter().toString(), QDateTime( QDate( 2006, 8, 16 ), QTime( 8, 32, 38 ), Qt::UTC ).toString() );

    CHECK( client1.constraints().contains(QCA::DigitalSignature), (QBool)true );
    CHECK( client1.constraints().contains(QCA::NonRepudiation), (QBool)true );
    CHECK( client1.constraints().contains(QCA::KeyEncipherment), (QBool)true );
    CHECK( client1.constraints().contains(QCA::DataEncipherment), (QBool)true );
    CHECK( client1.constraints().contains(QCA::KeyAgreement), (QBool)false );
    CHECK( client1.constraints().contains(QCA::KeyCertificateSign), (QBool)false );
    CHECK( client1.constraints().contains(QCA::CRLSign), (QBool)false );
    CHECK( client1.constraints().contains(QCA::EncipherOnly), (QBool)false );
    CHECK( client1.constraints().contains(QCA::DecipherOnly), (QBool)false );
    CHECK( client1.constraints().contains(QCA::ServerAuth), (QBool)false );
    CHECK( client1.constraints().contains(QCA::ClientAuth), (QBool)true );
    CHECK( client1.constraints().contains(QCA::CodeSigning), (QBool)false );
    CHECK( client1.constraints().contains(QCA::EmailProtection), (QBool)true );
    CHECK( client1.constraints().contains(QCA::IPSecEndSystem), (QBool)false );
    CHECK( client1.constraints().contains(QCA::IPSecTunnel), (QBool)false);
    CHECK( client1.constraints().contains(QCA::IPSecUser), (QBool)false );
    CHECK( client1.constraints().contains(QCA::TimeStamping), (QBool)false );
    CHECK( client1.constraints().contains(QCA::OCSPSigning), (QBool)false );

    // no policies on this cert
    CHECK( client1.policies().count(), 0 );

    QCA::CertificateInfo subject1 = client1.subjectInfo();
    CHECK( subject1.isEmpty(), false );
    CHECK( subject1.values(QCA::Country).contains("de"), (QBool)true );
    CHECK( subject1.values(QCA::Organization).contains("InsecureTestCertificate"), (QBool)true );
    CHECK( subject1.values(QCA::CommonName).contains("Insecure User Test Cert"), (QBool)true );

    QCA::CertificateInfo issuer1 = client1.issuerInfo();
    CHECK( issuer1.isEmpty(), false );
    CHECK( issuer1.values(QCA::Country).contains("de"), (QBool)true );
    CHECK( issuer1.values(QCA::Organization).contains("InsecureTestCertificate"), (QBool)true );
    CHECK( issuer1.values(QCA::CommonName).contains("For Tests Only"), (QBool)true );

    QByteArray subjectKeyID = QCA::Hex().stringToArray("889E7EF729719D7B280F361AAE6D00D39DE1AADB").toByteArray();
    CHECK( client1.subjectKeyId(), subjectKeyID );
    CHECK( QCA::Hex().arrayToString(client1.issuerKeyId()), QString("BF53438278D09EC380E51B67CA0500DFB94883A5") );

    QCA::PublicKey pubkey1 = client1.subjectPublicKey();
    CHECK( pubkey1.isNull(), false );
    CHECK( pubkey1.isRSA(), true );
    CHECK( pubkey1.isDSA(), false );
    CHECK( pubkey1.isDH(), false );
    CHECK( pubkey1.isPublic(), true );
    CHECK( pubkey1.isPrivate(), false );
    XFAIL( pubkey1.bitSize(), 1024 );

    CHECK( client1.pathLimit(), 0 );

    CHECK( client1.signatureAlgorithm(), QCA::EMSA3_MD5 );

    QCA::CertificateCollection trusted;
    QCA::CertificateCollection untrusted;
    CHECK( client1.validate( trusted, untrusted ), QCA::ErrorInvalidCA );

    QCA::ConvertResult resultca1;
    QCA::Certificate ca1 = QCA::Certificate::fromPEMFile( "certs/RootCAcert.pem", &resultca1, provider);
    CHECK( resultca1, QCA::ConvertGood );
    trusted.addCertificate( ca1 );
    CHECK( client1.validate( trusted, untrusted ), QCA::ValidityGood );
    CHECK( client1.validate( trusted, untrusted, QCA::UsageAny ), QCA::ValidityGood );
    CHECK( client1.validate( trusted, untrusted, QCA::UsageTLSServer ), QCA::ErrorInvalidPurpose );
    CHECK( client1.validate( trusted, untrusted, QCA::UsageTLSClient ), QCA::ValidityGood );
    CHECK( client1.validate( trusted, untrusted, QCA::UsageCodeSigning ), QCA::ErrorInvalidPurpose );
    CHECK( client1.validate( trusted, untrusted, QCA::UsageTimeStamping ), QCA::ErrorInvalidPurpose );
    CHECK( client1.validate( trusted, untrusted, QCA::UsageEmailProtection ), QCA::ValidityGood );
    CHECK( client1.validate( trusted, untrusted, QCA::UsageCRLSigning ), QCA::ErrorInvalidPurpose );

    QSecureArray derClient1 = client1.toDER();
    CHECK( derClient1.isEmpty(), false );
    QCA::Certificate fromDer1 = QCA::Certificate::fromDER( derClient1, &resultClient1, provider );
    CHECK( resultClient1, QCA::ConvertGood );
    CHECK( fromDer1 == client1, true );
}


void CertUnitTest::checkServerCerts(const QString &provider)
{
    QCA::ConvertResult resultServer1;
    QCA::Certificate server1 = QCA::Certificate::fromPEMFile( "certs/Server.pem", &resultServer1, provider);
    CHECK( resultServer1, QCA::ConvertGood );
    CHECK( server1.isNull(), false );
    CHECK( server1.isCA(), false );
    CHECK( server1.isSelfSigned(), false );

    CHECK( server1.serialNumber(), QBigInteger(4) );

    CHECK( server1.commonName(), QString("Insecure Server Cert") );

    CHECK( server1.notValidBefore().toString(), QDateTime( QDate( 2001, 8, 17 ), QTime( 8, 46, 24 ), Qt::UTC ).toString() );
    CHECK( server1.notValidAfter().toString(), QDateTime( QDate( 2006, 8, 16 ), QTime( 8, 46, 24 ), Qt::UTC ).toString() );

    CHECK( server1.constraints().contains(QCA::DigitalSignature), (QBool)true );
    CHECK( server1.constraints().contains(QCA::NonRepudiation), (QBool)false );
    CHECK( server1.constraints().contains(QCA::KeyEncipherment), (QBool)true );
    CHECK( server1.constraints().contains(QCA::DataEncipherment), (QBool)false );
    CHECK( server1.constraints().contains(QCA::KeyAgreement), (QBool)true );
    CHECK( server1.constraints().contains(QCA::KeyCertificateSign), (QBool)false );
    CHECK( server1.constraints().contains(QCA::CRLSign), (QBool)false );
    CHECK( server1.constraints().contains(QCA::EncipherOnly), (QBool)false );
    CHECK( server1.constraints().contains(QCA::DecipherOnly), (QBool)false );
    CHECK( server1.constraints().contains(QCA::ServerAuth), (QBool)true );
    CHECK( server1.constraints().contains(QCA::ClientAuth), (QBool)false );
    CHECK( server1.constraints().contains(QCA::CodeSigning), (QBool)false );
    CHECK( server1.constraints().contains(QCA::EmailProtection), (QBool)false );
    CHECK( server1.constraints().contains(QCA::IPSecEndSystem), (QBool)false );
    CHECK( server1.constraints().contains(QCA::IPSecTunnel), (QBool)false);
    CHECK( server1.constraints().contains(QCA::IPSecUser), (QBool)false );
    CHECK( server1.constraints().contains(QCA::TimeStamping), (QBool)false );
    CHECK( server1.constraints().contains(QCA::OCSPSigning), (QBool)false );

    // no policies on this cert
    CHECK( server1.policies().count(), 0 );

    QCA::CertificateInfo subject1 = server1.subjectInfo();
    CHECK( subject1.isEmpty(), false );
    CHECK( subject1.values(QCA::Country).contains("de"), (QBool)true );
    CHECK( subject1.values(QCA::Organization).contains("InsecureTestCertificate"), (QBool)true );
    CHECK( subject1.values(QCA::CommonName).contains("Insecure Server Cert"), (QBool)true );

    QCA::CertificateInfo issuer1 = server1.issuerInfo();
    CHECK( issuer1.isEmpty(), false );
    CHECK( issuer1.values(QCA::Country).contains("de"), (QBool)true );
    CHECK( issuer1.values(QCA::Organization).contains("InsecureTestCertificate"), (QBool)true );
    CHECK( issuer1.values(QCA::CommonName).contains("For Tests Only"), (QBool)true );

    QByteArray subjectKeyID = QCA::Hex().stringToArray("0234E2C906F6E0B44253BE04C0CBA7823A6DB509").toByteArray();
    CHECK( server1.subjectKeyId(), subjectKeyID );
    QByteArray authorityKeyID = QCA::Hex().stringToArray("BF53438278D09EC380E51B67CA0500DFB94883A5").toByteArray();
    CHECK( server1.issuerKeyId(), authorityKeyID );

    QCA::PublicKey pubkey1 = server1.subjectPublicKey();
    CHECK( pubkey1.isNull(), false );
    CHECK( pubkey1.isRSA(), true );
    CHECK( pubkey1.isDSA(), false );
    CHECK( pubkey1.isDH(), false );
    CHECK( pubkey1.isPublic(), true );
    CHECK( pubkey1.isPrivate(), false );
    XFAIL( pubkey1.bitSize(), 1024 );

    CHECK( server1.pathLimit(), 0 );

    CHECK( server1.signatureAlgorithm(), QCA::EMSA3_MD5 );

    QCA::CertificateCollection trusted;
    QCA::CertificateCollection untrusted;
    CHECK( server1.validate( trusted, untrusted ), QCA::ErrorInvalidCA );

    QCA::ConvertResult resultca1;
    QCA::Certificate ca1 = QCA::Certificate::fromPEMFile( "certs/RootCAcert.pem", &resultca1, provider);
    CHECK( resultca1, QCA::ConvertGood );
    trusted.addCertificate( ca1 );
    CHECK( server1.validate( trusted, untrusted ), QCA::ValidityGood );
    CHECK( server1.validate( trusted, untrusted, QCA::UsageAny ), QCA::ValidityGood );
    CHECK( server1.validate( trusted, untrusted, QCA::UsageTLSServer ), QCA::ValidityGood);
    CHECK( server1.validate( trusted, untrusted, QCA::UsageTLSClient ), QCA::ErrorInvalidPurpose );
    CHECK( server1.validate( trusted, untrusted, QCA::UsageCodeSigning ), QCA::ErrorInvalidPurpose );
    CHECK( server1.validate( trusted, untrusted, QCA::UsageTimeStamping ), QCA::ErrorInvalidPurpose );
    CHECK( server1.validate( trusted, untrusted, QCA::UsageEmailProtection ), QCA::ErrorInvalidPurpose );
    CHECK( server1.validate( trusted, untrusted, QCA::UsageCRLSigning ), QCA::ErrorInvalidPurpose );

    QSecureArray derServer1 = server1.toDER();
    CHECK( derServer1.isEmpty(), false );
    QCA::Certificate fromDer1 = QCA::Certificate::fromDER( derServer1, &resultServer1, provider );
    CHECK( resultServer1, QCA::ConvertGood );
    CHECK( fromDer1 == server1, true );
}


void CertUnitTest::allTests()
{
    QCA::Initializer init;

    CHECK( QCA::haveSystemStore(), true );

    if ( QCA::haveSystemStore() ) {
	QCA::CertificateCollection collection1;
	collection1 = QCA::systemStore();
    }

    checkCAcerts(QString());
    checkClientCerts(QString());
    checkServerCerts(QString());
}

