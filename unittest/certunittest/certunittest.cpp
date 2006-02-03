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
#include "certunittest.h"

void CertUnitTest::initTestCase()
{
    m_init = new QCA::Initializer;
#include "../fixpaths.include"
}

void CertUnitTest::cleanupTestCase()
{
    delete m_init;
}

void CertUnitTest::nullCert()
{
    QStringList providersToTest;
    providersToTest.append("qca-openssl");
    providersToTest.append("qca-gcrypt");
    providersToTest.append("qca-botan");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::Certificate nullCert;
	    QCOMPARE(nullCert.isNull(), true);
	}
    }
}

void CertUnitTest::CAcertstest()
{
    QStringList providersToTest;
    providersToTest.append("qca-openssl");
    providersToTest.append("qca-gcrypt");
    providersToTest.append("qca-botan");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate handling not supported for "+provider).toLocal8Bit() );
        else {
	    QCA::ConvertResult resultca1;
	    QCA::Certificate ca1 = QCA::Certificate::fromPEMFile( "certs/RootCAcert.pem", &resultca1, provider);

	    QCOMPARE( ca1.pathLimit(), 0 );
	    
	    QCOMPARE( resultca1, QCA::ConvertGood );
	    QCOMPARE( ca1.isNull(), false );
	    QCOMPARE( ca1.isCA(), true );
	    QCOMPARE( ca1.isSelfSigned(), true );
    
	    QCOMPARE( ca1.serialNumber(), QBigInteger(0) );
	    
	    QCOMPARE( ca1.commonName(), QString("For Tests Only") );
	    
	    QCOMPARE( ca1.notValidBefore().toString(), QDateTime( QDate( 2001, 8, 17 ), QTime( 8, 30, 39 ), Qt::UTC ).toString() );
	    QCOMPARE( ca1.notValidAfter().toString(), QDateTime( QDate( 2011, 8, 15 ), QTime( 8, 30, 39 ), Qt::UTC ).toString() );
	    
	    QCOMPARE( ca1.constraints().contains(QCA::DigitalSignature), (QBool)true );
	    QCOMPARE( ca1.constraints().contains(QCA::NonRepudiation), (QBool)true );
	    QCOMPARE( ca1.constraints().contains(QCA::KeyEncipherment), (QBool)true );
	    QCOMPARE( ca1.constraints().contains(QCA::DataEncipherment), (QBool)false );
	    QCOMPARE( ca1.constraints().contains(QCA::KeyAgreement), (QBool)false );
	    QCOMPARE( ca1.constraints().contains(QCA::KeyCertificateSign), (QBool)true );
	    QCOMPARE( ca1.constraints().contains(QCA::CRLSign), (QBool)true );
	    QCOMPARE( ca1.constraints().contains(QCA::EncipherOnly), (QBool)false );
	    QCOMPARE( ca1.constraints().contains(QCA::DecipherOnly), (QBool)false );
	    QCOMPARE( ca1.constraints().contains(QCA::ServerAuth), (QBool)false );
	    QCOMPARE( ca1.constraints().contains(QCA::ClientAuth), (QBool)false );
	    QCOMPARE( ca1.constraints().contains(QCA::CodeSigning), (QBool)false );
	    QCOMPARE( ca1.constraints().contains(QCA::EmailProtection), (QBool)false );
	    QCOMPARE( ca1.constraints().contains(QCA::IPSecEndSystem), (QBool)false );
	    QCOMPARE( ca1.constraints().contains(QCA::IPSecTunnel), (QBool)false);
	    QCOMPARE( ca1.constraints().contains(QCA::IPSecUser), (QBool)false );
	    QCOMPARE( ca1.constraints().contains(QCA::TimeStamping), (QBool)false );
	    QCOMPARE( ca1.constraints().contains(QCA::OCSPSigning), (QBool)false );

	    // no policies on this cert
	    QCOMPARE( ca1.policies().count(), 0 );
	}
    }
}

void CertUnitTest::qualitysslcatest()
{
    QStringList providersToTest;
    providersToTest.append("qca-openssl");
    providersToTest.append("qca-gcrypt");
    providersToTest.append("qca-botan");

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

	    QSecureArray expectedSig = 
		QCA::hexToArray("3a1e246fdadb366cfe3a7339ddcd6a1c69a1"
				"001f6fd4aed51fd48829a521c257f6557b30"
				"e7d264d60ec4aa703c7674e22aaec7466732"
				"92c94bf1a7d7e056bcf672109d7fb075d69d"
				"57b57185aac43aa74bb8ec0fe6d2f8ffb5cd"
				"d44525acea06a78ab5cd3222e421921befce"
				"34ae30441aee9b7ff09411868a871901283a"
				"cfb3");
	    QCOMPARE( ca1.signature(), expectedSig );
    
	    QCOMPARE( ca1.signatureAlgorithm(), QCA::EMSA3_SHA1 );

	    QCOMPARE( ca1.serialNumber(), QBigInteger("33555098") );
	    
	    QCOMPARE( ca1.commonName(), QString("Comodo Class 3 Security Services CA") );
	    
	    QCOMPARE( ca1.notValidBefore().toString(), QDateTime( QDate( 2002, 8, 27 ), QTime( 19, 02, 00 ), Qt::UTC ).toString() );
	    QCOMPARE( ca1.notValidAfter().toString(), QDateTime( QDate( 2012, 8, 27 ), QTime( 23, 59, 00 ), Qt::UTC ).toString() );
	    

	    QCOMPARE( ca1.pathLimit(), 0 );

	    QCOMPARE( ca1.constraints().contains(QCA::DigitalSignature), (QBool)true );
	    QCOMPARE( ca1.constraints().contains(QCA::NonRepudiation), (QBool)true );
	    QCOMPARE( ca1.constraints().contains(QCA::KeyEncipherment), (QBool)true );
	    QCOMPARE( ca1.constraints().contains(QCA::DataEncipherment), (QBool)false );
	    QCOMPARE( ca1.constraints().contains(QCA::KeyAgreement), (QBool)false );
	    QCOMPARE( ca1.constraints().contains(QCA::KeyCertificateSign), (QBool)true );
	    QCOMPARE( ca1.constraints().contains(QCA::CRLSign), (QBool)true );
	    QCOMPARE( ca1.constraints().contains(QCA::EncipherOnly), (QBool)false );
	    QCOMPARE( ca1.constraints().contains(QCA::DecipherOnly), (QBool)false );
	    QCOMPARE( ca1.constraints().contains(QCA::ServerAuth), (QBool)false );
	    QCOMPARE( ca1.constraints().contains(QCA::ClientAuth), (QBool)false );
	    QCOMPARE( ca1.constraints().contains(QCA::CodeSigning), (QBool)false );
	    QCOMPARE( ca1.constraints().contains(QCA::EmailProtection), (QBool)false );
	    QCOMPARE( ca1.constraints().contains(QCA::IPSecEndSystem), (QBool)false );
	    QCOMPARE( ca1.constraints().contains(QCA::IPSecTunnel), (QBool)false);
	    QCOMPARE( ca1.constraints().contains(QCA::IPSecUser), (QBool)false );
	    QCOMPARE( ca1.constraints().contains(QCA::TimeStamping), (QBool)false );
	    QCOMPARE( ca1.constraints().contains(QCA::OCSPSigning), (QBool)false );
	}
    }
}

void CertUnitTest::checkClientCerts()
{
    QStringList providersToTest;
    providersToTest.append("qca-openssl");
    providersToTest.append("qca-gcrypt");
    providersToTest.append("qca-botan");

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
	    
	    QCOMPARE( client1.serialNumber(), QBigInteger(2) );
	    
	    QCOMPARE( client1.commonName(), QString("Insecure User Test Cert") );

	    QSecureArray expectedSig = 
		QCA::hexToArray("791044711ff1a78a4b1f755b4264db6441a3"
				"544043c4d01aa6c7480eb281d5e700dc9321"
				"6438f078a738306e4cf8543985c093f244a2"
				"fba6cbd79049472c8c078ef6ecd4520b58bf"
				"d959199941a1864dc047d523b2fac20b4d03"
				"80fb877503eb23197df822b6eb2a404e2cdb"
				"e556a9ce6a0173607f75679587e2896c4920"
				"4ee75f163f7c0ea9fc9225276ea6c2dce30f"
				"6b5ba27b3f287abf21e8e0323a29e6c746ad"
				"8d3a92e5238b23edbea75969307321a1d9f8"
				"8e099df0f9ac290d23332034650d6da33417"
				"3b0f55a5161e82c9bc2ccab47a675fc9bc69"
				"c066eb088224ec15e30480eb8586e76f718a"
				"6e5ca4cede1ba8e783b49b9383204e4b72dd"
				"c6a81fce");
	    QCOMPARE( client1.signature(), expectedSig );
	    
	    QCOMPARE( client1.notValidBefore().toString(), QDateTime( QDate( 2001, 8, 17 ), QTime( 8, 32, 38 ), Qt::UTC ).toString() );
	    QCOMPARE( client1.notValidAfter().toString(), QDateTime( QDate( 2006, 8, 16 ), QTime( 8, 32, 38 ), Qt::UTC ).toString() );
	    
	    QCOMPARE( client1.constraints().contains(QCA::DigitalSignature), (QBool)true );
	    QCOMPARE( client1.constraints().contains(QCA::NonRepudiation), (QBool)true );
	    QCOMPARE( client1.constraints().contains(QCA::KeyEncipherment), (QBool)true );
	    QCOMPARE( client1.constraints().contains(QCA::DataEncipherment), (QBool)true );
	    QCOMPARE( client1.constraints().contains(QCA::KeyAgreement), (QBool)false );
	    QCOMPARE( client1.constraints().contains(QCA::KeyCertificateSign), (QBool)false );
	    QCOMPARE( client1.constraints().contains(QCA::CRLSign), (QBool)false );
	    QCOMPARE( client1.constraints().contains(QCA::EncipherOnly), (QBool)false );
	    QCOMPARE( client1.constraints().contains(QCA::DecipherOnly), (QBool)false );
	    QCOMPARE( client1.constraints().contains(QCA::ServerAuth), (QBool)false );
	    QCOMPARE( client1.constraints().contains(QCA::ClientAuth), (QBool)true );
	    QCOMPARE( client1.constraints().contains(QCA::CodeSigning), (QBool)false );
	    QCOMPARE( client1.constraints().contains(QCA::EmailProtection), (QBool)true );
	    QCOMPARE( client1.constraints().contains(QCA::IPSecEndSystem), (QBool)false );
	    QCOMPARE( client1.constraints().contains(QCA::IPSecTunnel), (QBool)false);
	    QCOMPARE( client1.constraints().contains(QCA::IPSecUser), (QBool)false );
	    QCOMPARE( client1.constraints().contains(QCA::TimeStamping), (QBool)false );
	    QCOMPARE( client1.constraints().contains(QCA::OCSPSigning), (QBool)false );

	    // no policies on this cert
	    QCOMPARE( client1.policies().count(), 0 );
	    
	    QCA::CertificateInfo subject1 = client1.subjectInfo();
	    QCOMPARE( subject1.isEmpty(), false );
	    QCOMPARE( subject1.values(QCA::Country).contains("de"), (QBool)true );
	    QCOMPARE( subject1.values(QCA::Organization).contains("InsecureTestCertificate"), (QBool)true );
	    QCOMPARE( subject1.values(QCA::CommonName).contains("Insecure User Test Cert"), (QBool)true );
	    
	    QCA::CertificateInfo issuer1 = client1.issuerInfo();
	    QCOMPARE( issuer1.isEmpty(), false );
	    QCOMPARE( issuer1.values(QCA::Country).contains("de"), (QBool)true );
	    QCOMPARE( issuer1.values(QCA::Organization).contains("InsecureTestCertificate"), (QBool)true );
	    QCOMPARE( issuer1.values(QCA::CommonName).contains("For Tests Only"), (QBool)true );

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
	    QCOMPARE( client1.validate( trusted, untrusted ), QCA::ValidityGood );
	    QCOMPARE( client1.validate( trusted, untrusted, QCA::UsageAny ), QCA::ValidityGood );
	    QCOMPARE( client1.validate( trusted, untrusted, QCA::UsageTLSServer ), QCA::ErrorInvalidPurpose );
	    QCOMPARE( client1.validate( trusted, untrusted, QCA::UsageTLSClient ), QCA::ValidityGood );
	    QCOMPARE( client1.validate( trusted, untrusted, QCA::UsageCodeSigning ), QCA::ErrorInvalidPurpose );
	    QCOMPARE( client1.validate( trusted, untrusted, QCA::UsageTimeStamping ), QCA::ErrorInvalidPurpose );
	    QCOMPARE( client1.validate( trusted, untrusted, QCA::UsageEmailProtection ), QCA::ValidityGood );
	    QCOMPARE( client1.validate( trusted, untrusted, QCA::UsageCRLSigning ), QCA::ErrorInvalidPurpose );

	    QSecureArray derClient1 = client1.toDER();
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


void CertUnitTest::checkServerCerts()
{
    QStringList providersToTest;
    providersToTest.append("qca-openssl");
    providersToTest.append("qca-gcrypt");
    providersToTest.append("qca-botan");

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
	    
	    QCOMPARE( server1.serialNumber(), QBigInteger(4) );

	    QCOMPARE( server1.commonName(), QString("Insecure Server Cert") );
	    
	    QSecureArray expectedSig = 
		QCA::hexToArray("43e7896443b7ffb4d579dcfef1566de3b871"
				"d9bdecf67c1b017ffa6f41192fa8f812826e"
				"5305f5ff4f265efd471f43d2cf6616476ece"
				"eeb9d9a2b9fff32af6ecc301b20b990c64de"
				"65dd9bd66a0e0d41912b68059c6d94e63240"
				"25babc3b8b80df8436dfcacef43a918a0655"
				"a6730fbba13ef0a12197ddc952d3613f1056"
				"c0fa0ee717cbf1def2d309b7538f9643fb12"
				"c2578eb60077cb6727e07709e285d968e7e5"
				"75a94254ea812ccc3a2936c6322dd0153d89"
				"d26aac86ec4b412d3ad03141c37fcbd3a81d"
				"7a5c1a6bdfe539441922f06d762f07d9e6b4"
				"8ce65f40e740d24fd429dfe3a7d49eaf9001"
				"f876550f69a1c13f1852133f64f47fb81b3c"
				"cc6a8812" );
	    QCOMPARE( server1.signature(), expectedSig );

	    QCOMPARE( server1.notValidBefore().toString(), QDateTime( QDate( 2001, 8, 17 ), QTime( 8, 46, 24 ), Qt::UTC ).toString() );
	    QCOMPARE( server1.notValidAfter().toString(), QDateTime( QDate( 2006, 8, 16 ), QTime( 8, 46, 24 ), Qt::UTC ).toString() );
	    
	    QCOMPARE( server1.constraints().contains(QCA::DigitalSignature), (QBool)true );
	    QCOMPARE( server1.constraints().contains(QCA::NonRepudiation), (QBool)false );
	    QCOMPARE( server1.constraints().contains(QCA::KeyEncipherment), (QBool)true );
	    QCOMPARE( server1.constraints().contains(QCA::DataEncipherment), (QBool)false );
	    QCOMPARE( server1.constraints().contains(QCA::KeyAgreement), (QBool)true );
	    QCOMPARE( server1.constraints().contains(QCA::KeyCertificateSign), (QBool)false );
	    QCOMPARE( server1.constraints().contains(QCA::CRLSign), (QBool)false );
	    QCOMPARE( server1.constraints().contains(QCA::EncipherOnly), (QBool)false );
	    QCOMPARE( server1.constraints().contains(QCA::DecipherOnly), (QBool)false );
	    QCOMPARE( server1.constraints().contains(QCA::ServerAuth), (QBool)true );
	    QCOMPARE( server1.constraints().contains(QCA::ClientAuth), (QBool)false );
	    QCOMPARE( server1.constraints().contains(QCA::CodeSigning), (QBool)false );
	    QCOMPARE( server1.constraints().contains(QCA::EmailProtection), (QBool)false );
	    QCOMPARE( server1.constraints().contains(QCA::IPSecEndSystem), (QBool)false );
	    QCOMPARE( server1.constraints().contains(QCA::IPSecTunnel), (QBool)false);
	    QCOMPARE( server1.constraints().contains(QCA::IPSecUser), (QBool)false );
	    QCOMPARE( server1.constraints().contains(QCA::TimeStamping), (QBool)false );
	    QCOMPARE( server1.constraints().contains(QCA::OCSPSigning), (QBool)false );
	    
	    // no policies on this cert
	    QCOMPARE( server1.policies().count(), 0 );
	    
	    QCA::CertificateInfo subject1 = server1.subjectInfo();
	    QCOMPARE( subject1.isEmpty(), false );
	    QCOMPARE( subject1.values(QCA::Country).contains("de"), (QBool)true );
	    QCOMPARE( subject1.values(QCA::Organization).contains("InsecureTestCertificate"), (QBool)true );
	    QCOMPARE( subject1.values(QCA::CommonName).contains("Insecure Server Cert"), (QBool)true );
    
	    QCA::CertificateInfo issuer1 = server1.issuerInfo();
	    QCOMPARE( issuer1.isEmpty(), false );
	    QCOMPARE( issuer1.values(QCA::Country).contains("de"), (QBool)true );
	    QCOMPARE( issuer1.values(QCA::Organization).contains("InsecureTestCertificate"), (QBool)true );
	    QCOMPARE( issuer1.values(QCA::CommonName).contains("For Tests Only"), (QBool)true );
	    
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
	    QCOMPARE( server1.validate( trusted, untrusted ), QCA::ValidityGood );
	    QCOMPARE( server1.validate( trusted, untrusted, QCA::UsageAny ), QCA::ValidityGood );
	    QCOMPARE( server1.validate( trusted, untrusted, QCA::UsageTLSServer ), QCA::ValidityGood);
	    QCOMPARE( server1.validate( trusted, untrusted, QCA::UsageTLSClient ), QCA::ErrorInvalidPurpose );
	    QCOMPARE( server1.validate( trusted, untrusted, QCA::UsageCodeSigning ), QCA::ErrorInvalidPurpose );
	    QCOMPARE( server1.validate( trusted, untrusted, QCA::UsageTimeStamping ), QCA::ErrorInvalidPurpose );
	    QCOMPARE( server1.validate( trusted, untrusted, QCA::UsageEmailProtection ), QCA::ErrorInvalidPurpose );
	    QCOMPARE( server1.validate( trusted, untrusted, QCA::UsageCRLSigning ), QCA::ErrorInvalidPurpose );
	    
	    QSecureArray derServer1 = server1.toDER();
	    QCOMPARE( derServer1.isEmpty(), false );
	    QCA::Certificate fromDer1 = QCA::Certificate::fromDER( derServer1, &resultServer1, provider );
	    QCOMPARE( resultServer1, QCA::ConvertGood );
	    QCOMPARE( fromDer1 == server1, true );
	}
    }
}


void CertUnitTest::checkSystemStore()
{
    QCOMPARE( QCA::haveSystemStore(), true );

    if ( QCA::haveSystemStore() && QCA::isSupported("cert") ) {
	QCA::CertificateCollection collection1;
	collection1 = QCA::systemStore();
    }
}

QTEST_MAIN(CertUnitTest)
