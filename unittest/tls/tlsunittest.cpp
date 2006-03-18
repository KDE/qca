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
#include "tlsunittest.h"
#include <QtCrypto>

void TLSUnitTest::initTestCase()
{
    m_init = new QCA::Initializer;
#include "../fixpaths.include"
}

void TLSUnitTest::cleanupTestCase()
{
    delete m_init;
}

void TLSUnitTest::testCipherList()
{
    if(!QCA::isSupported("tls", "qca-openssl"))
	QWARN("TLS not supported for qca-openssl");
    else {
	QStringList cipherList = QCA::TLS::supportedCipherSuites(QCA::TLS::TLS_v1, "qca-openssl");
	QVERIFY( cipherList.contains("TLS_DHE_RSA_WITH_AES_256_CBC_SHA") );
	QVERIFY( cipherList.contains("TLS_DHE_DSS_WITH_AES_256_CBC_SHA") );
	QVERIFY( cipherList.contains("TLS_RSA_WITH_AES_256_CBC_SHA") );
	QVERIFY( cipherList.contains("TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA") );
	QVERIFY( cipherList.contains("TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA") );
	QVERIFY( cipherList.contains("TLS_RSA_WITH_3DES_EDE_CBC_SHA") );
	QVERIFY( cipherList.contains("TLS_DHE_RSA_WITH_AES_128_CBC_SHA") );
	QVERIFY( cipherList.contains("TLS_DHE_DSS_WITH_AES_128_CBC_SHA") );
	QVERIFY( cipherList.contains("TLS_RSA_WITH_AES_128_CBC_SHA") );
	QVERIFY( cipherList.contains("TLS_RSA_WITH_IDEA_CBC_SHA") );
	QVERIFY( cipherList.contains("TLS_CK_DHE_DSS_WITH_RC4_128_SHA") );
	QVERIFY( cipherList.contains("TLS_RSA_WITH_RC4_128_SHA") );
	QVERIFY( cipherList.contains("TLS_RSA_WITH_RC4_128_MD5") );
	QVERIFY( cipherList.contains("TLS_CK_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA") );
	QVERIFY( cipherList.contains("TLS_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA") );
	QVERIFY( cipherList.contains("TLS_CK_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5") );
	QVERIFY( cipherList.contains("TLS_DHE_RSA_WITH_DES_CBC_SHA") );
	QVERIFY( cipherList.contains("TLS_DHE_DSS_WITH_DES_CBC_SHA") );
	QVERIFY( cipherList.contains("TLS_RSA_WITH_DES_CBC_SHA") );
	QVERIFY( cipherList.contains("TLS_CK_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA") );
	QVERIFY( cipherList.contains("TLS_CK_RSA_EXPORT1024_WITH_RC4_56_SHA") );
	QVERIFY( cipherList.contains("TLS_CK_RSA_EXPORT1024_WITH_RC4_56_MD5") );
	QVERIFY( cipherList.contains("TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA") );
	QVERIFY( cipherList.contains("TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA") );
	QVERIFY( cipherList.contains("TLS_RSA_EXPORT_WITH_DES40_CBC_SHA") );
	QVERIFY( cipherList.contains("TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5") );
	QVERIFY( cipherList.contains("TLS_RSA_EXPORT_WITH_RC4_40_MD5") );

	cipherList = QCA::TLS::supportedCipherSuites(QCA::TLS::SSL_v3, "qca-openssl");
	QVERIFY( cipherList.contains("SSL_DHE_RSA_WITH_AES_256_CBC_SHA") );
	QVERIFY( cipherList.contains("SSL_DHE_DSS_WITH_AES_256_CBC_SHA") );
	QVERIFY( cipherList.contains("SSL_RSA_WITH_AES_256_CBC_SHA") );
	QVERIFY( cipherList.contains("SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA") );
	QVERIFY( cipherList.contains("SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA") );
	QVERIFY( cipherList.contains("SSL_RSA_WITH_3DES_EDE_CBC_SHA") );
	QVERIFY( cipherList.contains("SSL_DHE_RSA_WITH_AES_128_CBC_SHA") );
	QVERIFY( cipherList.contains("SSL_DHE_DSS_WITH_AES_128_CBC_SHA") );
	QVERIFY( cipherList.contains("SSL_RSA_WITH_AES_128_CBC_SHA") );
	QVERIFY( cipherList.contains("SSL_RSA_WITH_IDEA_CBC_SHA") );
	QVERIFY( cipherList.contains("SSL_CK_DHE_DSS_WITH_RC4_128_SHA") );
	QVERIFY( cipherList.contains("SSL_RSA_WITH_RC4_128_SHA") );
	QVERIFY( cipherList.contains("SSL_RSA_WITH_RC4_128_MD5") );
	QVERIFY( cipherList.contains("SSL_CK_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA") );
	QVERIFY( cipherList.contains("SSL_CK_RSA_EXPORT1024_WITH_DES_CBC_SHA") );
	QVERIFY( cipherList.contains("SSL_CK_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5") );
	QVERIFY( cipherList.contains("SSL_DHE_RSA_WITH_DES_CBC_SHA") );
	QVERIFY( cipherList.contains("SSL_DHE_DSS_WITH_DES_CBC_SHA") );
	QVERIFY( cipherList.contains("SSL_RSA_WITH_DES_CBC_SHA") );
	QVERIFY( cipherList.contains("SSL_CK_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA") );
	QVERIFY( cipherList.contains("SSL_CK_RSA_EXPORT1024_WITH_RC4_56_SHA") );
	QVERIFY( cipherList.contains("SSL_CK_RSA_EXPORT1024_WITH_RC4_56_MD5") );
	QVERIFY( cipherList.contains("SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA") );
	QVERIFY( cipherList.contains("SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA") );
	QVERIFY( cipherList.contains("SSL_RSA_EXPORT_WITH_DES40_CBC_SHA") );
	QVERIFY( cipherList.contains("SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5") );
	QVERIFY( cipherList.contains("SSL_RSA_EXPORT_WITH_RC4_40_MD5") );

	cipherList = QCA::TLS::supportedCipherSuites(QCA::TLS::SSL_v2, "qca-openssl");
	QVERIFY( cipherList.contains("SSL_CK_DES_192_EDE3_CBC_WITH_MD5") );
	QVERIFY( cipherList.contains("SSL_CK_RC4_128_EXPORT40_WITH_MD5") );
	QVERIFY( cipherList.contains("SSL_CK_RC2_128_CBC_WITH_MD5") );
	QVERIFY( cipherList.contains("SSL_CK_RC4_128_WITH_MD5") );
	QVERIFY( cipherList.contains("SSL_CK_RC4_64_WITH_MD5") );
	QVERIFY( cipherList.contains("SSL_CK_DES_64_CBC_WITH_MD5") );
	QVERIFY( cipherList.contains("SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5") );
	QVERIFY( cipherList.contains("SSL_CK_RC4_128_EXPORT40_WITH_MD5") );
    }
}

QTEST_MAIN(TLSUnitTest)
