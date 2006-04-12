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

#include "cms.h"

#include <QtCrypto>

void CMSut::initTestCase()
{
    m_init = new QCA::Initializer;
#include "../fixpaths.include"
}

void CMSut::cleanupTestCase()
{
    delete m_init;
}

void CMSut::xcrypt_data()
{
    QTest::addColumn<QByteArray>("testText");

    QTest::newRow("empty") << QByteArray("");
    QTest::newRow("0") << QByteArray("0");
    QTest::newRow("07") << QByteArray("07899847jkjjfasjaJKJLJkljklj&kjlj;/**-+.01");
    QTest::newRow("dubious") << QByteArray("~!#**$#&&%^@#^&()");
}

void CMSut::xcrypt()
{
    QStringList providersToTest;
    providersToTest.append("qca-openssl");

    foreach(const QString provider, providersToTest) {
        if( !QCA::isSupported( "cert", provider ) )
            QWARN( QString( "Certificate not supported for "+provider).toLocal8Bit() );
        else if( !QCA::isSupported( "cms", provider ) )
	    QWARN( QString( "CMS not supported for "+provider).toLocal8Bit() );
	else {
	    QCA::Certificate pubCert( "User.pem" );
	    QCOMPARE( pubCert.isNull(), false );

	    QCA::SecureMessageKey secMsgKey;
	    QCA::CertificateChain chain;
	    chain += pubCert;
	    secMsgKey.setX509CertificateChain( chain );

	    QCA::CMS cms;
	    QCA::SecureMessage msg(&cms);
	    QCOMPARE( msg.canClearsign(), false );
	    QCOMPARE( msg.canSignAndEncrypt(), false );
	    
	    msg.setRecipient(secMsgKey);

	    QFETCH( QByteArray, testText );

	    msg.startEncrypt();
	    msg.update(testText);
	    msg.end();

	    msg.waitForFinished(-1);
	    
	    QByteArray result1 = msg.read();
	    QCOMPARE( result1.isEmpty(), false );
	    
	    msg.reset();
	    msg.startEncrypt();
	    msg.update( testText );
	    msg.end();

	    msg.waitForFinished(-1);
	    
	    QByteArray result2 = msg.read();

	    QCOMPARE( result1, result2 );
	}
    }
};


QTEST_MAIN(CMSut)


