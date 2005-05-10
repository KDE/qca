/**
 * Copyright (C)  2004  Brad Hards <bradh@frogmouth.net>
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
#include "staticunittest.h"
#include <QtCrypto>

StaticUnitTest::StaticUnitTest()
    : Tester()
{

}

void StaticUnitTest::allTests()
{
    QCA::Initializer init;

    QByteArray test(10, 'a');

    CHECK( QCA::arrayToHex(test), QString("61616161616161616161") );

    test.fill('b');
    test[7] = 0x00;

    CHECK( test == QCA::hexToArray(QString("62626262626262006262")), true );

    QSecureArray testArray(10);
    //testArray.fill( 'a' );
    for (int i = 0; i < testArray.size(); i++) {
	testArray[ i ] = 0x61;
    }
    CHECK( QCA::arrayToHex( testArray ), QString( "61616161616161616161" ) );
    //testArray.fill( 'b' );
    for (int i = 0; i < testArray.size(); i++) {
	testArray[ i ] = 0x62;
    }
    testArray[6] = 0x00;
    CHECK( testArray == QCA::hexToArray(QString("62626262626200626262")), true );

    CHECK( testArray == QCA::hexToArray( QCA::arrayToHex( testArray ) ), true );

    testArray[9] = 0x00;
    CHECK( testArray == QCA::hexToArray( QCA::arrayToHex( testArray ) ), true );

    // capabilities are reported as a list - that is a problem for
    // doing a direct comparison, since they change
    // We try to work around that using contains()
    QStringList supportedCapabilities = QCA::supportedFeatures();
    CHECK( supportedCapabilities.contains("random"), (QBool)true );
    CHECK( supportedCapabilities.contains("sha1"), (QBool)true );
    CHECK( supportedCapabilities.contains("sha0"), (QBool)true );
    CHECK( supportedCapabilities.contains("md2"),(QBool) true );
    CHECK( supportedCapabilities.contains("md4"), (QBool)true );
    CHECK( supportedCapabilities.contains("md5"), (QBool)true );
    CHECK( supportedCapabilities.contains("ripemd160"), (QBool)true );

    QStringList defaultCapabilities = QCA::defaultFeatures();
    CHECK( defaultCapabilities.contains("random"), (QBool)true );

    CHECK( QCA::isSupported("random"), true );
    CHECK( QCA::isSupported("sha0"), true );
    CHECK( QCA::isSupported("sha0,sha1"), true );
    CHECK( QCA::isSupported("md2,md4,md5"), true );
    CHECK( QCA::isSupported("md5"), true );
    CHECK( QCA::isSupported("ripemd160"), true );
    CHECK( QCA::isSupported("sha256,sha384,sha512"), true );
    CHECK( QCA::isSupported("nosuchfeature"), false );

    QString caps( "random,sha1,md5,ripemd160");
    QStringList capList;
    capList = caps.split( "," );
    CHECK( QCA::isSupported(capList), true );
    capList.append("noSuch");
    CHECK( QCA::isSupported(capList), false );
    capList.clear();
    capList.append("noSuch");
    CHECK( QCA::isSupported(capList), false );


    // this should be reliably true
    CHECK( QCA::haveSecureMemory(), true );

    // providers are obviously variable, this might be a bit brittle
    QStringList providerNames;
    QCA::ProviderList qcaProviders = QCA::providers();
    for (int i = 0; i < qcaProviders.size(); ++i) {
	providerNames.append( qcaProviders[i]->name() );
    }
    CHECK( providerNames.contains("qca-openssl"), (QBool)true );
    CHECK( providerNames.contains("qca-gcrypt"), (QBool)true );
    CHECK( providerNames.contains("qca-botan"), (QBool)true );

    QCA::setProviderPriority("qca-openssl", 4);
    QCA::setProviderPriority("qca-botan", 2);
    CHECK( QCA::providerPriority( "qca-openssl"), 4 );
    CHECK( QCA::providerPriority( "qca-gcrypt"), 0 );
    CHECK( QCA::providerPriority( "qca-botan"), 2 );
    QCA::setProviderPriority("qca-openssl", 3);
    // reuse last
    QCA::setProviderPriority("qca-botan", -1);
    CHECK( QCA::providerPriority( "qca-botan"), 3 );

    QCA::unloadAllPlugins();
}

