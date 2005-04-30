/**
 * certunittest.cpp
 *
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

CertUnitTest::CertUnitTest()
    : Tester()
{

}

void CertUnitTest::checkCAcerts(QString provider)
{
    QCA::ConvertResult resultca1;
    QCA::Certificate ca1 = QCA::Certificate::fromPEMFile( "certs/RootCAcert.pem", &resultca1, provider);

    CHECK( resultca1, QCA::ConvertGood );
    CHECK( ca1.isNull(), false );
    CHECK( ca1.isCA(), true );
    CHECK( ca1.isSelfSigned(), true );

    CHECK( ca1.serialNumber(), QBigInteger(0) );
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
}

