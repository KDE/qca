/**
 * Copyright (C)  2005  Brad Hards <bradh@frogmouth.net>
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
#include "keygenunittest.h"
#include <QtCrypto>
#include <QList>

KeyGenUnitTest::KeyGenUnitTest()
    : Tester()
{

}

void KeyGenUnitTest::allTests()
{
    QCA::Initializer init;

    QCA::KeyGenerator keygen;
    CHECK( keygen.isBusy(), false );
    CHECK( keygen.blocking(), true );

    if(!QCA::isSupported("pkey") ||
       !QCA::PKey::supportedTypes().contains(QCA::PKey::RSA) ||
       !QCA::PKey::supportedIOTypes().contains(QCA::PKey::RSA))
        SKIP("RSA not supported!");
    else {
      QCA::PrivateKey priv1 = keygen.createRSA( 1024, 65537 );
      QCA::RSAPrivateKey rsa1 = priv1.toRSA();
      CHECK( rsa1.isNull(), false );
      CHECK( rsa1.e(), QBigInteger(65537) );
      CHECK( rsa1.bitSize(), 1024);

      priv1 = keygen.createRSA( 512, 17 );
      rsa1 = priv1.toRSA();
      CHECK( rsa1.isNull(), false );
      CHECK( rsa1.e(), QBigInteger(17) );
      CHECK( rsa1.bitSize(), 512);

      priv1 = keygen.createRSA( 512, 3 );
      rsa1 = priv1.toRSA();
      CHECK( rsa1.isNull(), false );
      CHECK( rsa1.e(), QBigInteger(3) );
      CHECK( rsa1.bitSize(), 512);
    }

    // DSA
    if(!QCA::isSupported("pkey") ||
       !QCA::PKey::supportedTypes().contains(QCA::PKey::DSA) ||
       !QCA::PKey::supportedIOTypes().contains(QCA::PKey::DSA))
        SKIP("DSA not supported!");
    else {
      QCA::DLGroup group = keygen.createDLGroup( QCA::DSA_512 );
      QCA::PrivateKey priv2 = keygen.createDSA( group );
      QCA::DSAPrivateKey dsa1 = priv2.toDSA();
      CHECK( dsa1.isNull(), false );
      CHECK( dsa1.bitSize(), 512 );
      
      group = keygen.createDLGroup( QCA::DSA_768 );
      priv2 = keygen.createDSA( group );
      dsa1 = priv2.toDSA();
      CHECK( dsa1.isNull(), false );
      CHECK( dsa1.bitSize(), 768 );
      
      group = keygen.createDLGroup( QCA::DSA_1024 );
      priv2 = keygen.createDSA( group );
      dsa1 = priv2.toDSA();
      CHECK( dsa1.isNull(), false );
      CHECK( dsa1.bitSize(), 1024 );
    }

    // DH
    if(!QCA::isSupported("pkey") ||
       !QCA::PKey::supportedTypes().contains(QCA::PKey::DH) ||
       !QCA::PKey::supportedIOTypes().contains(QCA::PKey::DH))
        SKIP("DH not supported!");
    else {
      QCA::DLGroup group = keygen.createDLGroup( QCA::IETF_1024 );
      QCA::PrivateKey priv3 = keygen.createDH( group );
      QCA::DHPrivateKey dh1 = priv3.toDH();
      CHECK( dh1.isNull(), false );
      CHECK( dh1.bitSize(), 1024 );
      
      group = keygen.createDLGroup( QCA::IETF_2048 );
      priv3 = keygen.createDH( group );
      dh1 = priv3.toDH();
      CHECK( dh1.isNull(), false );
      CHECK( dh1.bitSize(), 2048 );
    }
}

