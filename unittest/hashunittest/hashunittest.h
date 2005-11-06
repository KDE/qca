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
#ifndef HASHUNITTEST_H
#define HASHUNITTEST_H

#include <QtCrypto>
#include <QtTest/QtTest>

class HashUnitTest : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase();
    void cleanupTestCase();
    void md2test_data();
    void md2test();
    void md4test_data();
    void md4test();
    void md5test_data();
    void md5test();
    void md5filetest();
    void sha0test_data();
    void sha0test();
    void sha0longtest();
    void sha1test_data();
    void sha1test();
    void sha1longtest();
    void sha224test_data();
    void sha224test();
    void sha224longtest();
    void sha256test_data();
    void sha256test();
    void sha256longtest();
    void sha384test_data();
    void sha384test();
    void sha384longtest();
    void sha512test_data();
    void sha512test();
    void sha512longtest();
    void rmd160test_data();
    void rmd160test();
    void rmd160longtest();
private:
    QCA::Initializer* m_init;
};
#endif
