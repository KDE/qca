/**
 * Copyright (C)  2004-2007  Brad Hards <bradh@frogmouth.net>
 * Copyright (C)  2013-2016  Ivan Romanov <drizt@land.ru>
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

#ifndef CIPHERUNITTEST_H
#define CIPHERUNITTEST_H

#include <QtCrypto>

class CipherUnitTest : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void initTestCase();
    void cleanupTestCase();
    void aes128_data();
    void aes128();
    void aes128_cbc_data();
    void aes128_cbc();
    void aes128_cbc_pkcs7_data();
    void aes128_cbc_pkcs7();
    void aes128_cfb_data();
    void aes128_cfb();
    void aes128_ofb_data();
    void aes128_ofb();
    void aes128_ctr_data();
    void aes128_ctr();
    void aes128_gcm_data();
    void aes128_gcm();
    void aes128_ccm_data();
    void aes128_ccm();

    void aes192_data();
    void aes192();
    void aes192_cbc_data();
    void aes192_cbc();
    void aes192_cbc_pkcs7_data();
    void aes192_cbc_pkcs7();
    void aes192_cfb_data();
    void aes192_cfb();
    void aes192_ofb_data();
    void aes192_ofb();
    void aes192_ctr_data();
    void aes192_ctr();
    void aes192_gcm_data();
    void aes192_gcm();
    void aes192_ccm_data();
    void aes192_ccm();

    void aes256_data();
    void aes256();
    void aes256_cbc_data();
    void aes256_cbc();
    void aes256_cbc_pkcs7_data();
    void aes256_cbc_pkcs7();
    void aes256_cfb_data();
    void aes256_cfb();
    void aes256_ofb_data();
    void aes256_ofb();
    void aes256_ctr_data();
    void aes256_ctr();
    void aes256_gcm_data();
    void aes256_gcm();
    void aes256_ccm_data();
    void aes256_ccm();

    void tripleDES_data();
    void tripleDES();

    void des_data();
    void des();
    void des_pkcs7_data();
    void des_pkcs7();
    void des_cbc_data();
    void des_cbc();
    void des_cbc_pkcs7_data();
    void des_cbc_pkcs7();
    void des_cfb_data();
    void des_cfb();
    void des_ofb_data();
    void des_ofb();

    void blowfish_data();
    void blowfish();
    void blowfish_cbc_data();
    void blowfish_cbc();
    void blowfish_cbc_pkcs7_data();
    void blowfish_cbc_pkcs7();
    void blowfish_cfb_data();
    void blowfish_cfb();
    void blowfish_ofb_data();
    void blowfish_ofb();

    void cast5_data();
    void cast5();

private:
    QCA::Initializer *m_init;
    QStringList       providersToTest;
};

#endif // CIPHERUNITTEST_H
