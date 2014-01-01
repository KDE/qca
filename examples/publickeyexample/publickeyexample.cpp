/*
 Copyright (C) 2003 Justin Karneges <justin@affinix.com>
 Copyright (C) 2005 Brad Hards <bradh@frogmouth.net>

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
 AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/


#include <QtCrypto>

#include <QCoreApplication>

#include <iostream>

#ifdef QT_STATICPLUGIN
#include "import_plugins.h"
#endif

int main(int argc, char** argv)
{
    // the Initializer object sets things up, and
    // also does cleanup when it goes out of scope
    QCA::Initializer init;

    QCoreApplication app(argc, argv);

    // We need to ensure that we have certificate handling support
    if ( !QCA::isSupported( "cert" ) ) {
	std::cout << "Sorry, no PKI certificate support" << std::endl;
    	return 1;
    }

    // Read in a private key
    QCA::PrivateKey privKey;
    QCA::ConvertResult convRes;
    QCA::SecureArray passPhrase = "start";
    privKey = QCA::PrivateKey::fromPEMFile( "Userkey.pem", passPhrase, &convRes );
    if ( convRes != QCA::ConvertGood ) {
	std::cout << "Sorry, could not import Private Key" << std::endl;
	return 1;
    }

    // Read in a matching public key cert
    // you could also build this using the fromPEMFile() method
    QCA::Certificate pubCert( "User.pem" );
    if ( pubCert.isNull() ) {
	std::cout << "Sorry, could not import public key certificate" << std::endl;
	return 1;
    }
    // We are building the certificate into a SecureMessageKey object, via a
    // CertificateChain
    QCA::SecureMessageKey secMsgKey;
    QCA::CertificateChain chain;
    chain += pubCert;
    secMsgKey.setX509CertificateChain( chain );

    // build up a SecureMessage object, based on our public key certificate
    QCA::CMS cms;
    QCA::SecureMessage msg(&cms);
    msg.setRecipient(secMsgKey);

    // Some plain text - we use the first command line argument if provided
    QByteArray plainText = (argc >= 2) ? argv[1] : "What do ya want for nuthin'";

    // Now use the SecureMessage object to encrypt the plain text.
    msg.startEncrypt();
    msg.update(plainText);
    msg.end();
    // I think it is reasonable to wait for 1 second for this
    msg.waitForFinished(1000);

    // check to see if it worked
    if(!msg.success())
    {
	std::cout << "Error encrypting: " << msg.errorCode() << std::endl;
	return 1;
    }

    // get the result
    QCA::SecureArray cipherText = msg.read();
    QCA::Base64 enc;
    std::cout << plainText.data() << " encrypts to (in base 64): ";
    std::cout << qPrintable( enc.arrayToString( cipherText ) ) << std::endl;

    // Show we can decrypt it with the private key
    if ( !privKey.canDecrypt() ) {
	std::cout << "Private key cannot be used to decrypt" << std::endl;
	return 1;
    }
    QCA::SecureArray plainTextResult;
    if ( 0 == privKey.decrypt(cipherText, &plainTextResult, QCA::EME_PKCS1_OAEP ) ) {
	std::cout << "Decryption process failed" << std::endl;
	return 1;
    }

    std::cout << qPrintable( enc.arrayToString( cipherText ) );
    std::cout << " (in base 64) decrypts to: ";
    std::cout << plainTextResult.data() << std::endl;

    return 0;
}

