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

int main(int argc, char **argv)
{
    // The Initializer object sets things up, and also
    // does cleanup when it goes out of scope
    QCA::Initializer init;

    QCoreApplication app(argc, argv);

    // we use the first argument if provided, or
    // use "hello" if no arguments
    QCA::SecureArray arg = (argc >= 2) ? argv[1] : "hello";

    // We demonstrate PEM usage here, so we need to test for
    // supportedIOTypes, not just supportedTypes
    if(!QCA::isSupported("pkey") ||
       !QCA::PKey::supportedIOTypes().contains(QCA::PKey::RSA))
	std::cout << "RSA not supported!\n";
    else {
	// When creating a public / private key pair, you make the
	// private key, and then extract the public key component from it
	// Using RSA is very common, however DSA can provide equivalent
	// signature/verification. This example applies to DSA to the
	// extent that the operations work on that key type.

	// QCA provides KeyGenerator as a convenient source of new keys,
	// however you could also import an existing key instead.
	QCA::PrivateKey seckey = QCA::KeyGenerator().createRSA(1024);
	if(seckey.isNull()) {
	    std::cout << "Failed to make private RSA key" << std::endl;
	    return 1;
	}

	QCA::PublicKey pubkey = seckey.toPublicKey();

	// check if the key can encrypt
	if(!pubkey.canEncrypt()) {
	    std::cout << "Error: this kind of key cannot encrypt" << std::endl;
	    return 1;
	}

	// encrypt some data - note that only the public key is required
	// you must also choose the algorithm to be used
	QCA::SecureArray result = pubkey.encrypt(arg, QCA::EME_PKCS1_OAEP);
	if(result.isEmpty()) {
	    std::cout << "Error encrypting" << std::endl;
	    return 1;
	}

	// output the encrypted data
	QString rstr = QCA::arrayToHex(result.toByteArray());
	std::cout << "\"" << arg.data() << "\" encrypted with RSA is \"";
	std::cout << qPrintable(rstr) << "\"" << std::endl;

	// save the private key - in a real example, make sure this goes
	// somewhere secure and has a good pass phrase
	// You can use the same technique with the public key too.
	QCA::SecureArray passPhrase = "pass phrase";
	seckey.toPEMFile("keyprivate.pem", passPhrase);

	// Read that key back in, checking if the read succeeded
	QCA::ConvertResult conversionResult;
	QCA::PrivateKey privateKey = QCA::PrivateKey::fromPEMFile( "keyprivate.pem",
								   passPhrase,
								   &conversionResult);
	if (! (QCA::ConvertGood == conversionResult) ) {
	    std::cout << "Private key read failed" << std::endl;
	}

	// now decrypt that encrypted data using the private key that
	// we read in. The algorithm is the same.
	QCA::SecureArray decrypt;
	if(0 == privateKey.decrypt(result, &decrypt, QCA::EME_PKCS1_OAEP)) {
	    std::cout << "Error decrypting.\n";
	    return 1;
	}

	// output the resulting decrypted string
	std::cout << "\"" << qPrintable(rstr) << "\" decrypted with RSA is \"";
	std::cout << decrypt.data() << "\"" << std::endl;


	// Some private keys can also be used for producing signatures
	if(!privateKey.canSign()) {
	    std::cout << "Error: this kind of key cannot sign" << std::endl;
	    return 1;
	}
	privateKey.startSign( QCA::EMSA3_MD5 );
	privateKey.update( arg ); // just reuse the same message
	QByteArray argSig = privateKey.signature();

	// instead of using the startSign(), update(), signature() calls,
	// you may be better doing the whole thing in one go, using the
	// signMessage call. Of course you need the whole message in one
	// hit, which may or may not be a problem

	// output the resulting signature
	rstr = QCA::arrayToHex(argSig);
	std::cout << "Signature for \"" << arg.data() << "\" using RSA, is ";
	std::cout << "\"" << qPrintable( rstr ) << "\"" << std::endl;

	// to check a signature, we must check that the key is
	// appropriate
	if(pubkey.canVerify()) {
	    pubkey.startVerify( QCA::EMSA3_MD5 );
	    pubkey.update( arg );
	    if ( pubkey.validSignature( argSig ) ) {
		std::cout << "Signature is valid" << std::endl;
	    } else {
		std::cout << "Bad signature" << std::endl;
	    }
	}

	// We can also do the verification in a single step if we
	// have all the message
	if ( pubkey.canVerify() &&
	     pubkey.verifyMessage( arg, argSig, QCA::EMSA3_MD5 ) ) {
	    std::cout << "Signature is valid" << std::endl;
	} else {
	    std::cout << "Signature could not be verified" << std::endl;
	}

    }

    return 0;
}

