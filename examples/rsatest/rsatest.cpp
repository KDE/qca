/*
 Copyright (C) 2003 Justin Karneges
 Copyright (C) 2005 Brad Hards

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

#include <iostream>

int main(int argc, char **argv)
{
    // the Initializer object sets things up, and 
    // also does cleanup when it goes out of scope
    QCA::Initializer init;
    
    QCoreApplication app(argc, argv);
    
    // we use the first argument if provided, or
    // use "hello" if no arguments
    QSecureArray arg = (argc >= 2) ? argv[1] : "hello";

    if(!QCA::isSupported("pkey") ||
       !QCA::PKey::supportedTypes().contains(QCA::PKey::RSA) ||
       !QCA::PKey::supportedIOTypes().contains(QCA::PKey::RSA))
	printf("RSA not supported!\n");
    else {
	QCA::PrivateKey seckey = QCA::KeyGenerator().createRSA(1024);
	if(seckey.isNull()) {
	    std::cout << "Failed to make private RSA key" << std::endl;
	    return 1;
	}
	QCA::PublicKey pubkey = seckey.toPublicKey();

	// check if the key can encrypt
	if(!pubkey.canEncrypt())
	{
	    std::cout << "Error: this kind of key cannot encrypt" << std::endl;
	    return 1;
	}

	// encrypt some data
	// you must also choose the algorithm to be used
	QSecureArray result = pubkey.encrypt(arg, QCA::EME_PKCS1_OAEP);
	if(result.isEmpty()) {
	    std::cout << "Error encrypting" << std::endl;
	    return 1;
	}

	// output the encrypted data
	QString rstr = QCA::arrayToHex(result);
	std::cout << "\"" << arg.data() << "\" encrypted with RSA is \"";
	std::cout << qPrintable(rstr) << "\"" << std::endl;

	// save the private key - in a real example, make sure this goes
	// somewhere secure! 
	// you can use the same technique with the public key too.
	QSecureArray passPhrase = "pass phrase";
	seckey.toPEMFile("keyprivate.pem", passPhrase);

	// Read that key back in, checking if the read succeeded
	QCA::ConvertResult conversionResult;
	QCA::PrivateKey privateKey = QCA::PrivateKey::fromPEMFile("keyprivate.pem", passPhrase, &conversionResult);
	if (! QCA::ConvertGood == conversionResult) {
	    std::cout << "Private key read failed" << std::endl;
	}

	// now decrypt that encrypted data using the private key that
	// we read in. The algorithm is the same.
	QSecureArray decrypt;
	if(0 == privateKey.decrypt(result, &decrypt, QCA::EME_PKCS1_OAEP)) {
	    printf("Error decrypting.\n");
	    return 1;
	}

	// output the resulting decrypted string
	std::cout << "\"" << qPrintable(rstr) << "\" decrypted with RSA is \"";
	std::cout << decrypt.data() << "\"" << std::endl;








#if 0
	QCA::RSAKey pubkey = readKeyFile("keypublic.der");
	if(pubkey.isNull())
	    return 1;
	QCA::RSAKey seckey = readKeyFile("keyprivate.der");
	if(seckey.isNull())
	    return 1;
#endif

    }

    return 0;
}

