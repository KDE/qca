/*
 Copyright (C) 2003 Justin Karneges <justin@affinix.com>
 Copyright (C) 2005-2006 Brad Hards <bradh@frogmouth.net>

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

// QtCrypto has the declarations for all of QCA
#include <QtCrypto>
#include <stdio.h>

#include <QCoreApplication>

int main(int argc, char **argv)
{
    // the Initializer object sets things up, and
    // also does cleanup when it goes out of scope
    QCA::Initializer init;

    QCoreApplication app(argc, argv);

    // we use the first argument if provided, or
    // use "hello" if no arguments
    QCA::SecureArray arg = (argc >= 2) ? argv[1] : "hello";

    // AES128 testing
    if(!QCA::isSupported("aes128-cbc-pkcs7"))
	printf("AES128-CBC not supported!\n");
    else {
	// Create a random key - you'd probably use one from another
	// source in a real application
	QCA::SymmetricKey key(16);

	// Create a random initialisation vector - you need this
	// value to decrypt the resulting cipher text, but it
	// need not be kept secret (unlike the key).
	QCA::InitializationVector iv(16);

	// create a 128 bit AES cipher object using Cipher Block Chaining (CBC) mode
	QCA::Cipher cipher(QString("aes128"),QCA::Cipher::CBC,
			   // use Default padding, which is equivalent to PKCS7 for CBC
			   QCA::Cipher::DefaultPadding,
			   // this object will encrypt
			   QCA::Encode,
			   key, iv);

	// we use the cipher object to encrypt the argument we passed in
	// the result of that is returned - note that if there is less than
	// 16 bytes (1 block), then nothing will be returned - it is buffered
	// update() can be called as many times as required.
	QCA::SecureArray u = cipher.update(arg);

	// We need to check if that update() call worked.
	if (!cipher.ok()) {
	    printf("Update failed\n");
	}
	// output the results of that stage
	printf("AES128 encryption of %s is [%s]\n",
	       arg.data(),
	       qPrintable(QCA::arrayToHex(u.toByteArray())) );


	// Because we are using PKCS7 padding, we need to output the final (padded) block
	// Note that we should always call final() even with no padding, to clean up
	QCA::SecureArray f = cipher.final();

	// Check if the final() call worked
	if (!cipher.ok()) {
	    printf("Final failed\n");
	}
	// and output the resulting block. The ciphertext is the results of update()
	// and the result of final()
	printf("Final block for AES128 encryption is [0x%s]\n", qPrintable(QCA::arrayToHex(f.toByteArray())) );

	// re-use the Cipher t decrypt. We need to use the same key and
	// initialisation vector as in the encryption.
	cipher.setup( QCA::Decode, key, iv );

	// Build a single cipher text array. You could also call update() with
	// each block as you receive it, if that is more useful.
	QCA::SecureArray cipherText = u.append(f);

	// take that cipher text, and decrypt it
	QCA::SecureArray plainText = cipher.update(cipherText);

	// check if the update() call worked
	if (!cipher.ok()) {
	    printf("Update failed\n");
	}

	// output results
	printf("Decryption using AES128 of [0x%s] is %s\n",
	       qPrintable(QCA::arrayToHex(cipherText.toByteArray())), plainText.data());

	// Again we need to call final(), to get the last block (with its padding removed)
	plainText = cipher.final();

	// check if the final() call worked
	if (!cipher.ok()) {
	    printf("Final failed\n");
	}

	// output results
	printf("Final decryption block using AES128 is %s\n", plainText.data());
	// instead of update() and final(), you can do the whole thing
	// in one step, using process()
	printf("One step decryption using AES128: %s\n",
	       QCA::SecureArray(cipher.process(cipherText)).data() );

    }

    return 0;
}

