/*
 Copyright (C) 2003 Justin Karneges
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

// QtCrypto has the declarations for all of QCA
#include <QtCrypto>
#include <stdio.h>

int main(int argc, char **argv)
{
	// the Initializer object sets things up, and 
	// also does cleanup when it goes out of scope
	QCA::Initializer init;

	QCoreApplication app(argc, argv);

	// we use the first argument if provided, or
	// use "hello" if no arguments
	QSecureArray arg = (argc >= 2) ? argv[1] : "hello";

	// AES128 test
	if(!QCA::isSupported("aes128-cbc"))
		printf("AES128-CBC not supported!\n");
	else {
		// encrypt
		QCA::AES128 c(QCA::Cipher::CBC, QCA::Cipher::DefaultPadding, QCA::Encode);
		c.update(arg);
		QSecureArray f = c.final();
		QString result = QCA::arrayToHex(f);
		printf(">aes128(\"%s\") = [%s]\n", arg.data(),qPrintable(result) );
	}

	return 0;
}

