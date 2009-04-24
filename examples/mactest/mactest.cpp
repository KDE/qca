/*
 Copyright (C) 2004, 2006 Brad Hards <bradh@frogmouth.net>

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

#include <QCoreApplication>
#include <QDebug>

// needed for printf
#include<stdio.h>

int main(int argc, char **argv)
{
	// the Initializer object sets things up, and
	// also does cleanup when it goes out of scope
	QCA::Initializer init;

	QCoreApplication app(argc, argv);

	qDebug() << "This example shows hashed MAC";

	// we use the first argument as the data to authenticate
	// if an argument is provided. Use "hello" if no argument
	QByteArray arg = (argc >= 2) ? argv[1] : "hello";

	// we use the second argument as the key to authenticate
	// with, if two arguments are provided. Use "secret" as
	// the key if less than two arguments.
	QCA::SecureArray key((argc >= 3) ? argv[2] : "secret");

	// must always check that an algorithm is supported before using it
	if( !QCA::isSupported("hmac(sha1)") ) {
		printf("HMAC(SHA1) not supported!\n");
	} else {
		// create the required object using HMAC with SHA-1, and an
		// empty key.
		QCA::MessageAuthenticationCode hmacObject(  "hmac(sha1)", QCA::SecureArray() );

		// create the key
		QCA::SymmetricKey keyObject(key);

		// set the HMAC object to use the key
		hmacObject.setup(key);
		// that could also have been done in the
		// QCA::MessageAuthenticationCode constructor

		// we split it into two parts to show incremental update
		QCA::SecureArray part1(arg.left(3)); // three chars - "hel"
		QCA::SecureArray part2(arg.mid(3)); // the rest - "lo"
		hmacObject.update(part1);
		hmacObject.update(part2);

		// no more updates after calling final.
		QCA::SecureArray resultArray = hmacObject.final();

		// convert the result into printable hexadecimal.
		QString result = QCA::arrayToHex(resultArray.toByteArray());
		printf("HMAC(SHA1) of \"%s\" with \"%s\" = [%s]\n", arg.data(), key.data(), result.toLatin1().data());
	}

	return 0;
}

