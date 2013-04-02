/*
 Copyright (C) 2004 Brad Hards <bradh@frogmouth.net>

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

// QtCrypto/QtCrypto has the declarations for all of QCA
#include <QtCrypto>

#include <QCoreApplication>

#include <stdio.h>

int main(int argc, char **argv)
{
	// the Initializer object sets things up, and
	// also does cleanup when it goes out of scope
	QCA::Initializer init;

	QCoreApplication app(argc, argv);

	// we use the first argument if provided, or
	// use "hello" if no arguments
	QCA::SecureArray arg = (argc >= 2) ? argv[1] : "hello";

	// must always check that an algorithm is supported before using it
	if( !QCA::isSupported("sha1") )
		printf("SHA1 not supported!\n");
	else {
		// this shows the "all in one" approach
		QString result = QCA::Hash("sha1").hashToString(arg);
		printf("sha1(\"%s\") = [%s]\n", arg.data(), qPrintable(result));
	}

	// must always check that an algorithm is supported before using it
	if( !QCA::isSupported("md5") )
		printf("MD5 not supported!\n");
	else {
		// this shows the incremental approach. Naturally
		// for this simple job, we could use the "all in one"
		// approach - this is an example, after all :-)
		QCA::SecureArray part1(arg.toByteArray().left(3)); // three chars - "hel"
		QCA::SecureArray part2(arg.toByteArray().mid(3)); // the rest - "lo"

		// create the required object.
		QCA::Hash hashObject("md5");
		// we split it into two parts to show incremental update
		hashObject.update(part1);
		hashObject.update(part2);
		// no more updates after calling final.
		QCA::SecureArray resultArray = hashObject.final();
		// convert the result into printable hexadecimal.
		QString result = QCA::arrayToHex(resultArray.toByteArray());
		printf("md5(\"%s\") = [%s]\n", arg.data(), qPrintable(result));
	}

	return 0;
}

