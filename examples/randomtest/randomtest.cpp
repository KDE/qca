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

#include <iostream>

int main(int argc, char **argv)
{
	// the Initializer object sets things up, and
	// also does cleanup when it goes out of scope
	QCA::Initializer init;

	QCoreApplication app(argc, argv);

	qDebug() << "This example generates random numbers";

	int randInt;
	// This is the standard way to generate a random integer.
	randInt = QCA::Random::randomInt();
	qDebug() << "A random number: " << randInt;

	// If you wanted a random character (octet), you could
	// use something like:
	unsigned char randChar;
	randChar = QCA::Random::randomChar();
	// It might not be printable, so this may not produce output
	std::cout << "A random character: " << randChar << std::endl;

	QCA::SecureArray tenBytes(10);
	// If you need more random values, you may want to
	// get an array, as shown below.
	tenBytes = QCA::Random::randomArray(10);

	// To make this viewable, we convert to hexadecimal.
	std::cout << "A random 10 byte array (in hex): ";
	std::cout << qPrintable(QCA::Hex().arrayToString(tenBytes)) << std::endl;

	// Under some circumstances, you may want to create a
	// Random object, rather than a static public member function.
	// This isn't normally the easiest way, but it does work
	QCA::Random myRandomObject;
	randChar = myRandomObject.nextByte();
	tenBytes = myRandomObject.nextBytes(10);
	return 0;
}

