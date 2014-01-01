/*
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

#include <QCoreApplication>

#include <iostream>

#ifdef QT_STATICPLUGIN
#include "import_plugins.h"
#endif

int main(int argc, char **argv)
{
	// the Initializer object sets things up, and
	// also does cleanup when it goes out of scope
	QCA::Initializer init;

	QCoreApplication app(argc, argv);

	// we use the first argument as the data to encode / decode
	// if an argument is provided. Use "hello" if no argument
	QByteArray arg; // empty array
	arg.append((argc >= 2) ? argv[1] : "hello");

	// create our object, which does encoding by default
	// QCA::Hex encoder(QCA::Encode); is equivalent
	QCA::Hex encoder;

	// You might prefer to use encoder.encode(); and have
	// it return a QCA::SecureArray, depending on your needs
	QString encoded = encoder.arrayToString(arg);

	std::cout << arg.data() << " in hex encoding is ";
	std::cout << encoded.toLatin1().data() << std::endl;

	// This time, we'll create an object to decode hexadecimal.
	// We could also have reused the existing object, calling
	// clear(); and setup(QCA::Decode); on it.
	QCA::Hex decoder(QCA::Decode);

	// This time, we convert a QString into a QString
	QString decoded = decoder.decodeString(encoded);

	std::cout << encoded.toLatin1().data() << " decoded from hex is ";
	std::cout << decoded.toLatin1().data() << std::endl;

	return 0;
}

