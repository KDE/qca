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

// QtCrypto has the declarations for all of QCA
#include <QtCrypto>
#include <QCoreApplication>

#include <iostream>
#include <qstringlist.h>

#ifdef QT_STATICPLUGIN
#include "import_plugins.h"
#endif

int main(int argc, char **argv)
{
    // the Initializer object sets things up, and
    // also does cleanup when it goes out of scope
    QCA::Initializer init;

    QCoreApplication app(argc, argv);

    // get all the available providers loaded.
    // you don't normally need this (because you test using isSupported())
    // but this is a special case.
    QCA::scanForPlugins();

    // this gives us all the plugin providers as a list
    QCA::ProviderList qcaProviders = QCA::providers();
    for (int i = 0; i < qcaProviders.size(); ++i) {
	// each provider has a name, which we can display
        std::cout << qcaProviders[i]->name().toLatin1().data() << ": ";
	// ... and also a list of features
	QStringList capabilities = qcaProviders[i]->features();
	// we turn the string list back into a single string,
	// and display it as well
	std::cout << capabilities.join(", ").toLatin1().data() << std::endl;
    }

    // Note that the default provider isn't included in
    // the result of QCA::providers()
    std::cout << "default: ";
    // However it is still possible to get the features
    // supported by the default provider
    QStringList capabilities = QCA::defaultFeatures();
    std::cout << capabilities.join(", ").toLatin1().data() << std::endl;
    return 0;
}

