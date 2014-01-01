/*
 Copyright (C) 2007 Justin Karneges <justin@affinix.com>

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
#include <QTimer>

#include <stdio.h>

#ifdef QT_STATICPLUGIN
#include "import_plugins.h"
#endif

class PassphraseHandler: public QObject
{
	Q_OBJECT
public:
	QCA::EventHandler handler;

	PassphraseHandler(QObject *parent = 0) : QObject(parent)
	{
		connect(&handler, SIGNAL(eventReady(int, const QCA::Event &)),
			SLOT(eh_eventReady(int, const QCA::Event &)));
		handler.start();
	}

private slots:
	void eh_eventReady(int id, const QCA::Event &event)
	{
		if(event.type() == QCA::Event::Password)
		{
			QCA::SecureArray pass;
			QCA::ConsolePrompt prompt;
			prompt.getHidden("Passphrase");
			prompt.waitForFinished();
			pass = prompt.result();
			handler.submitPassword(id, pass);
		}
		else
			handler.reject(id);
	}
};

class App : public QObject
{
	Q_OBJECT
public:
	QCA::KeyLoader keyLoader;
	QString str;

	App()
	{
		connect(&keyLoader, SIGNAL(finished()), SLOT(kl_finished()));
	}

public slots:
	void start()
	{
		keyLoader.loadPrivateKeyFromPEMFile(str);
	}

signals:
	void quit();

private slots:
	void kl_finished()
	{
		if(keyLoader.convertResult() == QCA::ConvertGood)
		{
			QCA::PrivateKey key = keyLoader.privateKey();
			printf("Loaded successfully.  Bits: %d\n", key.bitSize());
		}
		else
			printf("Unable to load.\n");

		emit quit();
	}
};

int main(int argc, char **argv)
{
	QCA::Initializer init;
	QCoreApplication qapp(argc, argv);

	if(argc < 2)
	{
		printf("usage: keyloader [privatekey.pem]\n");
		return 0;
	}

	PassphraseHandler passphraseHandler;
	App app;
	app.str = argv[1];
	QObject::connect(&app, SIGNAL(quit()), &qapp, SLOT(quit()));
	QTimer::singleShot(0, &app, SLOT(start()));
	qapp.exec();
	return 0;
}

#include "keyloader.moc"
