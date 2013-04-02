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

#include "prompter.h"

#include <QtCore>
#include <QtGui>
#include <QtCrypto>
#include <QMessageBox>
#include <QInputDialog>
#include <QApplication>

class Prompter::Private : public QObject
{
	Q_OBJECT
public:
	Prompter *q;

	class Item
	{
	public:
		int id;
		QCA::Event event;
	};

	QCA::EventHandler handler;
	QList<Item> pending;
	bool prompting;
	QMessageBox *token_prompt;
	bool auto_accept;

	QCA::KeyStoreManager ksm;
	QList<QCA::KeyStore*> keyStores;

	Private(Prompter *_q) :
		QObject(_q),
		q(_q),
		handler(this),
		prompting(false),
		token_prompt(0),
		ksm(this)
	{
		connect(&handler, SIGNAL(eventReady(int, const QCA::Event &)), SLOT(ph_eventReady(int, const QCA::Event &)));
		handler.start();

		connect(&ksm, SIGNAL(keyStoreAvailable(const QString &)), SLOT(ks_available(const QString &)));
		foreach(const QString &keyStoreId, ksm.keyStores())
			ks_available(keyStoreId);
	}

	~Private()
	{
		qDeleteAll(keyStores);

		while(!pending.isEmpty())
			handler.reject(pending.takeFirst().id);
	}

private slots:
	void ph_eventReady(int id, const QCA::Event &event)
	{
		Item i;
		i.id = id;
		i.event = event;
		pending += i;
		nextEvent();
	}

	void nextEvent()
	{
		if(prompting || pending.isEmpty())
			return;

		prompting = true;

		const Item &i = pending.first();
		const int &id = i.id;
		const QCA::Event &event = i.event;

		if(event.type() == QCA::Event::Password)
		{
			QCA::SecureArray known = q->knownPassword(event);
			if(!known.isEmpty())
			{
				handler.submitPassword(id, known);
				goto end;
			}

			QString type = Prompter::tr("password");
			if(event.passwordStyle() == QCA::Event::StylePassphrase)
				type = Prompter::tr("passphrase");
			else if(event.passwordStyle() == QCA::Event::StylePIN)
				type = Prompter::tr("PIN");

			QString str;
			if(event.source() == QCA::Event::KeyStore)
			{
				QString name;
				QCA::KeyStoreEntry entry = event.keyStoreEntry();
				if(!entry.isNull())
				{
					name = entry.name();
				}
				else
				{
					if(event.keyStoreInfo().type() == QCA::KeyStore::SmartCard)
						name = Prompter::tr("the '%1' token").arg(event.keyStoreInfo().name());
					else
						name = event.keyStoreInfo().name();
				}
				str = Prompter::tr("Enter %1 for %2").arg(type, name);
			}
			else if(!event.fileName().isEmpty())
			{
				QFileInfo fi(event.fileName());
				str = Prompter::tr("Enter %1 for %2:").arg(type, fi.fileName());
			}
			else
				str = Prompter::tr("Enter %1:").arg(type);

			bool ok;
			QString pass = QInputDialog::getText(0, QApplication::instance()->applicationName() + ": " + tr("Prompt"), str, QLineEdit::Password, QString(), &ok);
			if(ok)
			{
				QCA::SecureArray password = pass.toUtf8();
				q->userSubmitted(password, event);
				handler.submitPassword(id, password);
			}
			else
				handler.reject(id);
		}
		else if(event.type() == QCA::Event::Token)
		{
			// even though we're being prompted for a missing token,
			//   we should still check if the token is present, due to
			//   a possible race between insert and token request.
			bool found = false;

			// token-only
			if(event.keyStoreEntry().isNull())
			{
				foreach(QCA::KeyStore *ks, keyStores)
				{
					if(ks->id() == event.keyStoreInfo().id())
					{
						found = true;
						break;
					}
				}
			}
			// token-entry
			else
			{
				QCA::KeyStoreEntry kse = event.keyStoreEntry();

				QCA::KeyStore *ks = 0;
				foreach(QCA::KeyStore *i, keyStores)
				{
					if(i->id() == event.keyStoreInfo().id())
					{
						ks = i;
						break;
					}
				}
				if(ks)
				{
					QList<QCA::KeyStoreEntry> list = ks->entryList();
					foreach(const QCA::KeyStoreEntry &e, list)
					{
						if(e.id() == kse.id() && kse.isAvailable())
						{
							found = true;
							break;
						}
					}
				}
			}
			if(found)
			{
				// auto-accept
				handler.tokenOkay(id);
				return;
			}

			QCA::KeyStoreEntry entry = event.keyStoreEntry();
			QString name;
			if(!entry.isNull())
			{
				name = Prompter::tr("Please make %1 (of %2) available").arg(entry.name(), entry.storeName());
			}
			else
			{
				name = Prompter::tr("Please insert the '%1' token").arg(event.keyStoreInfo().name());
			}

			QString str = Prompter::tr("%1 and click OK.").arg(name);

			QMessageBox msgBox(QMessageBox::Information, QApplication::instance()->applicationName() + ": " + tr("Prompt"), str, QMessageBox::Ok | QMessageBox::Cancel, 0);
			token_prompt = &msgBox;
			auto_accept = false;
			if(msgBox.exec() == QMessageBox::Ok || auto_accept)
				handler.tokenOkay(id);
			else
				handler.reject(id);
			token_prompt = 0;
		}
		else
			handler.reject(id);

	end:
		pending.removeFirst();
		prompting = false;

		if(!pending.isEmpty())
			QMetaObject::invokeMethod(this, "nextEvent", Qt::QueuedConnection);
	}

	void ks_available(const QString &keyStoreId)
	{
		QCA::KeyStore *ks = new QCA::KeyStore(keyStoreId, &ksm);
		connect(ks, SIGNAL(updated()), SLOT(ks_updated()));
		connect(ks, SIGNAL(unavailable()), SLOT(ks_unavailable()));
		keyStores += ks;
		ks->startAsynchronousMode();

		// are we currently in a token-only prompt?
		if(token_prompt && pending.first().event.type() == QCA::Event::Token && pending.first().event.keyStoreEntry().isNull())
		{
			// was the token we're looking for just inserted?
			if(pending.first().event.keyStoreInfo().id() == keyStoreId)
			{
				// auto-accept
				auto_accept = true;
				token_prompt->accept();
			}
		}
	}

	void ks_unavailable()
	{
		QCA::KeyStore *ks = (QCA::KeyStore *)sender();
		keyStores.removeAll(ks);
		delete ks;
	}

	void ks_updated()
	{
		QCA::KeyStore *ks = (QCA::KeyStore *)sender();

		// are we currently in a token-entry prompt?
		if(token_prompt && pending.first().event.type() == QCA::Event::Token && !pending.first().event.keyStoreEntry().isNull())
		{
			QCA::KeyStoreEntry kse = pending.first().event.keyStoreEntry();

			// was the token of the entry we're looking for updated?
			if(pending.first().event.keyStoreInfo().id() == ks->id())
			{
				// is the entry available?
				bool avail = false;
				QList<QCA::KeyStoreEntry> list = ks->entryList();
				foreach(const QCA::KeyStoreEntry &e, list)
				{
					if(e.id() == kse.id())
					{
						avail = kse.isAvailable();
						break;
					}
				}
				if(avail)
				{
					// auto-accept
					auto_accept = true;
					token_prompt->accept();
				}
			}
		}
	}
};

Prompter::Prompter(QObject *parent) :
	QObject(parent)
{
	d = new Private(this);
}

Prompter::~Prompter()
{
	delete d;
}

QCA::SecureArray Prompter::knownPassword(const QCA::Event &event)
{
	Q_UNUSED(event);
	return QCA::SecureArray();
}

void Prompter::userSubmitted(const QCA::SecureArray &password, const QCA::Event &event)
{
	Q_UNUSED(password);
	Q_UNUSED(event);
}

#include "prompter.moc"
