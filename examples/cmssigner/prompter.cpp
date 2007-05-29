/*
 * Copyright (C) 2007  Justin Karneges <justin@affinix.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 *
 */

#include "prompter.h"

#include <QtCore>
#include <QtGui>
#include <QtCrypto>

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
			foreach(QCA::KeyStore *ks, keyStores)
			{
				if(ks->id() == event.keyStoreInfo().id())
				{
					found = true;
					break;
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
				name = Prompter::tr("the '%1' token for %2").arg(entry.storeName(), entry.name());
			}
			else
			{
				name = Prompter::tr("the '%1' token").arg(event.keyStoreInfo().name());
			}

			QString str = Prompter::tr("Please insert %1 and click OK.").arg(name);

			QMessageBox msgBox(QMessageBox::Information, QApplication::instance()->applicationName() + ": " + tr("Prompt"), str, QMessageBox::Ok | QMessageBox::Cancel, 0);
			token_prompt = &msgBox;
			if(msgBox.exec() == QDialog::Accepted)
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
		connect(ks, SIGNAL(unavailable()), SLOT(ks_unavailable()));
		keyStores += ks;

		// are we currently in a token prompt?
		if(token_prompt && pending.first().event.type() == QCA::Event::Token)
		{
			// was the token we're looking for just inserted?
			if(pending.first().event.keyStoreInfo().id() == keyStoreId)
			{
				// auto-accept
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
