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

#include "keyselectdlg.h"

#include <QtCore>
#include <QtGui>
#include <QtCrypto>
#include "ui_keyselect.h"

class KeyStoreModel : public QStandardItemModel
{
	Q_OBJECT
public:
	QMap<KeySelectDlg::IconType,QPixmap> iconset;

	QCA::KeyStoreManager ksm;
	QList<QCA::KeyStore*> stores;
	QList<QStandardItem*> storeItems;
	QList< QList<QCA::KeyStoreEntry> > storeEntries;
	QList< QList<QStandardItem*> > storeEntryItems;

	QPixmap entryTypeToIcon(QCA::KeyStoreEntry::Type type)
	{
		QPixmap out;
		switch(type)
		{
			case QCA::KeyStoreEntry::TypeKeyBundle:     out = iconset[KeySelectDlg::IconKeyBundle]; break;
			case QCA::KeyStoreEntry::TypeCertificate:   out = iconset[KeySelectDlg::IconCert]; break;
			case QCA::KeyStoreEntry::TypeCRL:           out = iconset[KeySelectDlg::IconCrl]; break;
			case QCA::KeyStoreEntry::TypePGPSecretKey:  out = iconset[KeySelectDlg::IconPgpSec]; break;
			case QCA::KeyStoreEntry::TypePGPPublicKey:  out = iconset[KeySelectDlg::IconPgpPub]; break;
			default:                                    break;
		}
		return out;
	}

	KeyStoreModel(QObject *parent = 0) :
		QStandardItemModel(parent), ksm(this)
	{
		// make sure keystores are started
		QCA::KeyStoreManager::start();

		connect(&ksm, SIGNAL(keyStoreAvailable(const QString &)), SLOT(ks_available(const QString &)));
		QStringList list = ksm.keyStores();
		foreach(const QString &s, list)
			ks_available(s);
	}

private slots:
	void ks_available(const QString &keyStoreId)
	{
		QCA::KeyStore *ks = new QCA::KeyStore(keyStoreId, &ksm);

		// TODO: only list non-pgp identity stores
		//if(!ks->holdsIdentities() || ks->type() == QCA::KeyStore::PGPKeyring)
		//	return;

		connect(ks, SIGNAL(updated()), SLOT(ks_updated()));
		connect(ks, SIGNAL(unavailable()), SLOT(ks_unavailable()));
		stores += ks;
		ks->startAsynchronousMode();

		QStandardItem *item = new QStandardItem(ks->name());
		storeItems += item;
		storeEntries += QList<QCA::KeyStoreEntry>();
		storeEntryItems += QList<QStandardItem*>();
		appendRow(item);
	}

	void ks_updated()
	{
		QCA::KeyStore *ks = (QCA::KeyStore *)sender();
		int at = stores.indexOf(ks);
		QList<QCA::KeyStoreEntry> entries = ks->entryList();

		// TODO: only list keybundles
		/*for(int n = 0; n < entries.count(); ++n)
		{
			if(entries[n].type() != QCA::KeyStoreEntry::TypeKeyBundle)
			{
				entries.removeAt(n);
				--n; // adjust position
			}
		}*/

		storeEntries[at] = entries;
		storeEntryItems[at].clear();

		// fake CRL, just to show off the icon
		/*if(ks->type() == QCA::KeyStore::System)
		{
			QStandardItem *item = new QStandardItem(entryTypeToIcon(QCA::KeyStoreEntry::TypeCRL), "Santa's Naughty List");
			storeEntryItems[at] += item;
			storeItems[at]->appendRow(item);
		}*/

		foreach(const QCA::KeyStoreEntry &entry, entries)
		{
			QStandardItem *item = new QStandardItem(entryTypeToIcon(entry.type()), entry.name());
			storeEntryItems[at] += item;
			storeItems[at]->appendRow(item);
		}
	}

	void ks_unavailable()
	{
		QCA::KeyStore *ks = (QCA::KeyStore *)sender();
		Q_UNUSED(ks);

		// TODO: remove from internal list and display
	}
};

class KeySelectDlg::Private : public QObject
{
	Q_OBJECT
public:
	KeySelectDlg *q;
	Ui_KeySelect ui;
	KeyStoreModel *model;
	QCA::KeyStoreEntry cur_entry;

	Private(KeySelectDlg *_q) :
		QObject(_q),
		q(_q)
	{
		ui.setupUi(q);

		model = new KeyStoreModel(this);

		ui.lv_stores->header()->hide();
		ui.buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);
		ui.lv_stores->setModel(model);
		connect(ui.lv_stores->selectionModel(), SIGNAL(selectionChanged(const QItemSelection &, const QItemSelection &)), SLOT(stores_selectionChanged(const QItemSelection &, const QItemSelection &)));
	}

private slots:
	void stores_selectionChanged(const QItemSelection &selected, const QItemSelection &deselected)
	{
		Q_UNUSED(deselected);

		bool valid = false;
		QCA::KeyStoreEntry entry;
		{
			QModelIndex index;
			if(!selected.indexes().isEmpty())
				index = selected.indexes().first();
			if(index.isValid())
			{
				QModelIndex pindex = index.parent();
				// are we clicking on an entry?
				if(pindex.isValid())
				{
					int store_at = pindex.row();
					int entry_at = index.row();

					entry = model->storeEntries[store_at][entry_at];
					if(entry.type() == QCA::KeyStoreEntry::TypeKeyBundle)
						valid = true;
				}
			}
		}

		if(valid)
			cur_entry = entry;
		else
			cur_entry = QCA::KeyStoreEntry();

		QPushButton *ok = ui.buttonBox->button(QDialogButtonBox::Ok);
		if(valid && !ok->isEnabled())
			ok->setEnabled(true);
		else if(!valid && ok->isEnabled())
			ok->setEnabled(false);
	}
};

KeySelectDlg::KeySelectDlg(QWidget *parent) :
	QDialog(parent)
{
	d = new Private(this);
}

KeySelectDlg::~KeySelectDlg()
{
	delete d;
}

void KeySelectDlg::setIcon(IconType type, const QPixmap &icon)
{
	d->model->iconset[type] = icon;
}

void KeySelectDlg::accept()
{
	QCA::KeyStoreEntry entry = d->cur_entry;
	QDialog::accept();
	emit selected(entry);
}

#include "keyselectdlg.moc"
