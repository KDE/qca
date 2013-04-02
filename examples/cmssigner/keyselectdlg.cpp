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
#include <QPushButton>
#include <QMenu>
#include <QMessageBox>
#include "ui_keyselect.h"

#define ONLY_SHOW_KEYBUNDLE

typedef QMap<KeySelectDlg::IconType,QPixmap> KeyStoreIconset;

class KeyStoreItemShared
{
public:
	KeyStoreIconset iconset;
	QString notAvailableString;
};

class KeyStoreItem : public QStandardItem
{
public:
	enum Type
	{
		Store = UserType,
		Entry
	};

	enum Role
	{
		NameRole = Qt::UserRole,
		SubTypeRole,
		AvailabilityRole,
		PositionRole
	};

	QPixmap entryTypeToIcon(QCA::KeyStoreEntry::Type type) const
	{
		QPixmap out;
		if(!_shared)
			return out;
		const KeyStoreIconset &iconset = _shared->iconset;
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

	Type _type;
	KeyStoreItemShared *_shared;

	QCA::KeyStore *keyStore;
	QCA::KeyStoreEntry keyStoreEntry;

	KeyStoreItem(Type type, KeyStoreItemShared *shared) :
		_type(type),
		_shared(shared)
	{
		setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
	}

	void setStore(const QString &name, QCA::KeyStore::Type type)
	{
		setData(name, NameRole);
		setData((int)type, SubTypeRole);
	}

	void setEntry(const QString &name, QCA::KeyStoreEntry::Type type, bool available, int pos)
	{
		setData(name, NameRole);
		setData((int)type, SubTypeRole);
		setData(available, AvailabilityRole);
		setData(pos, PositionRole);
	}

	virtual QVariant data(int role) const
	{
		if(role == Qt::DisplayRole)
		{
			if(_type == Store)
			{
				return data(NameRole).toString();
			}
			else if(_type == Entry)
			{
				QString str = data(NameRole).toString();
				if(_shared && !data(AvailabilityRole).toBool())
					str += QString(" ") + _shared->notAvailableString;
				return str;
			}
			else
				return QStandardItem::data(role);
		}
		else if(role == Qt::DecorationRole)
		{
			if(_type == Entry)
			{
				QCA::KeyStoreEntry::Type type = (QCA::KeyStoreEntry::Type)data(SubTypeRole).toInt();
				return entryTypeToIcon(type);
			}
			else
				return QStandardItem::data(role);
		}
		else
			return QStandardItem::data(role);
	}

	virtual int type() const
	{
		return _type;
	}

	virtual QStandardItem *clone() const
	{
		return new KeyStoreItem(*this);
	}
};

class KeyStoreModel : public QStandardItemModel
{
	Q_OBJECT
public:
	KeyStoreItemShared shared;

	QCA::KeyStoreManager ksm;

	KeyStoreModel(QObject *parent = 0) :
		QStandardItemModel(parent), ksm(this)
	{
		shared.notAvailableString = tr("(not available)");

		// make sure keystores are started
		QCA::KeyStoreManager::start();

		connect(&ksm, SIGNAL(keyStoreAvailable(const QString &)), SLOT(ks_available(const QString &)));
		QStringList list = ksm.keyStores();
		foreach(const QString &s, list)
			ks_available(s);

		setSortRole(KeyStoreItem::PositionRole);
	}

	KeyStoreItem *itemFromStore(QCA::KeyStore *ks) const
	{
		for(int n = 0; n < rowCount(); ++n)
		{
			KeyStoreItem *i = (KeyStoreItem *)item(n);
			if(i->keyStore == ks)
				return i;
		}
		return 0;
	}

private slots:
	void ks_available(const QString &keyStoreId)
	{
		QCA::KeyStore *ks = new QCA::KeyStore(keyStoreId, &ksm);

#ifdef ONLY_SHOW_KEYBUNDLE
		// only list stores containing keybundles (non-pgp identities)
		if(!ks->holdsIdentities() || ks->type() == QCA::KeyStore::PGPKeyring)
			return;
#endif

		connect(ks, SIGNAL(updated()), SLOT(ks_updated()));
		connect(ks, SIGNAL(unavailable()), SLOT(ks_unavailable()));

		KeyStoreItem *store_item = new KeyStoreItem(KeyStoreItem::Store, &shared);
		store_item->setStore(ks->name(), ks->type());
		store_item->keyStore = ks;
		ks->startAsynchronousMode();
		appendRow(store_item);
	}

	void ks_updated()
	{
		QCA::KeyStore *ks = (QCA::KeyStore *)sender();
		KeyStoreItem *store_item = itemFromStore(ks);
		Q_ASSERT(store_item);

		QList<QCA::KeyStoreEntry> newEntries = ks->entryList();

#ifdef ONLY_SHOW_KEYBUNDLE
		// ignore entries that are not keybundles
		for(int n = 0; n < newEntries.count(); ++n)
		{
			if(newEntries[n].type() != QCA::KeyStoreEntry::TypeKeyBundle)
			{
				newEntries.removeAt(n);
				--n; // adjust position
			}
		}
#endif

		// update the store item itself
		store_item->setStore(ks->name(), ks->type());

		// handle removed child entries
		for(int n = 0; n < store_item->rowCount(); ++n)
		{
			KeyStoreItem *i = (KeyStoreItem *)store_item->child(n);

			// is the existing entry in the new list?
			bool found = false;
			foreach(const QCA::KeyStoreEntry &ne, newEntries)
			{
				if(ne.id() == i->keyStoreEntry.id())
				{
					found = true;
					break;
				}
			}

			// if not, remove it
			if(!found)
			{
				store_item->removeRow(n);
				--n; // adjust position
			}
		}

		// handle added/updated child entries
		for(int n = 0; n < newEntries.count(); ++n)
		{
			const QCA::KeyStoreEntry &ne = newEntries[n];

			// was this entry in the original list?
			KeyStoreItem *entry_item = 0;
			for(int k = 0; k < store_item->rowCount(); ++k)
			{
				KeyStoreItem *i = (KeyStoreItem *)store_item->child(k);
				if(i->keyStoreEntry.id() == ne.id())
				{
					entry_item = i;
					break;
				}
			}

			// if not, add it
			if(!entry_item)
			{
				entry_item = new KeyStoreItem(KeyStoreItem::Entry, &shared);
				entry_item->keyStoreEntry = ne;
				entry_item->setEntry(newEntries[n].name(), newEntries[n].type(), newEntries[n].isAvailable(), n);
				store_item->appendRow(entry_item);
			}
			// if so, update it
			else
			{
				entry_item->keyStoreEntry = ne;
				entry_item->setEntry(newEntries[n].name(), newEntries[n].type(), newEntries[n].isAvailable(), n);
			}
		}

		store_item->sortChildren(0);
	}

	void ks_unavailable()
	{
		QCA::KeyStore *ks = (QCA::KeyStore *)sender();
		KeyStoreItem *store_item = itemFromStore(ks);
		Q_ASSERT(store_item);

		store_item->removeRows(0, store_item->rowCount());
		removeRow(store_item->row());
		delete ks;
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
	QAction *actionView;

	Private(KeySelectDlg *_q) :
		QObject(_q),
		q(_q)
	{
		ui.setupUi(q);

		model = new KeyStoreModel(this);
		connect(&model->ksm, SIGNAL(busyStarted()), SLOT(ksm_busyStarted()));
		connect(&model->ksm, SIGNAL(busyFinished()), SLOT(ksm_busyFinished()));
		if(model->ksm.isBusy())
			ksm_busyStarted();

		ui.lv_stores->header()->hide();
		ui.buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);
		ui.lv_stores->setModel(model);
		ui.lv_stores->setContextMenuPolicy(Qt::CustomContextMenu);
		connect(ui.lv_stores->selectionModel(), SIGNAL(selectionChanged(const QItemSelection &, const QItemSelection &)), SLOT(stores_selectionChanged(const QItemSelection &, const QItemSelection &)));
		connect(ui.lv_stores, SIGNAL(customContextMenuRequested(const QPoint &)), SLOT(stores_customContextMenuRequested(const QPoint &)));

		actionView = new QAction(tr("&View"), this);
		connect(actionView, SIGNAL(triggered()), SLOT(view()));
		actionView->setEnabled(false);
	}

private slots:
	void ksm_busyStarted()
	{
		ui.lb_busy->setText(tr("Looking for devices..."));
	}

	void ksm_busyFinished()
	{
		ui.lb_busy->setText("");
	}

	void stores_selectionChanged(const QItemSelection &selected, const QItemSelection &deselected)
	{
		Q_UNUSED(deselected);

		KeyStoreItem *i = 0;
		if(!selected.indexes().isEmpty())
		{
			QModelIndex index = selected.indexes().first();
			i = (KeyStoreItem *)model->itemFromIndex(index);
		}

		bool viewable = false;
		bool choosable = false;
		if(i && i->type() == KeyStoreItem::Entry)
		{
			QCA::KeyStoreEntry entry = i->keyStoreEntry;
			if(entry.type() == QCA::KeyStoreEntry::TypeKeyBundle)
			{
				viewable = true;
				choosable = true;
				cur_entry = entry;
			}
		}

		if(!choosable)
			cur_entry = QCA::KeyStoreEntry();

		actionView->setEnabled(viewable);

		QPushButton *ok = ui.buttonBox->button(QDialogButtonBox::Ok);
		if(choosable && !ok->isEnabled())
			ok->setEnabled(true);
		else if(!choosable && ok->isEnabled())
			ok->setEnabled(false);
	}

	void stores_customContextMenuRequested(const QPoint &pos)
	{
		QItemSelection selection = ui.lv_stores->selectionModel()->selection();
		if(selection.indexes().isEmpty())
			return;

		QModelIndex index = selection.indexes().first();
		KeyStoreItem *i = (KeyStoreItem *)model->itemFromIndex(index);
		if(i && i->type() == KeyStoreItem::Entry)
		{
			QMenu menu(q);
			menu.addAction(actionView);
			menu.exec(ui.lv_stores->viewport()->mapToGlobal(pos));
		}
	}

	void view()
	{
		emit q->viewCertificate(cur_entry.keyBundle().certificateChain());
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
	d->model->shared.iconset[type] = icon;
}

void KeySelectDlg::accept()
{
	QCA::KeyStoreEntry entry = d->cur_entry;
	QDialog::accept();
	emit selected(entry);
}

#include "keyselectdlg.moc"
