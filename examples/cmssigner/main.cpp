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

#include <QtCore>
#include <QtGui>
#include <QtCrypto>

#include "ui_mainwin.h"
#include "mylistview.h"
#include "ui_loadstore.h"
#include "pkcs11configdlg/pkcs11configdlg.h"

QString escape(const QString &in)
{
	QString out;
	for(int n = 0; n < in.length(); ++n)
	{
		if(in[n] == '\\')
			out += "\\\\";
		else if(in[n] == ':')
			out += "\\c";
		else
			out += in[n];
	}
	return out;
}

QString unescape(const QString &in)
{
	QString out;
	for(int n = 0; n < in.length(); ++n)
	{
		if(in[n] == '\\')
		{
			if(n + 1 < in.length())
			{
				++n;
				if(in[n] == '\\')
					out += '\\';
				else if(in[n] == 'c')
					out += ':';
			}
		}
		else
			out += in[n];
	}
	return out;
}

class IdentityItem
{
public:
	enum Type { File, Entry };

	Type type;
	QString name;
	QString fileName;
	QCA::KeyStoreEntry entry;
	QCA::SecureArray password; // for runtime of File type only
	bool usable;

	QString toString() const
	{
		QStringList parts;
		if(type == File)
		{
			parts += "file";
			parts += name;
			parts += fileName;
		}
		else // Entry
		{
			parts += "entry";
			parts += name;
			parts += entry.toString();
		}

		for(int n = 0; n < parts.count(); ++n)
			parts[n] = escape(parts[n]);
		return parts.join(":");
	}

	bool fromString(const QString &in)
	{
		QStringList parts = in.split(':');
		for(int n = 0; n < parts.count(); ++n)
			parts[n] = unescape(parts[n]);

		if(parts.count() < 3)
			return false;

		usable = false;

		if(parts[0] == "file")
		{
			type = File;
			name = parts[1];
			fileName = parts[2];
			if(QFile::exists(fileName))
				usable = true;
		}
		else if(parts[0] == "entry")
		{
			type = Entry;
			name = parts[1];
			entry = QCA::KeyStoreEntry(parts[2]);
			if(!entry.isNull())
				usable = true;
		}
		else
			return false;

		return true;
	}
};

class IdentityListModel : public QAbstractListModel
{
	Q_OBJECT
//private:
public:
	QList<IdentityItem> list;

public:
	IdentityListModel(QObject *parent = 0) :
		QAbstractListModel(parent)
	{
	}

	int rowCount(const QModelIndex &parent = QModelIndex()) const
	{
		Q_UNUSED(parent);
		return list.count();
	}

	QVariant data(const QModelIndex &index, int role) const
	{
		if(!index.isValid())
			return QVariant();

		if(index.row() >= list.count())
			return QVariant();

		if(role == Qt::DisplayRole)
		{
			return list[index.row()].name;
		}
		else if(role == Qt::DecorationRole)
		{
			const IdentityItem &i = list[index.row()];
			if(i.type == IdentityItem::File)
				return QPixmap(":/gfx/key.png");
			else // Entry
				return QPixmap(":/gfx/key.png");
		}
		else
			return QVariant();
	}

	void addItem(const IdentityItem &i)
	{
		beginInsertRows(QModelIndex(), list.size(), list.size());
		list += i;
		endInsertRows();
	}

	void removeItem(int at)
	{
		beginRemoveRows(QModelIndex(), at, at);
		list.removeAt(at);
		endRemoveRows();
	}

	QString getUniqueName(const QString &name)
	{
		int num = 1;
		while(1)
		{
			QString tryname;
			if(num == 1)
				tryname = name;
			else
				tryname = name + QString(" (%1)").arg(num);

			bool found = false;
			foreach(const IdentityItem &i, list)
			{
				if(i.name == tryname)
				{
					found = true;
					break;
				}
			}
			if(!found)
				return tryname;

			++num;
		}
	}
};

class KnownItem
{
public:
	QString name;
	QCA::Certificate cert;

	QString toString() const
	{
		QStringList parts;
		parts += name;
		parts += QCA::Base64().arrayToString(cert.toDER());
		for(int n = 0; n < parts.count(); ++n)
			parts[n] = escape(parts[n]);
		return parts.join(":");
	}

	bool fromString(const QString &in)
	{
		QStringList parts = in.split(':');
		for(int n = 0; n < parts.count(); ++n)
			parts[n] = unescape(parts[n]);

		if(parts.count() < 2)
			return false;

		name = parts[0];
		cert = QCA::Certificate::fromDER(QCA::Base64().stringToArray(parts[1]));
		if(cert.isNull())
			return false;

		return true;
	}
};

class KnownListModel : public QAbstractListModel
{
	Q_OBJECT
//private:
public:
	QList<KnownItem> list;

public:
	KnownListModel(QObject *parent = 0) :
		QAbstractListModel(parent)
	{
	}

	int rowCount(const QModelIndex &parent = QModelIndex()) const
	{
		Q_UNUSED(parent);
		return list.count();
	}

	QVariant data(const QModelIndex &index, int role) const
	{
		if(!index.isValid())
			return QVariant();

		if(index.row() >= list.count())
			return QVariant();

		if(role == Qt::DisplayRole)
		{
			return list[index.row()].name;
		}
		else if(role == Qt::DecorationRole)
		{
			return QPixmap(":/gfx/key.png");
		}
		else
			return QVariant();
	}

	void addItem(const KnownItem &i)
	{
		beginInsertRows(QModelIndex(), list.size(), list.size());
		list += i;
		endInsertRows();
	}

	void removeItem(int at)
	{
		beginRemoveRows(QModelIndex(), at, at);
		list.removeAt(at);
		endRemoveRows();
	}
};

class Operation : public QObject
{
	Q_OBJECT
public:
	Operation(QObject *parent = 0) :
		QObject(parent)
	{
	}

signals:
	void error(const QString &str);
};

class SignOperation : public Operation
{
	Q_OBJECT
private:
	QByteArray in;
	IdentityItem *item;
	QCA::CMS *cms;
	QCA::KeyLoader *loader;
	QCA::KeyBundle key;
	QCA::SecureMessage *msg;

public:
	SignOperation(const QByteArray &_in, IdentityItem *_item, QCA::CMS *_cms, QObject *parent = 0) :
		Operation(parent),
		in(_in),
		item(_item),
		cms(_cms),
		loader(0),
		msg(0)
	{
		if(item->type == IdentityItem::File)
		{
			loader = new QCA::KeyLoader(this);
			connect(loader, SIGNAL(finished()), SLOT(loaded()));
			loader->loadKeyBundleFromFile(item->fileName);
		}
		else // Entry
		{
			key = item->entry.keyBundle();
			QMetaObject::invokeMethod(this, "do_sign", Qt::QueuedConnection);
		}
	}

	~SignOperation()
	{
	}

signals:
	void finished(const QString &sig);

private slots:
	void loaded()
	{
		if(loader->convertResult() != QCA::ConvertGood)
		{
			emit error(tr("Error opening key file."));
			return;
		}

		key = loader->keyBundle();
		delete loader;
		loader = 0;

		do_sign();
	}

	void do_sign()
	{
		printf("do_sign\n");

		QCA::SecureMessageKey signer;
		signer.setX509CertificateChain(key.certificateChain());
		signer.setX509PrivateKey(key.privateKey());

		msg = new QCA::SecureMessage(cms);
		connect(msg, SIGNAL(finished()), SLOT(msg_finished()));
		msg->setFormat(QCA::SecureMessage::Ascii);
		msg->setSigner(signer);
		msg->startSign(QCA::SecureMessage::Detached);
		update();
	}

	void update()
	{
		printf("update\n");

		QByteArray buf = in.mid(0, 16384); // 16k chunks
		in = in.mid(buf.size());
		msg->update(buf);

		if(in.isEmpty())
			msg->end();
		else
			QMetaObject::invokeMethod(this, "update", Qt::QueuedConnection);
	}

	void msg_finished()
	{
		printf("msg_finished\n");

		if(!msg->success())
		{
			delete msg;
			msg = 0;
			emit error(tr("Error during sign operation."));
			return;
		}

		QByteArray result = msg->signature();
		delete msg;
		msg = 0;

		emit finished(QString::fromLatin1(result));
	}
};

class VerifyOperation : public Operation
{
	Q_OBJECT
private:
	QByteArray in, sig;
	QCA::CMS *cms;
	QCA::SecureMessage *msg;

public:
	VerifyOperation(const QByteArray &_in, const QByteArray &_sig, QCA::CMS *_cms, QObject *parent = 0) :
		Operation(parent),
		in(_in),
		sig(_sig),
		cms(_cms),
		msg(0)
	{
		printf("do_verify\n");

		msg = new QCA::SecureMessage(cms);
		connect(msg, SIGNAL(finished()), SLOT(msg_finished()));
		msg->setFormat(QCA::SecureMessage::Ascii);
		msg->startVerify(sig);
		QMetaObject::invokeMethod(this, "update", Qt::QueuedConnection);
	}

signals:
	void finished();

private slots:
	void update()
	{
		printf("update\n");

		QByteArray buf = in.mid(0, 16384); // 16k chunks
		in = in.mid(buf.size());
		msg->update(buf);

		if(in.isEmpty())
			msg->end();
		else
			QMetaObject::invokeMethod(this, "update", Qt::QueuedConnection);
	}

	void msg_finished()
	{
		printf("msg_finished\n");

		if(!msg->success())
		{
			delete msg;
			msg = 0;
			emit error(tr("Error during verify operation."));
			return;
		}

		QCA::SecureMessageSignature signer = msg->signer();
		QCA::SecureMessageSignature::IdentityResult r = signer.identityResult();
		delete msg;
		msg = 0;

		if(r != QCA::SecureMessageSignature::Valid)
		{
			emit error(tr("Verification failed! [%1]").arg((int)r));
			return;
		}

		emit finished();
	}
};

QAction *actionView, *actionRename, *actionRemove;

MyListView::MyListView(QWidget *parent) :
	QListView(parent)
{
}

void MyListView::contextMenuEvent(QContextMenuEvent *event)
{
	QItemSelection selection = selectionModel()->selection();
	if(selection.indexes().isEmpty())
		return;

	QMenu menu(this);
	menu.addAction(actionView);
	menu.addAction(actionRename);
	menu.addAction(actionRemove);
	menu.exec(event->globalPos());
}

static QString entryTypeToString(QCA::KeyStoreEntry::Type type)
{
	QString out;
	switch(type)
	{
		case QCA::KeyStoreEntry::TypeKeyBundle:     out = "X"; break;
		case QCA::KeyStoreEntry::TypeCertificate:   out = "C"; break;
		case QCA::KeyStoreEntry::TypeCRL:           out = "R"; break;
		case QCA::KeyStoreEntry::TypePGPSecretKey:  out = "S"; break;
		case QCA::KeyStoreEntry::TypePGPPublicKey:  out = "P"; break;
		default:                                    out = "U"; break;
	}
	return out;
}

class KeyStoreModel : public QStandardItemModel
{
	Q_OBJECT
public:
	QCA::KeyStoreManager ksm;
	QList<QCA::KeyStore*> stores;
	QList<QStandardItem*> storeItems;
	QList< QList<QCA::KeyStoreEntry> > storeEntries;
	QList< QList<QStandardItem*> > storeEntryItems;

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

		// only list keybundles
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
		foreach(const QCA::KeyStoreEntry &entry, entries)
		{
			QStandardItem *item = new QStandardItem(entryTypeToString(entry.type()) + " - " + entry.name());
			storeEntryItems[at] += item;
			storeItems[at]->appendRow(item);
		}
	}

	void ks_unavailable()
	{
		QCA::KeyStore *ks = (QCA::KeyStore *)sender();
		Q_UNUSED(ks);

		// TODO
	}
};

class LoadStore : public QDialog
{
	Q_OBJECT
private:
	Ui_LoadStore ui;
	KeyStoreModel *model;
	QCA::KeyStoreEntry cur_entry;

public:
	LoadStore(QWidget *parent = 0) :
		QDialog(parent)
	{
		ui.setupUi(this);

		ui.lv_stores->header()->hide();

		ui.buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);

		model = new KeyStoreModel(this);
		ui.lv_stores->setModel(model);
		connect(ui.lv_stores->selectionModel(), SIGNAL(selectionChanged(const QItemSelection &, const QItemSelection &)), SLOT(stores_selectionChanged(const QItemSelection &, const QItemSelection &)));
	}

signals:
	void entrySelected(const QCA::KeyStoreEntry &entry);

protected slots:
	virtual void accept()
	{
		QCA::KeyStoreEntry entry = cur_entry;
		QDialog::accept();
		emit entrySelected(entry);
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

class MainWin : public QMainWindow
{
	Q_OBJECT
private:
	Ui_MainWin ui;
	QCA::EventHandler *eventHandler;
	QCA::SecureArray lastPassword;
	QCA::KeyLoader *keyLoader;
	QString keyLoader_fileName;
	IdentityListModel *model;
	KnownListModel *known;
	QCA::CMS *cms;
	Operation *op;

public:
	MainWin(QWidget *parent = 0) :
		QMainWindow(parent),
		keyLoader(0),
		op(0)
	{
		ui.setupUi(this);

		actionView = new QAction(tr("&View"), this);
		actionRename = new QAction(tr("Re&name"), this);
		actionRemove = new QAction(tr("Rem&ove"), this);

		// TODO
		actionView->setEnabled(false);

		connect(ui.actionLoad_Identity_From_File, SIGNAL(triggered()), SLOT(load_file()));
		connect(ui.actionLoad_Identity_From_Storage_Device, SIGNAL(triggered()), SLOT(load_device()));
		connect(ui.actionConfigure_PKCS_11_Modules, SIGNAL(triggered()), SLOT(mod_config()));
		connect(ui.actionQuit, SIGNAL(triggered()), SLOT(close()));
		connect(ui.actionAbout_CMS_Signer, SIGNAL(triggered()), SLOT(about()));
		connect(ui.pb_sign, SIGNAL(clicked()), SLOT(do_sign()));
		connect(ui.pb_verify, SIGNAL(clicked()), SLOT(do_verify()));

		connect(actionView, SIGNAL(triggered()), SLOT(item_view()));
		connect(actionRename, SIGNAL(triggered()), SLOT(item_rename()));
		connect(actionRemove, SIGNAL(triggered()), SLOT(item_remove()));

		ui.pb_sign->setEnabled(false);

		eventHandler = new QCA::EventHandler(this);
		connect(eventHandler, SIGNAL(eventReady(int, const QCA::Event &)), SLOT(eh_eventReady(int, const QCA::Event &)));
		eventHandler->start();

		model = new IdentityListModel(this);
		ui.lv_identities->setModel(model);
		connect(ui.lv_identities->selectionModel(), SIGNAL(selectionChanged(const QItemSelection &, const QItemSelection &)), SLOT(identities_selectionChanged(const QItemSelection &, const QItemSelection &)));

		known = new KnownListModel(this);
		ui.lv_known->setModel(known);

		ui.lv_identities->model = model;
		ui.lv_known->model = known;

		cms = new QCA::CMS(this);
	}

private slots:
	void eh_eventReady(int id, const QCA::Event &event)
	{
		QString promptType;
		if(event.passwordStyle() == QCA::Event::StylePassphrase)
			promptType = tr("Passphrase");
		else if(event.passwordStyle() == QCA::Event::StylePIN)
			promptType = tr("PIN");
		else // Password
			promptType = tr("Password");

		QString promptStr = promptType + ": ";

		bool ok;
		QString pass = QInputDialog::getText(this, tr("CMS Signer"), promptStr, QLineEdit::Password, QString(), &ok);
		if(!ok)
		{
			eventHandler->reject(id);
			return;
		}

		QCA::SecureArray password = pass.toUtf8();

		// cache file passwords
		if(event.source() == QCA::Event::Data)
			lastPassword = password;

		eventHandler->submitPassword(id, password);
	}

	void load_file()
	{
		QString fileName = QFileDialog::getOpenFileName(this, tr("Open File"), QString(), tr("X.509 Identities (*.p12 *.pfx)"));
		if(fileName.isEmpty())
			return;

		setEnabled(false);
		keyLoader = new QCA::KeyLoader(this);
		connect(keyLoader, SIGNAL(finished()), SLOT(load_file_finished()));
		keyLoader_fileName = fileName;
		keyLoader->loadKeyBundleFromFile(fileName);
	}

	void load_device()
	{
		LoadStore *w = new LoadStore(this);
		w->setAttribute(Qt::WA_DeleteOnClose, true);
		w->setWindowModality(Qt::WindowModal);
		connect(w, SIGNAL(entrySelected(const QCA::KeyStoreEntry &)), SLOT(load_device_finished(const QCA::KeyStoreEntry &)));
		w->show();
	}

	void load_file_finished()
	{
		if(keyLoader->convertResult() != QCA::ConvertGood)
		{
			setEnabled(true);
			QMessageBox::information(this, tr("Error"), tr("Error opening key file."));
			return;
		}

		QCA::KeyBundle kb = keyLoader->keyBundle();
		delete keyLoader;
		keyLoader = 0;

		QCA::Certificate cert = kb.certificateChain().primary();

		QString name = model->getUniqueName(cert.commonName());

		// TODO: check for duplicate identities?
		IdentityItem i;
		i.type = IdentityItem::File;
		i.name = name;
		i.fileName = keyLoader_fileName;
		i.password = lastPassword;
		i.usable = true;
		lastPassword.clear();
		model->addItem(i);

		ui.lv_identities->selectionModel()->select(model->index(model->list.count()-1), QItemSelectionModel::Clear | QItemSelectionModel::Select | QItemSelectionModel::Current);

		// TODO: give unique names to knowns?  check for dups also?
		KnownItem ki;
		ki.name = i.name;
		ki.cert = cert;
		known->addItem(ki);

		setEnabled(true);
	}

	void load_device_finished(const QCA::KeyStoreEntry &entry)
	{
		QCA::KeyBundle kb = entry.keyBundle();

		QCA::Certificate cert = kb.certificateChain().primary();

		QString name = model->getUniqueName(entry.name());

		IdentityItem i;
		i.type = IdentityItem::Entry;
		i.name = name;
		i.entry = entry;
		i.usable = true;
		model->addItem(i);

		ui.lv_identities->selectionModel()->select(model->index(model->list.count()-1), QItemSelectionModel::Clear | QItemSelectionModel::Select | QItemSelectionModel::Current);

		KnownItem ki;
		ki.name = i.name;
		ki.cert = cert;
		known->addItem(ki);

		setEnabled(true);
	}

	void mod_config()
	{
		if(!Pkcs11ConfigDlg::isSupported())
		{
			QMessageBox::information(this, tr("Error"), tr("No provider available supporting standard PKCS#11 configuration."));
			return;
		}

		Pkcs11ConfigDlg *w = new Pkcs11ConfigDlg(this);
		w->setAttribute(Qt::WA_DeleteOnClose, true);
		w->setWindowModality(Qt::WindowModal);
		w->show();
	}

	void identities_selectionChanged(const QItemSelection &selected, const QItemSelection &deselected)
	{
		Q_UNUSED(deselected);

		if(!selected.indexes().isEmpty() && !ui.pb_sign->isEnabled())
			ui.pb_sign->setEnabled(true);
		else if(selected.indexes().isEmpty() && ui.pb_sign->isEnabled())
			ui.pb_sign->setEnabled(false);
	}

	void item_view()
	{
		if(ui.lv_identities->hasFocus())
		{
			QItemSelection selection = ui.lv_identities->selectionModel()->selection();
			if(selection.indexes().isEmpty())
				return;
			QModelIndex index = selection.indexes().first();
			identity_view(index.row());
		}
		else // lv_known
		{
			QItemSelection selection = ui.lv_known->selectionModel()->selection();
			if(selection.indexes().isEmpty())
				return;
			QModelIndex index = selection.indexes().first();
			known_view(index.row());
		}
	}

	void item_rename()
	{
		if(ui.lv_identities->hasFocus())
		{
			QItemSelection selection = ui.lv_identities->selectionModel()->selection();
			if(selection.indexes().isEmpty())
				return;
			QModelIndex index = selection.indexes().first();
			identity_rename(index.row());
		}
		else // lv_known
		{
			QItemSelection selection = ui.lv_known->selectionModel()->selection();
			if(selection.indexes().isEmpty())
				return;
			QModelIndex index = selection.indexes().first();
			known_rename(index.row());
		}
	}

	void item_remove()
	{
		if(ui.lv_identities->hasFocus())
		{
			QItemSelection selection = ui.lv_identities->selectionModel()->selection();
			if(selection.indexes().isEmpty())
				return;
			QModelIndex index = selection.indexes().first();
			identity_remove(index.row());
		}
		else // lv_known
		{
			QItemSelection selection = ui.lv_known->selectionModel()->selection();
			if(selection.indexes().isEmpty())
				return;
			QModelIndex index = selection.indexes().first();
			known_remove(index.row());
		}
	}

	void identity_view(int at)
	{
		printf("identity_view: %d\n", at);
	}

	void identity_rename(int at)
	{
		printf("identity_rename: %d\n", at);
	}

	void identity_remove(int at)
	{
		model->removeItem(at);
	}

	void known_view(int at)
	{
		printf("known_view: %d\n", at);
	}

	void known_rename(int at)
	{
		printf("known_rename: %d\n", at);
	}

	void known_remove(int at)
	{
		known->removeItem(at);
	}

	void do_sign()
	{
		op = new SignOperation(ui.te_data->toPlainText().toUtf8(), &model->list[0], cms, this);
		connect(op, SIGNAL(finished(const QString &)), SLOT(sign_finished(const QString &)));
		connect(op, SIGNAL(error(const QString &)), SLOT(op_error(const QString &)));
	}

	void do_verify()
	{
		// get known
		QCA::CertificateCollection col;
		foreach(const KnownItem &i, known->list)
			col.addCertificate(i.cert);
		col += QCA::systemStore();
		cms->setTrustedCertificates(col);

		op = new VerifyOperation(ui.te_data->toPlainText().toUtf8(), ui.te_sig->toPlainText().toUtf8(), cms, this);
		connect(op, SIGNAL(finished()), SLOT(verify_finished()));
		connect(op, SIGNAL(error(const QString &)), SLOT(op_error(const QString &)));
	}

	void about()
	{
		QMessageBox::about(this, tr("About CMS Signer"), tr("CMS Signer v0.1\nA simple tool for creating and verifying digital signatures."));
	}

	void sign_finished(const QString &sig)
	{
		ui.te_sig->setPlainText(sig);
	}

	void verify_finished()
	{
		QMessageBox::information(this, tr("Verify"), tr("Signature verified successfully."));
	}

	void op_error(const QString &msg)
	{
		QMessageBox::information(this, tr("Error"), msg);
		delete op;
		op = 0;
	}
};

int main(int argc, char **argv)
{
	QCA::Initializer qcaInit;
	QApplication qapp(argc, argv);
	if(!QCA::isSupported("cms"))
	{
		QMessageBox::critical(0, MainWin::tr("CMS Signer: Error"), MainWin::tr("No support for CMS is available.  Please install an appropriate QCA plugin, such as qca-openssl."));
		return 1;
	}
	MainWin mainWin;
	mainWin.show();
	return qapp.exec();
}

#include "main.moc"
