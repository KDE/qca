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

#include <QtCore>
#include <QtGui>
#include <QtCrypto>

#include "ui_mainwin.h"
#include "prompter.h"
#include "mylistview.h"
#include "ui_loadstore.h"
#include "pkcs11configdlg/pkcs11configdlg.h"

#define VERSION "0.0.1"

class Icons
{
public:
	QPixmap cert, crl, keybundle, pgppub, pgpsec;
};

Icons *g_icons = 0;

//----------------------------------------------------------------------------
// CertItem
//----------------------------------------------------------------------------
class CertItem
{
public:
	enum StorageType { File, Entry };

	QString name;
	QCA::CertificateChain chain;
	bool havePrivate;
	StorageType storageType; // private storage type
	bool usable; // storage is accessible
	QString fileName;
	QCA::KeyStoreEntry keyStoreEntry;

	CertItem();
	QString toString() const;
	bool fromString(const QString &in);
};

static QString escape(const QString &in)
{
	QString out;
	for(int n = 0; n < in.length(); ++n)
	{
		if(in[n] == '\\')
			out += "\\\\";
		else if(in[n] == ':')
			out += "\\c";
		else if(in[n] == '\n')
			out += "\\n";
		else
			out += in[n];
	}
	return out;
}

static QString unescape(const QString &in)
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
				else if(in[n] == 'n')
					out += '\n';
			}
		}
		else
			out += in[n];
	}
	return out;
}

CertItem::CertItem() :
	havePrivate(false),
	storageType(File),
	usable(false)
{
}

QString CertItem::toString() const
{
	QStringList parts;

	parts += name;
	parts += QString::number(chain.count());
	foreach(const QCA::Certificate &cert, chain)
		parts += QCA::Base64().arrayToString(cert.toDER());

	if(havePrivate)
	{
		if(storageType == File)
		{
			parts += "privateFile";
			parts += fileName;
		}
		else // Entry
		{
			parts += "privateEntry";
			parts += keyStoreEntry.toString();
		}
	}

	for(int n = 0; n < parts.count(); ++n)
		parts[n] = escape(parts[n]);
	return parts.join(":");
}

bool CertItem::fromString(const QString &in)
{
	QStringList parts = in.split(':');
	for(int n = 0; n < parts.count(); ++n)
		parts[n] = unescape(parts[n]);

	if(parts.count() < 3)
		return false;

	name = parts[0];
	int chainCount = parts[1].toInt();
	if(chainCount < 1 || chainCount > parts.count() - 2)
		return false;
	chain.clear();
	for(int n = 0; n < chainCount; ++n)
	{
		QCA::Certificate cert = QCA::Certificate::fromDER(QCA::Base64().stringToArray(parts[n + 2]));
		if(cert.isNull())
			return false;
		chain += cert;
	}
	int at = chain.count() + 2;

	if(at < parts.count())
	{
		havePrivate = true;
		usable = false;

		if(parts[at] == "privateFile")
		{
			storageType = File;
			fileName = parts[at + 1];
			if(QFile::exists(fileName))
				usable = true;
		}
		else if(parts[at] == "privateEntry")
		{
			storageType = Entry;
			keyStoreEntry = QCA::KeyStoreEntry(parts[at + 1]);
			if(!keyStoreEntry.isNull())
				usable = true;
		}
		else
			return false;
	}

	return true;
}

//----------------------------------------------------------------------------
// CertListModel
//----------------------------------------------------------------------------
class CertListModel : public QAbstractListModel
{
	Q_OBJECT
public:
	QList<CertItem> list;

	CertListModel(QObject *parent = 0) :
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
			return list[index.row()].name;
		else if(role == Qt::EditRole)
			return list[index.row()].name;
		else if(role == Qt::DecorationRole && g_icons)
		{
			const CertItem &i = list[index.row()];
			if(i.havePrivate)
				return g_icons->keybundle;
			else
				return g_icons->cert;
		}
		else
			return QVariant();
	}

	Qt::ItemFlags flags(const QModelIndex &index) const
	{
		if(!index.isValid())
			return Qt::ItemIsEnabled;

		return QAbstractItemModel::flags(index) | Qt::ItemIsEditable;
	}

	bool setData(const QModelIndex &index, const QVariant &value, int role)
	{
		if(index.isValid() && role == Qt::EditRole)
		{
			QString str = value.toString();
			list[index.row()].name = str;
			emit dataChanged(index, index);
			return true;
		}
		return false;
	}

	void addItems(const QList<CertItem> &items)
	{
		if(items.isEmpty())
			return;

		beginInsertRows(QModelIndex(), list.size(), list.size() + items.count() - 1);
		list += items;
		endInsertRows();
	}

	void addItem(const CertItem &i)
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
			foreach(const CertItem &i, list)
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

//----------------------------------------------------------------------------
// Operation
//----------------------------------------------------------------------------
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

static QString validityToString(QCA::Validity v)
{
	QString s;
	switch(v)
	{
		case QCA::ValidityGood:
			s = Operation::tr("Validated");
			break;
		case QCA::ErrorRejected:
			s = Operation::tr("Root CA is marked to reject the specified purpose");
			break;
		case QCA::ErrorUntrusted:
			s = Operation::tr("Certificate not trusted for the required purpose");
			break;
		case QCA::ErrorSignatureFailed:
			s = Operation::tr("Invalid signature");
			break;
		case QCA::ErrorInvalidCA:
			s = Operation::tr("Invalid CA certificate");
			break;
		case QCA::ErrorInvalidPurpose:
			s = Operation::tr("Invalid certificate purpose");
			break;
		case QCA::ErrorSelfSigned:
			s = Operation::tr("Certificate is self-signed");
			break;
		case QCA::ErrorRevoked:
			s = Operation::tr("Certificate has been revoked");
			break;
		case QCA::ErrorPathLengthExceeded:
			s = Operation::tr("Maximum certificate chain length exceeded");
			break;
		case QCA::ErrorExpired:
			s = Operation::tr("Certificate has expired");
			break;
		case QCA::ErrorExpiredCA:
			s = Operation::tr("CA has expired");
			break;
		case QCA::ErrorValidityUnknown:
		default:
			s = Operation::tr("General certificate validation error");
			break;
	}
	return s;
}

static QString smErrorToString(QCA::SecureMessage::Error e)
{
	QMap<QCA::SecureMessage::Error,QString> map;
	map[QCA::SecureMessage::ErrorPassphrase] = Operation::tr("Invalid passphrase");
	map[QCA::SecureMessage::ErrorFormat] = Operation::tr("Bad input format");
	map[QCA::SecureMessage::ErrorSignerExpired] = Operation::tr("Signer key is expired");
	map[QCA::SecureMessage::ErrorSignerInvalid] = Operation::tr("Signer key is invalid");
	map[QCA::SecureMessage::ErrorEncryptExpired] = Operation::tr("Encrypting key is expired");
	map[QCA::SecureMessage::ErrorEncryptUntrusted] = Operation::tr("Encrypting key is untrusted");
	map[QCA::SecureMessage::ErrorEncryptInvalid] = Operation::tr("Encrypting key is invalid");
	map[QCA::SecureMessage::ErrorNeedCard] = Operation::tr("Card was needed but not found");
	map[QCA::SecureMessage::ErrorCertKeyMismatch] = Operation::tr("Certificate and private key don't match");
	map[QCA::SecureMessage::ErrorUnknown] = Operation::tr("General error");
	return map[e];
}

class SignOperation : public Operation
{
	Q_OBJECT
private:
	QByteArray in;
	CertItem *item;
	QCA::CMS *cms;
	QCA::KeyLoader *loader;
	QCA::KeyBundle key;
	QCA::SecureMessage *msg;

public:
	SignOperation(const QByteArray &_in, CertItem *_item, QCA::CMS *_cms, QObject *parent = 0) :
		Operation(parent),
		in(_in),
		item(_item),
		cms(_cms),
		loader(0),
		msg(0)
	{
		if(item->storageType == CertItem::File)
		{
			loader = new QCA::KeyLoader(this);
			connect(loader, SIGNAL(finished()), SLOT(loaded()));
			loader->loadKeyBundleFromFile(item->fileName);
		}
		else // Entry
		{
			key = item->keyStoreEntry.keyBundle();
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
		//printf("do_sign\n");

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
		//printf("update\n");

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
		//printf("msg_finished\n");

		if(!msg->success())
		{
			QString str = smErrorToString(msg->errorCode());
			delete msg;
			msg = 0;
			emit error(tr("Error during sign operation.\nReason: %1").arg(str));
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
		//printf("do_verify\n");

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
		//printf("update\n");

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
		//printf("msg_finished\n");

		if(!msg->success())
		{
			QString str = smErrorToString(msg->errorCode());
			delete msg;
			msg = 0;
			emit error(tr("Error during verify operation.\nReason: %1").arg(str));
			return;
		}

		QCA::SecureMessageSignature signer = msg->signer();
		QCA::SecureMessageSignature::IdentityResult r = signer.identityResult();
		delete msg;
		msg = 0;

		if(r != QCA::SecureMessageSignature::Valid)
		{
			QString str;
			if(r == QCA::SecureMessageSignature::InvalidSignature)
				str = tr("Invalid signature");
			else if(r == QCA::SecureMessageSignature::InvalidKey)
				str = tr("Invalid key: %1").arg(validityToString(signer.keyValidity()));
			else if(r == QCA::SecureMessageSignature::NoKey)
				str = tr("Key not found");
			else // unknown
				str = tr("Unknown");

			emit error(tr("Verification failed!\nReason: %1").arg(str));
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

/*static QString entryTypeToString(QCA::KeyStoreEntry::Type type)
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
}*/

static QPixmap entryTypeToIcon(QCA::KeyStoreEntry::Type type)
{
	QPixmap out;
	switch(type)
	{
		case QCA::KeyStoreEntry::TypeKeyBundle:     out = g_icons->keybundle; break;
		case QCA::KeyStoreEntry::TypeCertificate:   out = g_icons->cert; break;
		case QCA::KeyStoreEntry::TypeCRL:           out = g_icons->crl; break;
		case QCA::KeyStoreEntry::TypePGPSecretKey:  out = g_icons->pgpsec; break;
		case QCA::KeyStoreEntry::TypePGPPublicKey:  out = g_icons->pgppub; break;
		default:                                    break;
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

class MyPrompter : public Prompter
{
	Q_OBJECT
private:
	QMap<QString,QCA::SecureArray> known;

public:
	MyPrompter(QObject *parent = 0) :
		Prompter(parent)
	{
	}

protected:
	virtual QCA::SecureArray knownPassword(const QCA::Event &event)
	{
		if(event.source() == QCA::Event::Data && !event.fileName().isEmpty())
			return known.value(event.fileName());
		else
			return QCA::SecureArray();
	}

	virtual void userSubmitted(const QCA::SecureArray &password, const QCA::Event &event)
	{
		if(event.source() == QCA::Event::Data && !event.fileName().isEmpty())
			known[event.fileName()] = password;
	}
};

class MainWin : public QMainWindow
{
	Q_OBJECT
private:
	Ui_MainWin ui;
	MyPrompter *prompter;
	QCA::KeyLoader *keyLoader;
	QString keyLoader_fileName;
	CertListModel *users, *roots;
	QCA::CMS *cms;
	Operation *op;

public:
	MainWin(QWidget *parent = 0) :
		QMainWindow(parent),
		keyLoader(0),
		op(0)
	{
		ui.setupUi(this);

		g_icons = new Icons;
		g_icons->cert = QPixmap(":/gfx/icons/cert16.png");
		g_icons->crl = QPixmap(":/gfx/icons/crl16.png");
		g_icons->keybundle = QPixmap(":/gfx/icons/keybundle16.png");
		g_icons->pgppub = QPixmap(":/gfx/icons/publickey16.png");
		g_icons->pgpsec = QPixmap(":/gfx/icons/keypair16.png");
		if(g_icons->cert.isNull() || g_icons->crl.isNull() || g_icons->keybundle.isNull() || g_icons->pgppub.isNull() || g_icons->pgpsec.isNull())
			printf("warning: not all icons loaded\n");

		actionView = new QAction(tr("&View"), this);
		actionRename = new QAction(tr("Re&name"), this);
		actionRemove = new QAction(tr("Rem&ove"), this);

		// TODO
		actionView->setEnabled(false);

		connect(ui.actionLoadIdentityFile, SIGNAL(triggered()), SLOT(load_file()));
		connect(ui.actionLoadIdentityEntry, SIGNAL(triggered()), SLOT(load_device()));
		connect(ui.actionLoadAuthority, SIGNAL(triggered()), SLOT(load_root()));
		connect(ui.actionConfigurePkcs11, SIGNAL(triggered()), SLOT(mod_config()));
		connect(ui.actionQuit, SIGNAL(triggered()), SLOT(close()));
		connect(ui.actionAbout, SIGNAL(triggered()), SLOT(about()));
		connect(ui.pb_sign, SIGNAL(clicked()), SLOT(do_sign()));
		connect(ui.pb_verify, SIGNAL(clicked()), SLOT(do_verify()));

		//connect(actionView, SIGNAL(triggered()), SLOT(item_view()));
		connect(actionRename, SIGNAL(triggered()), SLOT(item_rename()));
		connect(actionRemove, SIGNAL(triggered()), SLOT(item_remove()));

		ui.pb_sign->setEnabled(false);

		prompter = new MyPrompter(this);

		users = new CertListModel(this);
		ui.lv_users->setModel(users);
		connect(ui.lv_users->selectionModel(), SIGNAL(selectionChanged(const QItemSelection &, const QItemSelection &)), SLOT(users_selectionChanged(const QItemSelection &, const QItemSelection &)));

		roots = new CertListModel(this);
		ui.lv_authorities->setModel(roots);

		// FIXME: is this redundant?
		ui.lv_users->model = users;
		ui.lv_authorities->model = roots;

		cms = new QCA::CMS(this);

		QStringList ulist, rlist;
		{
			QSettings settings("Affinix", "CMS Signer");
			ulist = settings.value("users").toStringList();
			rlist = settings.value("roots").toStringList();
		}

		QList<CertItem> userslist;
		foreach(const QString &s, ulist)
		{
			CertItem i;
			if(i.fromString(s))
				userslist += i;
		}

		QList<CertItem> rootslist;
		foreach(const QString &s, rlist)
		{
			CertItem i;
			if(i.fromString(s))
				rootslist += i;
		}

		users->addItems(userslist);
		roots->addItems(rootslist);
	}

	~MainWin()
	{
		QStringList ulist;
		foreach(const CertItem &i, users->list)
			ulist += i.toString();
		QStringList rlist;
		foreach(const CertItem &i, roots->list)
			rlist += i.toString();

		QSettings settings("Affinix", "CMS Signer");
		settings.setValue("users", ulist);
		settings.setValue("roots", rlist);

		delete g_icons;
		g_icons = 0;
	}

private slots:
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

	void load_root()
	{
		QString fileName = QFileDialog::getOpenFileName(this, tr("Open File"), QString(), tr("X.509 Certificates (*.pem *.crt)"));
		if(fileName.isEmpty())
			return;

		QCA::Certificate cert = QCA::Certificate::fromPEMFile(fileName);
		if(cert.isNull())
		{
			QMessageBox::information(this, tr("Error"), tr("Error opening certificate file."));
			return;
		}

		QString name = roots->getUniqueName(cert.commonName());

		// TODO: check for duplicate entries?
		CertItem i;
		i.name = name;
		i.chain += cert;
		roots->addItem(i);
	}

	void load_file_finished()
	{
		// TODO: show more descriptive reason?
		if(keyLoader->convertResult() != QCA::ConvertGood)
		{
			setEnabled(true);
			QMessageBox::information(this, tr("Error"), tr("Error opening key file."));
			return;
		}

		QCA::KeyBundle kb = keyLoader->keyBundle();
		delete keyLoader;
		keyLoader = 0;

		QCA::CertificateChain chain = kb.certificateChain();
		QCA::Certificate cert = chain.primary();

		QString name = users->getUniqueName(cert.commonName());

		// TODO: check for duplicate identities?
		CertItem i;
		i.name = name;
		i.chain = chain;
		i.havePrivate = true;
		i.storageType = CertItem::File;
		i.fileName = keyLoader_fileName;
		i.usable = true;
		users->addItem(i);

		ui.lv_users->selectionModel()->select(users->index(users->list.count()-1), QItemSelectionModel::Clear | QItemSelectionModel::Select | QItemSelectionModel::Current);

		setEnabled(true);
	}

	void load_device_finished(const QCA::KeyStoreEntry &entry)
	{
		QCA::KeyBundle kb = entry.keyBundle();

		QCA::CertificateChain chain = kb.certificateChain();
		QCA::Certificate cert = chain.primary();

		QString name = users->getUniqueName(entry.name());

		// TODO: check for duplicate identities?
		CertItem i;
		i.name = name;
		i.chain = chain;
		i.havePrivate = true;
		i.storageType = CertItem::Entry;
		i.keyStoreEntry = entry;
		i.usable = true;
		users->addItem(i);

		ui.lv_users->selectionModel()->select(users->index(users->list.count()-1), QItemSelectionModel::Clear | QItemSelectionModel::Select | QItemSelectionModel::Current);

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

	void users_selectionChanged(const QItemSelection &selected, const QItemSelection &deselected)
	{
		Q_UNUSED(deselected);

		if(!selected.indexes().isEmpty() && !ui.pb_sign->isEnabled())
			ui.pb_sign->setEnabled(true);
		else if(selected.indexes().isEmpty() && ui.pb_sign->isEnabled())
			ui.pb_sign->setEnabled(false);
	}

	/*void item_view()
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
	}*/

	void item_rename()
	{
		if(ui.lv_users->hasFocus())
		{
			QItemSelection selection = ui.lv_users->selectionModel()->selection();
			if(selection.indexes().isEmpty())
				return;
			QModelIndex index = selection.indexes().first();
			users_rename(index.row());
		}
		else // lv_authorities
		{
			QItemSelection selection = ui.lv_authorities->selectionModel()->selection();
			if(selection.indexes().isEmpty())
				return;
			QModelIndex index = selection.indexes().first();
			roots_rename(index.row());
		}
	}

	void item_remove()
	{
		if(ui.lv_users->hasFocus())
		{
			QItemSelection selection = ui.lv_users->selectionModel()->selection();
			if(selection.indexes().isEmpty())
				return;
			QModelIndex index = selection.indexes().first();
			users_remove(index.row());
		}
		else // lv_authorities
		{
			QItemSelection selection = ui.lv_authorities->selectionModel()->selection();
			if(selection.indexes().isEmpty())
				return;
			QModelIndex index = selection.indexes().first();
			roots_remove(index.row());
		}
	}

	/*void identity_view(int at)
	{
		printf("identity_view: %d\n", at);
	}*/

	void users_rename(int at)
	{
		QModelIndex index = users->index(at);
		ui.lv_users->setFocus();
		ui.lv_users->setCurrentIndex(index);
		ui.lv_users->selectionModel()->select(index, QItemSelectionModel::Clear | QItemSelectionModel::Select | QItemSelectionModel::Current);
		ui.lv_users->edit(index);
	}

	void users_remove(int at)
	{
		users->removeItem(at);
	}

	/*void known_view(int at)
	{
		printf("known_view: %d\n", at);
	}*/

	void roots_rename(int at)
	{
		QModelIndex index = roots->index(at);
		ui.lv_authorities->setFocus();
		ui.lv_authorities->setCurrentIndex(index);
		ui.lv_authorities->selectionModel()->select(index, QItemSelectionModel::Clear | QItemSelectionModel::Select | QItemSelectionModel::Current);
		ui.lv_authorities->edit(index);
	}

	void roots_remove(int at)
	{
		roots->removeItem(at);
	}

	void do_sign()
	{
		QItemSelection selection = ui.lv_users->selectionModel()->selection();
		if(selection.indexes().isEmpty())
			return;
		QModelIndex index = selection.indexes().first();
		int at = index.row();

		op = new SignOperation(ui.te_data->toPlainText().toUtf8(), &users->list[at], cms, this);
		connect(op, SIGNAL(finished(const QString &)), SLOT(sign_finished(const QString &)));
		connect(op, SIGNAL(error(const QString &)), SLOT(op_error(const QString &)));
	}

	void do_verify()
	{
		// prepare root certs
		QCA::CertificateCollection col;

		// system store
		col += QCA::systemStore();

		// additional roots configured in application
		foreach(const CertItem &i, roots->list)
			col.addCertificate(i.chain.primary());

		// consider self-signed users as roots
		// (it is therefore not possible with this application to
		// have people in your keyring that you don't trust)
		foreach(const CertItem &i, users->list)
		{
			QCA::Certificate cert = i.chain.primary();
			if(cert.isSelfSigned())
				col.addCertificate(cert);
		}

		cms->setTrustedCertificates(col);

		op = new VerifyOperation(ui.te_data->toPlainText().toUtf8(), ui.te_sig->toPlainText().toUtf8(), cms, this);
		connect(op, SIGNAL(finished()), SLOT(verify_finished()));
		connect(op, SIGNAL(error(const QString &)), SLOT(op_error(const QString &)));
	}

	void about()
	{
		int ver = qcaVersion();
		int maj = (ver >> 16) & 0xff;
		int min = (ver >> 8) & 0xff;
		int bug = ver & 0xff;
		QString verstr;
		verstr.sprintf("%d.%d.%d", maj, min, bug);

		QString str;
		str += tr("CMS Signer version %1 by Justin Karneges").arg(VERSION) + '\n';
		str += tr("A simple tool for creating and verifying digital signatures.") + '\n';
		str += '\n';
		str += tr("Using QCA version %1").arg(verstr) + '\n';
		str += '\n';
		str += tr("Icons by Jason Kim") + '\n';

		QCA::ProviderList list = QCA::providers();
		foreach(QCA::Provider *p, list)
		{
			QString credit = p->credit();
			if(!credit.isEmpty())
			{
				str += '\n';
				str += credit;
			}
		}

		QMessageBox::about(this, tr("About CMS Signer"), str);
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
	qapp.setApplicationName(MainWin::tr("CMS Signer"));
	if(!QCA::isSupported("cms"))
	{
		QMessageBox::critical(0, qapp.applicationName() + ": " + MainWin::tr("Error"), MainWin::tr("No support for CMS is available.  Please install an appropriate QCA plugin, such as qca-openssl."));
		return 1;
	}
	MainWin mainWin;
	mainWin.show();
	return qapp.exec();
}

#include "main.moc"
