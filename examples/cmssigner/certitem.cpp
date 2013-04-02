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

#include "certitem.h"

#include <QtCore>
#include <QtGui>
#include <QtCrypto>
#include <QMessageBox>
#include "prompter.h"

typedef QMap<CertItemStore::IconType,QPixmap> CertItemIconset;

//----------------------------------------------------------------------------
// MyPrompter
//----------------------------------------------------------------------------
class MyPrompter : public Prompter
{
	Q_OBJECT
private:
	QMap<QString,QCA::SecureArray> known;
	QMap<QString,QCA::SecureArray> maybe;

public:
	MyPrompter(QObject *parent = 0) :
		Prompter(parent)
	{
	}

	void fileSuccess(const QString &fileName)
	{
		if(maybe.contains(fileName))
		{
			known[fileName] = maybe[fileName];
			maybe.remove(fileName);
		}
	}

	void fileFailed(const QString &fileName)
	{
		maybe.remove(fileName);
		known.remove(fileName);
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
			maybe[event.fileName()] = password;
	}
};

//----------------------------------------------------------------------------
// CertItem
//----------------------------------------------------------------------------
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

class CertItem::Private : public QSharedData
{
public:
	QString name;
	QCA::CertificateChain chain;
	bool havePrivate;
	StorageType storageType;
	bool usable;

	QString fileName;
	QCA::KeyStoreEntry keyStoreEntry;
	QString keyStoreEntryString;

	Private() :
		havePrivate(false),
		storageType(File),
		usable(false)
	{
	}

	QString toString() const
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
			else // KeyStoreEntry
			{
				parts += "privateEntry";
				if(!keyStoreEntry.isNull())
					parts += keyStoreEntry.toString();
				else
					parts += keyStoreEntryString;
			}
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

		name = parts[0];
		int chainCount = parts[1].toInt();
		if(chainCount < 1 || chainCount > parts.count() - 2)
			return false;
		chain.clear();
		for(int n = 0; n < chainCount; ++n)
		{
			QCA::Certificate cert = QCA::Certificate::fromDER(QCA::Base64().stringToArray(parts[n + 2]).toByteArray());
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
				storageType = KeyStore;
				keyStoreEntryString = parts[at + 1];
				keyStoreEntry = QCA::KeyStoreEntry(keyStoreEntryString);
				if(!keyStoreEntry.isNull())
					usable = true;
			}
			else
				return false;
		}

		return true;
	}
};

CertItem::CertItem()
{
}

CertItem::CertItem(const CertItem &from) :
	d(from.d)
{
}

CertItem::~CertItem()
{
}

CertItem & CertItem::operator=(const CertItem &from)
{
	d = from.d;
	return *this;
}

QString CertItem::name() const
{
	return d->name;
}

QCA::CertificateChain CertItem::certificateChain() const
{
	return d->chain;
}

bool CertItem::havePrivate() const
{
	return d->havePrivate;
}

CertItem::StorageType CertItem::storageType() const
{
	return d->storageType;
}

bool CertItem::isUsable() const
{
	return d->usable;
}

//----------------------------------------------------------------------------
// CertItemStore
//----------------------------------------------------------------------------
static MyPrompter *g_prompter = 0;
static int g_prompter_refs = 0;

class CertItemStorePrivate : public QObject
{
	Q_OBJECT
public:
	CertItemStore *q;
	MyPrompter *prompter;
	QList<CertItem> list;
	QList<int> idList;
	CertItemIconset iconset;
	int next_id;
	int next_req_id;

	class LoaderItem
	{
	public:
		int req_id;
		QCA::KeyLoader *keyLoader;
		QString fileName;
	};

	QList<LoaderItem> loaders;

	CertItemStorePrivate(CertItemStore *_q) :
		QObject(_q),
		q(_q),
		next_id(0),
		next_req_id(0)
	{
		if(!g_prompter)
		{
			g_prompter = new MyPrompter;
			g_prompter_refs = 1;
		}
		else
			++g_prompter_refs;

		prompter = g_prompter;
	}

	~CertItemStorePrivate()
	{
		foreach(const LoaderItem &i, loaders)
			delete i.keyLoader;

		--g_prompter_refs;
		if(g_prompter_refs == 0)
		{
			delete g_prompter;
			g_prompter = 0;
		}
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
				if(i.name() == tryname)
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

	static QString convertErrorToString(QCA::ConvertResult r)
	{
		QString str;
		switch(r)
		{
			case QCA::ConvertGood:      break;
			case QCA::ErrorPassphrase:  str = tr("Incorrect passphrase.");
			case QCA::ErrorFile:        str = tr("Unable to open or read file.");
			case QCA::ErrorDecode:
			default:                    str = tr("Unable to decode format.");
		}
		return str;
	}

public slots:
	void loader_finished()
	{
		QCA::KeyLoader *keyLoader = (QCA::KeyLoader *)sender();
		int at = -1;
		for(int n = 0; n < loaders.count(); ++n)
		{
			if(loaders[n].keyLoader == keyLoader)
			{
				at = n;
				break;
			}
		}
		Q_ASSERT(at != -1);

		int req_id = loaders[at].req_id;
		QString fileName = loaders[at].fileName;
		loaders.removeAt(at);

		QCA::ConvertResult r = keyLoader->convertResult();
		if(r != QCA::ConvertGood)
		{
			delete keyLoader;
			prompter->fileFailed(fileName);
			QMessageBox::information(0, tr("Error"),
				tr("Error importing certificate and private key.\nReason: %1").arg(convertErrorToString(r)));
			emit q->addFailed(req_id);
			return;
		}

		prompter->fileSuccess(fileName);

		QCA::KeyBundle kb = keyLoader->keyBundle();
		delete keyLoader;

		QCA::CertificateChain chain = kb.certificateChain();
		QCA::Certificate cert = chain.primary();

		QString name = getUniqueName(cert.commonName());

		CertItem i;
		i.d = new CertItem::Private;
		i.d->name = name;
		i.d->chain = chain;
		i.d->havePrivate = true;
		i.d->storageType = CertItem::File;
		i.d->usable = true;
		i.d->fileName = fileName;

		int id = next_id++;

		q->beginInsertRows(QModelIndex(), list.size(), list.size());
		list += i;
		idList += id;
		q->endInsertRows();

		emit q->addSuccess(req_id, id);
	}
};

CertItemStore::CertItemStore(QObject *parent) :
	QAbstractListModel(parent)
{
	d = new CertItemStorePrivate(this);
}

CertItemStore::~CertItemStore()
{
	delete d;
}

int CertItemStore::idFromRow(int row) const
{
	return d->idList[row];
}

int CertItemStore::rowFromId(int id) const
{
	for(int n = 0; n < d->idList.count(); ++n)
	{
		if(d->idList[n] == id)
			return n;
	}
	return -1;
}

CertItem CertItemStore::itemFromId(int id) const
{
	return d->list[rowFromId(id)];
}

CertItem CertItemStore::itemFromRow(int row) const
{
	return d->list[row];
}

QList<CertItem> CertItemStore::items() const
{
	return d->list;
}

QStringList CertItemStore::save() const
{
	QStringList out;
	foreach(const CertItem &i, d->list)
		out += i.d->toString();
	return out;
}

bool CertItemStore::load(const QStringList &in)
{
	QList<CertItem> addList;
	QList<int> addIdList;
	foreach(const QString &s, in)
	{
		CertItem i;
		i.d = new CertItem::Private;
		if(i.d->fromString(s))
		{
			addList += i;
			addIdList += d->next_id++;
		}
	}

	if(addList.isEmpty())
		return true;

	beginInsertRows(QModelIndex(), d->list.size(), d->list.size() + addList.count() - 1);
	d->list += addList;
	d->idList += addIdList;
	endInsertRows();

	return true;
}

int CertItemStore::addFromFile(const QString &fileName)
{
	CertItemStorePrivate::LoaderItem i;
	i.req_id = d->next_req_id++;
	i.keyLoader = new QCA::KeyLoader(d);
	i.fileName = fileName;
	connect(i.keyLoader, SIGNAL(finished()), d, SLOT(loader_finished()));
	d->loaders += i;
	i.keyLoader->loadKeyBundleFromFile(fileName);
	return i.req_id;
}

int CertItemStore::addFromKeyStore(const QCA::KeyStoreEntry &entry)
{
	QCA::KeyBundle kb = entry.keyBundle();

	QCA::CertificateChain chain = kb.certificateChain();
	QCA::Certificate cert = chain.primary();

	QString name = d->getUniqueName(entry.name());

	CertItem i;
	i.d = new CertItem::Private;
	i.d->name = name;
	i.d->chain = chain;
	i.d->havePrivate = true;
	i.d->storageType = CertItem::KeyStore;
	i.d->usable = true;
	i.d->keyStoreEntry = entry;

	int id = d->next_id++;

	beginInsertRows(QModelIndex(), d->list.size(), d->list.size());
	d->list += i;
	d->idList += id;
	endInsertRows();

	int req_id = d->next_req_id++;
	QMetaObject::invokeMethod(this, "addSuccess", Qt::QueuedConnection, Q_ARG(int, req_id), Q_ARG(int, id));
	return req_id;
}

int CertItemStore::addUser(const QCA::CertificateChain &chain)
{
	QCA::Certificate cert = chain.primary();

	QString name = d->getUniqueName(cert.commonName());

	CertItem i;
	i.d = new CertItem::Private;
	i.d->name = name;
	i.d->chain = chain;

	int id = d->next_id++;

	beginInsertRows(QModelIndex(), d->list.size(), d->list.size());
	d->list += i;
	d->idList += id;
	endInsertRows();

	int req_id = d->next_req_id++;
	QMetaObject::invokeMethod(this, "addSuccess", Qt::QueuedConnection, Q_ARG(int, req_id), Q_ARG(int, id));
	return req_id;
}

void CertItemStore::updateChain(int id, const QCA::CertificateChain &chain)
{
	int at = rowFromId(id);
	d->list[at].d->chain = chain;
}

void CertItemStore::removeItem(int id)
{
	int at = rowFromId(id);

	beginRemoveRows(QModelIndex(), at, at);
	d->list.removeAt(at);
	d->idList.removeAt(at);
	endRemoveRows();
}

void CertItemStore::setIcon(IconType type, const QPixmap &icon)
{
	d->iconset[type] = icon;
}

int CertItemStore::rowCount(const QModelIndex &parent) const
{
	Q_UNUSED(parent);
	return d->list.count();
}

QVariant CertItemStore::data(const QModelIndex &index, int role) const
{
	if(!index.isValid())
		return QVariant();

	int at = index.row();
	QList<CertItem> &list = d->list;

	if(at >= list.count())
		return QVariant();

	if(role == Qt::DisplayRole)
	{
		QString str = list[at].name();
		if(list[at].havePrivate() && !list[at].isUsable())
			str += QString(" ") + tr("(not usable)");
		return str;
	}
	else if(role == Qt::EditRole)
		return list[at].name();
	else if(role == Qt::DecorationRole)
	{
		if(list[at].havePrivate())
			return d->iconset[CertItemStore::IconKeyBundle];
		else
			return d->iconset[CertItemStore::IconCert];
	}
	else
		return QVariant();
}

Qt::ItemFlags CertItemStore::flags(const QModelIndex &index) const
{
	if(!index.isValid())
		return Qt::ItemIsEnabled;

	return Qt::ItemIsEnabled | Qt::ItemIsSelectable | Qt::ItemIsEditable;
}

bool CertItemStore::setData(const QModelIndex &index, const QVariant &value, int role)
{
	if(index.isValid() && role == Qt::EditRole)
	{
		QString str = value.toString();
		d->list[index.row()].d->name = str;
		emit dataChanged(index, index);
		return true;
	}
	return false;
}

//----------------------------------------------------------------------------
// CertItemPrivateLoader
//----------------------------------------------------------------------------
class CertItemPrivateLoaderPrivate : public QObject
{
	Q_OBJECT
public:
	CertItemPrivateLoader *q;
	CertItemStore *store;
	QCA::KeyLoader *loader;
	QString fileName;
	QCA::PrivateKey key;

	CertItemPrivateLoaderPrivate(CertItemPrivateLoader *_q) :
		QObject(_q),
		q(_q)
	{
	}

public slots:
	void loader_finished()
	{
		QCA::ConvertResult r = loader->convertResult();
		if(r != QCA::ConvertGood)
		{
			delete loader;
			loader = 0;
			store->d->prompter->fileFailed(fileName);
			QMessageBox::information(0, tr("Error"),
				tr("Error accessing private key.\nReason: %1").arg(CertItemStorePrivate::convertErrorToString(r)));
			emit q->finished();
			return;
		}

		store->d->prompter->fileSuccess(fileName);

		key = loader->keyBundle().privateKey();
		delete loader;
		loader = 0;
		emit q->finished();
	}
};

CertItemPrivateLoader::CertItemPrivateLoader(CertItemStore *store, QObject *parent) :
	QObject(parent)
{
	d = new CertItemPrivateLoaderPrivate(this);
	d->store = store;
}

CertItemPrivateLoader::~CertItemPrivateLoader()
{
	delete d;
}

void CertItemPrivateLoader::start(int id)
{
	CertItem i = d->store->itemFromId(id);

	if(i.storageType() == CertItem::KeyStore)
	{
		d->key = i.d->keyStoreEntry.keyBundle().privateKey();
		QMetaObject::invokeMethod(this, "finished", Qt::QueuedConnection);
		return;
	}

	d->key = QCA::PrivateKey();
	d->fileName = i.d->fileName;
	d->loader = new QCA::KeyLoader(d);
	connect(d->loader, SIGNAL(finished()), d, SLOT(loader_finished()));
	d->loader->loadKeyBundleFromFile(d->fileName);
}

QCA::PrivateKey CertItemPrivateLoader::privateKey() const
{
	return d->key;
}

#include "certitem.moc"
