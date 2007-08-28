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

#ifndef CERTITEM_H
#define CERTITEM_H

#include <QAbstractListModel>
#include <QSharedDataPointer>

class QString;
class QStringList;

namespace QCA
{
	class PrivateKey;
	class CertificateChain;
	class KeyStoreEntry;
}

class CertItemStore;
class CertItemStorePrivate;
class CertItemPrivateLoaderPrivate;

class CertItem
{
public:
	enum StorageType
	{
		File,
		KeyStore
	};

	CertItem();
	CertItem(const CertItem &from);
	~CertItem();
	CertItem & operator=(const CertItem &from);

	QString name() const;
	QCA::CertificateChain certificateChain() const;
	bool havePrivate() const;
	StorageType storageType() const; // private key storage type
	bool isUsable() const; // file/provider present

private:
	class Private;
	QSharedDataPointer<Private> d;

	friend class CertItemStore;
	friend class CertItemStorePrivate;
	friend class CertItemPrivateLoader;
	friend class CertItemPrivateLoaderPrivate;
};

class CertItemStore : public QAbstractListModel
{
	Q_OBJECT
public:
	enum IconType
	{
		IconCert,
		IconCrl,
		IconKeyBundle,
		IconPgpPub,
		IconPgpSec
	};

	CertItemStore(QObject *parent = 0);
	~CertItemStore();

	int idFromRow(int row) const;
	int rowFromId(int id) const;
	CertItem itemFromId(int id) const;
	CertItem itemFromRow(int row) const;

	QList<CertItem> items() const;

	QStringList save() const;
	bool load(const QStringList &in);

	// returns a reqId
	int addFromFile(const QString &fileName);
	int addFromKeyStore(const QCA::KeyStoreEntry &entry);
	int addUser(const QCA::CertificateChain &chain);

	void updateChain(int id, const QCA::CertificateChain &chain);

	void removeItem(int id);

	void setIcon(IconType type, const QPixmap &icon);

	// reimplemented
	int rowCount(const QModelIndex &parent = QModelIndex()) const;
	QVariant data(const QModelIndex &index, int role) const;
	Qt::ItemFlags flags(const QModelIndex &index) const;
	bool setData(const QModelIndex &index, const QVariant &value, int role);

signals:
	void addSuccess(int reqId, int id);
	void addFailed(int reqId);

private:
	friend class CertItemStorePrivate;
	CertItemStorePrivate *d;

	friend class CertItemPrivateLoader;
	friend class CertItemPrivateLoaderPrivate;
};

class CertItemPrivateLoader : public QObject
{
	Q_OBJECT
public:
	explicit CertItemPrivateLoader(CertItemStore *store, QObject *parent = 0);
	~CertItemPrivateLoader();

	void start(int id);

	QCA::PrivateKey privateKey() const;

signals:
	void finished();

private:
	friend class CertItemPrivateLoaderPrivate;
	CertItemPrivateLoaderPrivate *d;
};

#endif
