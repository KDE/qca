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

#ifndef KEYSELECTDLG_H
#define KEYSELECTDLG_H

#include <QDialog>

class QPixmap;

namespace QCA
{
	class CertificateChain;
	class KeyStoreEntry;
}

class KeySelectDlg : public QDialog
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

	KeySelectDlg(QWidget *parent = 0);
	~KeySelectDlg();

	void setIcon(IconType type, const QPixmap &icon);

signals:
	void selected(const QCA::KeyStoreEntry &entry);
	void viewCertificate(const QCA::CertificateChain &chain);

protected slots:
	virtual void accept();

private:
	class Private;
	friend class Private;
	Private *d;
};

#endif
