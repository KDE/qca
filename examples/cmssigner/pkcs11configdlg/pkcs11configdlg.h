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

#ifndef PKCS11CONFIGDLG_H
#define PKCS11CONFIGDLG_H

#include <QDialog>
#include <QVariantMap>

// support for the 'http://affinix.com/qca/forms/qca-pkcs11#1.0' provider form

class Pkcs11ConfigDlg : public QDialog
{
public:
	Pkcs11ConfigDlg(QWidget *parent = 0);
	Pkcs11ConfigDlg(const QString &providerName, const QVariantMap &config, QWidget *parent = 0);
	~Pkcs11ConfigDlg();

	static bool isSupported();

protected slots:
	virtual void done(int r);

private:
	class Private;
	Private *d;
};

#endif
