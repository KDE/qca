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
	virtual void accept();

private:
	class Private;
	Private *d;
};

#endif
