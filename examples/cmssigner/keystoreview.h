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

#ifndef KEYSTOREVIEW_H
#define KEYSTOREVIEW_H

#include <QTreeView>

//class QAbstractListModel;

class KeyStoreView : public QTreeView
{
	Q_OBJECT
public:
	KeyStoreView(QWidget *parent = 0) : QTreeView(parent) {}

	//QAbstractListModel *model;

/*protected:
	virtual void contextMenuEvent(QContextMenuEvent *event);*/
};

#endif
