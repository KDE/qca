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

#ifndef MYLISTVIEW_H
#define MYLISTVIEW_H

#include <QListView>

class QAbstractListModel;

class MyListView : public QListView
{
	Q_OBJECT
public:
	MyListView(QWidget *parent = 0);

	QAbstractListModel *model;

protected:
	virtual void contextMenuEvent(QContextMenuEvent *event);
};

#endif
