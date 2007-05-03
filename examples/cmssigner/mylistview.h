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
