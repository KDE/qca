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
