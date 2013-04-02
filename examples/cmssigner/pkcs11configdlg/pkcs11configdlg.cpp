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

#include "pkcs11configdlg.h"

#include <QtCore>
#include <QtGui>
#include <QtCrypto>
#include <QMessageBox>
#include <QFileDialog>
#include "ui_pkcs11config.h"

//----------------------------------------------------------------------------
// Pkcs11ProviderConfig
//----------------------------------------------------------------------------
class Pkcs11ProviderConfig
{
public:
	bool allow_protected_authentication;
	bool cert_private;
	bool enabled;
	QString library;
	QString name;
	int private_mask;
	QString slotevent_method;
	int slotevent_timeout;

	Pkcs11ProviderConfig() :
		allow_protected_authentication(true),
		cert_private(false),
		enabled(false),
		private_mask(0),
		slotevent_method("auto"),
		slotevent_timeout(0)
	{
	}

	QVariantMap toVariantMap() const
	{
		QVariantMap out;
		out["allow_protected_authentication"] = allow_protected_authentication;
		out["cert_private"] = cert_private;
		out["enabled"] = enabled;
		out["library"] = library;
		out["name"] = name;
		out["private_mask"] = private_mask;
		out["slotevent_method"] = slotevent_method;
		out["slotevent_timeout"] = slotevent_timeout;
		return out;
	}

	bool fromVariantMap(const QVariantMap &in)
	{
		allow_protected_authentication = in["allow_protected_authentication"].toBool();
		cert_private = in["cert_private"].toBool();
		enabled = in["enabled"].toBool();
		library = in["library"].toString();
		name = in["name"].toString();
		private_mask = in["private_mask"].toInt();
		slotevent_method = in["slotevent_method"].toString();
		slotevent_timeout = in["slotevent_timeout"].toInt();
		return true;
	}
};

//----------------------------------------------------------------------------
// Pkcs11Config
//----------------------------------------------------------------------------
class Pkcs11Config
{
public:
	bool allow_load_rootca;
	bool allow_protected_authentication;
	int log_level;
	int pin_cache;
	QList<Pkcs11ProviderConfig> providers;

	QVariantMap orig_config;

	Pkcs11Config() :
		allow_load_rootca(false),
		allow_protected_authentication(true),
		log_level(0),
		pin_cache(-1)
	{
	}

	QVariantMap toVariantMap() const
	{
		QVariantMap out = orig_config;

		// form type
		out["formtype"] = "http://affinix.com/qca/forms/qca-pkcs11#1.0";

		// base settings
		out["allow_load_rootca"] = allow_load_rootca;
		out["allow_protected_authentication"] = allow_protected_authentication;
		out["log_level"] = log_level;
		out["pin_cache"] = pin_cache;

		// provider settings (always write at least 10 providers)
		for(int n = 0; n < 10 || n < providers.count(); ++n)
		{
			QString prefix = QString().sprintf("provider_%02d_", n);

			Pkcs11ProviderConfig provider;
			if(n < providers.count())
				provider = providers[n];

			QVariantMap subconfig = provider.toVariantMap();
			QMapIterator<QString,QVariant> it(subconfig);
			while(it.hasNext())
			{
				it.next();
				out.insert(prefix + it.key(), it.value());
			}
		}

		return out;
	}

	bool fromVariantMap(const QVariantMap &in)
	{
		if(in["formtype"] != "http://affinix.com/qca/forms/qca-pkcs11#1.0")
			return false;

		allow_load_rootca = in["allow_load_rootca"].toBool();
		allow_protected_authentication = in["allow_protected_authentication"].toBool();
		log_level = in["log_level"].toInt();
		pin_cache = in["pin_cache"].toInt();

		for(int n = 0;; ++n)
		{
			QString prefix = QString().sprintf("provider_%02d_", n);

			// collect all key/values with this prefix into a
			//   a separate container, leaving out the prefix
			//   from the keys.
			QVariantMap subconfig;
			QMapIterator<QString,QVariant> it(in);
			while(it.hasNext())
			{
				it.next();
				if(it.key().startsWith(prefix))
					subconfig.insert(it.key().mid(prefix.length()), it.value());
			}

			// if there are no config items with this prefix, we're done
			if(subconfig.isEmpty())
				break;

			Pkcs11ProviderConfig provider;
			if(!provider.fromVariantMap(subconfig))
				return false;

			// skip unnamed entries
			if(provider.name.isEmpty())
				continue;

			// skip duplicate entries
			bool have_name_already = false;
			foreach(const Pkcs11ProviderConfig &i, providers)
			{
				if(i.name == provider.name)
				{
					have_name_already = true;
					break;
				}
			}
			if(have_name_already)
				continue;

			providers += provider;
		}

		orig_config = in;
		return true;
	}
};

//----------------------------------------------------------------------------
// ModuleListModel
//----------------------------------------------------------------------------
class ModuleListModel : public QAbstractListModel
{
	Q_OBJECT
public:
	QList<Pkcs11ProviderConfig> list;

	ModuleListModel(QObject *parent = 0) :
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

			if(str.isEmpty())
			{
				emit editFailed(index, tr("Module name cannot be blank."));
				return false;
			}

			bool have_name_already = false;
			int at = index.row();
			for(int n = 0; n < list.count(); ++n)
			{
				const Pkcs11ProviderConfig &i = list[n];

				// skip self
				if(n == at)
					continue;

				if(i.name == str)
				{
					have_name_already = true;
					break;
				}
			}
			if(have_name_already)
			{
				emit editFailed(index, tr("There is already a module with this name."));
				return false;
			}

			list[index.row()].name = str;
			emit dataChanged(index, index);
			return true;
		}
		return false;
	}

	void addItems(const QList<Pkcs11ProviderConfig> &items)
	{
		if(items.isEmpty())
			return;

		beginInsertRows(QModelIndex(), list.size(), list.size() + items.count() - 1);
		list += items;
		endInsertRows();
	}

	void addItem(const Pkcs11ProviderConfig &i)
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

signals:
	void editFailed(const QModelIndex &index, const QString &reasonString);
};

//----------------------------------------------------------------------------
// Pkcs11ConfigDlg
//----------------------------------------------------------------------------
static QCA::Provider *get_pkcs11_provider(QVariantMap *_config = 0)
{
	QCA::ProviderList providers = QCA::providers();
	providers += QCA::defaultProvider();

	QCA::Provider *provider = 0;
	QVariantMap config;
	foreach(QCA::Provider *p, providers)
	{
		config = QCA::getProviderConfig(p->name());
		if(!config.isEmpty() && config["formtype"] == "http://affinix.com/qca/forms/qca-pkcs11#1.0")
		{
			provider = p;
			break;
		}
	}

	if(provider && _config)
		*_config = config;

	return provider;
}

class Pkcs11ConfigDlg::Private : public QObject
{
	Q_OBJECT
public:
	Pkcs11ConfigDlg *q;
	Ui_Pkcs11Config ui;
	QString providerName;
	ModuleListModel *model;
	Pkcs11Config config;
	bool dirty;

	// for safe dialog closing behavior during QListView editing
	bool allow_close;
	bool done;

	// for ignoring modifications that we cause when populating fields
	bool ignore_dataChanged;

	Private(Pkcs11ConfigDlg *_q, const QString &_providerName, const QVariantMap &configmap) :
		QObject(_q),
		q(_q),
		providerName(_providerName),
		dirty(false),
		allow_close(true),
		done(false),
		ignore_dataChanged(true)
	{
		ui.setupUi(q);
		q->resize(q->minimumSize());

		model = new ModuleListModel(this);
		qRegisterMetaType<QModelIndex>("QModelIndex");
		// do this queued for two reasons:
		//   1) if we throw an error dialog, it will occur after the
		//      row text has reverted, and the call stack completed
		//      (the latter may not be required, but it helps me
		//      sleep).
		//   2) if the user accepts/rejects the dialog while editing,
		//      it is easy to ensure that the signal is not processed
		//	(if it gets delivered at all).
		connect(model,
			SIGNAL(editFailed(const QModelIndex &, const QString &)),
			SLOT(model_editFailed(const QModelIndex &, const QString &)),
			Qt::QueuedConnection);

		// set up widgets
		ui.rb_pincache_nolimit->setChecked(true);
		ui.sb_pincache_time->setEnabled(false);
		ui.sb_pincache_time->setValue(300);
		ui.lv_modules->setModel(model);
		ui.lv_modules->setEditTriggers(QAbstractItemView::DoubleClicked | QAbstractItemView::SelectedClicked | QAbstractItemView::EditKeyPressed);
		ui.pb_remove->setEnabled(false);
		ui.tb_details->setEnabled(false);
		ui.gb_poll->setEnabled(false);
		ui.rb_polldefault->setChecked(true);
		ui.sb_pollcustom->setEnabled(false);
		ui.sb_pollcustom->setValue(5);
		ui.ck_modeauto->setChecked(true);

		// disable this by default, enable on dataChanged
		ui.buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);

		// general
		connect(ui.ck_allowroot, SIGNAL(toggled(bool)), SLOT(dataChanged()));
		connect(ui.ck_allowprotected, SIGNAL(toggled(bool)), SLOT(dataChanged()));
		connect(ui.sb_loglevel, SIGNAL(valueChanged(int)), SLOT(dataChanged()));
		connect(ui.gb_pincache, SIGNAL(toggled(bool)), SLOT(dataChanged()));
		connect(ui.rb_pincache_nolimit, SIGNAL(toggled(bool)), SLOT(dataChanged()));
		connect(ui.rb_pincache_time, SIGNAL(toggled(bool)), ui.sb_pincache_time, SLOT(setEnabled(bool)));
		connect(ui.rb_pincache_time, SIGNAL(toggled(bool)), SLOT(dataChanged()));
		connect(ui.sb_pincache_time, SIGNAL(valueChanged(int)), SLOT(dataChanged()));

		// modules
		connect(model, SIGNAL(dataChanged(const QModelIndex &, const QModelIndex &)), SLOT(dataChanged()));
		connect(ui.lv_modules->selectionModel(), SIGNAL(selectionChanged(const QItemSelection &, const QItemSelection &)), SLOT(module_selectionChanged(const QItemSelection &, const QItemSelection &)));
		connect(ui.pb_add, SIGNAL(clicked()), SLOT(module_add()));
		connect(ui.pb_remove, SIGNAL(clicked()), SLOT(module_remove()));
		connect(ui.le_library, SIGNAL(textChanged(const QString &)), SLOT(dataChanged()));
		connect(ui.pb_browse, SIGNAL(clicked()), SLOT(library_browse()));
		connect(ui.cb_slotmethod, SIGNAL(currentIndexChanged(int)), SLOT(slotmethod_currentIndexChanged(int)));
		connect(ui.rb_polldefault, SIGNAL(toggled(bool)), SLOT(dataChanged()));
		connect(ui.rb_pollcustom, SIGNAL(toggled(bool)), ui.sb_pollcustom, SLOT(setEnabled(bool)));
		connect(ui.rb_pollcustom, SIGNAL(toggled(bool)), SLOT(dataChanged()));
		connect(ui.sb_pollcustom, SIGNAL(valueChanged(int)), SLOT(dataChanged()));
		connect(ui.ck_modallowprotected, SIGNAL(toggled(bool)), SLOT(dataChanged()));
		connect(ui.ck_certprivate, SIGNAL(toggled(bool)), SLOT(dataChanged()));
		connect(ui.ck_modeauto, SIGNAL(toggled(bool)), SLOT(modeauto_toggled(bool)));
		connect(ui.ck_modesign, SIGNAL(toggled(bool)), SLOT(modenonauto_toggled(bool)));
		connect(ui.ck_modesignrecover, SIGNAL(toggled(bool)), SLOT(modenonauto_toggled(bool)));
		connect(ui.ck_modedecrypt, SIGNAL(toggled(bool)), SLOT(modenonauto_toggled(bool)));
		connect(ui.ck_modeunwrap, SIGNAL(toggled(bool)), SLOT(modenonauto_toggled(bool)));

		// is this a valid config?
		if(!providerName.isEmpty() && config.fromVariantMap(configmap))
		{
			// if so, load everything up
			ui.ck_allowroot->setChecked(config.allow_load_rootca);
			ui.ck_allowprotected->setChecked(config.allow_protected_authentication);
			ui.sb_loglevel->setValue(config.log_level);
			if(config.pin_cache != 0)
			{
				ui.gb_pincache->setChecked(true);
				if(config.pin_cache <= -1)
					ui.rb_pincache_nolimit->setChecked(true);
				else
				{
					ui.rb_pincache_time->setChecked(true);
					ui.sb_pincache_time->setValue(config.pin_cache);
				}
			}

			model->addItems(config.providers);
			if(!model->list.isEmpty())
			{
				QModelIndex index = model->index(0);
				ui.lv_modules->setCurrentIndex(index);
				ui.lv_modules->selectionModel()->select(index, QItemSelectionModel::Clear | QItemSelectionModel::Select | QItemSelectionModel::Current);
			}
			ui.buttonBox->setFocus();
			ui.buttonBox->button(QDialogButtonBox::Cancel)->setFocus();
		}
		else
		{
			// otherwise, disable everything
			ui.gb_general->setEnabled(false);
			ui.gb_modules->setEnabled(false);
			ui.buttonBox->setFocus();
			ui.buttonBox->button(QDialogButtonBox::Cancel)->setFocus();
		}

		ignore_dataChanged = false;
	}

	void save_module(int at)
	{
		// save all options (except the name, which is handled by the model)
		Pkcs11ProviderConfig &i = model->list[at];

		i.library = ui.le_library->text();
		i.enabled = true;

		int x = ui.cb_slotmethod->currentIndex();
		if(x == 0)
			i.slotevent_method = "auto";
		else if(x == 1)
			i.slotevent_method = "trigger";
		else // 2
			i.slotevent_method = "poll";
		if(x == 2)
		{
			if(ui.rb_polldefault->isChecked())
				i.slotevent_timeout = 0;
			else
				i.slotevent_timeout = ui.sb_pollcustom->value();
		}
		else
			i.slotevent_timeout = 0;

		i.allow_protected_authentication = ui.ck_modallowprotected->isChecked();
		i.cert_private = ui.ck_certprivate->isChecked();

		i.private_mask = 0;
		if(ui.ck_modesign->isChecked())
			i.private_mask |= 1;
		if(ui.ck_modesignrecover->isChecked())
			i.private_mask |= 2;
		if(ui.ck_modedecrypt->isChecked())
			i.private_mask |= 4;
		if(ui.ck_modeunwrap->isChecked())
			i.private_mask |= 8;
	}

	void save()
	{
		// save currently selected module, which may not be saved yet
		QItemSelection selection = ui.lv_modules->selectionModel()->selection();
		if(!selection.indexes().isEmpty())
		{
			QModelIndex index = selection.indexes().first();
			save_module(index.row());
		}

		config.allow_load_rootca = ui.ck_allowroot->isChecked();
		config.allow_protected_authentication = ui.ck_allowprotected->isChecked();
		config.log_level = ui.sb_loglevel->value();
		if(ui.gb_pincache->isChecked())
		{
			if(ui.rb_pincache_nolimit->isChecked())
				config.pin_cache = -1;
			else
				config.pin_cache = ui.sb_pincache_time->value();
		}
		else
			config.pin_cache = 0;

		config.providers = model->list;

		QVariantMap configmap = config.toVariantMap();
		QCA::setProviderConfig(providerName, configmap);
		QCA::saveProviderConfig(providerName);
	}

private slots:
	void model_editFailed(const QModelIndex &index, const QString &reasonString)
	{
		// if the dialog has already been dismissed, then don't
		//   bother with handling the editing failure
		if(done)
			return;

		// show error dialog, and don't allow dimissing the dialog
		//   during.  we need this, because the the dismiss request
		//   can be queued, and end up being invoked during the
		//   QMessageBox nested eventloop.
		allow_close = false;
		QMessageBox::information(q, tr("Module Configuration"), reasonString);
		allow_close = true;

		// return to edit mode for the item
		ui.lv_modules->setFocus();
		ui.lv_modules->setCurrentIndex(index);
		ui.lv_modules->selectionModel()->select(index, QItemSelectionModel::Clear | QItemSelectionModel::Select | QItemSelectionModel::Current);
		ui.lv_modules->edit(index);
	}

	void dataChanged()
	{
		if(ignore_dataChanged)
			return;

		if(dirty)
			return;

		dirty = true;
		ui.buttonBox->button(QDialogButtonBox::Ok)->setEnabled(true);
	}

	void module_selectionChanged(const QItemSelection &selected, const QItemSelection &deselected)
	{
		if(!deselected.indexes().isEmpty())
		{
			QModelIndex index = deselected.indexes().first();
			save_module(index.row());
		}

		ignore_dataChanged = true;

		if(!selected.indexes().isEmpty())
		{
			if(deselected.indexes().isEmpty())
			{
				ui.pb_remove->setEnabled(true);
				ui.tb_details->setEnabled(true);
			}

			QModelIndex index = selected.indexes().first();
			const Pkcs11ProviderConfig &i = model->list[index.row()];

			ui.le_library->setText(i.library);

			if(i.slotevent_method == "trigger")
				ui.cb_slotmethod->setCurrentIndex(1);
			else if(i.slotevent_method == "poll")
			{
				ui.cb_slotmethod->setCurrentIndex(2);
				if(i.slotevent_timeout <= 0)
					ui.rb_polldefault->setChecked(true);
				else
				{
					ui.rb_pollcustom->setChecked(true);
					ui.sb_pollcustom->setValue(i.slotevent_timeout);
				}
			}
			else // auto
				ui.cb_slotmethod->setCurrentIndex(0);
			if(i.slotevent_method != "poll")
			{
				ui.rb_polldefault->setChecked(true);
				ui.sb_pollcustom->setValue(5);
			}

			ui.ck_modallowprotected->setChecked(i.allow_protected_authentication);
			ui.ck_certprivate->setChecked(i.cert_private);

			if(i.private_mask == 0)
				ui.ck_modeauto->setChecked(true);
			else
			{
				ui.ck_modesign->setChecked(i.private_mask & 1);
				ui.ck_modesignrecover->setChecked(i.private_mask & 2);
				ui.ck_modedecrypt->setChecked(i.private_mask & 4);
				ui.ck_modeunwrap->setChecked(i.private_mask & 8);
			}
		}
		else if(selected.indexes().isEmpty() && !deselected.indexes().isEmpty())
		{
			// restore defaults for all details widgets
			ui.le_library->setText(QString());
			ui.cb_slotmethod->setCurrentIndex(0);
			ui.rb_polldefault->setChecked(true);
			ui.sb_pollcustom->setValue(5);
			ui.ck_modallowprotected->setChecked(false);
			ui.ck_certprivate->setChecked(false);
			ui.ck_modeauto->setChecked(true);

			// flip to first page, disable
			ui.tb_details->setCurrentIndex(0);
			ui.pb_remove->setEnabled(false);
			ui.tb_details->setEnabled(false);
		}

		ignore_dataChanged = false;
	}

	void module_add()
	{
		// find unused default name
		QString name;
		for(int n = 1;; ++n)
		{
			if(n == 1)
				name = tr("New Module");
			else
				name = tr("New Module (%1)").arg(n);

			bool have_name_already = false;
			for(int n = 0; n < model->list.count(); ++n)
			{
				const Pkcs11ProviderConfig &i = model->list[n];
				if(i.name == name)
				{
					have_name_already = true;
					break;
				}
			}
			if(!have_name_already)
				break;
		}

		Pkcs11ProviderConfig i;
		i.name = name;
		i.enabled = true;
		model->addItem(i);

		dataChanged();

		QModelIndex index = model->index(model->list.count() - 1);

		// flip to first page
		ui.tb_details->setCurrentIndex(0);

		// edit this item
		ui.lv_modules->setFocus();
		ui.lv_modules->setCurrentIndex(index);
		ui.lv_modules->selectionModel()->select(index, QItemSelectionModel::Clear | QItemSelectionModel::Select | QItemSelectionModel::Current);
		ui.lv_modules->edit(index);
	}

	void module_remove()
	{
		QItemSelection selection = ui.lv_modules->selectionModel()->selection();
		if(selection.indexes().isEmpty())
			return;
		QModelIndex index = selection.indexes().first();
		model->removeItem(index.row());

		dataChanged();
	}

	void library_browse()
	{
		QString fileName = QFileDialog::getOpenFileName(q, tr("Select PKCS#11 Module"), QString(), tr("PKCS#11 Modules (*.*)"));
		if(fileName.isEmpty())
			return;

		ui.le_library->setText(fileName);
	}

	void slotmethod_currentIndexChanged(int index)
	{
		if(index == 2) // Polling
			ui.gb_poll->setEnabled(true);
		else
			ui.gb_poll->setEnabled(false);

		dataChanged();
	}

	void modeauto_toggled(bool checked)
	{
		if(checked)
		{
			if(ui.ck_modesign->isChecked())
				ui.ck_modesign->setChecked(false);
			if(ui.ck_modesignrecover->isChecked())
				ui.ck_modesignrecover->setChecked(false);
			if(ui.ck_modedecrypt->isChecked())
				ui.ck_modedecrypt->setChecked(false);
			if(ui.ck_modeunwrap->isChecked())
				ui.ck_modeunwrap->setChecked(false);
		}
		else
		{
			if(!ui.ck_modesign->isChecked()
				&& !ui.ck_modesignrecover->isChecked()
				&& !ui.ck_modedecrypt->isChecked()
				&& !ui.ck_modeunwrap->isChecked())
			{
				ui.ck_modesign->setChecked(true);
				ui.ck_modesignrecover->setChecked(true);
				ui.ck_modedecrypt->setChecked(true);
				ui.ck_modeunwrap->setChecked(true);
			}
		}

		dataChanged();
	}

	void modenonauto_toggled(bool checked)
	{
		if(checked)
		{
			if(ui.ck_modeauto->isChecked())
				ui.ck_modeauto->setChecked(false);
		}
		else
		{
			if(!ui.ck_modesign->isChecked()
				&& !ui.ck_modesignrecover->isChecked()
				&& !ui.ck_modedecrypt->isChecked()
				&& !ui.ck_modeunwrap->isChecked())
			{
				ui.ck_modeauto->setChecked(true);
			}
		}

		dataChanged();
	}
};

Pkcs11ConfigDlg::Pkcs11ConfigDlg(QWidget *parent) :
	QDialog(parent)
{
	QVariantMap config;
	QCA::Provider *p = get_pkcs11_provider(&config);
	if(p)
		d = new Private(this, p->name(), config);
	else
		d = new Private(this, QString(), QVariantMap());
}

Pkcs11ConfigDlg::Pkcs11ConfigDlg(const QString &providerName, const QVariantMap &config, QWidget *parent) :
	QDialog(parent)
{
	d = new Private(this, providerName, config);
}

Pkcs11ConfigDlg::~Pkcs11ConfigDlg()
{
	delete d;
}

void Pkcs11ConfigDlg::done(int r)
{
	if(!d->allow_close)
		return;

	d->done = true;
	if(r == Accepted)
		d->save();
	QDialog::done(r);
}

bool Pkcs11ConfigDlg::isSupported()
{
	return (get_pkcs11_provider() ? true : false);
}

#include "pkcs11configdlg.moc"
