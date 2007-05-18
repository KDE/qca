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

#include "pkcs11configdlg.h"

#include <QtCore>
#include <QtGui>
#include <QtCrypto>
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
		else
			return QVariant();
	}

	/*void addItem(const ModItem &i)
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

	void updateItem(int at)
	{
		QModelIndex i = index(at);
		emit dataChanged(i, i);
	}*/
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

	Private(Pkcs11ConfigDlg *_q, const QString &_providerName, const QVariantMap &configmap) :
		q(_q),
		providerName(_providerName)
	{
		ui.setupUi(q);
		q->resize(q->minimumSize());

		model = new ModuleListModel(q);
		ui.lv_modules->setModel(model);
		connect(ui.lv_modules->selectionModel(), SIGNAL(selectionChanged(const QItemSelection &, const QItemSelection &)), SLOT(modules_selectionChanged(const QItemSelection &, const QItemSelection &)));

		/*
#if defined(Q_OS_WIN)
		ui.lb_file->setText("Module File (.dll):");
#elif defined(Q_OS_MAC)
		ui.lb_file->setText("Module File (.dylib):");
#else
		ui.lb_file->setText("Module File (.so):");
#endif
		*/

		connect(ui.pb_add, SIGNAL(clicked()), SLOT(mod_add()));
		connect(ui.pb_remove, SIGNAL(clicked()), SLOT(mod_remove()));
		connect(ui.pb_browse, SIGNAL(clicked()), SLOT(mod_browse()));

		connect(ui.le_name, SIGNAL(textEdited(const QString &)), SLOT(name_edited(const QString &)));
		connect(ui.le_library, SIGNAL(textEdited(const QString &)), SLOT(library_edited(const QString &)));

		ui.pb_remove->setEnabled(false);
		ui.gb_details->setEnabled(false);

		// is this a valid config?
		if(!providerName.isEmpty() && config.fromVariantMap(configmap))
		{
			// if so, load everything up
			ui.ck_allowroot->setChecked(config.allow_load_rootca);
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

		/*for(int n = 0; n < 10; ++n)
		{
			ModItem i;
			QString prefix = QString().sprintf("provider_%02d_", n);
			i.name = config[prefix + "name"].toString();
			if(i.name.isEmpty())
				continue;
			i.library = config[prefix + "library"].toString();
			i.enabled = config[prefix + "enabled"].toBool();
			i.allow_protected_auth = config[prefix + "allow_protected_authentication"].toBool();
			i.cert_private = config[prefix + "cert_private"].toBool();
			i.private_mask = config[prefix + "private_mask"].toInt();
			i.slotevent_method = config[prefix + "slotevent_method"].toString();
			i.slotevent_timeout = config[prefix + "slotevent_method"].toInt();
			model->addItem(i);
		}*/

		if(!model->list.isEmpty())
			ui.lv_modules->selectionModel()->select(model->index(0), QItemSelectionModel::Clear | QItemSelectionModel::Select | QItemSelectionModel::Current);
	}

	void save()
	{
		/*for(int n = 0; n < 10 || n < model->list.count(); ++n)
		{
			ModItem i;
			if(n < model->list.count())
				i = model->list[n];
			else
				i = ModItem(); // default for padded items

			QString prefix = QString().sprintf("provider_%02d_", n);
			config[prefix + "name"] = i.name;
			config[prefix + "library"] = i.library;
			config[prefix + "enabled"] = i.enabled;
			config[prefix + "allow_protected_authentication"] = i.allow_protected_auth;
			config[prefix + "cert_private"] = i.cert_private;
			config[prefix + "private_mask"] = i.private_mask;
			config[prefix + "slotevent_method"] = i.slotevent_method;
			config[prefix + "slotevent_method"] = i.slotevent_timeout;
		}

		QCA::setProviderConfig(providerName, config);
		QCA::saveProviderConfig(providerName);*/
	}

private slots:
	void modules_selectionChanged(const QItemSelection &selected, const QItemSelection &deselected)
	{
		Q_UNUSED(deselected);

		if(!selected.indexes().isEmpty())
		{
			/*if(!ui.pb_remove->isEnabled())
			{
				ui.pb_remove->setEnabled(true);
				ui.gb_details->setEnabled(true);
			}

			QModelIndex index = selected.indexes().first();

			// TODO: ensure plaintext only
			ui.le_name->setText(model->list[index.row()].name);
			ui.le_library->setText(model->list[index.row()].library);*/
		}
		else if(selected.indexes().isEmpty() && ui.pb_remove->isEnabled())
		{
			/*ui.le_name->setText("");
			ui.le_library->setText("");

			ui.pb_remove->setEnabled(false);
			ui.gb_details->setEnabled(false);*/
		}
	}

	/*void name_edited(const QString &text)
	{
		QItemSelection selection = ui.lv_modules->selectionModel()->selection();
		if(selection.indexes().isEmpty())
			return;
		QModelIndex index = selection.indexes().first();
		int at = index.row();

		model->list[at].name = text;
		model->updateItem(at);
	}

	void library_edited(const QString &text)
	{
		QItemSelection selection = ui.lv_modules->selectionModel()->selection();
		if(selection.indexes().isEmpty())
			return;
		QModelIndex index = selection.indexes().first();
		int at = index.row();

		model->list[at].library = text;
	}

	void mod_add()
	{
		ModItem i;
		i.name = "New Module";
		i.enabled = true;
		model->addItem(i);

		ui.lv_modules->selectionModel()->select(model->index(model->list.count()-1), QItemSelectionModel::Clear | QItemSelectionModel::Select | QItemSelectionModel::Current);

		ui.le_name->setFocus();
		ui.le_name->selectAll();
	}

	void mod_remove()
	{
		QItemSelection selection = ui.lv_modules->selectionModel()->selection();
		if(selection.indexes().isEmpty())
			return;
		QModelIndex index = selection.indexes().first();
		model->removeItem(index.row());
	}*/

	void mod_browse()
	{
		QString spec;

		// FIXME: is this too restrictive?
#if defined(Q_OS_WIN)
		spec = "(*.dll)";
#elif defined(Q_OS_MAC)
		spec = "(*.dylib)";
#else
		spec = "(*.so)";
#endif

		QString fileName = QFileDialog::getOpenFileName(q, tr("Select PKCS#11 Module"), QString(), tr("PKCS#11 Modules") + ' ' + spec);
		if(fileName.isEmpty())
			return;

		ui.le_library->setText(fileName);
		//library_edited(fileName);
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

void Pkcs11ConfigDlg::accept()
{
	d->save();
	QDialog::accept();
}

bool Pkcs11ConfigDlg::isSupported()
{
	return (get_pkcs11_provider() ? true : false);
}

#include "pkcs11configdlg.moc"
