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

#include <QtCore>
#include <QtGui>
#include <QtCrypto>

#include "ui_mainwin.h"
#include "prompter.h"
#include "certviewdlg.h"
#include "keyselectdlg.h"
#include "pkcs11configdlg/pkcs11configdlg.h"
#include "certitem.h"

#define VERSION "0.0.1"

class Icons
{
public:
	QPixmap cert, crl, keybundle, pgppub, pgpsec;
};

Icons *g_icons = 0;

//----------------------------------------------------------------------------
// Operation
//----------------------------------------------------------------------------
class Operation : public QObject
{
	Q_OBJECT
public:
	Operation(QObject *parent = 0) :
		QObject(parent)
	{
	}

signals:
	void error(const QString &str);
};

static QString validityToString(QCA::Validity v)
{
	QString s;
	switch(v)
	{
		case QCA::ValidityGood:
			s = Operation::tr("Validated");
			break;
		case QCA::ErrorRejected:
			s = Operation::tr("Root CA is marked to reject the specified purpose");
			break;
		case QCA::ErrorUntrusted:
			s = Operation::tr("Certificate not trusted for the required purpose");
			break;
		case QCA::ErrorSignatureFailed:
			s = Operation::tr("Invalid signature");
			break;
		case QCA::ErrorInvalidCA:
			s = Operation::tr("Invalid CA certificate");
			break;
		case QCA::ErrorInvalidPurpose:
			s = Operation::tr("Invalid certificate purpose");
			break;
		case QCA::ErrorSelfSigned:
			s = Operation::tr("Certificate is self-signed");
			break;
		case QCA::ErrorRevoked:
			s = Operation::tr("Certificate has been revoked");
			break;
		case QCA::ErrorPathLengthExceeded:
			s = Operation::tr("Maximum certificate chain length exceeded");
			break;
		case QCA::ErrorExpired:
			s = Operation::tr("Certificate has expired");
			break;
		case QCA::ErrorExpiredCA:
			s = Operation::tr("CA has expired");
			break;
		case QCA::ErrorValidityUnknown:
		default:
			s = Operation::tr("General certificate validation error");
			break;
	}
	return s;
}

static QString smErrorToString(QCA::SecureMessage::Error e)
{
	QMap<QCA::SecureMessage::Error,QString> map;
	map[QCA::SecureMessage::ErrorPassphrase] = Operation::tr("Invalid passphrase");
	map[QCA::SecureMessage::ErrorFormat] = Operation::tr("Bad input format");
	map[QCA::SecureMessage::ErrorSignerExpired] = Operation::tr("Signer key is expired");
	map[QCA::SecureMessage::ErrorSignerInvalid] = Operation::tr("Signer key is invalid");
	map[QCA::SecureMessage::ErrorEncryptExpired] = Operation::tr("Encrypting key is expired");
	map[QCA::SecureMessage::ErrorEncryptUntrusted] = Operation::tr("Encrypting key is untrusted");
	map[QCA::SecureMessage::ErrorEncryptInvalid] = Operation::tr("Encrypting key is invalid");
	map[QCA::SecureMessage::ErrorNeedCard] = Operation::tr("Card was needed but not found");
	map[QCA::SecureMessage::ErrorCertKeyMismatch] = Operation::tr("Certificate and private key don't match");
	map[QCA::SecureMessage::ErrorUnknown] = Operation::tr("General error");
	return map[e];
}

class SignOperation : public Operation
{
	Q_OBJECT
private:
	QByteArray in;
	CertItem item;
	QCA::CMS *cms;
	CertItemPrivateLoader *loader;
	QCA::KeyBundle key;
	QCA::SecureMessage *msg;

public:
	SignOperation(const QByteArray &_in, const CertItem &_item, CertItemStore *store, int id, QCA::CMS *_cms, QObject *parent = 0) :
		Operation(parent),
		in(_in),
		item(_item),
		cms(_cms),
		msg(0)
	{
		loader = new CertItemPrivateLoader(store, this);
		connect(loader, SIGNAL(finished()), SLOT(loader_finished()));
		loader->start(id);
	}

	~SignOperation()
	{
		delete loader;
	}

signals:
	void finished(const QString &sig);

private slots:
	void loader_finished()
	{
		QCA::PrivateKey privateKey = loader->privateKey();
		if(privateKey.isNull())
		{
			emit error(tr("Error loading key for use."));
			return;
		}

		delete loader;
		loader = 0;

		key = QCA::KeyBundle();
		key.setCertificateChainAndKey(item.certificateChain(), privateKey);

		do_sign();
	}

	void do_sign()
	{
		//printf("do_sign\n");

		QCA::SecureMessageKey signer;
		signer.setX509CertificateChain(key.certificateChain());
		signer.setX509PrivateKey(key.privateKey());

		msg = new QCA::SecureMessage(cms);
		connect(msg, SIGNAL(finished()), SLOT(msg_finished()));
		msg->setFormat(QCA::SecureMessage::Ascii);
		msg->setSigner(signer);
		msg->startSign(QCA::SecureMessage::Detached);
		update();
	}

	void update()
	{
		//printf("update\n");

		QByteArray buf = in.mid(0, 16384); // 16k chunks
		in = in.mid(buf.size());
		msg->update(buf);

		if(in.isEmpty())
			msg->end();
		else
			QMetaObject::invokeMethod(this, "update", Qt::QueuedConnection);
	}

	void msg_finished()
	{
		//printf("msg_finished\n");

		if(!msg->success())
		{
			QString str = smErrorToString(msg->errorCode());
			delete msg;
			msg = 0;
			emit error(tr("Error during sign operation.\nReason: %1").arg(str));
			return;
		}

		QByteArray result = msg->signature();
		delete msg;
		msg = 0;

		emit finished(QString::fromLatin1(result));
	}
};

class VerifyOperation : public Operation
{
	Q_OBJECT
private:
	QByteArray in, sig;
	QCA::CMS *cms;
	QCA::SecureMessage *msg;

public:
	VerifyOperation(const QByteArray &_in, const QByteArray &_sig, QCA::CMS *_cms, QObject *parent = 0) :
		Operation(parent),
		in(_in),
		sig(_sig),
		cms(_cms),
		msg(0)
	{
		//printf("do_verify\n");

		msg = new QCA::SecureMessage(cms);
		connect(msg, SIGNAL(finished()), SLOT(msg_finished()));
		msg->setFormat(QCA::SecureMessage::Ascii);
		msg->startVerify(sig);
		QMetaObject::invokeMethod(this, "update", Qt::QueuedConnection);
	}

signals:
	void finished();

private slots:
	void update()
	{
		//printf("update\n");

		QByteArray buf = in.mid(0, 16384); // 16k chunks
		in = in.mid(buf.size());
		msg->update(buf);

		if(in.isEmpty())
			msg->end();
		else
			QMetaObject::invokeMethod(this, "update", Qt::QueuedConnection);
	}

	void msg_finished()
	{
		//printf("msg_finished\n");

		if(!msg->success())
		{
			QString str = smErrorToString(msg->errorCode());
			delete msg;
			msg = 0;
			emit error(tr("Error during verify operation.\nReason: %1").arg(str));
			return;
		}

		QCA::SecureMessageSignature signer = msg->signer();
		QCA::SecureMessageSignature::IdentityResult r = signer.identityResult();
		delete msg;
		msg = 0;

		if(r != QCA::SecureMessageSignature::Valid)
		{
			QString str;
			if(r == QCA::SecureMessageSignature::InvalidSignature)
				str = tr("Invalid signature");
			else if(r == QCA::SecureMessageSignature::InvalidKey)
				str = tr("Invalid key: %1").arg(validityToString(signer.keyValidity()));
			else if(r == QCA::SecureMessageSignature::NoKey)
				str = tr("Key not found");
			else // unknown
				str = tr("Unknown");

			emit error(tr("Verification failed!\nReason: %1").arg(str));
			return;
		}

		emit finished();
	}
};

class MainWin : public QMainWindow
{
	Q_OBJECT
private:
	Ui_MainWin ui;
	CertItemStore *users, *roots;
	QCA::CMS *cms;
	Operation *op;
	QAction *actionView, *actionRename, *actionRemove;

public:
	MainWin(QWidget *parent = 0) :
		QMainWindow(parent),
		op(0)
	{
		ui.setupUi(this);

		g_icons = new Icons;
		g_icons->cert = QPixmap(":/gfx/icons/cert16.png");
		g_icons->crl = QPixmap(":/gfx/icons/crl16.png");
		g_icons->keybundle = QPixmap(":/gfx/icons/keybundle16.png");
		g_icons->pgppub = QPixmap(":/gfx/icons/publickey16.png");
		g_icons->pgpsec = QPixmap(":/gfx/icons/keypair16.png");
		if(g_icons->cert.isNull() || g_icons->crl.isNull() || g_icons->keybundle.isNull() || g_icons->pgppub.isNull() || g_icons->pgpsec.isNull())
			printf("Warning: not all icons loaded\n");

		users = new CertItemStore(this);
		roots = new CertItemStore(this);

		setIcons(users);
		setIcons(roots);

		connect(users, SIGNAL(addSuccess(int, int)), SLOT(users_addSuccess(int, int)));
		connect(users, SIGNAL(addFailed(int)), SLOT(users_addFailed(int)));

		actionView = new QAction(tr("&View"), this);
		actionRename = new QAction(tr("Re&name"), this);
		actionRemove = new QAction(tr("Rem&ove"), this);

		// TODO
		//actionView->setEnabled(false);

		connect(ui.actionLoadIdentityFile, SIGNAL(triggered()), SLOT(load_file()));
		connect(ui.actionLoadIdentityEntry, SIGNAL(triggered()), SLOT(load_device()));
		connect(ui.actionLoadAuthority, SIGNAL(triggered()), SLOT(load_root()));
		connect(ui.actionConfigurePkcs11, SIGNAL(triggered()), SLOT(mod_config()));
		connect(ui.actionQuit, SIGNAL(triggered()), SLOT(close()));
		connect(ui.actionAbout, SIGNAL(triggered()), SLOT(about()));
		connect(ui.pb_sign, SIGNAL(clicked()), SLOT(do_sign()));
		connect(ui.pb_verify, SIGNAL(clicked()), SLOT(do_verify()));

		connect(actionView, SIGNAL(triggered()), SLOT(item_view()));
		connect(actionRename, SIGNAL(triggered()), SLOT(item_rename()));
		connect(actionRemove, SIGNAL(triggered()), SLOT(item_remove()));

		ui.pb_sign->setEnabled(false);

		ui.lv_users->setModel(users);
		connect(ui.lv_users->selectionModel(), SIGNAL(selectionChanged(const QItemSelection &, const QItemSelection &)), SLOT(users_selectionChanged(const QItemSelection &, const QItemSelection &)));

		ui.lv_users->setContextMenuPolicy(Qt::CustomContextMenu);
		connect(ui.lv_users, SIGNAL(customContextMenuRequested(const QPoint &)), SLOT(users_customContextMenuRequested(const QPoint &)));

		ui.lv_authorities->setModel(roots);

		cms = new QCA::CMS(this);

		QStringList ulist, rlist;
		{
			QSettings settings("Affinix", "CMS Signer");
			ulist = settings.value("users").toStringList();
			rlist = settings.value("roots").toStringList();
		}

		users->load(ulist);
		roots->load(rlist);
	}

	~MainWin()
	{
		QStringList ulist = users->save();
		QStringList rlist = roots->save();

		QSettings settings("Affinix", "CMS Signer");
		settings.setValue("users", ulist);
		settings.setValue("roots", rlist);

		delete g_icons;
		g_icons = 0;
	}

	void setIcons(CertItemStore *store)
	{
		store->setIcon(CertItemStore::IconCert, g_icons->cert);
		store->setIcon(CertItemStore::IconCrl, g_icons->crl);
		store->setIcon(CertItemStore::IconKeyBundle, g_icons->keybundle);
		store->setIcon(CertItemStore::IconPgpPub, g_icons->pgppub);
		store->setIcon(CertItemStore::IconPgpSec, g_icons->pgpsec);
	}

private slots:
	void load_file()
	{
		QString fileName = QFileDialog::getOpenFileName(this, tr("Open File"), QString(), tr("X.509 Identities (*.p12 *.pfx)"));
		if(fileName.isEmpty())
			return;

		setEnabled(false);

		users->addFromFile(fileName);
	}

	void load_device()
	{
		KeySelectDlg *w = new KeySelectDlg(this);
		w->setAttribute(Qt::WA_DeleteOnClose, true);
		w->setWindowModality(Qt::WindowModal);
		connect(w, SIGNAL(selected(const QCA::KeyStoreEntry &)), SLOT(load_device_finished(const QCA::KeyStoreEntry &)));
		connect(w, SIGNAL(viewCertificate(const QCA::CertificateChain &)), SLOT(keyselect_viewCertificate(const QCA::CertificateChain &)));
		w->setIcon(KeySelectDlg::IconCert, g_icons->cert);
		w->setIcon(KeySelectDlg::IconCrl, g_icons->crl);
		w->setIcon(KeySelectDlg::IconKeyBundle, g_icons->keybundle);
		w->setIcon(KeySelectDlg::IconPgpPub, g_icons->pgppub);
		w->setIcon(KeySelectDlg::IconPgpSec, g_icons->pgpsec);
		w->show();
	}

	void load_root()
	{
		QString fileName = QFileDialog::getOpenFileName(this, tr("Open File"), QString(), tr("X.509 Certificates (*.pem *.crt)"));
		if(fileName.isEmpty())
			return;

		QCA::Certificate cert = QCA::Certificate::fromPEMFile(fileName);
		if(cert.isNull())
		{
			QMessageBox::information(this, tr("Error"), tr("Error opening certificate file."));
			return;
		}

		roots->addUser(cert);
	}

	void users_addSuccess(int req_id, int id)
	{
		Q_UNUSED(req_id);
		Q_UNUSED(id);

		ui.lv_users->selectionModel()->select(users->index(users->rowCount()-1), QItemSelectionModel::Clear | QItemSelectionModel::Select | QItemSelectionModel::Current);

		setEnabled(true);
	}

	void users_addFailed(int req_id)
	{
		Q_UNUSED(req_id);

		setEnabled(true);
	}

	void mod_config()
	{
		if(!Pkcs11ConfigDlg::isSupported())
		{
			QMessageBox::information(this, tr("Error"), tr("No provider available supporting standard PKCS#11 configuration."));
			return;
		}

		Pkcs11ConfigDlg *w = new Pkcs11ConfigDlg(this);
		w->setAttribute(Qt::WA_DeleteOnClose, true);
		w->setWindowModality(Qt::WindowModal);
		w->show();
	}

	void users_selectionChanged(const QItemSelection &selected, const QItemSelection &deselected)
	{
		Q_UNUSED(deselected);

		int at = -1;
		if(!selected.indexes().isEmpty())
		{
			QModelIndex index = selected.indexes().first();
			at = index.row();
		}

		if(at != -1 && users->itemFromRow(at).isUsable() && !ui.pb_sign->isEnabled())
			ui.pb_sign->setEnabled(true);
		else if(ui.pb_sign->isEnabled())
			ui.pb_sign->setEnabled(false);
	}

	void item_view()
	{
		if(ui.lv_users->hasFocus())
		{
			QItemSelection selection = ui.lv_users->selectionModel()->selection();
			if(selection.indexes().isEmpty())
				return;
			QModelIndex index = selection.indexes().first();
			users_view(index.row());
		}
		/*else // lv_authorities
		{
			QItemSelection selection = ui.lv_known->selectionModel()->selection();
			if(selection.indexes().isEmpty())
				return;
			QModelIndex index = selection.indexes().first();
			known_view(index.row());
		}*/
	}

	void item_rename()
	{
		if(ui.lv_users->hasFocus())
		{
			QItemSelection selection = ui.lv_users->selectionModel()->selection();
			if(selection.indexes().isEmpty())
				return;
			QModelIndex index = selection.indexes().first();
			users_rename(index.row());
		}
		else // lv_authorities
		{
			QItemSelection selection = ui.lv_authorities->selectionModel()->selection();
			if(selection.indexes().isEmpty())
				return;
			QModelIndex index = selection.indexes().first();
			roots_rename(index.row());
		}
	}

	void item_remove()
	{
		if(ui.lv_users->hasFocus())
		{
			QItemSelection selection = ui.lv_users->selectionModel()->selection();
			if(selection.indexes().isEmpty())
				return;
			QModelIndex index = selection.indexes().first();
			users_remove(index.row());
		}
		else // lv_authorities
		{
			QItemSelection selection = ui.lv_authorities->selectionModel()->selection();
			if(selection.indexes().isEmpty())
				return;
			QModelIndex index = selection.indexes().first();
			roots_remove(index.row());
		}
	}

	/*void identity_view(int at)
	{
		printf("identity_view: %d\n", at);
	}*/

	void users_view(int at)
	{
		CertItem i = users->itemFromRow(at);
		CertViewDlg *w = new CertViewDlg(i.certificateChain(), this);
		w->setAttribute(Qt::WA_DeleteOnClose, true);
		w->show();
	}

	void users_rename(int at)
	{
		QModelIndex index = users->index(at);
		ui.lv_users->setFocus();
		ui.lv_users->setCurrentIndex(index);
		ui.lv_users->selectionModel()->select(index, QItemSelectionModel::Clear | QItemSelectionModel::Select | QItemSelectionModel::Current);
		ui.lv_users->edit(index);
	}

	void users_remove(int at)
	{
		users->removeItem(users->idFromRow(at));
	}

	/*void known_view(int at)
	{
		printf("known_view: %d\n", at);
	}*/

	void roots_rename(int at)
	{
		QModelIndex index = roots->index(at);
		ui.lv_authorities->setFocus();
		ui.lv_authorities->setCurrentIndex(index);
		ui.lv_authorities->selectionModel()->select(index, QItemSelectionModel::Clear | QItemSelectionModel::Select | QItemSelectionModel::Current);
		ui.lv_authorities->edit(index);
	}

	void roots_remove(int at)
	{
		roots->removeItem(roots->idFromRow(at));
	}

	void keyselect_viewCertificate(const QCA::CertificateChain &chain)
	{
		// TODO: completion?
		CertViewDlg *w = new CertViewDlg(chain, (QWidget *)sender());
		w->setAttribute(Qt::WA_DeleteOnClose, true);
		w->show();
	}

	void users_customContextMenuRequested(const QPoint &pos)
	{
		QItemSelection selection = ui.lv_users->selectionModel()->selection();
		if(selection.indexes().isEmpty())
			return;

		QMenu menu(this);
		menu.addAction(actionView);
		menu.addAction(actionRename);
		menu.addAction(actionRemove);
		menu.exec(ui.lv_users->viewport()->mapToGlobal(pos));
	}

	void do_sign()
	{
		QItemSelection selection = ui.lv_users->selectionModel()->selection();
		if(selection.indexes().isEmpty())
			return;
		QModelIndex index = selection.indexes().first();
		int at = index.row();

		op = new SignOperation(ui.te_data->toPlainText().toUtf8(), users->itemFromRow(at), users, users->idFromRow(at), cms, this);
		connect(op, SIGNAL(finished(const QString &)), SLOT(sign_finished(const QString &)));
		connect(op, SIGNAL(error(const QString &)), SLOT(op_error(const QString &)));
	}

	void do_verify()
	{
		// prepare root certs
		QCA::CertificateCollection col;

		// system store
		col += QCA::systemStore();

		// TODO
		// additional roots configured in application
		foreach(const CertItem &i, roots->items())
			col.addCertificate(i.certificateChain().primary());

		// consider self-signed users as roots
		// (it is therefore not possible with this application to
		// have people in your keyring that you don't trust)
		foreach(const CertItem &i, users->items())
		{
			QCA::Certificate cert = i.certificateChain().primary();
			if(cert.isSelfSigned())
				col.addCertificate(cert);
		}

		cms->setTrustedCertificates(col);

		op = new VerifyOperation(ui.te_data->toPlainText().toUtf8(), ui.te_sig->toPlainText().toUtf8(), cms, this);
		connect(op, SIGNAL(finished()), SLOT(verify_finished()));
		connect(op, SIGNAL(error(const QString &)), SLOT(op_error(const QString &)));
	}

	void about()
	{
		int ver = qcaVersion();
		int maj = (ver >> 16) & 0xff;
		int min = (ver >> 8) & 0xff;
		int bug = ver & 0xff;
		QString verstr;
		verstr.sprintf("%d.%d.%d", maj, min, bug);

		QString str;
		str += tr("CMS Signer version %1 by Justin Karneges").arg(VERSION) + '\n';
		str += tr("A simple tool for creating and verifying digital signatures.") + '\n';
		str += '\n';
		str += tr("Using QCA version %1").arg(verstr) + '\n';
		str += '\n';
		str += tr("Icons by Jason Kim") + '\n';

		QCA::ProviderList list = QCA::providers();
		foreach(QCA::Provider *p, list)
		{
			QString credit = p->credit();
			if(!credit.isEmpty())
			{
				str += '\n';
				str += credit;
			}
		}

		QMessageBox::about(this, tr("About CMS Signer"), str);
	}

	void sign_finished(const QString &sig)
	{
		ui.te_sig->setPlainText(sig);
	}

	void verify_finished()
	{
		QMessageBox::information(this, tr("Verify"), tr("Signature verified successfully."));
	}

	void op_error(const QString &msg)
	{
		QMessageBox::information(this, tr("Error"), msg);
		delete op;
		op = 0;
	}
};

int main(int argc, char **argv)
{
	QCA::Initializer qcaInit;
	QApplication qapp(argc, argv);
	qapp.setApplicationName(MainWin::tr("CMS Signer"));
	if(!QCA::isSupported("cms"))
	{
		QMessageBox::critical(0, qapp.applicationName() + ": " + MainWin::tr("Error"),
			MainWin::tr("No support for CMS is available.  Please install an appropriate QCA plugin, such as qca-ossl."));
		return 1;
	}
	QCA::KeyStoreManager::start();
	MainWin mainWin;
	mainWin.show();
	return qapp.exec();
}

#include "main.moc"
