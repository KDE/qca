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
#include <QMessageBox>
#include <QFileDialog>

#include "ui_mainwin.h"
#include "certviewdlg.h"
#include "keyselectdlg.h"
#include "pkcs11configdlg/pkcs11configdlg.h"
#include "certitem.h"

#ifdef QT_STATICPLUGIN
#include "import_plugins.h"
#endif

#define VERSION "1.0.0"

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
	QString s;
	switch(e)
	{
		case QCA::SecureMessage::ErrorPassphrase:
			s = Operation::tr("Invalid passphrase.");
			break;
		case QCA::SecureMessage::ErrorFormat:
			s = Operation::tr("Bad input format.");
			break;
		case QCA::SecureMessage::ErrorSignerExpired:
			s = Operation::tr("Signer key is expired.");
			break;
		case QCA::SecureMessage::ErrorSignerInvalid:
			s = Operation::tr("Signer key is invalid.");
			break;
		case QCA::SecureMessage::ErrorEncryptExpired:
			s = Operation::tr("Encrypting key is expired.");
			break;
		case QCA::SecureMessage::ErrorEncryptUntrusted:
			s = Operation::tr("Encrypting key is untrusted.");
			break;
		case QCA::SecureMessage::ErrorEncryptInvalid:
			s = Operation::tr("Encrypting key is invalid.");
			break;
		case QCA::SecureMessage::ErrorNeedCard:
			s = Operation::tr("Card was needed but not found.");
			break;
		case QCA::SecureMessage::ErrorCertKeyMismatch:
			s = Operation::tr("Certificate and private key don't match.");
			break;
		case QCA::SecureMessage::ErrorUnknown:
		default:
			s = Operation::tr("General error.");
			break;
	}
	return s;
}

static QString smsIdentityToString(const QCA::SecureMessageSignature &sig)
{
	QString s;
	switch(sig.identityResult())
	{
		case QCA::SecureMessageSignature::Valid:
			break;
		case QCA::SecureMessageSignature::InvalidSignature:
			s = Operation::tr("Invalid signature");
			break;
		case QCA::SecureMessageSignature::InvalidKey:
			s = Operation::tr("Invalid key: %1").arg(validityToString(sig.keyValidity()));
			break;
		case QCA::SecureMessageSignature::NoKey:
			s = Operation::tr("Key not found");
			break;
		default: // this should not really be possible
			s = Operation::tr("Unknown");
			break;
	}
	return s;
}

class SignOperation : public Operation
{
	Q_OBJECT
private:
	QByteArray in;
	CertItemStore *store;
	int id;
	QCA::CMS *cms;
	CertItemPrivateLoader *loader;
	QCA::SecureMessage *msg;
	int pending;

public:
	SignOperation(const QByteArray &_in, CertItemStore *_store, int _id, QCA::CMS *_cms, QObject *parent = 0) :
		Operation(parent),
		in(_in),
		store(_store),
		id(_id),
		cms(_cms),
		msg(0)
	{
		loader = new CertItemPrivateLoader(store, this);
		connect(loader, SIGNAL(finished()), SLOT(loader_finished()));
		loader->start(id);
	}

signals:
	void loadError();
	void finished(const QString &sig);

private slots:
	void loader_finished()
	{
		QCA::PrivateKey privateKey = loader->privateKey();
		delete loader;
		loader = 0;

		if(privateKey.isNull())
		{
			emit loadError();
			return;
		}

		CertItem item = store->itemFromId(id);

		QCA::SecureMessageKey signer;
		signer.setX509CertificateChain(item.certificateChain());
		signer.setX509PrivateKey(privateKey);

		msg = new QCA::SecureMessage(cms);
		connect(msg, SIGNAL(bytesWritten(int)), SLOT(msg_bytesWritten(int)));
		connect(msg, SIGNAL(finished()), SLOT(msg_finished()));
		msg->setFormat(QCA::SecureMessage::Ascii);
		msg->setSigner(signer);
		msg->startSign(QCA::SecureMessage::Detached);

		pending = 0;
		update();
	}

	void update()
	{
		QByteArray buf = in.mid(0, 16384 - pending); // 16k chunks
		in = in.mid(buf.size());
		pending += buf.size();
		msg->update(buf);
	}

	void msg_bytesWritten(int x)
	{
		pending -= x;

		if(in.isEmpty() && pending == 0)
			msg->end();
		else
			update();
	}

	void msg_finished()
	{
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
	int pending;

public:
	QCA::SecureMessageSignature signer;

	VerifyOperation(const QByteArray &_in, const QByteArray &_sig, QCA::CMS *_cms, QObject *parent = 0) :
		Operation(parent),
		in(_in),
		sig(_sig),
		cms(_cms),
		msg(0)
	{
		msg = new QCA::SecureMessage(cms);
		connect(msg, SIGNAL(bytesWritten(int)), SLOT(msg_bytesWritten(int)));
		connect(msg, SIGNAL(finished()), SLOT(msg_finished()));
		msg->setFormat(QCA::SecureMessage::Ascii);
		msg->startVerify(sig);

		pending = 0;
		update();
	}

signals:
	void finished();

private slots:
	void update()
	{
		QByteArray buf = in.mid(0, 16384 - pending); // 16k chunks
		in = in.mid(buf.size());
		pending += buf.size();
		msg->update(buf);
	}

	void msg_bytesWritten(int x)
	{
		pending -= x;

		if(in.isEmpty() && pending == 0)
			msg->end();
		else
			update();
	}

	void msg_finished()
	{
		if(!msg->success())
		{
			QString str = smErrorToString(msg->errorCode());
			delete msg;
			msg = 0;
			emit error(tr("Error during verify operation.\nReason: %1").arg(str));
			return;
		}

		signer = msg->signer();
		delete msg;
		msg = 0;

		if(signer.identityResult() != QCA::SecureMessageSignature::Valid)
		{
			QString str = smsIdentityToString(signer);
			emit error(tr("Verification failed!\nReason: %1").arg(str));
			return;
		}

		emit finished();
	}
};

//----------------------------------------------------------------------------
// MainWin
//----------------------------------------------------------------------------
static QString get_fingerprint(const QCA::Certificate &cert)
{
	QString hex = QCA::Hash("sha1").hashToString(cert.toDER());
	QString out;
	for(int n = 0; n < hex.count(); ++n)
	{
		if(n != 0 && n % 2 == 0)
			out += ':';
		out += hex[n];
	}
	return out;
}

class MainWin : public QMainWindow
{
	Q_OBJECT
private:
	Ui_MainWin ui;
	CertItemStore *users, *roots;
	QCA::CMS *cms;
	Operation *op;
	QAction *actionView, *actionRename, *actionRemove;
	QCA::Certificate self_signed_verify_cert;
	int auto_import_req_id;

public:
	MainWin(QWidget *parent = 0) :
		QMainWindow(parent),
		op(0),
		auto_import_req_id(-1)
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

		ui.lv_authorities->setContextMenuPolicy(Qt::CustomContextMenu);
		connect(ui.lv_authorities, SIGNAL(customContextMenuRequested(const QPoint &)), SLOT(roots_customContextMenuRequested(const QPoint &)));

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

	QCA::CertificateCollection allCerts()
	{
		QCA::CertificateCollection col;

		// system store
		col += QCA::systemStore();

		// additional roots configured in application
		foreach(const CertItem &i, roots->items())
			col.addCertificate(i.certificateChain().primary());

		// user chains
		foreach(const CertItem &i, users->items())
		{
			foreach(const QCA::Certificate &cert, i.certificateChain())
				col.addCertificate(cert);
		}

		return col;
	}

	QCA::CertificateChain complete(const QCA::CertificateChain &chain)
	{
		return chain.complete(allCerts().certificates());
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

	void load_device_finished(const QCA::KeyStoreEntry &entry)
	{
		users->addFromKeyStore(entry);
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
		if(req_id == auto_import_req_id)
		{
			auto_import_req_id = -1;

			CertItem i = users->itemFromId(id);

			QMessageBox::information(this, tr("User added"), tr(
				"This signature was made by a previously unknown user, and so the "
				"user has now been added to the keyring as \"%1\"."
				).arg(i.name()));

			verify_next();
			return;
		}

		ui.lv_users->selectionModel()->select(users->index(users->rowFromId(id)), QItemSelectionModel::Clear | QItemSelectionModel::Select | QItemSelectionModel::Current);

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

		bool usable = false;
		if(at != -1 && users->itemFromRow(at).isUsable())
			usable = true;

		if(usable && !ui.pb_sign->isEnabled())
			ui.pb_sign->setEnabled(true);
		else if(!usable && ui.pb_sign->isEnabled())
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
		else // lv_authorities
		{
			QItemSelection selection = ui.lv_authorities->selectionModel()->selection();
			if(selection.indexes().isEmpty())
				return;
			QModelIndex index = selection.indexes().first();
			roots_view(index.row());
		}
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

	void users_view(int at)
	{
		CertItem i = users->itemFromRow(at);
		CertViewDlg *w = new CertViewDlg(complete(i.certificateChain()), this);
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

	void roots_view(int at)
	{
		CertItem i = roots->itemFromRow(at);
		CertViewDlg *w = new CertViewDlg(complete(i.certificateChain()), this);
		w->setAttribute(Qt::WA_DeleteOnClose, true);
		w->show();
	}

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
		CertViewDlg *w = new CertViewDlg(complete(chain), (QWidget *)sender());
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

	void roots_customContextMenuRequested(const QPoint &pos)
	{
		QItemSelection selection = ui.lv_authorities->selectionModel()->selection();
		if(selection.indexes().isEmpty())
			return;

		QMenu menu(this);
		menu.addAction(actionView);
		menu.addAction(actionRename);
		menu.addAction(actionRemove);
		menu.exec(ui.lv_authorities->viewport()->mapToGlobal(pos));
	}

	void do_sign()
	{
		QItemSelection selection = ui.lv_users->selectionModel()->selection();
		if(selection.indexes().isEmpty())
			return;
		QModelIndex index = selection.indexes().first();
		int at = index.row();

		setEnabled(false);

		op = new SignOperation(ui.te_data->toPlainText().toUtf8(), users, users->idFromRow(at), cms, this);
		connect(op, SIGNAL(loadError()), SLOT(sign_loadError()));
		connect(op, SIGNAL(finished(const QString &)), SLOT(sign_finished(const QString &)));
		connect(op, SIGNAL(error(const QString &)), SLOT(sign_error(const QString &)));
	}

	void do_verify()
	{
		// prepare root certs
		QCA::CertificateCollection col;

		// system store
		col += QCA::systemStore();

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

		// the self signed verify cert, if applicable
		if(!self_signed_verify_cert.isNull())
		{
			col.addCertificate(self_signed_verify_cert);
			self_signed_verify_cert = QCA::Certificate();
		}

		cms->setTrustedCertificates(col);

		setEnabled(false);

		op = new VerifyOperation(ui.te_data->toPlainText().toUtf8(), ui.te_sig->toPlainText().toUtf8(), cms, this);
		connect(op, SIGNAL(finished()), SLOT(verify_finished()));
		connect(op, SIGNAL(error(const QString &)), SLOT(verify_error(const QString &)));
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

	void sign_loadError()
	{
		delete op;
		op = 0;

		setEnabled(true);
	}

	void sign_finished(const QString &sig)
	{
		delete op;
		op = 0;

		ui.te_sig->setPlainText(sig);

		setEnabled(true);
	}

	void sign_error(const QString &msg)
	{
		delete op;
		op = 0;

		setEnabled(true);

		QMessageBox::information(this, tr("Error"), msg);
	}

	void verify_finished()
	{
		QCA::SecureMessageSignature signer = ((VerifyOperation *)op)->signer;
		delete op;
		op = 0;

		// import the cert?
		QCA::SecureMessageKey skey = signer.key();
		if(!skey.isNull())
		{
			QCA::CertificateChain chain = skey.x509CertificateChain();

			int at = -1;
			QList<CertItem> items = users->items();
			for(int n = 0; n < items.count(); ++n)
			{
				const CertItem &i = items[n];
				if(i.certificateChain().primary() == chain.primary())
				{
					at = n;
					break;
				}
			}

			// add
			if(at == -1)
			{
				auto_import_req_id = users->addUser(chain);
				return;
			}
			// update
			else
			{
				users->updateChain(users->idFromRow(at), chain);
			}
		}

		verify_next();
	}

	void verify_next()
	{
		setEnabled(true);

		QMessageBox::information(this, tr("Verify"), tr("Signature verified successfully."));
	}

	void verify_error(const QString &msg)
	{
		QCA::SecureMessageSignature signer = ((VerifyOperation *)op)->signer;
		delete op;
		op = 0;

		QCA::SecureMessageKey skey = signer.key();
		if(signer.keyValidity() == QCA::ErrorSelfSigned && !skey.isNull())
		{
			QCA::CertificateChain chain = skey.x509CertificateChain();
			if(chain.count() == 1 && chain.primary().isSelfSigned())
			{
				QCA::Certificate cert = chain.primary();

				int ret = QMessageBox::warning(this, tr("Self-signed certificate"), tr(
					"<qt>The signature is made by an unknown user, and the certificate is self-signed.<br>\n"
					"<br>\n"
					"<nobr>Common Name: %1</nobr><br>\n"
					"<nobr>SHA1 Fingerprint: %2</nobr><br>\n"
					"<br>\n"
					"Trust the certificate?</qt>"
					).arg(cert.commonName(), get_fingerprint(cert)),
					QMessageBox::Yes | QMessageBox::No,
					QMessageBox::No);

				if(ret == QMessageBox::Yes)
				{
					self_signed_verify_cert = cert;
					do_verify();
					return;
				}
			}
		}

		setEnabled(true);

		QMessageBox::information(this, tr("Error"), msg);
	}
};

int main(int argc, char **argv)
{
	QCA::Initializer qcaInit;
	QApplication qapp(argc, argv);

	qapp.setApplicationName(MainWin::tr("CMS Signer"));

	if(!QCA::isSupported("cert,crl,cms"))
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
