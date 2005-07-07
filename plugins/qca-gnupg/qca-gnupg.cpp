/*
 * Copyright (C) 2003-2005  Justin Karneges <justin@affinix.com>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <QtCore>
#include <QtCrypto>
#ifdef Q_OS_WIN
# include<windows.h>
#endif
#include "gpgop.h"

#ifdef Q_OS_WIN
static QString find_reg_gpgProgram()
{
	HKEY root;
	root = HKEY_CURRENT_USER;

	HKEY hkey;
	const char *path = "Software\\GNU\\GnuPG";
	if(RegOpenKeyExA(HKEY_CURRENT_USER, path, 0, KEY_QUERY_VALUE, &hkey) != ERROR_SUCCESS)
	{
		if(RegOpenKeyExA(HKEY_LOCAL_MACHINE, path, 0, KEY_QUERY_VALUE, &hkey) != ERROR_SUCCESS)
			return QString::null;
	}

	char szValue[256];
	DWORD dwLen = 256;
	if(RegQueryValueExA(hkey, "gpgProgram", NULL, NULL, (LPBYTE)szValue, &dwLen) != ERROR_SUCCESS)
	{
		RegCloseKey(hkey);
		return QString::null;
	}

	RegCloseKey(hkey);
	return QString::fromLatin1(szValue);
}
#endif

static QString find_bin()
{
	QString bin = "gpg";
#ifdef Q_OS_WIN
	QString s = find_reg_gpgProgram();
	if(!s.isNull())
		bin = s;
#endif
	return bin;
}

using namespace QCA;

namespace gpgQCAPlugin {

class MyPGPKeyContext : public PGPKeyContext
{
public:
	PGPKeyContextProps _props;

	MyPGPKeyContext(Provider *p) : PGPKeyContext(p)
	{
	}

	virtual Provider::Context *clone() const
	{
		return new MyPGPKeyContext(*this);
	}

	virtual const PGPKeyContextProps *props() const
	{
		return &_props;
	}

	virtual QSecureArray toBinary() const
	{
		// TODO
		return QSecureArray();
	}

	virtual QString toAscii() const
	{
		// TODO
		return QString();
	}

	virtual ConvertResult fromBinary(const QSecureArray &a)
	{
		// TODO
		Q_UNUSED(a);
		return ErrorDecode;
	}

	virtual ConvertResult fromAscii(const QString &s)
	{
		// TODO
		Q_UNUSED(s);
		return ErrorDecode;
	}
};

class MyKeyStoreEntry : public KeyStoreEntryContext
{
public:
	KeyStoreEntry::Type item_type;
	PGPKey pub, sec;

	MyKeyStoreEntry(const PGPKey &_pub, const PGPKey &_sec, Provider *p) : KeyStoreEntryContext(p)
	{
		pub = _pub;
		sec = _sec;
		if(!sec.isNull())
			item_type = KeyStoreEntry::TypePGPSecretKey;
		else
			item_type = KeyStoreEntry::TypePGPPublicKey;
	}

	MyKeyStoreEntry(const MyKeyStoreEntry &from) : KeyStoreEntryContext(from)
	{
	}

	~MyKeyStoreEntry()
	{
	}

	virtual Provider::Context *clone() const
	{
		return new MyKeyStoreEntry(*this);
	}

	virtual KeyStoreEntry::Type type() const
	{
		return item_type;
	}

	virtual QString name() const
	{
		return pub.primaryUserId();
	}

	virtual QString id() const
	{
		return pub.keyId();
	}

	virtual PGPKey pgpSecretKey() const
	{
		return sec;
	}

	virtual PGPKey pgpPublicKey() const
	{
		return pub;
	}
};

class MyMessageContext;

GpgOp *global_gpg;

class MyKeyStore : public KeyStoreContext
{
	Q_OBJECT
public:
	friend class MyMessageContext;

	MyKeyStore(Provider *p) : KeyStoreContext(p) {}

	virtual Provider::Context *clone() const
	{
		return 0;
	}

	virtual int contextId() const
	{
		// TODO
		return 0; // there is only 1 context, so this can be static
	}

	virtual QString deviceId() const
	{
		// TODO
		return "qca-gnupg-(gpg)";
	}

	virtual KeyStore::Type type() const
	{
		return KeyStore::PGPKeyring;
	}

	virtual QString name() const
	{
		return "GnuPG Keyring";
	}

	virtual QList<KeyStoreEntryContext*> entryList() const
	{
		QList<KeyStoreEntryContext*> out;

		GpgOp::KeyList seckeys;
		{
			GpgOp gpg(find_bin());
			gpg.doSecretKeys();
			while(1)
			{
				GpgOp::Event e = gpg.waitForEvent(-1);
				if(e.type == GpgOp::Event::Finished)
					break;
			}
			if(!gpg.success())
				return out;
			seckeys = gpg.keys();
		}

		GpgOp::KeyList pubkeys;
		{
			GpgOp gpg(find_bin());
			gpg.doPublicKeys();
			while(1)
			{
				GpgOp::Event e = gpg.waitForEvent(-1);
				if(e.type == GpgOp::Event::Finished)
					break;
			}
			if(!gpg.success())
				return out;
			pubkeys = gpg.keys();
		}

		for(int n = 0; n < pubkeys.count(); ++n)
		{
			QString id = pubkeys[n].keyItems.first().id;
			MyPGPKeyContext *kc = new MyPGPKeyContext(provider());
			kc->_props.keyId = id;
			kc->_props.userIds = QStringList() << pubkeys[n].userIds.first();
			PGPKey pub, sec;
			pub.change(kc);
			for(int i = 0; i < seckeys.count(); ++i)
			{
				if(seckeys[i].keyItems.first().id == id)
				{
					MyPGPKeyContext *kc = new MyPGPKeyContext(provider());
					kc->_props.keyId = id;
					kc->_props.userIds = QStringList() << pubkeys[n].userIds.first();
					sec.change(kc);
				}
			}

			MyKeyStoreEntry *c = new MyKeyStoreEntry(pub, sec, provider());
			out.append(c);
		}

		return out;
	}

	virtual QList<KeyStoreEntry::Type> entryTypes() const
	{
		QList<KeyStoreEntry::Type> list;
		list += KeyStoreEntry::TypePGPSecretKey;
		list += KeyStoreEntry::TypePGPPublicKey;
		return list;
	}

	virtual void submitPassphrase(const QSecureArray &a)
	{
		global_gpg->submitPassphrase(a.toByteArray());
	}
};

class MyKeyStoreList;

static MyKeyStoreList *keyStoreList = 0;

class MyKeyStoreList : public KeyStoreListContext
{
	Q_OBJECT
public:
	MyKeyStore *ks;

	MyKeyStoreList(Provider *p) : KeyStoreListContext(p)
	{
		keyStoreList = this;

		ks = 0;

		ks = new MyKeyStore(provider());
	}

	~MyKeyStoreList()
	{
		delete ks;

		keyStoreList = 0;
	}

	virtual Provider::Context *clone() const
	{
		return 0;
	}

	virtual QList<KeyStoreContext*> keyStores() const
	{
		QList<KeyStoreContext*> list;
		if(ks)
			list.append(ks);
		return list;
	}
};

class MyOpenPGPContext : public SMSContext
{
public:
	MyOpenPGPContext(Provider *p) : SMSContext(p, "openpgp")
	{
		// TODO
	}

	virtual Provider::Context *clone() const
	{
		return 0;
	}

	virtual MessageContext *createMessage();
};

class MyMessageContext : public MessageContext
{
	Q_OBJECT
public:
	MyOpenPGPContext *sms;

	QString signerId;
	QByteArray in, out;
	bool ok;

	MyMessageContext(MyOpenPGPContext *_sms, Provider *p) : MessageContext(p, "pgpmsg")
	{
		sms = _sms;
		ok = false;
	}

	virtual Provider::Context *clone() const
	{
		return 0;
	}

	virtual bool canSignMultiple() const
	{
		return false;
	}

	virtual SecureMessage::Type type() const
	{
		return SecureMessage::OpenPGP;
	}

	virtual void reset()
	{
	}

	virtual void setupEncrypt(const SecureMessageKeyList &keys)
	{
		Q_UNUSED(keys);
	}

	virtual void setupSign(const SecureMessageKeyList &keys, SecureMessage::SignMode m, bool, bool)
	{
		signerId = keys.first().pgpSecretKey().keyId();
		Q_UNUSED(m);
	}

	virtual void setupVerify(const QByteArray &detachedSig)
	{
		Q_UNUSED(detachedSig);
	}

	virtual void start(SecureMessage::Format f, Operation op)
	{
		Q_UNUSED(f);
		Q_UNUSED(op);
	}

	virtual void update(const QByteArray &in)
	{
		this->in.append(in);
	}

	virtual QByteArray read()
	{
		return out;
	}

	virtual void end()
	{
		GpgOp gpg(find_bin());
		global_gpg = &gpg;
		gpg.doSignClearsign(signerId);
		gpg.write(in);
		gpg.endWrite();
		while(1)
		{
			GpgOp::Event e = gpg.waitForEvent(-1);
			if(e.type == GpgOp::Event::NeedPassphrase)
			{
				emit keyStoreList->ks->needPassphrase();
			}
			else if(e.type == GpgOp::Event::Finished)
				break;
		}
		ok = gpg.success();
		out = gpg.read();
		global_gpg = 0;
	}

	virtual bool finished() const
	{
		// TODO
		return true;
	}

	virtual void waitForFinished(int msecs)
	{
		Q_UNUSED(msecs);
	}

	virtual bool success() const
	{
		return ok;
	}

	virtual SecureMessage::Error errorCode() const
	{
		return SecureMessage::ErrorUnknown;
	}

	virtual QByteArray signature() const
	{
		return QByteArray();
	}

	virtual QString hashName() const
	{
		// TODO
		return "sha1";
	}

	virtual SecureMessageSignatureList signers() const
	{
		return SecureMessageSignatureList();
	}
};

MessageContext *MyOpenPGPContext::createMessage()
{
	return new MyMessageContext(this, provider());
}

}

using namespace gpgQCAPlugin;

class gnupgProvider : public QCA::Provider
{
public:
	virtual void init()
	{
	}

	virtual QString name() const
	{
		return "qca-gnupg";
	}

	virtual QStringList features() const
	{
		QStringList list;
		list += "pgpkey";
		list += "openpgp";
		list += "keystorelist";
		return list;
	}

	virtual Context *createContext(const QString &type)
	{
		if(type == "pgpkey")
			return new MyPGPKeyContext(this);
		else if(type == "openpgp")
			return new MyOpenPGPContext(this);
		else if(type == "keystorelist")
			return new MyKeyStoreList(this);
		else
			return 0;
	}
};

class gnupgPlugin : public QCAPlugin
{
	Q_OBJECT
public:
	virtual int version() const { return QCA_PLUGIN_VERSION; }
	virtual QCA::Provider *createProvider() { return new gnupgProvider; }
};

#include "qca-gnupg.moc"

Q_EXPORT_PLUGIN(gnupgPlugin);
