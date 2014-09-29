#include "mypgpkeycontext.h"
#include "utils.h"
#include "gpgop.h"
#include <QTemporaryFile>
#include <QDir>

using namespace QCA;

namespace gpgQCAPlugin
{

MyPGPKeyContext::MyPGPKeyContext(Provider *p)
	: PGPKeyContext(p)
{
	// zero out the props
	_props.isSecret = false;
	_props.inKeyring = true;
	_props.isTrusted = false;
}

Provider::Context *MyPGPKeyContext::clone() const
{
	return new MyPGPKeyContext(*this);
}

const PGPKeyContextProps *MyPGPKeyContext::props() const
{
	return &_props;
}

QByteArray MyPGPKeyContext::toBinary() const
{
	if(_props.inKeyring)
	{
		GpgOp gpg(find_bin());
		gpg.setAsciiFormat(false);
		gpg.doExport(_props.keyId);
		gpg_waitForFinished(&gpg);
		gpg_keyStoreLog(gpg.readDiagnosticText());
		if(!gpg.success())
			return QByteArray();
		return gpg.read();
	}
	else
		return cacheExportBinary;
}

ConvertResult MyPGPKeyContext::fromBinary(const QByteArray &a)
{
	GpgOp::Key key;
	bool sec = false;

	// temporary keyrings
	QString pubname, secname;

	QTemporaryFile pubtmp(QDir::tempPath() + QLatin1String("/qca_gnupg_tmp.XXXXXX.gpg"));
	if(!pubtmp.open())
		return ErrorDecode;

	QTemporaryFile sectmp(QDir::tempPath() + QLatin1String("/qca_gnupg_tmp.XXXXXX.gpg"));
	if(!sectmp.open())
		return ErrorDecode;

	pubname = pubtmp.fileName();
	secname = sectmp.fileName();

	// we turn off autoRemove so that we can close the files
	//   without them getting deleted
	pubtmp.setAutoRemove(false);
	sectmp.setAutoRemove(false);
	pubtmp.close();
	sectmp.close();

	// import key into temporary keyring
	GpgOp gpg(find_bin());
	gpg.setKeyrings(pubname, secname);
	gpg.doImport(a);
	gpg_waitForFinished(&gpg);
	gpg_keyStoreLog(gpg.readDiagnosticText());
	// comment this out.  apparently gpg will report failure for
	//   an import if there are trust issues, even though the
	//   key actually did get imported
	/*if(!gpg.success())
	  {
	  cleanup_temp_keyring(pubname);
	  cleanup_temp_keyring(secname);
	  return ErrorDecode;
	  }*/

	// now extract the key from gpg like normal

	// is it a public key?
	gpg.doPublicKeys();
	gpg_waitForFinished(&gpg);
	gpg_keyStoreLog(gpg.readDiagnosticText());
	if(!gpg.success())
	{
		cleanup_temp_keyring(pubname);
		cleanup_temp_keyring(secname);
		return ErrorDecode;
	}

	GpgOp::KeyList pubkeys = gpg.keys();
	if(!pubkeys.isEmpty())
	{
		key = pubkeys.first();
	}
	else
	{
		// is it a secret key?
		gpg.doSecretKeys();
		gpg_waitForFinished(&gpg);
		gpg_keyStoreLog(gpg.readDiagnosticText());
		if(!gpg.success())
		{
			cleanup_temp_keyring(pubname);
			cleanup_temp_keyring(secname);
			return ErrorDecode;
		}

		GpgOp::KeyList seckeys = gpg.keys();
		if(!seckeys.isEmpty())
		{
			key = seckeys.first();
			sec = true;
		}
		else
		{
			// no keys found
			cleanup_temp_keyring(pubname);
			cleanup_temp_keyring(secname);
			return ErrorDecode;
		}
	}

	// export binary/ascii and cache

	gpg.setAsciiFormat(false);
	gpg.doExport(key.keyItems.first().id);
	gpg_waitForFinished(&gpg);
	gpg_keyStoreLog(gpg.readDiagnosticText());
	if(!gpg.success())
	{
		cleanup_temp_keyring(pubname);
		cleanup_temp_keyring(secname);
		return ErrorDecode;
	}
	cacheExportBinary = gpg.read();

	gpg.setAsciiFormat(true);
	gpg.doExport(key.keyItems.first().id);
	gpg_waitForFinished(&gpg);
	gpg_keyStoreLog(gpg.readDiagnosticText());
	if(!gpg.success())
	{
		cleanup_temp_keyring(pubname);
		cleanup_temp_keyring(secname);
		return ErrorDecode;
	}
	cacheExportAscii = QString::fromLocal8Bit(gpg.read());

	// all done

	cleanup_temp_keyring(pubname);
	cleanup_temp_keyring(secname);

	set(key, sec, false, false);
	return ConvertGood;
}

QString MyPGPKeyContext::toAscii() const
{
	if(_props.inKeyring)
	{
		GpgOp gpg(find_bin());
		gpg.setAsciiFormat(true);
		gpg.doExport(_props.keyId);
		gpg_waitForFinished(&gpg);
		gpg_keyStoreLog(gpg.readDiagnosticText());
		if(!gpg.success())
			return QString();
		return QString::fromLocal8Bit(gpg.read());
	}
	else
	{
		return cacheExportAscii;
	}
}

ConvertResult MyPGPKeyContext::fromAscii(const QString &s)
{
	// GnuPG does ascii/binary detection for imports, so for
	//   simplicity we consider an ascii import to just be a
	//   binary import that happens to be comprised of ascii
	return fromBinary(s.toLocal8Bit());
}

void MyPGPKeyContext::set(const GpgOp::Key &i, bool isSecret, bool inKeyring, bool isTrusted)
{
	const GpgOp::KeyItem &ki = i.keyItems.first();

	_props.keyId = ki.id;
	_props.userIds = i.userIds;
	_props.isSecret = isSecret;
	_props.creationDate = ki.creationDate;
	_props.expirationDate = ki.expirationDate;
	_props.fingerprint = ki.fingerprint.toLower();
	_props.inKeyring = inKeyring;
	_props.isTrusted = isTrusted;
}

void MyPGPKeyContext::cleanup_temp_keyring(const QString &name)
{
	QFile::remove(name);
	QFile::remove(name + '~'); // remove possible backup file
}

} // end namespace gpgQCAPlugin
