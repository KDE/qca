/*
 * Copyright (C) 2003-2008  Justin Karneges <justin@affinix.com>
 * Copyright (C) 2014  Ivan Romanov <drizt@land.ru>
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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include "utils.h"
#include "mykeystorelist.h"
#include <QFileInfo>
#include <QStringList>
#include <QCoreApplication>
#ifdef Q_OS_WIN
#include <windows.h>
#endif

using namespace QCA;

namespace gpgQCAPlugin
{

void gpg_waitForFinished(GpgOp *gpg)
{
	while(true)
	{
		GpgOp::Event e = gpg->waitForEvent(-1);
		if(e.type == GpgOp::Event::Finished)
			break;
	}
}

void gpg_keyStoreLog(const QString &str)
{
	MyKeyStoreList *ksl = MyKeyStoreList::instance();
	if(ksl)
		ksl->ext_keyStoreLog(str);
}

inline bool check_bin(const QString &bin)
{
	QFileInfo fi(bin);
	return fi.exists();
}

#ifdef Q_OS_WIN
static bool get_reg_key(HKEY root, const char *path, QString &value)
{
	HKEY hkey = 0;

	char szValue[256];
	DWORD dwLen = 256;

	bool res = false;

	if(RegOpenKeyExA(root, path, 0, KEY_QUERY_VALUE, &hkey) == ERROR_SUCCESS)
	{
		if (RegQueryValueExA(hkey, "Install Directory", NULL, NULL, (LPBYTE)szValue, &dwLen) == ERROR_SUCCESS)
		{
			value = QString::fromLocal8Bit(szValue);
			res = true;
		}
		RegCloseKey(hkey);
	}
	return res;
}


static QString find_reg_gpgProgram()
{
	QStringList bins;
	bins << "gpg.exe" << "gpg2.exe";

	HKEY root;
	root = HKEY_CURRENT_USER;

	const char *path = "Software\\GNU\\GnuPG";
	const char *path2 = "Software\\Wow6432Node\\GNU\\GnuPG";

	QString dir;
	// check list of possible places in registry
	get_reg_key(HKEY_CURRENT_USER, path, dir)  ||
	get_reg_key(HKEY_CURRENT_USER, path2, dir) ||
	get_reg_key(HKEY_LOCAL_MACHINE, path, dir) ||
	get_reg_key(HKEY_LOCAL_MACHINE, path2, dir);

	if (!dir.isEmpty())
	{
		foreach (const QString &bin, bins)
		{
			if (check_bin(dir + "\\" + bin))
			{
				return dir + "\\" + bin;
			}
		}
	}
	return QString();
}
#endif

QString find_bin()
{
	// gpg and gpg2 has identical semantics
	// so any from them can be used
	QStringList bins;
#ifdef Q_OS_WIN
	bins << "gpg.exe" << "gpg2.exe";
#else
	bins << QStringLiteral("gpg") << QStringLiteral("gpg2");
#endif

	// Prefer bundled gpg
	foreach (const QString &bin, bins)
	{
		if (check_bin(QCoreApplication::applicationDirPath() + QLatin1Char('/') + bin))
		{
			return QCoreApplication::applicationDirPath() + QLatin1Char('/') + bin;
		}
	}

#ifdef Q_OS_WIN
	// On Windows look up at registry
	QString bin = find_reg_gpgProgram();
	if (!bin.isEmpty())
		return bin;
#endif

	// Look up at PATH environment
#ifdef Q_OS_WIN
	QString pathSep = ";";
#else
	const QString pathSep = QStringLiteral(":");
#endif

	QStringList paths = QString::fromLocal8Bit(qgetenv("PATH")).split(pathSep, QString::SkipEmptyParts);

#ifdef Q_OS_MAC
	// On Mac OS bundled always uses system default PATH
	// so it need explicity add extra paths which can
	// contain gpg
	// Mac GPG and brew use /usr/local/bin
	// MacPorts uses /opt/local/bin
	paths << "/usr/local/bin" << "/opt/local/bin";
#endif
	paths.removeDuplicates();

	foreach (const QString &path, paths)
	{
		foreach (const QString &bin, bins)
		{
			if (check_bin(path + QLatin1Char('/') + bin))
			{
				return path + QLatin1Char('/') + bin;
			}
		}
	}

	// Return nothing if gpg not found
	return QString();
}

QString escape_string(const QString &in)
{
	QString out;
	for(const QChar &c : in)
	{
		if(c == QLatin1Char('\\'))
			out += QStringLiteral("\\\\");
		else if(c == QLatin1Char(':'))
			out += QStringLiteral("\\c");
		else
			out += c;
	}
	return out;
}

QString unescape_string(const QString &in)
{
	QString out;
	for(int n = 0; n < in.length(); ++n)
	{
		if(in[n] == QLatin1Char('\\'))
		{
			if(n + 1 < in.length())
			{
				if(in[n + 1] == QLatin1Char('\\'))
					out += QLatin1Char('\\');
				else if(in[n + 1] == QLatin1Char('c'))
					out += QLatin1Char(':');
				++n;
			}
		}
		else
			out += in[n];
	}
	return out;
}

PGPKey publicKeyFromId(const QString &id)
{
	MyKeyStoreList *ksl = MyKeyStoreList::instance();
	if(!ksl)
		return PGPKey();

	return ksl->publicKeyFromId(id);
}

PGPKey secretKeyFromId(const QString &id)
{
	MyKeyStoreList *ksl = MyKeyStoreList::instance();
	if(!ksl)
		return PGPKey();

	return ksl->secretKeyFromId(id);
}

} // end namespace gpgQCAPlugin
