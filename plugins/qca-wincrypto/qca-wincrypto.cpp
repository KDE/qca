/*
 * Copyright (C) 2008  Michael Leupold <lemma@confuego.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 *
 */

#include <QtCrypto>
#include <QtPlugin>

#include <qstringlist.h>

#ifdef Q_OS_WIN32

#include <wincrypt.h>

//-----------------------------------------------------------
class WinCryptoRandomContext : public QCA::RandomContext
{
public:
   WinCryptoRandomContext(QCA::Provider *p) : RandomContext(p)
   {
   }

   Context *clone() const
   {
      return new WinCryptoRandomContext(*this);
   }

   QCA::SecureArray nextBytes(int size)
   {
      QCA::SecureArray buf(size);
      HCRYPTPROV hProv;

      /* FIXME: currently loop while there's an error. */
      while (true)
      {
         // acquire the crypto context
         if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL,
               CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) continue;
          
         if (CryptGenRandom(hProv, static_cast<DWORD>(size), (BYTE*)buf.data())) {
            break;
         }
      }

      // release the crypto context
      CryptReleaseContext(hProv, 0);

      return buf;
   }
};

//-----------------------------------------------------------
class WinCryptoProvider : public QCA::Provider
{
public:
   void init()
   {
   }

   ~WinCryptoProvider()
   {
   }

   int qcaVersion() const
   {
      return QCA_VERSION;
   }

   QString name() const
   {
      return "qca-wincrypto";
   }

   QStringList features() const
   {
      QStringList list;
      list += "random";
      return list;
   }

   Context *createContext(const QString &type)
   {
      if ( type == "random" )
         return new WinCryptoRandomContext(this);
      else
         return 0;
   }
};

//-----------------------------------------------------------
class WinCryptoPlugin : public QObject, public QCAPlugin
{
   Q_OBJECT
	Q_PLUGIN_METADATA(IID "com.affinix.qca.Plugin/1.0")
   Q_INTERFACES(QCAPlugin)

public:
   virtual QCA::Provider *createProvider() { return new WinCryptoProvider; }
};

Q_EXPORT_PLUGIN2(qca_wincrypto, WinCryptoPlugin);

#endif // Q_OS_WIN32
