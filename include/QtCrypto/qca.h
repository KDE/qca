/*
 * qca.h - Qt Cryptographic Architecture
 * Copyright (C) 2003-2005  Justin Karneges <justin@affinix.com>
 * Copyright (C) 2004,2005  Brad Hards <bradh@frogmouth.net>
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

#ifndef QCA_H
#define QCA_H

#include "qca_core.h"
#include "qca_textfilter.h"
#include "qca_basic.h"
#include "qca_publickey.h"
#include "qca_cert.h"
#include "qca_securelayer.h"
#include "qca_securemessage.h"
#include "qcaprovider.h"

/**
   \mainpage %Qt Cryptographic Architecture

   Taking a hint from the similarly-named
   <a href="http://java.sun.com/j2se/1.4/docs/guide/security/CryptoSpec.html">Java
   Cryptography Architecture</a>, %QCA aims to provide a
   straightforward and cross-platform cryptographic API, using Qt
   datatypes and conventions.  %QCA separates the API from the
   implementation, using plugins known as Providers.  The advantage
   of this model is to allow applications to avoid linking to or
   explicitly depending on any particular cryptographic library.
   This allows one to easily change or upgrade Provider
   implementations without even needing to recompile the
   application!

   %QCA should work everywhere %Qt does, including Windows/Unix/MacOSX.

   \section features Features

   This library provides an easy API for the following features:
     - Secure byte arrays (QSecureArray)
     - Arbitrary precision integers (QBigInteger)
     - Random number generation (QCA::Random)
     - SSL/TLS (ToDo)
     - X509 certificate (Cert) (ToDo)
     - Simple Authentication and Security Layer (SASL) (ToDo)
     - RSA (ToDo)
     - Hashing (QCA::Hash)
         - QCA::SHA0
         - QCA::SHA1
         - QCA::MD2
         - QCA::MD4
         - QCA::MD5
         - QCA::RIPEMD160
         - QCA::SHA256
         - QCA::SHA384
         - QCA::SHA512
     - Ciphers (QCA::Cipher)
         - BlowFish  (QCA::BlowFish)
         - Triple %DES (QCA::TripleDES)
         - %DES (QCA::DES)
         - AES (QCA::AES128, QCA::AES192, QCA::AES256)
     - Keyed Hash Message Authentication Code (QCA::HMAC), using
         - SHA1
         - MD5
         - RIPEMD160
     - Encoding and decoding of hexadecimal (QCA::Hex) and 
     Base64 (QCA::Base64)
  
   Functionality is supplied via plugins.  This is useful for avoiding
   dependence on a particular crypto library and makes upgrading easier,
   as there is no need to recompile your application when adding or
   upgrading a crypto plugin.  Also, by pushing crypto functionality into
   plugins, your application is free of legal issues, such as export
   regulation.
 
   And of course, you get a very simple crypto API for Qt, where you can
   do things like:
   \code
   QString hash = QCA::SHA1().hashToString(blockOfData);
   \endcode

   \section using Using QCA

   The application simply includes &lt;QtCrypto> and links to
   libqca, which provides the 'wrapper API' and plugin loader.  Crypto
   functionality is determined during runtime, and plugins are loaded
   from the 'crypto' subfolder of the %Qt library paths. There are <a
   href="examples.html">additional examples available</a>.

   \section availability Availability

   \subsection qca2code Current development

   The latest version of the code is available from the KDE CVS
   server (there is no formal release of the current version at this time). See
   <a href="http://developer.kde.org/source/anoncvs.html">
   http://developer.kde.org/source/anoncvs.html
   </a> for general instructions. You do <i>not</i> need kdelibs or
   arts modules for %QCA - just pull down kdesupport/qca. The plugins
   are in the same tree. Naturally you will need %Qt properly set up
   and configured in order to build and use %QCA.

   The CVS code can also be browsed
   <a href="http://webcvs.kde.org/cgi-bin/cvsweb.cgi/kdesupport/qca/">
   via the web</a>

   \subsection qca1code Previous versions
   
   A previous version of %QCA (sometimes referred to as QCA1) is still available.
   You will need to get the main library 
   (<a href="src/qca1/qca-1.0.tar.bz2">qca-1.0.tar.bz2</a>) and one or
   more providers
   (<a href="src/qca1/qca-tls-1.0.tar.bz2">qca-tls-1.0.tar.bz2</a> for
   the OpenSSL based provider, or
   <a href="src/qca1/qca-sasl-1.0.tar.bz2">qca-sasl-1.0.tar.bz2</a> for
   the SASL based provider). Note that development of QCA1 has basically
   stopped.

 */

#endif
