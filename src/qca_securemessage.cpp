/*
 * qca_securemessage.cpp - Qt Cryptographic Architecture
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

#include "qca_securemessage.h"

#include <qdatetime.h>
#include "qca_publickey.h"
#include "qca_cert.h"

namespace QCA {

//----------------------------------------------------------------------------
// SecureMessageKey
//----------------------------------------------------------------------------
SecureMessageKey::SecureMessageKey()
{
}

SecureMessageKey::SecureMessageKey(const SecureMessageKey &from)
{
	Q_UNUSED(from);
}

SecureMessageKey::~SecureMessageKey()
{
}

SecureMessageKey & SecureMessageKey::operator=(const SecureMessageKey &from)
{
	Q_UNUSED(from);
	return *this;
}

SecureMessageKey::Type SecureMessageKey::type() const
{
	return None;
}

QString SecureMessageKey::pgpPublicKey() const
{
	return QString();
}

QString SecureMessageKey::pgpSecretKey() const
{
	return QString();
}

void SecureMessageKey::setPGPPublicKey(const QString &id, const QString &name)
{
	Q_UNUSED(id);
	Q_UNUSED(name);
}

void SecureMessageKey::setPGPSecretKey(const QString &id)
{
	Q_UNUSED(id);
}

Certificate SecureMessageKey::x509Certificate() const
{
	return Certificate();
}

PrivateKey SecureMessageKey::x509PrivateKey() const
{
	return PrivateKey();
}

void SecureMessageKey::setX509Certificate(const Certificate &c)
{
	Q_UNUSED(c);
}

void SecureMessageKey::setX509PrivateKey(const PrivateKey &k)
{
	Q_UNUSED(k);
}

bool SecureMessageKey::havePrivate() const
{
	return false;
}

QString SecureMessageKey::id() const
{
	return QString();
}

QString SecureMessageKey::name() const
{
	return QString();
}

//----------------------------------------------------------------------------
// SecureMessage
//----------------------------------------------------------------------------
SecureMessage::SecureMessage(SecureMessageSystem *system)
{
	Q_UNUSED(system);
}

SecureMessage::~SecureMessage()
{
}

bool SecureMessage::canEncryptMultiple() const
{
	return false;
}

void SecureMessage::encrypt(const QSecureArray &in, const SecureMessageKey &key)
{
	Q_UNUSED(in);
	Q_UNUSED(key);
}

void SecureMessage::encrypt(const QSecureArray &in, const SecureMessageKeyList &keys)
{
	Q_UNUSED(in);
	Q_UNUSED(keys);
}

void SecureMessage::encryptAndSign(const QSecureArray &in, const SecureMessageKey &key, const SecureMessageKey &signer, Mode m)
{
	Q_UNUSED(in);
	Q_UNUSED(key);
	Q_UNUSED(signer);
	Q_UNUSED(m);
}

void SecureMessage::encryptAndSign(const QSecureArray &in, const SecureMessageKeyList &keys, const SecureMessageKey &signer, Mode m)
{
	Q_UNUSED(in);
	Q_UNUSED(keys);
	Q_UNUSED(signer);
	Q_UNUSED(m);
}

void SecureMessage::decrypt(const QString &in)
{
	Q_UNUSED(in);
}

void SecureMessage::sign(const QSecureArray &in, const SecureMessageKey &signer)
{
	Q_UNUSED(in);
	Q_UNUSED(signer);
}

void SecureMessage::verify(const QSecureArray &in, const QString &sig)
{
	Q_UNUSED(in);
	Q_UNUSED(sig);
}

bool SecureMessage::waitForFinished()
{
	return false;
}

bool SecureMessage::success() const
{
	return false;
}

SecureMessage::Error SecureMessage::errorCode() const
{
	return ErrUnknown;
}

QString SecureMessage::encrypted() const
{
	return QString();
}

QSecureArray SecureMessage::decrypted() const
{
	return QSecureArray();
}

QString SecureMessage::signature() const
{
	return QString();
}

SecureMessageKey SecureMessage::key() const
{
	return SecureMessageKey();
}

QDateTime SecureMessage::timestamp() const
{
	return QDateTime();
}

SecureMessage::VerifyResult SecureMessage::verifyResult()
{
	return VerifyError;
}

//----------------------------------------------------------------------------
// SecureMessageSystem
//----------------------------------------------------------------------------
SecureMessageSystem::SecureMessageSystem(QObject *parent, const char *name)
:QObject(parent, name)
{
}

SecureMessageSystem::~SecureMessageSystem()
{
}

//----------------------------------------------------------------------------
// OpenPGP
//----------------------------------------------------------------------------
OpenPGP::OpenPGP(QObject *parent, const char *name, const QString &provider)
:SecureMessageSystem(parent, name), Algorithm("openpgp", provider)
{
}

OpenPGP::~OpenPGP()
{
}

void OpenPGP::setAllowAgent(bool)
{
}

void OpenPGP::submitPassphrase(const QSecureArray &passphrase)
{
	Q_UNUSED(passphrase);
}

SecureMessageKeyList OpenPGP::secretKeys() const
{
	return SecureMessageKeyList();
}

SecureMessageKeyList OpenPGP::publicKeys() const
{
	return SecureMessageKeyList();
}

//----------------------------------------------------------------------------
// SMIME
//----------------------------------------------------------------------------
SMIME::SMIME(QObject *parent, const char *name, const QString &provider)
:SecureMessageSystem(parent, name), Algorithm("smime", provider)
{
}

SMIME::~SMIME()
{
}

void SMIME::setStore(const Store &store)
{
	Q_UNUSED(store);
}

}
