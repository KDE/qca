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

CertificateChain SecureMessageKey::x509CertificateChain() const
{
	return CertificateChain();
}

PrivateKey SecureMessageKey::x509PrivateKey() const
{
	return PrivateKey();
}

void SecureMessageKey::setX509CertificateChain(const CertificateChain &c)
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
// SecureMessageSignature
//----------------------------------------------------------------------------
SecureMessageSignature::SecureMessageSignature()
{
}

SecureMessageSignature::SecureMessageSignature(const SecureMessageSignature &from)
{
	Q_UNUSED(from);
}

SecureMessageSignature::~SecureMessageSignature()
{
}

SecureMessageSignature & SecureMessageSignature::operator=(const SecureMessageSignature &from)
{
	Q_UNUSED(from);
	return *this;
}

SecureMessageSignature::IdentityResult SecureMessageSignature::identityResult() const
{
	return Invalid;
}

Validity SecureMessageSignature::keyValidity() const
{
	return ErrorValidityUnknown;
}

SecureMessageKey SecureMessageSignature::key() const
{
	return SecureMessageKey();
}

QDateTime SecureMessageSignature::timestamp() const
{
	return QDateTime();
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

bool SecureMessage::canSignMultiple() const
{
	return false;
}

void SecureMessage::setEnableBundleSigner(bool b)
{
	Q_UNUSED(b);
}

void SecureMessage::setFormat(Format f)
{
	Q_UNUSED(f);
}

void SecureMessage::setRecipient(const SecureMessageKey &key)
{
	Q_UNUSED(key);
}

void SecureMessage::setRecipients(const SecureMessageKeyList &keys)
{
	Q_UNUSED(keys);
}

void SecureMessage::setSigner(const SecureMessageKey &key)
{
	Q_UNUSED(key);
}

void SecureMessage::setSigners(const SecureMessageKeyList &keys)
{
	Q_UNUSED(keys);
}

void SecureMessage::startEncrypt()
{
}

void SecureMessage::startDecrypt()
{
}

void SecureMessage::startSign(SignMode m)
{
	Q_UNUSED(m);
}

void SecureMessage::startVerify(const QSecureArray &sig)
{
	Q_UNUSED(sig);
}

void SecureMessage::startEncryptAndSign(Order o)
{
	Q_UNUSED(o);
}

void SecureMessage::startDecryptAndVerify(Order o)
{
	Q_UNUSED(o);
}

void SecureMessage::update(const QSecureArray &in)
{
	Q_UNUSED(in);
}

QSecureArray SecureMessage::read(int size)
{
	Q_UNUSED(size);
	return QSecureArray();
}

int SecureMessage::bytesAvailable() const
{
	return 0;
}

void SecureMessage::end()
{
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
	return ErrorUnknown;
}

QSecureArray SecureMessage::signature() const
{
	return QSecureArray();
}

bool SecureMessage::verifySuccess() const
{
	return false;
}

SecureMessageSignature SecureMessage::signer() const
{
	return SecureMessageSignature();
}

SecureMessageSignatureList SecureMessage::signers() const
{
	return SecureMessageSignatureList();
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

QString OpenPGP::diagnosticText() const
{
	return QString();
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

void SMIME::setPrivateKeys(const QValueList<PrivateKey> &keys)
{
	Q_UNUSED(keys);
}

}
