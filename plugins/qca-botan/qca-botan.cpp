/*
 * Copyright (C) 2004  Justin Karneges
 * Copyright (C) 2004  Brad Hards <bradh@frogmouth.net>
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
#include "qcaprovider.h"
#include <qstringlist.h>
#include <iostream>

#include <botan/rng.h>
#include <botan/md2.h>
#include <botan/md4.h>
#include <botan/md5.h>
#include <botan/sha160.h>
#include <botan/sha256.h>
#include <botan/sha_64.h>
#include <botan/rmd160.h>

#include <stdlib.h>

class botanRandomContext : public QCA::RandomContext
{
public:
    botanRandomContext(QCA::Provider *p) : RandomContext(p)
    {
    }
	
    Context *clone() const
    {
	return new botanRandomContext( *this );
    }
    
    QSecureArray nextBytes(int size, QCA::Random::Quality quality)
    {
	QSecureArray buf(size);
	Botan::Global_RNG::randomize( (Botan::byte*)buf.data(), buf.size(), lookup_quality(quality) );
	return buf;
    }

private:
    Botan::RNG_Quality lookup_quality( QCA::Random::Quality quality )
    {
	if ( QCA::Random::Nonce == quality )
	    return Botan::Nonce;
	else if ( QCA::Random::PublicValue == quality )
	    return Botan::PublicValue;
	else if ( QCA::Random::SessionKey == quality )
	    return Botan::SessionKey;
	else if ( QCA::Random::LongTermKey == quality )
	    return Botan::LongTermKey;
	else
	    // this can't happen, but insurance against an accidental
	    // addition of a value to the enum
	    return Botan::SessionKey;
    }
};

class BotanMD2Context : public QCA::HashContext
{
public:
    BotanMD2Context(QCA::Provider *p) : QCA::HashContext(p, "md2")
    {
	hashObj = new Botan::MD2;
    }

    ~BotanMD2Context()
    {
	delete hashObj;
    }

    Context *clone() const
    {
	return new BotanMD2Context(*this);
    }

    void clear()
    {
	hashObj->clear();
    }
    
    void update(const QSecureArray &a)
    {
	hashObj->update( (const Botan::byte*)a.data(), a.size() );
    }
    
    QSecureArray final()
    {
	QSecureArray a( hashObj->OUTPUT_LENGTH );
	hashObj->final( (Botan::byte *)a.data() );
	return a;
    }
    
private:
    Botan::MD2 *hashObj;
};	


class BotanMD4Context : public QCA::HashContext
{
public:
    BotanMD4Context(QCA::Provider *p) : QCA::HashContext(p, "md4")
    {
	hashObj = new Botan::MD4;
    }

    ~BotanMD4Context()
    {
	delete hashObj;
    }

    Context *clone() const
    {
	return new BotanMD4Context(*this);
    }

    void clear()
    {
	hashObj->clear();
    }
    
    void update(const QSecureArray &a)
    {
	hashObj->update( (const Botan::byte*)a.data(), a.size() );
    }
    
    QSecureArray final()
    {
	QSecureArray a( hashObj->OUTPUT_LENGTH );
	hashObj->final( (Botan::byte *)a.data() );
	return a;
    }
    
private:
    Botan::MD4 *hashObj;
};	


class BotanMD5Context : public QCA::HashContext
{
public:
    BotanMD5Context(QCA::Provider *p) : QCA::HashContext(p, "md5")
    {
	hashObj = new Botan::MD5;
    }

    ~BotanMD5Context()
    {
	delete hashObj;
    }

    Context *clone() const
    {
	return new BotanMD5Context(*this);
    }

    void clear()
    {
	hashObj->clear();
    }
    
    void update(const QSecureArray &a)
    {
	hashObj->update( (const Botan::byte*)a.data(), a.size() );
    }
    
    QSecureArray final()
    {
	QSecureArray a( hashObj->OUTPUT_LENGTH );
	hashObj->final( (Botan::byte *)a.data() );
	return a;
    }
    
private:
    Botan::MD5 *hashObj;
};	


class BotanSHA1Context : public QCA::HashContext
{
public:
    BotanSHA1Context(QCA::Provider *p) : QCA::HashContext(p, "sha1")
    {
	hashObj = new Botan::SHA_160;
    }

    ~BotanSHA1Context()
    {
	delete hashObj;
    }

    Context *clone() const
    {
	return new BotanSHA1Context(*this);
    }

    void clear()
    {
	hashObj->clear();
    }
    
    void update(const QSecureArray &a)
    {
	hashObj->update( (const Botan::byte*)a.data(), a.size() );
    }
    
    QSecureArray final()
    {
	QSecureArray a( hashObj->OUTPUT_LENGTH );
	hashObj->final( (Botan::byte *)a.data() );
	return a;
    }
    
private:
    Botan::SHA_160 *hashObj;
};	


class BotanSHA256Context : public QCA::HashContext
{
public:
    BotanSHA256Context(QCA::Provider *p) : QCA::HashContext(p, "sha256")
    {
	hashObj = new Botan::SHA_256;
    }

    ~BotanSHA256Context()
    {
	delete hashObj;
    }

    Context *clone() const
    {
	return new BotanSHA256Context(*this);
    }

    void clear()
    {
	hashObj->clear();
    }
    
    void update(const QSecureArray &a)
    {
	hashObj->update( (const Botan::byte*)a.data(), a.size() );
    }
    
    QSecureArray final()
    {
	QSecureArray a( hashObj->OUTPUT_LENGTH );
	hashObj->final( (Botan::byte *)a.data() );
	return a;
    }
    
private:
    Botan::SHA_256 *hashObj;
};	

class BotanSHA384Context : public QCA::HashContext
{
public:
    BotanSHA384Context(QCA::Provider *p) : QCA::HashContext(p, "sha384")
    {
	hashObj = new Botan::SHA_384;
    }

    ~BotanSHA384Context()
    {
	delete hashObj;
    }

    Context *clone() const
    {
	return new BotanSHA384Context(*this);
    }

    void clear()
    {
	hashObj->clear();
    }
    
    void update(const QSecureArray &a)
    {
	hashObj->update( (const Botan::byte*)a.data(), a.size() );
    }
    
    QSecureArray final()
    {
	QSecureArray a( hashObj->OUTPUT_LENGTH );
	hashObj->final( (Botan::byte *)a.data() );
	return a;
    }
    
private:
    Botan::SHA_384 *hashObj;
};	

class BotanSHA512Context : public QCA::HashContext
{
public:
    BotanSHA512Context(QCA::Provider *p) : QCA::HashContext(p, "sha512")
    {
	hashObj = new Botan::SHA_512;
    }

    ~BotanSHA512Context()
    {
	delete hashObj;
    }

    Context *clone() const
    {
	return new BotanSHA512Context(*this);
    }

    void clear()
    {
	hashObj->clear();
    }
    
    void update(const QSecureArray &a)
    {
	hashObj->update( (const Botan::byte*)a.data(), a.size() );
    }
    
    QSecureArray final()
    {
	QSecureArray a( hashObj->OUTPUT_LENGTH );
	hashObj->final( (Botan::byte *)a.data() );
	return a;
    }
    
private:
    Botan::SHA_512 *hashObj;
};	



class BotanRIPEMD160Context : public QCA::HashContext
{
public:
    BotanRIPEMD160Context(QCA::Provider *p) : QCA::HashContext(p, "ripemd160")
    {
	hashObj = new Botan::RIPEMD_160;
    }

    ~BotanRIPEMD160Context()
    {
	delete hashObj;
    }

    Context *clone() const
    {
	return new BotanRIPEMD160Context(*this);
    }

    void clear()
    {
	hashObj->clear();
    }
    
    void update(const QSecureArray &a)
    {
	hashObj->update( (const Botan::byte*)a.data(), a.size() );
    }
    
    QSecureArray final()
    {
	QSecureArray a( hashObj->OUTPUT_LENGTH );
	hashObj->final( (Botan::byte *)a.data() );
	return a;
    }
    
private:
    Botan::RIPEMD_160 *hashObj;
};	


class botanProvider : public QCA::Provider
{
public:
    void init()
    { 
	Botan::LibraryInitializer *init;
	init = new Botan::LibraryInitializer;
    }

    QString name() const
    {
	return "qca-botan";
    }
    
    QStringList features() const
    {
	QStringList list;
	list += "random";
	list += "md2";
	list += "md4";
	list += "md5";
	list += "sha1";
	list += "sha256";
	list += "sha384";
	list += "sha512";
	list += "ripemd160";
	return list;
    }
    
    Context *createContext(const QString &type)
    {
	if ( type == "random" )
	    return new botanRandomContext( this );
	else if ( type == "md2" )
	    return new BotanMD2Context( this );
	else if ( type == "md4" )
	    return new BotanMD4Context( this );
	else if ( type == "md5" )
	    return new BotanMD5Context( this );
	else if ( type == "sha1" )
	    return new BotanSHA1Context( this );
	else if ( type == "sha256" )
	    return new BotanSHA256Context( this );
	else if ( type == "sha384" )
	    return new BotanSHA384Context( this );
	else if ( type == "sha512" )
	    return new BotanSHA512Context( this );
	else if ( type == "ripemd160" )
	    return new BotanRIPEMD160Context( this );
	else
	    return 0;
    }
};

QCA_EXPORT_PLUGIN(botanProvider);
