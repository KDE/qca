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
	return list;
    }
    
    Context *createContext(const QString &type)
    {
	if ( type == "random" )
	    return new botanRandomContext( this );
	else
	    return 0;
    }
};

QCA_EXPORT_PLUGIN(botanProvider);
