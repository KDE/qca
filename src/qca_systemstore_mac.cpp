/*
 * qca_systemstore_mac.cpp - Qt Cryptographic Architecture
 * Copyright (C) 2004  Justin Karneges
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

#include "qca_systemstore.h"

#include "Carbon.h"
#include "Security/SecTrust.h"
#include "Security/SecCertificate.h"

namespace QCA {

bool qca_have_systemstore()
{
	return true;
}

Store qca_get_systemstore(const QString &provider)
{
	Store store(provider);
	CFArrayRef anchors;
	if(SecTrustCopyAnchorCertificates(&anchors) != 0)
		return store;
	for(int n = 0; n < CFArrayGetCount(anchors); ++n)
	{
		SecCertificateRef cr = (SecCertificateRef)CFArrayGetValueAtIndex(anchors, n);
		CSSM_DATA cssm;
		SecCertificateGetData(cr, &cssm);
		QByteArray der(cssm.Length);
		memcpy(der.data(), cssm.Data, cssm.Length);

		Certificate cert = Certificate::fromDER(der, provider);
		if(!cert.isNull())
			store.addCertificate(cert);
	}
	CFRelease(anchors);
	return store;
}

}
