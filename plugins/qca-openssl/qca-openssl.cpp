/*
 * Copyright (C) 2004  Justin Karneges
 * Copyright (C) 2004-2005  Brad Hards <bradh@frogmouth.net>
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

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <stdio.h>
#include <stdlib.h>
#include <iostream>

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

// comment this out if you'd rather use openssl 0.9.6
//#define OSSL_097

namespace opensslQCAPlugin {

//----------------------------------------------------------------------------
// Util
//----------------------------------------------------------------------------
static QSecureArray bio2buf(BIO *b)
{
	QSecureArray buf;
	while(1) {
		QSecureArray block(1024);
		int ret = BIO_read(b, block.data(), block.size());
		if(ret <= 0)
			break;
		block.resize(ret);
		buf.append(block);
		if(ret != 1024)
			break;
	}
	BIO_free(b);
	return buf;
}

static QBigInteger bn2bi(BIGNUM *n)
{
	QSecureArray buf(BN_num_bytes(n) + 1);
	buf[0] = 0; // positive
	BN_bn2bin(n, (unsigned char *)buf.data() + 1);
	return QBigInteger(buf);
}

static BIGNUM *bi2bn(const QBigInteger &n)
{
	QSecureArray buf = n.toArray();
	return BN_bin2bn((const unsigned char *)buf.data(), buf.size(), NULL);
}

static QSecureArray dsasig_der_to_raw(const QSecureArray &in)
{
	DSA_SIG *sig = DSA_SIG_new();
	const unsigned char *inp = (const unsigned char *)in.data();
	d2i_DSA_SIG(&sig, &inp, in.size());

	QSecureArray part_r(20);
	QSecureArray part_s(20);
	memset(part_r.data(), 0, 20);
	memset(part_s.data(), 0, 20);
	unsigned char *p = (unsigned char *)part_r.data();
	BN_bn2bin(sig->r, p);
	p = (unsigned char *)part_s.data();
	BN_bn2bin(sig->s, p);
	QSecureArray result;
	result.append(part_r);
	result.append(part_s);

	DSA_SIG_free(sig);
	return result;
}

static QSecureArray dsasig_raw_to_der(const QSecureArray &in)
{
	if(in.size() != 40)
		return QSecureArray();

	DSA_SIG *sig = DSA_SIG_new();
	QSecureArray part_r(20);
	QSecureArray part_s(20);
	memcpy(part_r.data(), in.data(), 20);
	memcpy(part_s.data(), in.data() + 20, 20);
	sig->r = BN_bin2bn((const unsigned char *)part_r.data(), part_r.size(), NULL);
	sig->s = BN_bin2bn((const unsigned char *)part_s.data(), part_s.size(), NULL);

	int len = i2d_DSA_SIG(sig, NULL);
	QSecureArray result(len);
	unsigned char *p = (unsigned char *)result.data();
	i2d_DSA_SIG(sig, &p);

	DSA_SIG_free(sig);
	return result;
}

static bool is_basic_constraint(QCA::ConstraintType t)
{
	bool basic = false;
	switch(t)
	{
		case QCA::DigitalSignature:
		case QCA::NonRepudiation:
		case QCA::KeyEncipherment:
		case QCA::DataEncipherment:
		case QCA::KeyAgreement:
		case QCA::KeyCertificateSign:
		case QCA::CRLSign:
		case QCA::EncipherOnly:
		case QCA::DecipherOnly:
			basic = true;
			break;

		case QCA::ServerAuth:
		case QCA::ClientAuth:
		case QCA::CodeSigning:
		case QCA::EmailProtection:
		case QCA::IPSecEndSystem:
		case QCA::IPSecTunnel:
		case QCA::IPSecUser:
		case QCA::TimeStamping:
		case QCA::OCSPSigning:
			break;
	}
	return basic;
}

static QCA::Constraints basic_only(const QCA::Constraints &list)
{
	QCA::Constraints out;
	for(int n = 0; n < list.count(); ++n)
	{
		if(is_basic_constraint(list[n]))
			out += list[n];
	}
	return out;
}

static QCA::Constraints ext_only(const QCA::Constraints &list)
{
	QCA::Constraints out;
	for(int n = 0; n < list.count(); ++n)
	{
		if(!is_basic_constraint(list[n]))
			out += list[n];
	}
	return out;
}

// logic from Botan
static QCA::Constraints find_constraints(const QCA::PKeyContext &key, const QCA::Constraints &orig)
{
	QCA::Constraints constraints;

	if(key.type() == QCA::PKey::RSA)
		constraints += QCA::KeyEncipherment;

	if(key.type() == QCA::PKey::DH)
		constraints += QCA::KeyAgreement;

	if(key.type() == QCA::PKey::RSA || key.type() == QCA::PKey::DSA)
	{
		constraints += QCA::DigitalSignature;
		constraints += QCA::NonRepudiation;
	}

	QCA::Constraints limits = basic_only(orig);
	QCA::Constraints the_rest = ext_only(orig);

	if(!limits.isEmpty())
	{
		QCA::Constraints reduced;
		for(int n = 0; n < constraints.count(); ++n)
		{
			if(limits.contains(constraints[n]))
				reduced += constraints[n];
		}
		constraints = reduced;
	}

	constraints += the_rest;

	return constraints;
}

static void try_add_name_item(X509_NAME **name, int nid, const QString &val)
{
	if(val.isEmpty())
		return;
	QByteArray buf = val.toLatin1();
	if(!(*name))
		*name = X509_NAME_new();
	X509_NAME_add_entry_by_NID(*name, nid, MBSTRING_ASC, (unsigned char *)buf.data(), buf.size(), -1, 0);
}

static X509_NAME *new_cert_name(const QCA::CertificateInfo &info)
{
	X509_NAME *name = 0;
	try_add_name_item(&name, NID_commonName, info.value(QCA::CommonName));
	try_add_name_item(&name, NID_countryName, info.value(QCA::Country));
	try_add_name_item(&name, NID_localityName, info.value(QCA::Locality));
	try_add_name_item(&name, NID_stateOrProvinceName, info.value(QCA::State));
	try_add_name_item(&name, NID_organizationName, info.value(QCA::Organization));
	try_add_name_item(&name, NID_organizationalUnitName, info.value(QCA::OrganizationalUnit));
	return name;
}

static void try_get_name_item(X509_NAME *name, int nid, QCA::CertificateInfoType t, QCA::CertificateInfo *info)
{
	int loc = X509_NAME_get_index_by_NID(name, nid, -1);
	if(loc == -1)
		return;
	X509_NAME_ENTRY *ne = X509_NAME_get_entry(name, loc);
	ASN1_STRING *data = X509_NAME_ENTRY_get_data(ne);
	QByteArray cs((const char *)data->data, data->length);
	info->insert(t, QString::fromLatin1(cs));
}

static QCA::CertificateInfo get_cert_name(X509_NAME *name)
{
	QCA::CertificateInfo info;
	try_get_name_item(name, NID_commonName, QCA::CommonName, &info);
	try_get_name_item(name, NID_countryName, QCA::Country, &info);
	try_get_name_item(name, NID_localityName, QCA::Locality, &info);
	try_get_name_item(name, NID_stateOrProvinceName, QCA::State, &info);
	try_get_name_item(name, NID_organizationName, QCA::Organization, &info);
	try_get_name_item(name, NID_organizationalUnitName, QCA::OrganizationalUnit, &info);
	return info;
}

static bool info_compare_item(const QCA::CertificateInfo &a, const QCA::CertificateInfo &b, QCA::CertificateInfoType t)
{
	if(a.contains(t) && b.contains(t) && a.value(t) == b.value(t))
		return true;
	return false;
}

static bool info_compare(const QCA::CertificateInfo &a, const QCA::CertificateInfo &b)
{
	if(!info_compare_item(a, b, QCA::CommonName))
		return false;
	if(!info_compare_item(a, b, QCA::Country))
		return false;
	if(!info_compare_item(a, b, QCA::Locality))
		return false;
	if(!info_compare_item(a, b, QCA::State))
		return false;
	if(!info_compare_item(a, b, QCA::Organization))
		return false;
	if(!info_compare_item(a, b, QCA::OrganizationalUnit))
		return false;
	return true;
}

static X509_EXTENSION *new_subject_key_id(X509 *cert)
{
	X509V3_CTX ctx;
	X509V3_set_ctx_nodb(&ctx);
	X509V3_set_ctx(&ctx, NULL, cert, NULL, NULL, 0);
	X509_EXTENSION *ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_key_identifier, "hash");
	return ex;
}

static X509_EXTENSION *new_basic_constraints(bool ca, int pathlen)
{
	BASIC_CONSTRAINTS *bs = BASIC_CONSTRAINTS_new();
	bs->ca = (ca ? 1: 0);
	bs->pathlen = ASN1_INTEGER_new();
	ASN1_INTEGER_set(bs->pathlen, pathlen);

	X509_EXTENSION *ex = X509V3_EXT_i2d(NID_basic_constraints, 1, bs); // 1 = critical
	BASIC_CONSTRAINTS_free(bs);
	return ex;
}

static void get_basic_constraints(X509_EXTENSION *ex, bool *ca, int *pathlen)
{
	BASIC_CONSTRAINTS *bs = (BASIC_CONSTRAINTS *)X509V3_EXT_d2i(ex);
	*ca = (bs->ca ? true: false);
	if(bs->pathlen)
		*pathlen = ASN1_INTEGER_get(bs->pathlen);
	else
		*pathlen = 0;
	BASIC_CONSTRAINTS_free(bs);
}

enum ConstraintBit
{
	Bit_DigitalSignature   = 0,
	Bit_NonRepudiation     = 1,
	Bit_KeyEncipherment    = 2,
	Bit_DataEncipherment   = 3,
	Bit_KeyAgreement       = 4,
	Bit_KeyCertificateSign = 5,
	Bit_CRLSign            = 6,
	Bit_EncipherOnly       = 7,
	Bit_DecipherOnly       = 8
};

static QByteArray ipaddress_string_to_bytes(const QString &)
{
	return QByteArray(4, 0);
}

static GENERAL_NAME *new_general_name(QCA::CertificateInfoType t, const QString &val)
{
	GENERAL_NAME *name;
	switch(t)
	{
		case QCA::Email:
		{
			QByteArray buf = val.toLatin1();

			ASN1_IA5STRING *str = M_ASN1_IA5STRING_new();
			ASN1_STRING_set((ASN1_STRING *)str, (unsigned char *)buf.data(), buf.size());

			name = GENERAL_NAME_new();
			name->type = GEN_EMAIL;
			name->d.rfc822Name = str;
			break;
		}
		case QCA::URI:
		{
			QByteArray buf = val.toLatin1();

			ASN1_IA5STRING *str = M_ASN1_IA5STRING_new();
			ASN1_STRING_set((ASN1_STRING *)str, (unsigned char *)buf.data(), buf.size());

			name = GENERAL_NAME_new();
			name->type = GEN_URI;
			name->d.uniformResourceIdentifier = str;
			break;
		}
		case QCA::DNS:
		{
			QByteArray buf = val.toLatin1();

			ASN1_IA5STRING *str = M_ASN1_IA5STRING_new();
			ASN1_STRING_set((ASN1_STRING *)str, (unsigned char *)buf.data(), buf.size());

			name = GENERAL_NAME_new();
			name->type = GEN_DNS;
			name->d.dNSName = str;
			break;
		}
		case QCA::IPAddress:
		{
			QByteArray buf = ipaddress_string_to_bytes(val);

			ASN1_OCTET_STRING *str = ASN1_OCTET_STRING_new();
			ASN1_STRING_set((ASN1_STRING *)str, (unsigned char *)buf.data(), buf.size());

			name = GENERAL_NAME_new();
			name->type = GEN_IPADD;
			name->d.iPAddress = str;
			break;
		}
		case QCA::XMPP:
		{
			QByteArray buf = val.toUtf8();

			ASN1_UTF8STRING *str = ASN1_UTF8STRING_new();
			ASN1_STRING_set((ASN1_STRING *)str, (unsigned char *)buf.data(), buf.size());

			ASN1_TYPE *at = ASN1_TYPE_new();
			at->type = V_ASN1_UTF8STRING;
			at->value.utf8string = str;

			OTHERNAME *other = OTHERNAME_new();
			other->type_id = OBJ_txt2obj("1.3.6.1.5.5.7.8.5", 1); // 1 = only accept dotted input
			other->value = at;

			name = GENERAL_NAME_new();
			name->type = GEN_OTHERNAME;
			name->d.otherName = other;
			break;
		}

		// the following are not alt_names
		case QCA::CommonName:
		case QCA::Organization:
		case QCA::OrganizationalUnit:
		case QCA::Locality:
		case QCA::State:
		case QCA::Country:
			break;
	}
	return name;
}

static void try_add_general_name(GENERAL_NAMES **gn, QCA::CertificateInfoType t, const QString &val)
{
	if(val.isEmpty())
		return;
	GENERAL_NAME *name = new_general_name(t, val);
	if(name)
	{
		if(!(*gn))
			*gn = sk_GENERAL_NAME_new_null();
		sk_GENERAL_NAME_push(*gn, name);
	}
}

static X509_EXTENSION *new_cert_subject_alt_name(const QCA::CertificateInfo &info)
{
	GENERAL_NAMES *gn = 0;
	try_add_general_name(&gn, QCA::Email, info.value(QCA::Email));
	try_add_general_name(&gn, QCA::URI, info.value(QCA::URI));
	try_add_general_name(&gn, QCA::DNS, info.value(QCA::DNS));
	try_add_general_name(&gn, QCA::IPAddress, info.value(QCA::IPAddress));
	try_add_general_name(&gn, QCA::XMPP, info.value(QCA::XMPP));
	if(!gn)
		return 0;

	X509_EXTENSION *ex = X509V3_EXT_i2d(NID_subject_alt_name, 0, gn);
	sk_GENERAL_NAME_pop_free(gn, GENERAL_NAME_free);
	return ex;
}

static GENERAL_NAME *find_general_name(GENERAL_NAMES *names, int type)
{
	GENERAL_NAME *gn = 0;
	for(int n = 0; n < sk_GENERAL_NAME_num(names); ++n)
	{
		GENERAL_NAME *i = sk_GENERAL_NAME_value(names, n);
		if(i->type == type)
		{
			gn = i;
			break;
		}
	}
	return gn;
}

static void try_get_general_name(GENERAL_NAMES *names, QCA::CertificateInfoType t, QCA::CertificateInfo *info)
{
	switch(t)
	{
		case QCA::Email:
		{
			GENERAL_NAME *gn = find_general_name(names, GEN_EMAIL);
			if(!gn)
				break;
			QByteArray cs((const char *)ASN1_STRING_data(gn->d.rfc822Name), ASN1_STRING_length(gn->d.rfc822Name));
			info->insert(t, QString::fromLatin1(cs));
			break;
		}
		case QCA::URI:
		{
			GENERAL_NAME *gn = find_general_name(names, GEN_URI);
			if(!gn)
				break;
			QByteArray cs((const char *)ASN1_STRING_data(gn->d.uniformResourceIdentifier), ASN1_STRING_length(gn->d.uniformResourceIdentifier));
			info->insert(t, QString::fromLatin1(cs));
			break;
		}
		case QCA::DNS:
		{
			GENERAL_NAME *gn = find_general_name(names, GEN_DNS);
			if(!gn)
				break;
			QByteArray cs((const char *)ASN1_STRING_data(gn->d.dNSName), ASN1_STRING_length(gn->d.dNSName));
			info->insert(t, QString::fromLatin1(cs));
			break;
		}
		case QCA::IPAddress:
		{
			GENERAL_NAME *gn = find_general_name(names, GEN_IPADD);
			if(!gn)
				break;

			ASN1_OCTET_STRING *str = gn->d.iPAddress;
			QByteArray buf((const char *)ASN1_STRING_data(str), ASN1_STRING_length(str));

			QString out;
			// IPv4 (TODO: handle IPv6)
			if(buf.size() == 4)
			{
				out = "0.0.0.0";
			}
			else
				break;

			info->insert(t, out);
			break;
		}
		case QCA::XMPP:
		{
			GENERAL_NAME *gn = find_general_name(names, GEN_OTHERNAME);
			if(!gn)
				break;

			OTHERNAME *other = gn->d.otherName;
			if(!other)
				break;

			ASN1_OBJECT *obj = OBJ_txt2obj("1.3.6.1.5.5.7.8.5", 1); // 1 = only accept dotted input
			if(OBJ_cmp(other->type_id, obj) != 0)
				break;
			ASN1_OBJECT_free(obj);

			ASN1_TYPE *at = other->value;
			if(at->type != V_ASN1_UTF8STRING)
				break;

			ASN1_UTF8STRING *str = at->value.utf8string;
			QByteArray buf((const char *)ASN1_STRING_data(str), ASN1_STRING_length(str));
			info->insert(t, QString::fromUtf8(buf));
			break;
		}

		// the following are not alt_names
		case QCA::CommonName:
		case QCA::Organization:
		case QCA::OrganizationalUnit:
		case QCA::Locality:
		case QCA::State:
		case QCA::Country:
			break;
	}
}

static QCA::CertificateInfo get_cert_subject_alt_name(X509_EXTENSION *ex)
{
	QCA::CertificateInfo info;
	GENERAL_NAMES *gn = (GENERAL_NAMES *)X509V3_EXT_d2i(ex);
	try_get_general_name(gn, QCA::Email, &info);
	try_get_general_name(gn, QCA::URI, &info);
	try_get_general_name(gn, QCA::DNS, &info);
	try_get_general_name(gn, QCA::IPAddress, &info);
	try_get_general_name(gn, QCA::XMPP, &info);
	GENERAL_NAMES_free(gn);
	return info;
}

static X509_EXTENSION *new_cert_key_usage(const QCA::Constraints &constraints)
{
	ASN1_BIT_STRING *keyusage = 0;
	for(int n = 0; n < constraints.count(); ++n)
	{
		int bit = -1;
		switch(constraints[n])
		{
			case QCA::DigitalSignature:
				bit = Bit_DigitalSignature;
				break;
			case QCA::NonRepudiation:
				bit = Bit_NonRepudiation;
				break;
			case QCA::KeyEncipherment:
				bit = Bit_KeyEncipherment;
				break;
			case QCA::DataEncipherment:
				bit = Bit_DataEncipherment;
				break;
			case QCA::KeyAgreement:
				bit = Bit_KeyAgreement;
				break;
			case QCA::KeyCertificateSign:
				bit = Bit_KeyCertificateSign;
				break;
			case QCA::CRLSign:
				bit = Bit_CRLSign;
				break;
			case QCA::EncipherOnly:
				bit = Bit_EncipherOnly;
				break;
			case QCA::DecipherOnly:
				bit = Bit_DecipherOnly;
				break;

			// the following are not basic key usage
			case QCA::ServerAuth:
			case QCA::ClientAuth:
			case QCA::CodeSigning:
			case QCA::EmailProtection:
			case QCA::IPSecEndSystem:
			case QCA::IPSecTunnel:
			case QCA::IPSecUser:
			case QCA::TimeStamping:
			case QCA::OCSPSigning:
				break;
		}
		if(bit != -1)
		{
			if(!keyusage)
				keyusage = ASN1_BIT_STRING_new();
			ASN1_BIT_STRING_set_bit(keyusage, bit, 1);
		}
	}
	if(!keyusage)
		return 0;

	X509_EXTENSION *ex = X509V3_EXT_i2d(NID_key_usage, 1, keyusage); // 1 = critical
	ASN1_BIT_STRING_free(keyusage);
	return ex;
}

static QCA::Constraints get_cert_key_usage(X509_EXTENSION *ex)
{
	QCA::Constraints constraints;
	int bit_table[9] =
	{
		QCA::DigitalSignature,
		QCA::NonRepudiation,
		QCA::KeyEncipherment,
		QCA::DataEncipherment,
		QCA::KeyAgreement,
		QCA::KeyCertificateSign,
		QCA::CRLSign,
		QCA::EncipherOnly,
		QCA::DecipherOnly
	};

	ASN1_BIT_STRING *keyusage = (ASN1_BIT_STRING *)X509V3_EXT_d2i(ex);
	for(int n = 0; n < 9; ++n)
	{
		if(ASN1_BIT_STRING_get_bit(keyusage, n))
			constraints += (QCA::ConstraintType)bit_table[n];
	}
	ASN1_BIT_STRING_free(keyusage);
	return constraints;
};

static X509_EXTENSION *new_cert_ext_key_usage(const QCA::Constraints &constraints)
{
	EXTENDED_KEY_USAGE *extkeyusage = 0;
	for(int n = 0; n < constraints.count(); ++n)
	{
		int nid = -1;
		switch(constraints[n])
		{
			case QCA::ServerAuth:
				nid = NID_server_auth;
				break;
			case QCA::ClientAuth:
				nid = NID_client_auth;
				break;
			case QCA::CodeSigning:
				nid = NID_code_sign;
				break;
			case QCA::EmailProtection:
				nid = NID_email_protect;
				break;
			case QCA::IPSecEndSystem:
				nid = NID_ipsecEndSystem;
				break;
			case QCA::IPSecTunnel:
				nid = NID_ipsecTunnel;
				break;
			case QCA::IPSecUser:
				nid = NID_ipsecUser;
				break;
			case QCA::TimeStamping:
				nid = NID_time_stamp;
				break;
			case QCA::OCSPSigning:
				nid = NID_OCSP_sign;
				break;

			// the following are not extended key usage
			case QCA::DigitalSignature:
			case QCA::NonRepudiation:
			case QCA::KeyEncipherment:
			case QCA::DataEncipherment:
			case QCA::KeyAgreement:
			case QCA::KeyCertificateSign:
			case QCA::CRLSign:
			case QCA::EncipherOnly:
			case QCA::DecipherOnly:
				break;
		}
		if(nid != -1)
		{
			if(!extkeyusage)
				extkeyusage = sk_ASN1_OBJECT_new_null();
			ASN1_OBJECT *obj = OBJ_nid2obj(nid);
			sk_ASN1_OBJECT_push(extkeyusage, obj);
		}
	}
	if(!extkeyusage)
		return 0;

	X509_EXTENSION *ex = X509V3_EXT_i2d(NID_ext_key_usage, 0, extkeyusage); // 0 = not critical
	sk_ASN1_OBJECT_pop_free(extkeyusage, ASN1_OBJECT_free);
	return ex;
}

static QCA::Constraints get_cert_ext_key_usage(X509_EXTENSION *ex)
{
	QCA::Constraints constraints;

	EXTENDED_KEY_USAGE *extkeyusage = (EXTENDED_KEY_USAGE *)X509V3_EXT_d2i(ex);
	for(int n = 0; n < sk_ASN1_OBJECT_num(extkeyusage); ++n)
	{
		ASN1_OBJECT *obj = sk_ASN1_OBJECT_value(extkeyusage, n);
		int nid = OBJ_obj2nid(obj);
		if(nid == NID_undef)
			continue;

		int t = -1;
		switch(nid)
		{
			case NID_server_auth:
				t = QCA::ServerAuth;
				break;
			case NID_client_auth:
				t = QCA::ClientAuth;
				break;
			case NID_code_sign:
				t = QCA::CodeSigning;
				break;
			case NID_email_protect:
				t = QCA::EmailProtection;
				break;
			case NID_ipsecEndSystem:
				t = QCA::IPSecEndSystem;
				break;
			case NID_ipsecTunnel:
				t = QCA::IPSecTunnel;
				break;
			case NID_ipsecUser:
				t = QCA::IPSecUser;
				break;
			case NID_time_stamp:
				t = QCA::TimeStamping;
				break;
			case NID_OCSP_sign:
				t = QCA::OCSPSigning;
				break;
		};

		if(t == -1)
			continue;

		constraints.append((QCA::ConstraintType)t);
	}
	sk_ASN1_OBJECT_pop_free(extkeyusage, ASN1_OBJECT_free);
	return constraints;
};

static X509_EXTENSION *new_cert_policies(const QStringList &policies)
{
	STACK_OF(POLICYINFO) *pols = 0;
	for(int n = 0; n < policies.count(); ++n)
	{
		QByteArray cs = policies[n].toLatin1();
		ASN1_OBJECT *obj = OBJ_txt2obj(cs.data(), 1); // 1 = only accept dotted input
		if(!obj)
			continue;
		if(!pols)
			pols = sk_POLICYINFO_new_null();
		POLICYINFO *pol = POLICYINFO_new();
		pol->policyid = obj;
		sk_POLICYINFO_push(pols, pol);
	}
	if(!pols)
		return 0;

	X509_EXTENSION *ex = X509V3_EXT_i2d(NID_certificate_policies, 0, pols); // 0 = not critical
	sk_POLICYINFO_pop_free(pols, POLICYINFO_free);
	return ex;
}

static QStringList get_cert_policies(X509_EXTENSION *ex)
{
	QStringList out;
	STACK_OF(POLICYINFO) *pols = (STACK_OF(POLICYINFO) *)X509V3_EXT_d2i(ex);
	for(int n = 0; n < sk_POLICYINFO_num(pols); ++n)
	{
		POLICYINFO *pol = sk_POLICYINFO_value(pols, n);
		QByteArray buf(128, 0);
		OBJ_obj2txt((char *)buf.data(), buf.size(), pol->policyid, 1); // 1 = only accept dotted input
		out += QString::fromLatin1(buf);
	}
	sk_POLICYINFO_pop_free(pols, POLICYINFO_free);
	return out;
}

static QCA::Validity convert_verify_error(int err)
{
	// TODO: ErrorExpiredCA
	QCA::Validity rc;
	switch(err)
	{
		case X509_V_ERR_CERT_REJECTED:
			rc = QCA::ErrorRejected;
			break;
		case X509_V_ERR_CERT_UNTRUSTED:
			rc = QCA::ErrorUntrusted;
			break;
		case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
		case X509_V_ERR_CERT_SIGNATURE_FAILURE:
		case X509_V_ERR_CRL_SIGNATURE_FAILURE:
		case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
		case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
			rc = QCA::ErrorSignatureFailed;
			break;
		case X509_V_ERR_INVALID_CA:
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
		case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
		case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
			rc = QCA::ErrorInvalidCA;
			break;
		case X509_V_ERR_INVALID_PURPOSE:  // note: not used by store verify
			rc = QCA::ErrorInvalidPurpose;
			break;
		case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
		case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
			rc = QCA::ErrorSelfSigned;
			break;
		case X509_V_ERR_CERT_REVOKED:
			rc = QCA::ErrorRevoked;
			break;
		case X509_V_ERR_PATH_LENGTH_EXCEEDED:
			rc = QCA::ErrorPathLengthExceeded;
			break;
		case X509_V_ERR_CERT_NOT_YET_VALID:
		case X509_V_ERR_CERT_HAS_EXPIRED:
		case X509_V_ERR_CRL_NOT_YET_VALID:
		case X509_V_ERR_CRL_HAS_EXPIRED:
		case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
		case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
		case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
		case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
			rc = QCA::ErrorExpired;
			break;
		case X509_V_ERR_APPLICATION_VERIFICATION:
		case X509_V_ERR_OUT_OF_MEM:
		case X509_V_ERR_UNABLE_TO_GET_CRL:
		case X509_V_ERR_CERT_CHAIN_TOO_LONG:
		default:
			rc = QCA::ErrorValidityUnknown;
			break;
	}
	return rc;
}


class opensslHashContext : public QCA::HashContext
{
public:
	opensslHashContext(const EVP_MD *algorithm, QCA::Provider *p, const QString &type) : QCA::HashContext(p, type)
	{
		m_algorithm = algorithm;
		clear();
	};

    void clear()
    {
	EVP_DigestInit( &m_context, m_algorithm );
    }
    
    void update(const QSecureArray &a)
    {
	EVP_DigestUpdate( &m_context, (unsigned char*)a.data(), a.size() );
    }
    
    QSecureArray final()
    {
	QSecureArray a( EVP_MD_size( m_algorithm ) );
	EVP_DigestFinal( &m_context, (unsigned char*)a.data(), 0 );
	return a;
    }

    Context *clone() const
    {
	return new opensslHashContext(*this);
    }
    
protected:
    const EVP_MD *m_algorithm;
    EVP_MD_CTX m_context;
};	



class opensslHMACContext : public QCA::MACContext
{
public:
  opensslHMACContext(const EVP_MD *algorithm, QCA::Provider *p, const QString &type) : QCA::MACContext(p, type)
    {
	m_algorithm = algorithm;
	HMAC_CTX_init( &m_context );
    };

    void setup(const QCA::SymmetricKey &key)
    {
	HMAC_Init_ex( &m_context, key.data(), key.size(), m_algorithm, 0 );
    }
    
    QCA::KeyLength keyLength() const
    {
	return anyKeyLength();
    }

    void update(const QSecureArray &a)
    {
	HMAC_Update( &m_context, (unsigned char *)a.data(), a.size() );
    }
    
    void final( QSecureArray *out)
    {
	out->resize( EVP_MD_size( m_algorithm ) );
	HMAC_Final(&m_context, (unsigned char *)out->data(), 0 );
	HMAC_CTX_cleanup(&m_context);
    }

    Context *clone() const
    {
	return new opensslHMACContext(*this);
    }
    
protected:
    HMAC_CTX m_context;
    const EVP_MD *m_algorithm;
};

//----------------------------------------------------------------------------
// EVPKey
//----------------------------------------------------------------------------

// note: this class squelches processing errors, since QCA doesn't care about them
class EVPKey
{
public:
	enum State { Idle, SignActive, SignError, VerifyActive, VerifyError };
	EVP_PKEY *pkey;
	EVP_MD_CTX mdctx;
	State state;

	EVPKey()
	{
		pkey = 0;
		state = Idle;
	}

	EVPKey(const EVPKey &from)
	{
		pkey = from.pkey;
		CRYPTO_add(&pkey->references, 1, CRYPTO_LOCK_EVP_PKEY);
		state = Idle;
	}

	~EVPKey()
	{
		reset();
	}

	void reset()
	{
		if(pkey)
			EVP_PKEY_free(pkey);
		pkey = 0;
	}

	void startSign(const EVP_MD *type)
	{
		if(!type)
		{
			state = SignError;
			return;
		}

		state = SignActive;
		EVP_MD_CTX_init(&mdctx);
		if(!EVP_SignInit_ex(&mdctx, type, NULL))
			state = SignError;
	}

	void startVerify(const EVP_MD *type)
	{
		if(!type)
		{
			state = VerifyError;
			return;
		}

		state = VerifyActive;
		EVP_MD_CTX_init(&mdctx);
		if(!EVP_VerifyInit_ex(&mdctx, type, NULL))
			state = VerifyError;
	}

	void update(const QSecureArray &in)
	{
		if(state == SignActive)
		{
			if(!EVP_SignUpdate(&mdctx, in.data(), (unsigned int)in.size()))
				state = SignError;
		}
		else if(state == VerifyActive)
		{
			if(!EVP_VerifyUpdate(&mdctx, in.data(), (unsigned int)in.size()))
				state = VerifyError;
		}
	}

	QSecureArray endSign()
	{
		if(state == SignActive)
		{
			QSecureArray out(EVP_PKEY_size(pkey));
			unsigned int len = out.size();
			if(!EVP_SignFinal(&mdctx, (unsigned char *)out.data(), &len, pkey))
			{
				state = SignError;
				return QSecureArray();
			}
			out.resize(len);
			state = Idle;
			return out;
		}
		else
			return QSecureArray();
	}

	bool endVerify(const QSecureArray &sig)
	{
		if(state == VerifyActive)
		{
			if(EVP_VerifyFinal(&mdctx, (unsigned char *)sig.data(), (unsigned int)sig.size(), pkey) != 1)
			{
				state = VerifyError;
				return false;
			}
			state = Idle;
			return true;
		}
		else
			return false;
	}
};

//----------------------------------------------------------------------------
// MyDLGroup
//----------------------------------------------------------------------------

// IETF primes from Botan
const char* IETF_1024_PRIME =
	"FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
	"29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
	"EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
	"E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
	"EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381"
	"FFFFFFFF FFFFFFFF";

const char* IETF_2048_PRIME =
	"FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
	"29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
	"EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
	"E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
	"EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D"
	"C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F"
	"83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D"
	"670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B"
	"E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9"
	"DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510"
	"15728E5A 8AACAA68 FFFFFFFF FFFFFFFF";
	
const char* IETF_4096_PRIME =
	"FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
	"29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
	"EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
	"E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
	"EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D"
	"C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F"
	"83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D"
	"670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B"
	"E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9"
	"DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510"
	"15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64"
	"ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7"
	"ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B"
	"F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C"
	"BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31"
	"43DB5BFC E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7"
	"88719A10 BDBA5B26 99C32718 6AF4E23C 1A946834 B6150BDA"
	"2583E9CA 2AD44CE8 DBBBC2DB 04DE8EF9 2E8EFC14 1FBECAA6"
	"287C5947 4E6BC05D 99B2964F A090C3A2 233BA186 515BE7ED"
	"1F612970 CEE2D7AF B81BDD76 2170481C D0069127 D5B05AA9"
	"93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34063199"
	"FFFFFFFF FFFFFFFF";

// JCE seeds from Botan
const char* JCE_512_SEED = "B869C82B 35D70E1B 1FF91B28 E37A62EC DC34409B";
const int JCE_512_COUNTER = 123;

const char* JCE_768_SEED = "77D0F8C4 DAD15EB8 C4F2F8D6 726CEFD9 6D5BB399";
const int JCE_768_COUNTER = 263;

const char* JCE_1024_SEED = "8D515589 4229D5E6 89EE01E6 018A237E 2CAE64CD";
const int JCE_1024_COUNTER = 92;

static QByteArray dehex(const QString &hex)
{
	QString str;
	for(int n = 0; n < hex.length(); ++n)
	{
		if(hex[n] != ' ')
			str += hex[n];
	}
	return QCA::hexToArray(str);
}

static QBigInteger decode(const QString &prime)
{
	QByteArray a(1, 0); // 1 byte of zero padding
	a.append(dehex(prime));
	return QBigInteger(QSecureArray(a));
}

static QByteArray decode_seed(const QString &hex_seed)
{
	return dehex(hex_seed);
}

class DLParams
{
public:
	QBigInteger p, q, g;
};

static bool make_dlgroup(const QByteArray &seed, int bits, int counter, DLParams *params)
{
	int ret_counter;
	DSA *dsa = DSA_generate_parameters(bits, (unsigned char *)seed.data(), seed.size(), &ret_counter, NULL, NULL, NULL);
	if(!dsa)
		return false;
	if(ret_counter != counter)
		return false;
	params->p = bn2bi(dsa->p);
	params->q = bn2bi(dsa->q);
	params->g = bn2bi(dsa->g);
	DSA_free(dsa);
	return true;
}

static bool get_dlgroup(const QBigInteger &p, const QBigInteger &g, DLParams *params)
{
	params->p = p;
	params->q = QBigInteger(0);
	params->g = g;
	return true;
}

class DLGroupMaker : public QThread
{
	Q_OBJECT
public:
	QCA::DLGroupSet set;
	bool ok;
	DLParams params;

	DLGroupMaker(QCA::DLGroupSet _set)
	{
		set = _set;
	}

	~DLGroupMaker()
	{
		wait();
	}

	virtual void run()
	{
		if(set == QCA::DSA_512)
			ok = make_dlgroup(decode_seed(JCE_512_SEED), 512, JCE_512_COUNTER, &params);
		else if(set == QCA::DSA_768)
			ok = make_dlgroup(decode_seed(JCE_768_SEED), 768, JCE_768_COUNTER, &params);
		else if(set == QCA::DSA_1024)
			ok = make_dlgroup(decode_seed(JCE_1024_SEED), 1024, JCE_1024_COUNTER, &params);
		else if(set == QCA::IETF_1024)
			ok = get_dlgroup(decode(IETF_1024_PRIME), 2, &params);
		else if(set == QCA::IETF_2048)
			ok = get_dlgroup(decode(IETF_2048_PRIME), 2, &params);
		else if(set == QCA::IETF_4096)
			ok = get_dlgroup(decode(IETF_4096_PRIME), 2, &params);
		else
			ok = false;
	}
};

class MyDLGroup : public QCA::DLGroupContext
{
	Q_OBJECT
public:
	DLGroupMaker *gm;
	bool wasBlocking;
	DLParams params;
	bool empty;

	MyDLGroup(QCA::Provider *p) : QCA::DLGroupContext(p)
	{
		gm = 0;
		empty = true;
	}

	MyDLGroup(const MyDLGroup &from) : QCA::DLGroupContext(from.provider())
	{
		gm = 0;
		empty = true;
	}

	~MyDLGroup()
	{
		delete gm;
	}

	virtual Context *clone() const
	{
		return new MyDLGroup(*this);
	}

	virtual QList<QCA::DLGroupSet> supportedGroupSets() const
	{
		QList<QCA::DLGroupSet> list;
		list += QCA::DSA_512;
		list += QCA::DSA_768;
		list += QCA::DSA_1024;
		list += QCA::IETF_1024;
		list += QCA::IETF_2048;
		list += QCA::IETF_4096;
		return list;
	}

	virtual bool isNull() const
	{
		return empty;
	}

	virtual void fetchGroup(QCA::DLGroupSet set, bool block)
	{
		params = DLParams();
		empty = true;

		gm = new DLGroupMaker(set);
		wasBlocking = block;
		if(block)
		{
			gm->run();
			gm_finished();
		}
		else
		{
			connect(gm, SIGNAL(finished()), SLOT(gm_finished()));
			gm->start();
		}
	}

	virtual void getResult(QBigInteger *p, QBigInteger *q, QBigInteger *g) const
	{
		*p = params.p;
		*q = params.q;
		*g = params.g;
	}

private slots:
	void gm_finished()
	{
		bool ok = gm->ok;
		if(ok)
		{
			params = gm->params;
			empty = false;
		}

		if(wasBlocking)
			delete gm;
		else
			gm->deleteLater();
		gm = 0;

		if(!wasBlocking)
			emit finished();
	}
};

//----------------------------------------------------------------------------
// RSAKey
//----------------------------------------------------------------------------
class RSAKeyMaker : public QThread
{
	Q_OBJECT
public:
	RSA *result;
	int bits, exp;

	RSAKeyMaker(int _bits, int _exp) : result(0), bits(_bits), exp(_exp)
	{
	}

	~RSAKeyMaker()
	{
		wait();
		if(result)
			RSA_free(result);
	}

	virtual void run()
	{
		RSA *rsa = RSA_generate_key(bits, exp, NULL, NULL);
		if(!rsa)
			return;
		result = rsa;
	}

	RSA *takeResult()
	{
		RSA *rsa = result;
		result = 0;
		return rsa;
	}
};

class RSAKey : public QCA::RSAContext
{
	Q_OBJECT
public:
	EVPKey evp;
	RSAKeyMaker *keymaker;
	bool wasBlocking;
	bool sec;

	RSAKey(QCA::Provider *p) : QCA::RSAContext(p)
	{
		keymaker = 0;
		sec = false;
	}

	RSAKey(const RSAKey &from) : QCA::RSAContext(from.provider()), evp(from.evp)
	{
		keymaker = 0;
		sec = from.sec;
	}

	~RSAKey()
	{
		delete keymaker;
	}

	virtual Context *clone() const
	{
		return new RSAKey(*this);
	}

	virtual bool isNull() const
	{
		return (evp.pkey ? false: true);
	}

	virtual bool isPrivate() const
	{
		return sec;
	}

	virtual void convertToPublic()
	{
		if(!sec)
			return;

		// extract the public key into DER format
		int len = i2d_RSAPublicKey(evp.pkey->pkey.rsa, NULL);
		QSecureArray result(len);
		unsigned char *p = (unsigned char *)result.data();
		i2d_RSAPublicKey(evp.pkey->pkey.rsa, &p);
		p = (unsigned char *)result.data();

		// put the DER public key back into openssl
		evp.reset();
		RSA *rsa;
#ifdef OSSL_097
		rsa = d2i_RSAPublicKey(NULL, (const unsigned char **)&p, result.size());
#else
		rsa = d2i_RSAPublicKey(NULL, (unsigned char **)&p, result.size());
#endif
		evp.pkey = EVP_PKEY_new();
		EVP_PKEY_assign_RSA(evp.pkey, rsa);
		sec = false;
	}

	virtual int maximumEncryptSize(QCA::EncryptionAlgorithm alg) const
	{
		RSA *rsa = evp.pkey->pkey.rsa;
		if(alg == QCA::EME_PKCS1v15)
			return RSA_size(rsa) - 11 - 1;
		else // oaep
			return RSA_size(rsa) - 41 - 1;
	}

	virtual QSecureArray encrypt(const QSecureArray &in, QCA::EncryptionAlgorithm alg) const
	{
		RSA *rsa = evp.pkey->pkey.rsa;

		QSecureArray buf = in;
		int max = maximumEncryptSize(alg);
		if(buf.size() > max)
			buf.resize(max);
		QSecureArray result(RSA_size(rsa));

		int pad;
		if(alg == QCA::EME_PKCS1v15)
			pad = RSA_PKCS1_PADDING;
		else // oaep
			pad = RSA_PKCS1_OAEP_PADDING;

		int ret = RSA_public_encrypt(buf.size(), (unsigned char *)buf.data(), (unsigned char *)result.data(), rsa, pad);
		if(ret < 0)
			return QSecureArray();
		result.resize(ret);

		return result;
	}

	virtual bool decrypt(const QSecureArray &in, QSecureArray *out, QCA::EncryptionAlgorithm alg) const
	{
		RSA *rsa = evp.pkey->pkey.rsa;

		QSecureArray result(RSA_size(rsa));

		int pad;
		if(alg == QCA::EME_PKCS1v15)
			pad = RSA_PKCS1_PADDING;
		else // oaep
			pad = RSA_PKCS1_OAEP_PADDING;

		int ret = RSA_private_decrypt(in.size(), (unsigned char *)in.data(), (unsigned char *)result.data(), rsa, pad);
		if(ret < 0)
			return false;
		result.resize(ret);

		*out = result;
		return true;
	}

	virtual void startSign(QCA::SignatureAlgorithm alg, QCA::SignatureFormat)
	{
		const EVP_MD *md = 0;
		if(alg == QCA::EMSA3_SHA1)
			md = EVP_sha1();
		else if(alg == QCA::EMSA3_MD5)
			md = EVP_md5();
		else if(alg == QCA::EMSA3_MD2)
			md = EVP_md2();
		else if(alg == QCA::EMSA3_RIPEMD160)
			md = EVP_ripemd160();
		evp.startSign(md);
	}

	virtual void startVerify(QCA::SignatureAlgorithm alg, QCA::SignatureFormat)
	{
		const EVP_MD *md = 0;
		if(alg == QCA::EMSA3_SHA1)
			md = EVP_sha1();
		else if(alg == QCA::EMSA3_MD5)
			md = EVP_md5();
		else if(alg == QCA::EMSA3_MD2)
			md = EVP_md2();
		else if(alg == QCA::EMSA3_RIPEMD160)
			md = EVP_ripemd160();
		evp.startVerify(md);
	}

	virtual void update(const QSecureArray &in)
	{
		evp.update(in);
	}

	virtual QSecureArray endSign()
	{
		return evp.endSign();
	}

	virtual bool endVerify(const QSecureArray &sig)
	{
		return evp.endVerify(sig);
	}

	virtual void createPrivate(int bits, int exp, bool block)
	{
		evp.reset();

		keymaker = new RSAKeyMaker(bits, exp);
		wasBlocking = block;
		if(block)
		{
			keymaker->run();
			km_finished();
		}
		else
		{
			connect(keymaker, SIGNAL(finished()), SLOT(km_finished()));
			keymaker->start();
		}
	}

	virtual void createPrivate(const QBigInteger &n, const QBigInteger &e, const QBigInteger &p, const QBigInteger &q, const QBigInteger &d)
	{
		evp.reset();

		RSA *rsa = RSA_new();
		rsa->n = bi2bn(n);
		rsa->e = bi2bn(e);
		rsa->p = bi2bn(p);
		rsa->q = bi2bn(q);
		rsa->d = bi2bn(d);

		if(!rsa->n || !rsa->e || !rsa->p || !rsa->q || !rsa->d)
		{
			RSA_free(rsa);
			return;
		}

		evp.pkey = EVP_PKEY_new();
		EVP_PKEY_assign_RSA(evp.pkey, rsa);
		sec = true;
	}

	virtual void createPublic(const QBigInteger &n, const QBigInteger &e)
	{
		evp.reset();

		RSA *rsa = RSA_new();
		rsa->n = bi2bn(n);
		rsa->e = bi2bn(e);

		if(!rsa->n || !rsa->e)
		{
			RSA_free(rsa);
			return;
		}

		evp.pkey = EVP_PKEY_new();
		EVP_PKEY_assign_RSA(evp.pkey, rsa);
		sec = false;
	}

	virtual QBigInteger n() const
	{
		return bn2bi(evp.pkey->pkey.rsa->n);
	}

	virtual QBigInteger e() const
	{
		return bn2bi(evp.pkey->pkey.rsa->e);
	}

	virtual QBigInteger p() const
	{
		return bn2bi(evp.pkey->pkey.rsa->p);
	}

	virtual QBigInteger q() const
	{
		return bn2bi(evp.pkey->pkey.rsa->q);
	}

	virtual QBigInteger d() const
	{
		return bn2bi(evp.pkey->pkey.rsa->d);
	}

private slots:
	void km_finished()
	{
		RSA *rsa = keymaker->takeResult();
		if(wasBlocking)
			delete keymaker;
		else
			keymaker->deleteLater();
		keymaker = 0;

		if(rsa)
		{
			evp.pkey = EVP_PKEY_new();
			EVP_PKEY_assign_RSA(evp.pkey, rsa);
			sec = true;
		}

		if(!wasBlocking)
			emit finished();
	}
};

//----------------------------------------------------------------------------
// DSAKey
//----------------------------------------------------------------------------
class DSAKeyMaker : public QThread
{
	Q_OBJECT
public:
	QCA::DLGroup domain;
	DSA *result;

	DSAKeyMaker(const QCA::DLGroup &_domain) : domain(_domain), result(0)
	{
	}

	~DSAKeyMaker()
	{
		wait();
		if(result)
			DSA_free(result);
	}

	virtual void run()
	{
		DSA *dsa = DSA_new();
		dsa->p = bi2bn(domain.p());
		dsa->q = bi2bn(domain.q());
		dsa->g = bi2bn(domain.g());
		if(!DSA_generate_key(dsa))
		{
			DSA_free(dsa);
			return;
		}
		result = dsa;
	}

	DSA *takeResult()
	{
		DSA *dsa = result;
		result = 0;
		return dsa;
	}
};

// note: DSA doesn't use SignatureAlgorithm, since EMSA1 is always assumed
class DSAKey : public QCA::DSAContext
{
	Q_OBJECT
public:
	EVPKey evp;
	DSAKeyMaker *keymaker;
	bool wasBlocking;
	bool transformsig;
	bool sec;

	DSAKey(QCA::Provider *p) : QCA::DSAContext(p)
	{
		keymaker = 0;
		sec = false;
	}

	DSAKey(const DSAKey &from) : QCA::DSAContext(from.provider()), evp(from.evp)
	{
		keymaker = 0;
		sec = from.sec;
	}

	~DSAKey()
	{
		delete keymaker;
	}

	virtual Context *clone() const
	{
		return new DSAKey(*this);
	}

	virtual bool isNull() const
	{
		return (evp.pkey ? false: true);
	}

	virtual bool isPrivate() const
	{
		return sec;
	}

	virtual void convertToPublic()
	{
		if(!sec)
			return;

		// extract the public key into DER format
		int len = i2d_DSAPublicKey(evp.pkey->pkey.dsa, NULL);
		QSecureArray result(len);
		unsigned char *p = (unsigned char *)result.data();
		i2d_DSAPublicKey(evp.pkey->pkey.dsa, &p);
		p = (unsigned char *)result.data();

		// put the DER public key back into openssl
		evp.reset();
		DSA *dsa;
#ifdef OSSL_097
		dsa = d2i_DSAPublicKey(NULL, (const unsigned char **)&p, result.size());
#else
		dsa = d2i_DSAPublicKey(NULL, (unsigned char **)&p, result.size());
#endif
		evp.pkey = EVP_PKEY_new();
		EVP_PKEY_assign_DSA(evp.pkey, dsa);
		sec = false;
	}

	virtual void startSign(QCA::SignatureAlgorithm, QCA::SignatureFormat format)
	{
		// openssl native format is DER, so transform otherwise
		if(format != QCA::DERSequence)
			transformsig = true;
		else
			transformsig = false;

		evp.startSign(EVP_dss1());
	}

	virtual void startVerify(QCA::SignatureAlgorithm, QCA::SignatureFormat format)
	{
		// openssl native format is DER, so transform otherwise
		if(format != QCA::DERSequence)
			transformsig = true;
		else
			transformsig = false;

		evp.startVerify(EVP_dss1());
	}

	virtual void update(const QSecureArray &in)
	{
		evp.update(in);
	}

	virtual QSecureArray endSign()
	{
		QSecureArray out = evp.endSign();
		if(transformsig)
			return dsasig_der_to_raw(out);
		else
			return out;
	}

	virtual bool endVerify(const QSecureArray &sig)
	{
		QSecureArray in;
		if(transformsig)
			in = dsasig_raw_to_der(sig);
		else
			in = sig;
		return evp.endVerify(in);
	}

	virtual void createPrivate(const QCA::DLGroup &domain, bool block)
	{
		evp.reset();

		keymaker = new DSAKeyMaker(domain);
		wasBlocking = block;
		if(block)
		{
			keymaker->run();
			km_finished();
		}
		else
		{
			connect(keymaker, SIGNAL(finished()), SLOT(km_finished()));
			keymaker->start();
		}
	}

	virtual void createPrivate(const QCA::DLGroup &domain, const QBigInteger &y, const QBigInteger &x)
	{
		evp.reset();

		DSA *dsa = DSA_new();
		dsa->p = bi2bn(domain.p());
		dsa->q = bi2bn(domain.q());
		dsa->g = bi2bn(domain.g());
		dsa->pub_key = bi2bn(y);
		dsa->priv_key = bi2bn(x);

		if(!dsa->p || !dsa->q || !dsa->g || !dsa->pub_key || !dsa->priv_key)
		{
			DSA_free(dsa);
			return;
		}

		evp.pkey = EVP_PKEY_new();
		EVP_PKEY_assign_DSA(evp.pkey, dsa);
		sec = true;
	}

	virtual void createPublic(const QCA::DLGroup &domain, const QBigInteger &y)
	{
		evp.reset();

		DSA *dsa = DSA_new();
		dsa->p = bi2bn(domain.p());
		dsa->q = bi2bn(domain.q());
		dsa->g = bi2bn(domain.g());
		dsa->pub_key = bi2bn(y);

		if(!dsa->p || !dsa->q || !dsa->g || !dsa->pub_key)
		{
			DSA_free(dsa);
			return;
		}

		evp.pkey = EVP_PKEY_new();
		EVP_PKEY_assign_DSA(evp.pkey, dsa);
		sec = false;
	}

	virtual QCA::DLGroup domain() const
	{
		return QCA::DLGroup(bn2bi(evp.pkey->pkey.dsa->p), bn2bi(evp.pkey->pkey.dsa->q), bn2bi(evp.pkey->pkey.dsa->g));
	}

	virtual QBigInteger y() const
	{
		return bn2bi(evp.pkey->pkey.dsa->pub_key);
	}

	virtual QBigInteger x() const
	{
		return bn2bi(evp.pkey->pkey.dsa->priv_key);
	}

private slots:
	void km_finished()
	{
		DSA *dsa = keymaker->takeResult();
		if(wasBlocking)
			delete keymaker;
		else
			keymaker->deleteLater();
		keymaker = 0;

		if(dsa)
		{
			evp.pkey = EVP_PKEY_new();
			EVP_PKEY_assign_DSA(evp.pkey, dsa);
			sec = true;
		}

		if(!wasBlocking)
			emit finished();
	}
};

//----------------------------------------------------------------------------
// DHKey
//----------------------------------------------------------------------------
class DHKeyMaker : public QThread
{
	Q_OBJECT
public:
	QCA::DLGroup domain;
	DH *result;

	DHKeyMaker(const QCA::DLGroup &_domain) : domain(_domain), result(0)
	{
	}

	~DHKeyMaker()
	{
		wait();
		if(result)
			DH_free(result);
	}

	virtual void run()
	{
		DH *dh = DH_new();
		dh->p = bi2bn(domain.p());
		dh->g = bi2bn(domain.g());
		if(!DH_generate_key(dh))
		{
			DH_free(dh);
			return;
		}
		result = dh;
	}

	DH *takeResult()
	{
		DH *dh = result;
		result = 0;
		return dh;
	}
};

class DHKey : public QCA::DHContext
{
	Q_OBJECT
public:
	EVPKey evp;
	DHKeyMaker *keymaker;
	bool wasBlocking;
	bool sec;

	DHKey(QCA::Provider *p) : QCA::DHContext(p)
	{
		keymaker = 0;
		sec = false;
	}

	DHKey(const DHKey &from) : QCA::DHContext(from.provider()), evp(from.evp)
	{
		keymaker = 0;
		sec = from.sec;
	}

	~DHKey()
	{
		delete keymaker;
	}

	virtual Context *clone() const
	{
		return new DHKey(*this);
	}

	virtual bool isNull() const
	{
		return (evp.pkey ? false: true);
	}

	virtual bool isPrivate() const
	{
		return sec;
	}

	virtual void convertToPublic()
	{
		if(!sec)
			return;

		DH *orig = evp.pkey->pkey.dh;
		DH *dh = DH_new();
		dh->p = BN_dup(orig->p);
		dh->g = BN_dup(orig->g);
		dh->pub_key = BN_dup(orig->pub_key);

		evp.reset();

		evp.pkey = EVP_PKEY_new();
		EVP_PKEY_assign_DH(evp.pkey, dh);
		sec = false;
	}

	virtual QCA::SymmetricKey deriveKey(const PKeyBase &theirs) const
	{
		DH *dh = evp.pkey->pkey.dh;
		DH *them = static_cast<const DHKey *>(&theirs)->evp.pkey->pkey.dh;
		QSecureArray result(DH_size(dh));
		int ret = DH_compute_key((unsigned char *)result.data(), them->pub_key, dh);
		if(ret <= 0)
			return QCA::SymmetricKey();
		result.resize(ret);
		return QCA::SymmetricKey(result);
	}

	virtual void createPrivate(const QCA::DLGroup &domain, bool block)
	{
		evp.reset();

		keymaker = new DHKeyMaker(domain);
		wasBlocking = block;
		if(block)
		{
			keymaker->run();
			km_finished();
		}
		else
		{
			connect(keymaker, SIGNAL(finished()), SLOT(km_finished()));
			keymaker->start();
		}
	}

	virtual void createPrivate(const QCA::DLGroup &domain, const QBigInteger &y, const QBigInteger &x)
	{
		evp.reset();

		DH *dh = DH_new();
		dh->p = bi2bn(domain.p());
		dh->g = bi2bn(domain.g());
		dh->pub_key = bi2bn(y);
		dh->priv_key = bi2bn(x);

		if(!dh->p || !dh->g || !dh->pub_key || !dh->priv_key)
		{
			DH_free(dh);
			return;
		}

		evp.pkey = EVP_PKEY_new();
		EVP_PKEY_assign_DH(evp.pkey, dh);
		sec = true;
	}

	virtual void createPublic(const QCA::DLGroup &domain, const QBigInteger &y)
	{
		evp.reset();

		DH *dh = DH_new();
		dh->p = bi2bn(domain.p());
		dh->g = bi2bn(domain.g());
		dh->pub_key = bi2bn(y);

		if(!dh->p || !dh->g || !dh->pub_key)
		{
			DH_free(dh);
			return;
		}

		evp.pkey = EVP_PKEY_new();
		EVP_PKEY_assign_DH(evp.pkey, dh);
		sec = false;
	}

	virtual QCA::DLGroup domain() const
	{
		return QCA::DLGroup(bn2bi(evp.pkey->pkey.dh->p), bn2bi(evp.pkey->pkey.dh->g));
	}

	virtual QBigInteger y() const
	{
		return bn2bi(evp.pkey->pkey.dh->pub_key);
	}

	virtual QBigInteger x() const
	{
		return bn2bi(evp.pkey->pkey.dh->priv_key);
	}

private slots:
	void km_finished()
	{
		DH *dh = keymaker->takeResult();
		if(wasBlocking)
			delete keymaker;
		else
			keymaker->deleteLater();
		keymaker = 0;

		if(dh)
		{
			evp.pkey = EVP_PKEY_new();
			EVP_PKEY_assign_DH(evp.pkey, dh);
			sec = true;
		}

		if(!wasBlocking)
			emit finished();
	}
};

//----------------------------------------------------------------------------
// MyPKeyContext
//----------------------------------------------------------------------------
class MyPKeyContext : public QCA::PKeyContext
{
public:
	QCA::PKeyBase *k;

	MyPKeyContext(QCA::Provider *p) : QCA::PKeyContext(p)
	{
		k = 0;
	}

	~MyPKeyContext()
	{
		delete k;
	}

	virtual Context *clone() const
	{
		MyPKeyContext *c = new MyPKeyContext(*this);
		c->k = (QCA::PKeyBase *)k->clone();
		return c;
	}

	virtual QList<QCA::PKey::Type> supportedTypes() const
	{
		QList<QCA::PKey::Type> list;
		list += QCA::PKey::RSA;
		list += QCA::PKey::DSA;
		list += QCA::PKey::DH;
		return list;
	}

	virtual QList<QCA::PKey::Type> supportedIOTypes() const
	{
		QList<QCA::PKey::Type> list;
		list += QCA::PKey::RSA;
		list += QCA::PKey::DSA;
		return list;
	}

	virtual QList<QCA::PBEAlgorithm> supportedPBEAlgorithms() const
	{
		QList<QCA::PBEAlgorithm> list;
		list += QCA::PBES2_DES_SHA1;
		list += QCA::PBES2_TripleDES_SHA1;
		return list;
	}

	virtual QCA::PKeyBase *key()
	{
		return k;
	}

	virtual const QCA::PKeyBase *key() const
	{
		return k;
	}

	virtual QCA::PKey::Type type() const
	{
		QString str = k->type();
		if(str == "rsa")
			return QCA::PKey::RSA;
		else if(str == "dsa")
			return QCA::PKey::DSA;
		else
			return QCA::PKey::DH;
	}

	virtual void setKey(QCA::PKeyBase *key)
	{
		k = key;
	}

	EVP_PKEY *get_pkey() const
	{
		QCA::PKey::Type t = type();
		if(t == QCA::PKey::RSA)
			return static_cast<RSAKey *>(k)->evp.pkey;
		else if(t == QCA::PKey::DSA)
			return static_cast<DSAKey *>(k)->evp.pkey;
		else
			return static_cast<DHKey *>(k)->evp.pkey;
	}

	QCA::PKeyBase *pkeyToBase(EVP_PKEY *pkey, bool sec) const
	{
		QCA::PKeyBase *nk = 0;
		if(pkey->type == EVP_PKEY_RSA)
		{
			RSAKey *c = new RSAKey(provider());
			c->evp.pkey = pkey;
			c->sec = sec;
			nk = c;
		}
		else if(pkey->type == EVP_PKEY_DSA)
		{
			DSAKey *c = new DSAKey(provider());
			c->evp.pkey = pkey;
			c->sec = sec;
			nk = c;
		}
		else if(pkey->type == EVP_PKEY_DH)
		{
			DHKey *c = new DHKey(provider());
			c->evp.pkey = pkey;
			c->sec = sec;
			nk = c;
		}
		else
		{
			EVP_PKEY_free(pkey);
		}
		return nk;
	}

	static int passphrase_cb(char *buf, int size, int rwflag, void *u)
	{
		Q_UNUSED(buf);
		Q_UNUSED(size);
		Q_UNUSED(rwflag);
		Q_UNUSED(u);
		return 0;
	}

	virtual QSecureArray publicToDER() const
	{
		EVP_PKEY *pkey = get_pkey();

		// OpenSSL does not have DH import/export support
		if(pkey->type == EVP_PKEY_DH)
			return QSecureArray();

		BIO *bo = BIO_new(BIO_s_mem());
		i2d_PUBKEY_bio(bo, pkey);
		QSecureArray buf = bio2buf(bo);
		return buf;
	}

	virtual QString publicToPEM() const
	{
		EVP_PKEY *pkey = get_pkey();

		// OpenSSL does not have DH import/export support
		if(pkey->type == EVP_PKEY_DH)
			return QString();

		BIO *bo = BIO_new(BIO_s_mem());
		PEM_write_bio_PUBKEY(bo, pkey);
		QSecureArray buf = bio2buf(bo);
		return QString::fromLatin1(buf.toByteArray());
	}

	virtual QCA::ConvertResult publicFromDER(const QSecureArray &in)
	{
		delete k;
		k = 0;

		BIO *bi = BIO_new(BIO_s_mem());
		BIO_write(bi, in.data(), in.size());
		EVP_PKEY *pkey = d2i_PUBKEY_bio(bi, NULL);
		BIO_free(bi);

		if(!pkey)
			return QCA::ErrorDecode;

		k = pkeyToBase(pkey, false);
		if(k)
			return QCA::ConvertGood;
		else
			return QCA::ErrorDecode;
	}

	virtual QCA::ConvertResult publicFromPEM(const QString &s)
	{
		delete k;
		k = 0;

		QByteArray in = s.toLatin1();
		BIO *bi = BIO_new(BIO_s_mem());
		BIO_write(bi, in.data(), in.size());
		EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bi, NULL, NULL, NULL);
		BIO_free(bi);

		if(!pkey)
			return QCA::ErrorDecode;

		k = pkeyToBase(pkey, false);
		if(k)
			return QCA::ConvertGood;
		else
			return QCA::ErrorDecode;
	}

	virtual QSecureArray privateToDER(const QSecureArray &passphrase, QCA::PBEAlgorithm pbe) const
	{
		if(pbe == QCA::PBEDefault)
			pbe = QCA::PBES2_TripleDES_SHA1;

		const EVP_CIPHER *cipher = 0;
		if(pbe == QCA::PBES2_TripleDES_SHA1)
			cipher = EVP_des_ede3_cbc();
		else if(pbe == QCA::PBES2_DES_SHA1)
			cipher = EVP_des_cbc();

		if(!cipher)
			return QSecureArray();

		EVP_PKEY *pkey = get_pkey();

		// OpenSSL does not have DH import/export support
		if(pkey->type == EVP_PKEY_DH)
			return QSecureArray();

		BIO *bo = BIO_new(BIO_s_mem());
		if(!passphrase.isEmpty())
			i2d_PKCS8PrivateKey_bio(bo, pkey, cipher, NULL, 0, NULL, (void *)passphrase.data());
		else
			i2d_PKCS8PrivateKey_bio(bo, pkey, NULL, NULL, 0, NULL, NULL);
		QSecureArray buf = bio2buf(bo);
		return buf;
	}

	virtual QString privateToPEM(const QSecureArray &passphrase, QCA::PBEAlgorithm pbe) const
	{
		if(pbe == QCA::PBEDefault)
			pbe = QCA::PBES2_TripleDES_SHA1;

		const EVP_CIPHER *cipher = 0;
		if(pbe == QCA::PBES2_TripleDES_SHA1)
			cipher = EVP_des_ede3_cbc();
		else if(pbe == QCA::PBES2_DES_SHA1)
			cipher = EVP_des_cbc();

		if(!cipher)
			return QString();

		EVP_PKEY *pkey = get_pkey();

		// OpenSSL does not have DH import/export support
		if(pkey->type == EVP_PKEY_DH)
			return QString();

		BIO *bo = BIO_new(BIO_s_mem());
		if(!passphrase.isEmpty())
			PEM_write_bio_PKCS8PrivateKey(bo, pkey, cipher, NULL, 0, NULL, (void *)passphrase.data());
		else
			PEM_write_bio_PKCS8PrivateKey(bo, pkey, NULL, NULL, 0, NULL, NULL);
		QSecureArray buf = bio2buf(bo);
		return QString::fromLatin1(buf.toByteArray());
	}

	virtual QCA::ConvertResult privateFromDER(const QSecureArray &in, const QSecureArray &passphrase)
	{
		delete k;
		k = 0;

		BIO *bi = BIO_new(BIO_s_mem());
		BIO_write(bi, in.data(), in.size());
		EVP_PKEY *pkey;
		if(!passphrase.isEmpty())
			pkey = d2i_PKCS8PrivateKey_bio(bi, NULL, NULL, (void *)passphrase.data());
		else
			pkey = d2i_PKCS8PrivateKey_bio(bi, NULL, &passphrase_cb, NULL);
		BIO_free(bi);

		if(!pkey)
			return QCA::ErrorDecode;

		k = pkeyToBase(pkey, true);
		if(k)
			return QCA::ConvertGood;
		else
			return QCA::ErrorDecode;
	}

	virtual QCA::ConvertResult privateFromPEM(const QString &s, const QSecureArray &passphrase)
	{
		delete k;
		k = 0;

		QByteArray in = s.toLatin1();
		BIO *bi = BIO_new(BIO_s_mem());
		BIO_write(bi, in.data(), in.size());
		EVP_PKEY *pkey;
		if(!passphrase.isEmpty())
			pkey = PEM_read_bio_PrivateKey(bi, NULL, NULL, (void *)passphrase.data());
		else
			pkey = PEM_read_bio_PrivateKey(bi, NULL, &passphrase_cb, NULL);
		BIO_free(bi);

		if(!pkey)
			return QCA::ErrorDecode;

		k = pkeyToBase(pkey, true);
		if(k)
			return QCA::ConvertGood;
		else
			return QCA::ErrorDecode;
	}
};

//----------------------------------------------------------------------------
// MyCertContext
//----------------------------------------------------------------------------
class X509Item
{
public:
	X509 *cert;
	X509_REQ *req;
	X509_CRL *crl;

	enum Type { TypeCert, TypeReq, TypeCRL };

	X509Item()
	{
		cert = 0;
		req = 0;
		crl = 0;
	}

	X509Item(const X509Item &from)
	{
		cert = from.cert;
		req = from.req;
		crl = from.crl;

		if(cert)
			CRYPTO_add(&cert->references, 1, CRYPTO_LOCK_X509);
		if(req)
			CRYPTO_add(&req->references, 1, CRYPTO_LOCK_X509_REQ);
		if(crl)
			CRYPTO_add(&crl->references, 1, CRYPTO_LOCK_X509_CRL);
	}

	~X509Item()
	{
		reset();
	}

	void reset()
	{
		if(cert)
		{
			X509_free(cert);
			cert = 0;
		}
		if(req)
		{
			X509_REQ_free(req);
			req = 0;
		}
		if(crl)
		{
			X509_CRL_free(crl);
			crl = 0;
		}
	}

	bool isNull() const
	{
		return (!cert && !req && !crl);
	}

	QSecureArray toDER() const
	{
		BIO *bo = BIO_new(BIO_s_mem());
		if(cert)
			i2d_X509_bio(bo, cert);
		else if(req)
			i2d_X509_REQ_bio(bo, req);
		else if(crl)
			i2d_X509_CRL_bio(bo, crl);
		QSecureArray buf = bio2buf(bo);
		return buf;
	}

	QString toPEM() const
	{
		BIO *bo = BIO_new(BIO_s_mem());
		if(cert)
			PEM_write_bio_X509(bo, cert);
		else if(req)
			PEM_write_bio_X509_REQ(bo, req);
		else if(crl)
			PEM_write_bio_X509_CRL(bo, crl);
		QSecureArray buf = bio2buf(bo);
		return QString::fromLatin1(buf.toByteArray());
	}

	QCA::ConvertResult fromDER(const QSecureArray &in, Type t)
	{
		reset();

		BIO *bi = BIO_new(BIO_s_mem());
		BIO_write(bi, in.data(), in.size());

		if(t == TypeCert)
			cert = d2i_X509_bio(bi, NULL);
		else if(t == TypeReq)
			req = d2i_X509_REQ_bio(bi, NULL);
		else if(t == TypeCRL)
			crl = d2i_X509_CRL_bio(bi, NULL);

		BIO_free(bi);

		if(isNull())
			return QCA::ErrorDecode;

		return QCA::ConvertGood;
	}

	QCA::ConvertResult fromPEM(const QString &s, Type t)
	{
		reset();

		QByteArray in = s.toLatin1();
		BIO *bi = BIO_new(BIO_s_mem());
		BIO_write(bi, in.data(), in.size());

		if(t == TypeCert)
			cert = PEM_read_bio_X509(bi, NULL, NULL, NULL);
		else if(t == TypeReq)
			req = PEM_read_bio_X509_REQ(bi, NULL, NULL, NULL);
		else if(t == TypeCRL)
			crl = PEM_read_bio_X509_CRL(bi, NULL, NULL, NULL);

		BIO_free(bi);

		if(isNull())
			return QCA::ErrorDecode;

		return QCA::ConvertGood;
	}
};

// (taken from kdelibs) -- Justin
//
// This code is mostly taken from OpenSSL v0.9.5a
// by Eric Young
QDateTime ASN1_UTCTIME_QDateTime(ASN1_UTCTIME *tm, int *isGmt)
{
	QDateTime qdt;
	char *v;
	int gmt=0;
	int i;
	int y=0,M=0,d=0,h=0,m=0,s=0;
	QDate qdate;
	QTime qtime;

	i = tm->length;
	v = (char *)tm->data;

	if (i < 10) goto auq_err;
	if (v[i-1] == 'Z') gmt=1;
	for (i=0; i<10; i++)
		if ((v[i] > '9') || (v[i] < '0')) goto auq_err;
	y = (v[0]-'0')*10+(v[1]-'0');
	if (y < 50) y+=100;
	M = (v[2]-'0')*10+(v[3]-'0');
	if ((M > 12) || (M < 1)) goto auq_err;
	d = (v[4]-'0')*10+(v[5]-'0');
	h = (v[6]-'0')*10+(v[7]-'0');
	m =  (v[8]-'0')*10+(v[9]-'0');
	if (    (v[10] >= '0') && (v[10] <= '9') &&
		(v[11] >= '0') && (v[11] <= '9'))
		s = (v[10]-'0')*10+(v[11]-'0');

	// localize the date and display it.
	qdate.setYMD(y+1900, M, d);
	qtime.setHMS(h,m,s);
	qdt.setDate(qdate); qdt.setTime(qtime);
auq_err:
	if (isGmt) *isGmt = gmt;
	return qdt;
}

class MyCertContext : public QCA::CertContext
{
public:
	X509Item item;
	QCA::CertContextProps _props;

	MyCertContext(QCA::Provider *p) : QCA::CertContext(p)
	{
	}

	MyCertContext(const MyCertContext &from) : QCA::CertContext(from), item(from.item), _props(from._props)
	{
	}

	virtual Context *clone() const
	{
		return new MyCertContext(*this);
	}

	virtual QSecureArray toDER() const
	{
		return item.toDER();
	}

	virtual QString toPEM() const
	{
		return item.toPEM();
	}

	virtual QCA::ConvertResult fromDER(const QSecureArray &a)
	{
		_props = QCA::CertContextProps();
		QCA::ConvertResult r = item.fromDER(a, X509Item::TypeCert);
		if(r == QCA::ConvertGood)
			make_props();
		return r;
	}

	virtual QCA::ConvertResult fromPEM(const QString &s)
	{
		_props = QCA::CertContextProps();
		QCA::ConvertResult r = item.fromPEM(s, X509Item::TypeCert);
		if(r == QCA::ConvertGood)
			make_props();
		return r;
	}

	virtual bool createSelfSigned(const QCA::CertificateOptions &opts, const QCA::PKeyContext &priv)
	{
		_props = QCA::CertContextProps();
		item.reset();

		QCA::CertificateInfo info = opts.info();

		// constraints - logic from Botan
		QCA::Constraints constraints;
		if(opts.isCA())
		{
			constraints += QCA::KeyCertificateSign;
			constraints += QCA::CRLSign;
		}
		else
			constraints = find_constraints(priv, opts.constraints());

		EVP_PKEY *pk = static_cast<const MyPKeyContext *>(&priv)->get_pkey();
		X509_EXTENSION *ex;

		const EVP_MD *md;
		if(priv.type() == QCA::PKey::RSA)
			md = EVP_sha1();
		else if(priv.type() == QCA::PKey::DSA)
			md = EVP_dss1();
		else
			return false;

		// create
		X509 *x = X509_new();
		X509_set_version(x, 2);

		// serial
		BIGNUM *bn = bi2bn(opts.serialNumber());
		BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(x));
		BN_free(bn);

		// validity period
		ASN1_TIME_set(X509_get_notBefore(x), opts.notValidBefore().toTime_t());
		ASN1_TIME_set(X509_get_notAfter(x), opts.notValidAfter().toTime_t());

		// public key
		X509_set_pubkey(x, pk);

		// subject
		X509_NAME *name = new_cert_name(info);
		X509_set_subject_name(x, name);

		// issuer == subject
		X509_set_issuer_name(x, name); 

		// subject key id
		ex = new_subject_key_id(x);
		{
			X509_add_ext(x, ex, -1);
			X509_EXTENSION_free(ex);
		}

		// CA mode
		ex = new_basic_constraints(opts.isCA(), opts.pathLimit());
		if(ex)
		{
			X509_add_ext(x, ex, -1);
			X509_EXTENSION_free(ex);
		}

		// subject alt name
		ex = new_cert_subject_alt_name(info);
		if(ex)
		{
			X509_add_ext(x, ex, -1);
			X509_EXTENSION_free(ex);
		}

		// key usage
		ex = new_cert_key_usage(constraints);
		if(ex)
		{
			X509_add_ext(x, ex, -1);
			X509_EXTENSION_free(ex);
		}

		// extended key usage
		ex = new_cert_ext_key_usage(constraints);
		if(ex)
		{
			X509_add_ext(x, ex, -1);
			X509_EXTENSION_free(ex);
		}

		// policies
		ex = new_cert_policies(opts.policies());
		if(ex)
		{
			X509_add_ext(x, ex, -1);
			X509_EXTENSION_free(ex);
		}

		// finished
		X509_sign(x, pk, md);

		item.cert = x;
		make_props();
		return true;
	}

	virtual const QCA::CertContextProps *props() const
	{
		return &_props;
	}

	// does a new
	virtual QCA::PKeyContext *subjectPublicKey() const
	{
		MyPKeyContext *kc = new MyPKeyContext(provider());
		EVP_PKEY *pkey = X509_get_pubkey(item.cert);
		QCA::PKeyBase *kb = kc->pkeyToBase(pkey, false);
		kc->setKey(kb);
		return kc;
	}

	void make_props()
	{
		X509 *x = item.cert;
		QCA::CertContextProps p;

		p.version = X509_get_version(x);

		ASN1_INTEGER *ai = X509_get_serialNumber(x);
		if(ai)
		{
			char *rep = i2s_ASN1_INTEGER(NULL, ai);
			QString str = rep;
			OPENSSL_free(rep);
			p.serial.fromString(str);
		}

		p.start = ASN1_UTCTIME_QDateTime(X509_get_notBefore(x), NULL);
		p.end = ASN1_UTCTIME_QDateTime(X509_get_notAfter(x), NULL);

		p.subject = get_cert_name(X509_get_subject_name(x));
		p.issuer = get_cert_name(X509_get_issuer_name(x));

		p.isSelfSigned = info_compare(p.subject, p.issuer);

		p.isCA = false;
		p.pathLimit = 0;
		int pos = X509_get_ext_by_NID(x, NID_basic_constraints, -1);
		if(pos != -1)
		{
			X509_EXTENSION *ex = X509_get_ext(x, pos);
			if(ex)
				get_basic_constraints(ex, &p.isCA, &p.pathLimit);
		}

		pos = X509_get_ext_by_NID(x, NID_subject_alt_name, -1);
		if(pos != -1)
		{
			X509_EXTENSION *ex = X509_get_ext(x, pos);
			if(ex)
				p.subject.unite(get_cert_subject_alt_name(ex));
		}

		pos = X509_get_ext_by_NID(x, NID_key_usage, -1);
		if(pos != -1)
		{
			X509_EXTENSION *ex = X509_get_ext(x, pos);
			if(ex)
				p.constraints = get_cert_key_usage(ex);
		}

		pos = X509_get_ext_by_NID(x, NID_ext_key_usage, -1);
		if(pos != -1)
		{
			X509_EXTENSION *ex = X509_get_ext(x, pos);
			if(ex)
				p.constraints += get_cert_ext_key_usage(ex);
		}

		pos = X509_get_ext_by_NID(x, NID_certificate_policies, -1);
		if(pos != -1)
		{
			X509_EXTENSION *ex = X509_get_ext(x, pos);
			if(ex)
				p.policies = get_cert_policies(ex);
		}

		// TODO:
		//QSecureArray sig;
		//SignatureAlgorithm sigalgo;

		_props = p;
	}
};

//----------------------------------------------------------------------------
// MyCSRContext
//----------------------------------------------------------------------------
class MyCSRContext : public QCA::CSRContext
{
public:
	X509Item item;
	QCA::CertContextProps _props;

	MyCSRContext(QCA::Provider *p) : QCA::CSRContext(p)
	{
	}

	MyCSRContext(const MyCSRContext &from) : QCA::CSRContext(from), item(from.item), _props(from._props)
	{
	}

	virtual Context *clone() const
	{
		return new MyCSRContext(*this);
	}

	virtual QSecureArray toDER() const
	{
		return item.toDER();
	}

	virtual QString toPEM() const
	{
		return item.toPEM();
	}

	virtual QCA::ConvertResult fromDER(const QSecureArray &a)
	{
		_props = QCA::CertContextProps();
		QCA::ConvertResult r = item.fromDER(a, X509Item::TypeReq);
		if(r == QCA::ConvertGood)
			make_props();
		return r;
	}

	virtual QCA::ConvertResult fromPEM(const QString &s)
	{
		_props = QCA::CertContextProps();
		QCA::ConvertResult r = item.fromPEM(s, X509Item::TypeReq);
		if(r == QCA::ConvertGood)
			make_props();
		return r;
	}

	virtual bool canUseFormat(QCA::CertificateRequestFormat f) const
	{
		if(f == QCA::PKCS10)
			return true;
		return false;
	}

	virtual bool createRequest(const QCA::CertificateOptions &opts, const QCA::PKeyContext &priv)
	{
		_props = QCA::CertContextProps();
		item.reset();

		QCA::CertificateInfo info = opts.info();

		// constraints - logic from Botan
		QCA::Constraints constraints;
		if(opts.isCA())
		{
			constraints += QCA::KeyCertificateSign;
			constraints += QCA::CRLSign;
		}
		else
			constraints = find_constraints(priv, opts.constraints());

		EVP_PKEY *pk = static_cast<const MyPKeyContext *>(&priv)->get_pkey();
		X509_EXTENSION *ex;

		const EVP_MD *md;
		if(priv.type() == QCA::PKey::RSA)
			md = EVP_sha1();
		else if(priv.type() == QCA::PKey::DSA)
			md = EVP_dss1();
		else
			return false;

		// create
		X509_REQ *x = X509_REQ_new();

		// public key
		X509_REQ_set_pubkey(x, pk);

		// subject
		X509_NAME *name = new_cert_name(info);
		X509_REQ_set_subject_name(x, name);

		// challenge
		QByteArray cs = opts.challenge().toLatin1();
		if(!cs.isEmpty())
			X509_REQ_add1_attr_by_NID(x, NID_pkcs9_challengePassword, MBSTRING_UTF8, (const unsigned char *)cs.data(), -1);

		STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();

		// CA mode
		ex = new_basic_constraints(opts.isCA(), opts.pathLimit());
		if(ex)
			sk_X509_EXTENSION_push(exts, ex);

		// subject alt name
		ex = new_cert_subject_alt_name(info);
		if(ex)
			sk_X509_EXTENSION_push(exts, ex);

		// key usage
		ex = new_cert_key_usage(constraints);
		if(ex)
			sk_X509_EXTENSION_push(exts, ex);

		// extended key usage
		ex = new_cert_ext_key_usage(constraints);
		if(ex)
			sk_X509_EXTENSION_push(exts, ex);

		// policies
		ex = new_cert_policies(opts.policies());
		if(ex)
			sk_X509_EXTENSION_push(exts, ex);

		if(sk_X509_EXTENSION_num(exts) > 0)
			X509_REQ_add_extensions(x, exts);
		sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

		// finished
		X509_REQ_sign(x, pk, md);

		item.req = x;
		make_props();
		return true;
	}

	virtual const QCA::CertContextProps *props() const
	{
		return &_props;
	}

	virtual QCA::PKeyContext *subjectPublicKey() const // does a new
	{
		MyPKeyContext *kc = new MyPKeyContext(provider());
		EVP_PKEY *pkey = X509_REQ_get_pubkey(item.req);
		QCA::PKeyBase *kb = kc->pkeyToBase(pkey, false);
		kc->setKey(kb);
		return kc;
	}

	virtual QString toSPKAC() const
	{
		return QString();
	}

	virtual QCA::ConvertResult fromSPKAC(const QString &s)
	{
		Q_UNUSED(s);
		return QCA::ErrorDecode;
	}

	void make_props()
	{
		X509_REQ *x = item.req;
		QCA::CertContextProps p;

		// TODO: QString challenge;

		p.format = QCA::PKCS10;

		p.subject = get_cert_name(X509_REQ_get_subject_name(x));

		STACK_OF(X509_EXTENSION) *exts = X509_REQ_get_extensions(x);

		p.isCA = false;
		p.pathLimit = 0;
		int pos = X509v3_get_ext_by_NID(exts, NID_basic_constraints, -1);
		if(pos != -1)
		{
			X509_EXTENSION *ex = X509v3_get_ext(exts, pos);
			if(ex)
				get_basic_constraints(ex, &p.isCA, &p.pathLimit);
		}

		pos = X509v3_get_ext_by_NID(exts, NID_subject_alt_name, -1);
		if(pos != -1)
		{
			X509_EXTENSION *ex = X509v3_get_ext(exts, pos);
			if(ex)
				p.subject.unite(get_cert_subject_alt_name(ex));
		}

		pos = X509v3_get_ext_by_NID(exts, NID_key_usage, -1);
		if(pos != -1)
		{
			X509_EXTENSION *ex = X509v3_get_ext(exts, pos);
			if(ex)
				p.constraints = get_cert_key_usage(ex);
		}

		pos = X509v3_get_ext_by_NID(exts, NID_ext_key_usage, -1);
		if(pos != -1)
		{
			X509_EXTENSION *ex = X509v3_get_ext(exts, pos);
			if(ex)
				p.constraints += get_cert_ext_key_usage(ex);
		}

		pos = X509v3_get_ext_by_NID(exts, NID_certificate_policies, -1);
		if(pos != -1)
		{
			X509_EXTENSION *ex = X509v3_get_ext(exts, pos);
			if(ex)
				p.policies = get_cert_policies(ex);
		}

		sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

		// TODO:
		//QSecureArray sig;
		//SignatureAlgorithm sigalgo;

		_props = p;
	}
};

//----------------------------------------------------------------------------
// MyCRLContext
//----------------------------------------------------------------------------
class MyCRLContext : public QCA::CRLContext
{
public:
	X509Item item;

	MyCRLContext(QCA::Provider *p) : QCA::CRLContext(p)
	{
	}

	MyCRLContext(const MyCRLContext &from) : QCA::CRLContext(from), item(from.item)
	{
	}

	virtual Context *clone() const
	{
		return new MyCRLContext(*this);
	}

	virtual QSecureArray toDER() const
	{
		return item.toDER();
	}

	virtual QString toPEM() const
	{
		return item.toPEM();
	}

	virtual QCA::ConvertResult fromDER(const QSecureArray &a)
	{
		return item.fromDER(a, X509Item::TypeCRL);
	}

	virtual QCA::ConvertResult fromPEM(const QString &s)
	{
		return item.fromPEM(s, X509Item::TypeCRL);
	}

	virtual const QCA::CRLContextProps *props() const
	{
		return 0;
	}
};

//----------------------------------------------------------------------------
// MyStoreContext
//----------------------------------------------------------------------------
class MyStoreContext : public QCA::StoreContext
{
public:
	STACK_OF(X509) *trusted, *untrusted;
	QList<X509_CRL*> crl_list;

	MyStoreContext(QCA::Provider *p) : QCA::StoreContext(p)
	{
		trusted = sk_X509_new_null();
		untrusted = sk_X509_new_null();
	}

	MyStoreContext(const MyStoreContext &from) : QCA::StoreContext(from), crl_list(from.crl_list)
	{
		int n;

		// shallow copy of list items
		trusted = sk_X509_dup(from.trusted);
		for(n = 0; n < sk_X509_num(trusted); ++n)
		{
			X509 *x = sk_X509_value(trusted, n);
			CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509);
		}

		untrusted = sk_X509_dup(from.untrusted);
		for(n = 0; n < sk_X509_num(untrusted); ++n)
		{
			X509 *x = sk_X509_value(untrusted, n);
			CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509);
		}

		for(n = 0; n < crl_list.count(); ++n)
		{
			X509_CRL *x = crl_list[n];
			CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509_CRL);
		}
	}

	~MyStoreContext()
	{
		sk_X509_pop_free(trusted, X509_free);
		sk_X509_pop_free(untrusted, X509_free);
		for(int n = 0; n < crl_list.count(); ++n)
			X509_CRL_free(crl_list[n]);
	}

	virtual Context *clone() const
	{
		return new MyStoreContext(*this);
	}

	virtual void addCertificate(const QCA::CertContext &cert, QCA::Store::TrustMode t)
	{
		const MyCertContext *cc = static_cast<const MyCertContext *>(&cert);
		X509 *x = cc->item.cert;
		CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509);
		if(t == QCA::Store::Trusted)
			sk_X509_push(trusted, x);
		else
			sk_X509_push(untrusted, x);
	}

	virtual void addCRL(const QCA::CRLContext &crl)
	{
		const MyCRLContext *cc = static_cast<const MyCRLContext *>(&crl);
		X509_CRL *x = cc->item.crl;
		CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509_CRL);
		crl_list.append(x);
	}

	virtual QCA::Validity validate(const QCA::CertContext &cert, QCA::Store::UsageMode u) const
	{
		const MyCertContext *cc = static_cast<const MyCertContext *>(&cert);
		X509 *x = cc->item.cert;

		// verification happens through a store "context"
		X509_STORE_CTX *ctx = X509_STORE_CTX_new();

		// make a store of crls
		X509_STORE *store = X509_STORE_new();
		for(int n = 0; n < crl_list.count(); ++n)
			X509_STORE_add_crl(store, crl_list[n]);

		// the first initialization handles untrusted certs, crls, and target cert
		X509_STORE_CTX_init(ctx, store, x, untrusted);

		// this initializes the trusted certs
		X509_STORE_CTX_trusted_stack(ctx, trusted);

		// verify!
		int ret = X509_verify_cert(ctx);
		int err = -1;
		if(!ret)
			err = ctx->error;

		// cleanup
		X509_STORE_CTX_free(ctx);
		X509_STORE_free(store);

		if(!ret)
			return convert_verify_error(err);

		if(!usage_check(*cc, u))
			return QCA::ErrorInvalidPurpose;

		return QCA::ValidityGood;
	}

	virtual QList<QCA::CertContext*> certificates() const
	{
		QList<QCA::CertContext*> list;

		int n;
		for(n = 0; n < sk_X509_num(trusted); ++n)
		{
			X509 *x = sk_X509_value(trusted, n);

			MyCertContext *cc = new MyCertContext(provider());
			CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509);
			cc->item.cert = x;
			list.append(cc);
		}
		for(n = 0; n < sk_X509_num(untrusted); ++n)
		{
			X509 *x = sk_X509_value(untrusted, n);

			MyCertContext *cc = new MyCertContext(provider());
			CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509);
			cc->item.cert = x;
			list.append(cc);
		}

		return list;
	}

	virtual QList<QCA::CRLContext*> crls() const
	{
		QList<QCA::CRLContext*> list;

		for(int n = 0; n < crl_list.count(); ++n)
		{
			X509_CRL *x = crl_list[n];

			MyCRLContext *cc = new MyCRLContext(provider());
			CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509_CRL);
			cc->item.crl = x;
			list.append(cc);
		}

		return list;
	}

	virtual void append(const QCA::StoreContext &s)
	{
		const MyStoreContext *from = static_cast<const MyStoreContext *>(&s);
		int n;

		for(n = 0; n < sk_X509_num(from->trusted); ++n)
		{
			X509 *x = sk_X509_value(from->trusted, n);
			CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509);
			sk_X509_push(trusted, x);
		}

		for(n = 0; n < sk_X509_num(from->untrusted); ++n)
		{
			X509 *x = sk_X509_value(from->untrusted, n);
			CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509);
			sk_X509_push(untrusted, x);
		}

		for(n = 0; n < from->crl_list.count(); ++n)
		{
			X509_CRL *x = from->crl_list[n];
			CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509_CRL);
			crl_list.append(x);
		}
	}

	virtual bool canUsePKCS7() const
	{
		return false;
	}

	virtual QByteArray toPKCS7() const
	{
		return QByteArray();
	}

	virtual QCA::ConvertResult fromPKCS7(const QByteArray &a, QCA::Store::TrustMode t)
	{
		Q_UNUSED(a);
		Q_UNUSED(t);
		return QCA::ErrorDecode;
	}

	bool usage_check(const MyCertContext &cc, QCA::Store::UsageMode u) const
	{
		// TODO: check usage
		Q_UNUSED(cc);
		Q_UNUSED(u);
		return true;
	}
};

class opensslCipherContext : public QCA::CipherContext
{
public:
	opensslCipherContext(const EVP_CIPHER *algorithm, const int pad, QCA::Provider *p, const QString &type) : QCA::CipherContext(p, type)
	{
		m_cryptoAlgorithm = algorithm;
		EVP_CIPHER_CTX_init(&m_context);
		m_pad = pad;
		m_type = type;
	}

		void setup(QCA::Direction dir,
			   const QCA::SymmetricKey &key,
			   const QCA::InitializationVector &iv)
		{
			m_direction = dir;
			if (QCA::Encode == m_direction) {
				EVP_EncryptInit_ex(&m_context, m_cryptoAlgorithm, 0,
						   (const unsigned char*)(key.data()),
						   (const unsigned char*)(iv.data()));
			} else {
				EVP_DecryptInit_ex(&m_context, m_cryptoAlgorithm, 0,
						   (const unsigned char*)(key.data()),
						   (const unsigned char*)(iv.data()));
			}
			EVP_CIPHER_CTX_set_key_length(&m_context, key.size());
			EVP_CIPHER_CTX_set_padding(&m_context, m_pad);
		}

		Context *clone() const
		{
			return new opensslCipherContext( *this );
		}

		unsigned int blockSize() const
		{
			return EVP_CIPHER_CTX_block_size(&m_context);
		}
    
		bool update(const QSecureArray &in, QSecureArray *out)
		{
			out->resize(in.size()+blockSize());
			int resultLength;
			if (QCA::Encode == m_direction) {
				if (0 == EVP_EncryptUpdate(&m_context,
							   (unsigned char*)out->data(),
							   &resultLength,
							   (unsigned char*)in.data(),
							   in.size())) {
					return false;
				}
			} else {
				if (0 == EVP_DecryptUpdate(&m_context,
							   (unsigned char*)out->data(),
							   &resultLength,
							   (unsigned char*)in.data(),
							   in.size())) {
					return false;
				}
			}
			out->resize(resultLength);
			return true;
		}
    
		bool final(QSecureArray *out)
		{
			out->resize(blockSize());
			int resultLength;
			if (QCA::Encode == m_direction) {
				if (0 == EVP_EncryptFinal_ex(&m_context,
							     (unsigned char*)out->data(),
							     &resultLength)) {
					return false;
				} 
			} else {
				if (0 == EVP_DecryptFinal_ex(&m_context,
							     (unsigned char*)out->data(),
							     &resultLength)) {
					return false;
				} 
			}
			out->resize(resultLength);
			return true;
		}

		// Change cipher names
		QCA::KeyLength keyLength() const
		{
			if (m_type.left(4) == "des-") {
				return QCA::KeyLength( 8, 8, 1);
			} else if (m_type.left(6) == "aes128") {
				return QCA::KeyLength( 16, 16, 1);
			} else if (m_type.left(6) == "aes192") {
				return QCA::KeyLength( 24, 24, 1);
			} else if (m_type.left(6) == "aes256") {
				return QCA::KeyLength( 32, 32, 1);
			} else if (m_type.left(8) == "blowfish") {
				// Don't know - TODO
				return QCA::KeyLength( 1, 32, 1);
			} else if (m_type.left(9) == "tripledes") {
				return QCA::KeyLength( 24, 24, 1);
			} else {
				return QCA::KeyLength( 0, 1, 1);
			}
		}


protected:
		EVP_CIPHER_CTX m_context;
		const EVP_CIPHER *m_cryptoAlgorithm;
		QCA::Direction m_direction;
		int m_pad;
		QString m_type;
};

}

using namespace opensslQCAPlugin;

class opensslProvider : public QCA::Provider
{
public:
	void init()
	{
		OpenSSL_add_all_algorithms();
		ERR_load_crypto_strings();

		srand(time(NULL));
		char buf[128];
		for(int n = 0; n < 128; ++n)
			buf[n] = rand();
		RAND_seed(buf, 128);
	}

	~opensslProvider()
	{
		// todo: any shutdown?
	}

	QString name() const
	{
		return "qca-openssl";
	}

	QStringList features() const
	{
		QStringList list;
		list += "sha1";
		list += "sha0";
		list += "ripemd160";
		list += "md2";
		list += "md4";
		list += "md5";
		list += "hmac(md5)";
		list += "hmac(sha1)";
		list += "hmac(ripemd160)";
		list += "aes128-ecb";
		list += "aes128-cfb";
		list += "aes128-cbc";
		list += "aes128-cbc-pkcs7";
		list += "aes192-ecb";
		list += "aes192-cfb";
		list += "aes192-cbc";
		list += "aes256-ecb";
		list += "aes256-cbc";
		list += "aes256-cfb";
		// Blowfish ECB is failing unit test.
		// list += "blowfish-ecb";
		list += "tripledes-ecb";
		list += "des-ecb";
		list += "des-ecb-pkcs7";
		list += "des-cbc";
		list += "des-cbc-pkcs7";
		list += "des-cfb";
		list += "des-ofb";
		list += "pkey";
		list += "dlgroup";
		list += "rsa";
		list += "dsa";
		list += "dh";
		list += "cert";
		list += "csr";
		list += "crl";
		list += "store";

		return list;
	}

	Context *createContext(const QString &type)
	{
		//OpenSSL_add_all_digests();
		if ( type == "sha1" )
			return new opensslHashContext( EVP_sha1(), this, type);
		else if ( type == "sha0" )
			return new opensslHashContext( EVP_sha(), this, type);
		else if ( type == "ripemd160" )
			return new opensslHashContext( EVP_ripemd160(), this, type);
		else if ( type == "md2" )
			return new opensslHashContext( EVP_md2(), this, type);
		else if ( type == "md4" )
			return new opensslHashContext( EVP_md4(), this, type);
		else if ( type == "md5" )
			return new opensslHashContext( EVP_md5(), this, type);
		else if ( type == "hmac(md5)" )
			return new opensslHMACContext( EVP_md5(), this, type );
		else if ( type == "hmac(sha1)" )
			return new opensslHMACContext( EVP_sha1(),this, type );
		else if ( type == "hmac(ripemd160)" )
			return new opensslHMACContext( EVP_ripemd160(), this, type );
		else if ( type == "aes128-ecb" )
			return new opensslCipherContext( EVP_aes_128_ecb(), 0, this, type);
		else if ( type == "aes128-cfb" )
			return new opensslCipherContext( EVP_aes_128_cfb(), 0, this, type);
		else if ( type == "aes128-cbc" )
			return new opensslCipherContext( EVP_aes_128_cbc(), 0, this, type);
		else if ( type == "aes128-cbc-pkcs7" )
			return new opensslCipherContext( EVP_aes_128_cbc(), 1, this, type);
		else if ( type == "aes192-ecb" )
			return new opensslCipherContext( EVP_aes_192_ecb(), 0, this, type);
		else if ( type == "aes192-cfb" )
			return new opensslCipherContext( EVP_aes_192_cfb(), 0, this, type);
		else if ( type == "aes192-cbc" )
			return new opensslCipherContext( EVP_aes_192_cbc(), 0, this, type);
		else if ( type == "aes256-ecb" )
			return new opensslCipherContext( EVP_aes_256_ecb(), 0, this, type);
		else if ( type == "aes256-cfb" )
			return new opensslCipherContext( EVP_aes_256_cfb(), 0, this, type);
		else if ( type == "aes256-cbc" )
			return new opensslCipherContext( EVP_aes_256_cbc(), 0, this, type);
		else if ( type == "blowfish-ecb" )
			return new opensslCipherContext( EVP_bf_ecb(), 0, this, type);
		else if ( type == "tripledes-ecb" )
			return new opensslCipherContext( EVP_des_ede3(), 0, this, type);
		else if ( type == "des-ecb" )
			return new opensslCipherContext( EVP_des_ecb(), 0, this, type);
		else if ( type == "des-ecb-pkcs7" )
			return new opensslCipherContext( EVP_des_ecb(), 1, this, type);
		else if ( type == "des-cbc" )
			return new opensslCipherContext( EVP_des_cbc(), 0, this, type);
		else if ( type == "des-cbc-pkcs7" )
			return new opensslCipherContext( EVP_des_cbc(), 1, this, type);
		else if ( type == "des-cfb" )
			return new opensslCipherContext( EVP_des_cfb(), 0, this, type);
		else if ( type == "des-ofb" )
			return new opensslCipherContext( EVP_des_ofb(), 0, this, type);
		else if ( type == "pkey" )
			return new MyPKeyContext( this );
		else if ( type == "dlgroup" )
			return new MyDLGroup( this );
		else if ( type == "rsa" )
			return new RSAKey( this );
		else if ( type == "dsa" )
			return new DSAKey( this );
		else if ( type == "dh" )
			return new DHKey( this );
		else if ( type == "cert" )
			return new MyCertContext( this );
		else if ( type == "csr" )
			return new MyCSRContext( this );
		else if ( type == "crl" )
			return new MyCRLContext( this );
		else if ( type == "store" )
			return new MyStoreContext( this );
		return 0;
	}
};

class opensslPlugin : public QCAPlugin
{
	Q_OBJECT
public:
	virtual int version() const { return QCA_PLUGIN_VERSION; }
	virtual QCA::Provider *createProvider() { return new opensslProvider; }
};

#include "qca-openssl.moc"

Q_EXPORT_PLUGIN(opensslPlugin);

