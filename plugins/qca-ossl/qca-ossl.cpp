/*
 * Copyright (C) 2004-2007  Justin Karneges <justin@affinix.com>
 * Copyright (C) 2004-2006  Brad Hards <bradh@frogmouth.net>
 * Copyright (C) 2013-2016  Ivan Romanov <drizt@land.ru>
 * Copyright (C) 2017       Fabian Vogt <fabian@ritter-vogt.de>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
 *
 */

#include <QDebug>
#include <QElapsedTimer>
#include <QtCrypto>
#include <QtPlugin>
#include <qcaprovider.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <cstdio>
#include <cstdlib>
#include <iostream>

#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#ifdef OPENSSL_VERSION_MAJOR
#include <openssl/provider.h>
#endif

#include <openssl/kdf.h>

using namespace QCA;

namespace {
static const auto DsaDeleter = [](DSA *pointer) {
    if (pointer)
        DSA_free((DSA *)pointer);
};
} // end of anonymous namespace

namespace opensslQCAPlugin {

//----------------------------------------------------------------------------
// Util
//----------------------------------------------------------------------------
static SecureArray bio2buf(BIO *b)
{
    SecureArray buf;
    while (true) {
        SecureArray block(1024);
        int         ret = BIO_read(b, block.data(), block.size());
        if (ret <= 0)
            break;
        block.resize(ret);
        buf.append(block);
        if (ret != 1024)
            break;
    }
    BIO_free(b);
    return buf;
}

static QByteArray bio2ba(BIO *b)
{
    QByteArray buf;
    while (true) {
        QByteArray block(1024, 0);
        int        ret = BIO_read(b, block.data(), block.size());
        if (ret <= 0)
            break;
        block.resize(ret);
        buf.append(block);
        if (ret != 1024)
            break;
    }
    BIO_free(b);
    return buf;
}

static BigInteger bn2bi(const BIGNUM *n)
{
    SecureArray buf(BN_num_bytes(n) + 1);
    buf[0] = 0; // positive
    BN_bn2bin(n, (unsigned char *)buf.data() + 1);
    return BigInteger(buf);
}

static BigInteger bn2bi_free(BIGNUM *n)
{
    BigInteger bi = bn2bi(n);
    BN_free(n);
    return bi;
}

static BIGNUM *bi2bn(const BigInteger &n)
{
    SecureArray buf = n.toArray();
    return BN_bin2bn((const unsigned char *)buf.data(), buf.size(), nullptr);
}

// take lowest bytes of BIGNUM to fit
// pad with high byte zeroes to fit
static SecureArray bn2fixedbuf(const BIGNUM *n, int size)
{
    SecureArray buf(BN_num_bytes(n));
    BN_bn2bin(n, (unsigned char *)buf.data());

    SecureArray out(size);
    memset(out.data(), 0, size);
    int len = qMin(size, buf.size());
    memcpy(out.data() + (size - len), buf.data(), len);
    return out;
}

static SecureArray dsasig_der_to_raw(const SecureArray &in)
{
    DSA_SIG *            sig = DSA_SIG_new();
    const unsigned char *inp = (const unsigned char *)in.data();
    d2i_DSA_SIG(&sig, &inp, in.size());

    const BIGNUM *bnr, *bns;
    DSA_SIG_get0(sig, &bnr, &bns);

    SecureArray part_r = bn2fixedbuf(bnr, 20);
    SecureArray part_s = bn2fixedbuf(bns, 20);
    SecureArray result;
    result.append(part_r);
    result.append(part_s);

    DSA_SIG_free(sig);
    return result;
}

static SecureArray dsasig_raw_to_der(const SecureArray &in)
{
    if (in.size() != 40)
        return SecureArray();

    DSA_SIG *   sig = DSA_SIG_new();
    SecureArray part_r(20);
    BIGNUM *    bnr;
    SecureArray part_s(20);
    BIGNUM *    bns;
    memcpy(part_r.data(), in.data(), 20);
    memcpy(part_s.data(), in.data() + 20, 20);
    bnr = BN_bin2bn((const unsigned char *)part_r.data(), part_r.size(), nullptr);
    bns = BN_bin2bn((const unsigned char *)part_s.data(), part_s.size(), nullptr);

    if (DSA_SIG_set0(sig, bnr, bns) == 0)
        return SecureArray();
    // Not documented what happens in the failure case, free bnr and bns?

    int            len = i2d_DSA_SIG(sig, nullptr);
    SecureArray    result(len);
    unsigned char *p = (unsigned char *)result.data();
    i2d_DSA_SIG(sig, &p);

    DSA_SIG_free(sig);
    return result;
}

static int passphrase_cb(char *buf, int size, int rwflag, void *u)
{
    Q_UNUSED(buf);
    Q_UNUSED(size);
    Q_UNUSED(rwflag);
    Q_UNUSED(u);
    return 0;
}

/*static bool is_basic_constraint(const ConstraintType &t)
{
    bool basic = false;
    switch(t.known())
    {
        case DigitalSignature:
        case NonRepudiation:
        case KeyEncipherment:
        case DataEncipherment:
        case KeyAgreement:
        case KeyCertificateSign:
        case CRLSign:
        case EncipherOnly:
        case DecipherOnly:
            basic = true;
            break;

        case ServerAuth:
        case ClientAuth:
        case CodeSigning:
        case EmailProtection:
        case IPSecEndSystem:
        case IPSecTunnel:
        case IPSecUser:
        case TimeStamping:
        case OCSPSigning:
            break;
    }
    return basic;
}

static Constraints basic_only(const Constraints &list)
{
    Constraints out;
    for(int n = 0; n < list.count(); ++n)
    {
        if(is_basic_constraint(list[n]))
            out += list[n];
    }
    return out;
}

static Constraints ext_only(const Constraints &list)
{
    Constraints out;
    for(int n = 0; n < list.count(); ++n)
    {
        if(!is_basic_constraint(list[n]))
            out += list[n];
    }
    return out;
}*/

// logic from Botan
/*static Constraints find_constraints(const PKeyContext &key, const Constraints &orig)
{
    Constraints constraints;

    if(key.key()->type() == PKey::RSA)
        constraints += KeyEncipherment;

    if(key.key()->type() == PKey::DH)
        constraints += KeyAgreement;

    if(key.key()->type() == PKey::RSA || key.key()->type() == PKey::DSA)
    {
        constraints += DigitalSignature;
        constraints += NonRepudiation;
    }

    Constraints limits = basic_only(orig);
    Constraints the_rest = ext_only(orig);

    if(!limits.isEmpty())
    {
        Constraints reduced;
        for(int n = 0; n < constraints.count(); ++n)
        {
            if(limits.contains(constraints[n]))
                reduced += constraints[n];
        }
        constraints = reduced;
    }

    constraints += the_rest;

    return constraints;
}*/

static void try_add_name_item(X509_NAME **name, int nid, const QString &val)
{
    if (val.isEmpty())
        return;
    const QByteArray buf = val.toLatin1();
    if (!(*name))
        *name = X509_NAME_new();
    X509_NAME_add_entry_by_NID(*name, nid, MBSTRING_ASC, (const unsigned char *)buf.data(), buf.size(), -1, 0);
}

static X509_NAME *new_cert_name(const CertificateInfo &info)
{
    X509_NAME *name = nullptr;
    // FIXME support multiple items of each type
    try_add_name_item(&name, NID_commonName, info.value(CommonName));
    try_add_name_item(&name, NID_countryName, info.value(Country));
    try_add_name_item(&name, NID_localityName, info.value(Locality));
    try_add_name_item(&name, NID_stateOrProvinceName, info.value(State));
    try_add_name_item(&name, NID_organizationName, info.value(Organization));
    try_add_name_item(&name, NID_organizationalUnitName, info.value(OrganizationalUnit));
    return name;
}

static void try_get_name_item(X509_NAME *name, int nid, const CertificateInfoType &t, CertificateInfo *info)
{
    int loc;
    loc = -1;
    while ((loc = X509_NAME_get_index_by_NID(name, nid, loc)) != -1) {
        X509_NAME_ENTRY *ne   = X509_NAME_get_entry(name, loc);
        ASN1_STRING *    data = X509_NAME_ENTRY_get_data(ne);
        QByteArray       cs((const char *)data->data, data->length);
        info->insert(t, QString::fromLatin1(cs));
    }
}

static void
try_get_name_item_by_oid(X509_NAME *name, const QString &oidText, const CertificateInfoType &t, CertificateInfo *info)
{
    ASN1_OBJECT *oid = OBJ_txt2obj(oidText.toLatin1().data(), 1); // 1 = only accept dotted input
    if (!oid)
        return;

    int loc;
    loc = -1;
    while ((loc = X509_NAME_get_index_by_OBJ(name, oid, loc)) != -1) {
        X509_NAME_ENTRY *ne   = X509_NAME_get_entry(name, loc);
        ASN1_STRING *    data = X509_NAME_ENTRY_get_data(ne);
        QByteArray       cs((const char *)data->data, data->length);
        info->insert(t, QString::fromLatin1(cs));
        qDebug() << "oid: " << oidText << ",  result: " << cs;
    }
    ASN1_OBJECT_free(oid);
}

static CertificateInfo get_cert_name(X509_NAME *name)
{
    CertificateInfo info;
    try_get_name_item(name, NID_commonName, CommonName, &info);
    try_get_name_item(name, NID_countryName, Country, &info);
    try_get_name_item_by_oid(name, QStringLiteral("1.3.6.1.4.1.311.60.2.1.3"), IncorporationCountry, &info);
    try_get_name_item(name, NID_localityName, Locality, &info);
    try_get_name_item_by_oid(name, QStringLiteral("1.3.6.1.4.1.311.60.2.1.1"), IncorporationLocality, &info);
    try_get_name_item(name, NID_stateOrProvinceName, State, &info);
    try_get_name_item_by_oid(name, QStringLiteral("1.3.6.1.4.1.311.60.2.1.2"), IncorporationState, &info);
    try_get_name_item(name, NID_organizationName, Organization, &info);
    try_get_name_item(name, NID_organizationalUnitName, OrganizationalUnit, &info);

    // legacy email
    {
        CertificateInfo p9_info;
        try_get_name_item(name, NID_pkcs9_emailAddress, EmailLegacy, &p9_info);
        const QList<QString> emails = info.values(Email);
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
        QMultiMapIterator<CertificateInfoType, QString> it(p9_info);
#else
        QMapIterator<CertificateInfoType, QString> it(p9_info);
#endif
        while (it.hasNext()) {
            it.next();
            if (!emails.contains(it.value()))
                info.insert(Email, it.value());
        }
    }

    return info;
}

static X509_EXTENSION *new_subject_key_id(X509 *cert)
{
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, nullptr, cert, nullptr, nullptr, 0);
    X509_EXTENSION *ex = X509V3_EXT_conf_nid(nullptr, &ctx, NID_subject_key_identifier, (char *)"hash");
    return ex;
}

static X509_EXTENSION *new_basic_constraints(bool ca, int pathlen)
{
    BASIC_CONSTRAINTS *bs = BASIC_CONSTRAINTS_new();
    bs->ca                = (ca ? 1 : 0);
    bs->pathlen           = ASN1_INTEGER_new();
    ASN1_INTEGER_set(bs->pathlen, pathlen);

    X509_EXTENSION *ex = X509V3_EXT_i2d(NID_basic_constraints, 1, bs); // 1 = critical
    BASIC_CONSTRAINTS_free(bs);
    return ex;
}

static void get_basic_constraints(X509_EXTENSION *ex, bool *ca, int *pathlen)
{
    BASIC_CONSTRAINTS *bs = (BASIC_CONSTRAINTS *)X509V3_EXT_d2i(ex);
    *ca                   = (bs->ca ? true : false);
    if (bs->pathlen)
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

static GENERAL_NAME *new_general_name(const CertificateInfoType &t, const QString &val)
{
    GENERAL_NAME *name = nullptr;
    switch (t.known()) {
    case Email:
    {
        const QByteArray buf = val.toLatin1();

        ASN1_IA5STRING *str = ASN1_IA5STRING_new();
        ASN1_STRING_set((ASN1_STRING *)str, (const unsigned char *)buf.data(), buf.size());

        name               = GENERAL_NAME_new();
        name->type         = GEN_EMAIL;
        name->d.rfc822Name = str;
        break;
    }
    case URI:
    {
        const QByteArray buf = val.toLatin1();

        ASN1_IA5STRING *str = ASN1_IA5STRING_new();
        ASN1_STRING_set((ASN1_STRING *)str, (const unsigned char *)buf.data(), buf.size());

        name                              = GENERAL_NAME_new();
        name->type                        = GEN_URI;
        name->d.uniformResourceIdentifier = str;
        break;
    }
    case DNS:
    {
        const QByteArray buf = val.toLatin1();

        ASN1_IA5STRING *str = ASN1_IA5STRING_new();
        ASN1_STRING_set((ASN1_STRING *)str, (const unsigned char *)buf.data(), buf.size());

        name            = GENERAL_NAME_new();
        name->type      = GEN_DNS;
        name->d.dNSName = str;
        break;
    }
    case IPAddress:
    {
        const QByteArray buf = ipaddress_string_to_bytes(val);

        ASN1_OCTET_STRING *str = ASN1_OCTET_STRING_new();
        ASN1_STRING_set((ASN1_STRING *)str, (const unsigned char *)buf.data(), buf.size());

        name              = GENERAL_NAME_new();
        name->type        = GEN_IPADD;
        name->d.iPAddress = str;
        break;
    }
    case XMPP:
    {
        const QByteArray buf = val.toUtf8();

        ASN1_UTF8STRING *str = ASN1_UTF8STRING_new();
        ASN1_STRING_set((ASN1_STRING *)str, (const unsigned char *)buf.data(), buf.size());

        ASN1_TYPE *at        = ASN1_TYPE_new();
        at->type             = V_ASN1_UTF8STRING;
        at->value.utf8string = str;

        OTHERNAME *other = OTHERNAME_new();
        other->type_id   = OBJ_txt2obj("1.3.6.1.5.5.7.8.5", 1); // 1 = only accept dotted input
        other->value     = at;

        name              = GENERAL_NAME_new();
        name->type        = GEN_OTHERNAME;
        name->d.otherName = other;
        break;
    }
    default:
        break;
    }
    return name;
}

static void try_add_general_name(GENERAL_NAMES **gn, const CertificateInfoType &t, const QString &val)
{
    if (val.isEmpty())
        return;
    GENERAL_NAME *name = new_general_name(t, val);
    if (name) {
        if (!(*gn))
            *gn = sk_GENERAL_NAME_new_null();
        sk_GENERAL_NAME_push(*gn, name);
    }
}

static X509_EXTENSION *new_cert_subject_alt_name(const CertificateInfo &info)
{
    GENERAL_NAMES *gn = nullptr;
    // FIXME support multiple items of each type
    try_add_general_name(&gn, Email, info.value(Email));
    try_add_general_name(&gn, URI, info.value(URI));
    try_add_general_name(&gn, DNS, info.value(DNS));
    try_add_general_name(&gn, IPAddress, info.value(IPAddress));
    try_add_general_name(&gn, XMPP, info.value(XMPP));
    if (!gn)
        return nullptr;

    X509_EXTENSION *ex = X509V3_EXT_i2d(NID_subject_alt_name, 0, gn);
    sk_GENERAL_NAME_pop_free(gn, GENERAL_NAME_free);
    return ex;
}

static GENERAL_NAME *find_next_general_name(GENERAL_NAMES *names, int type, int *pos)
{
    int           temp = *pos;
    GENERAL_NAME *gn   = nullptr;
    *pos               = -1;
    for (int n = temp; n < sk_GENERAL_NAME_num(names); ++n) {
        GENERAL_NAME *i = sk_GENERAL_NAME_value(names, n);
        if (i->type == type) {
            gn   = i;
            *pos = n;
            break;
        }
    }
    return gn;
}

static QByteArray qca_ASN1_STRING_toByteArray(ASN1_STRING *x)
{
    return QByteArray(reinterpret_cast<const char *>(ASN1_STRING_get0_data(x)), ASN1_STRING_length(x));
}

static void try_get_general_name(GENERAL_NAMES *names, const CertificateInfoType &t, CertificateInfo *info)
{
    switch (t.known()) {
    case Email:
    {
        int pos = 0;
        while (pos != -1) {
            GENERAL_NAME *gn = find_next_general_name(names, GEN_EMAIL, &pos);
            if (pos != -1) {
                const QByteArray cs = qca_ASN1_STRING_toByteArray(gn->d.rfc822Name);
                info->insert(t, QString::fromLatin1(cs));
                ++pos;
            }
        }
        break;
    }
    case URI:
    {
        int pos = 0;
        while (pos != -1) {
            GENERAL_NAME *gn = find_next_general_name(names, GEN_URI, &pos);
            if (pos != -1) {
                const QByteArray cs = qca_ASN1_STRING_toByteArray(gn->d.uniformResourceIdentifier);
                info->insert(t, QString::fromLatin1(cs));
                ++pos;
            }
        }
        break;
    }
    case DNS:
    {
        int pos = 0;
        while (pos != -1) {
            GENERAL_NAME *gn = find_next_general_name(names, GEN_DNS, &pos);
            if (pos != -1) {
                const QByteArray cs = qca_ASN1_STRING_toByteArray(gn->d.dNSName);
                info->insert(t, QString::fromLatin1(cs));
                ++pos;
            }
        }
        break;
    }
    case IPAddress:
    {
        int pos = 0;
        while (pos != -1) {
            GENERAL_NAME *gn = find_next_general_name(names, GEN_IPADD, &pos);
            if (pos != -1) {
                ASN1_OCTET_STRING *str = gn->d.iPAddress;
                const QByteArray   buf = qca_ASN1_STRING_toByteArray(str);

                QString out;
                // IPv4 (TODO: handle IPv6)
                if (buf.size() == 4) {
                    out = QStringLiteral("0.0.0.0");
                } else
                    break;
                info->insert(t, out);
                ++pos;
            }
        }
        break;
    }
    case XMPP:
    {
        int pos = 0;
        while (pos != -1) {
            GENERAL_NAME *gn = find_next_general_name(names, GEN_OTHERNAME, &pos);
            if (pos != -1) {
                OTHERNAME *other = gn->d.otherName;
                if (!other)
                    break;

                ASN1_OBJECT *obj = OBJ_txt2obj("1.3.6.1.5.5.7.8.5", 1); // 1 = only accept dotted input
                if (OBJ_cmp(other->type_id, obj) != 0)
                    break;
                ASN1_OBJECT_free(obj);

                ASN1_TYPE *at = other->value;
                if (at->type != V_ASN1_UTF8STRING)
                    break;

                ASN1_UTF8STRING *str = at->value.utf8string;
                const QByteArray buf = qca_ASN1_STRING_toByteArray(str);
                info->insert(t, QString::fromUtf8(buf));
                ++pos;
            }
        }
        break;
    }
    default:
        break;
    }
}

static CertificateInfo get_cert_alt_name(X509_EXTENSION *ex)
{
    CertificateInfo info;
    GENERAL_NAMES * gn = (GENERAL_NAMES *)X509V3_EXT_d2i(ex);
    try_get_general_name(gn, Email, &info);
    try_get_general_name(gn, URI, &info);
    try_get_general_name(gn, DNS, &info);
    try_get_general_name(gn, IPAddress, &info);
    try_get_general_name(gn, XMPP, &info);
    GENERAL_NAMES_free(gn);
    return info;
}

static X509_EXTENSION *new_cert_key_usage(const Constraints &constraints)
{
    ASN1_BIT_STRING *keyusage = nullptr;
    for (int n = 0; n < constraints.count(); ++n) {
        int bit = -1;
        switch (constraints[n].known()) {
        case DigitalSignature:
            bit = Bit_DigitalSignature;
            break;
        case NonRepudiation:
            bit = Bit_NonRepudiation;
            break;
        case KeyEncipherment:
            bit = Bit_KeyEncipherment;
            break;
        case DataEncipherment:
            bit = Bit_DataEncipherment;
            break;
        case KeyAgreement:
            bit = Bit_KeyAgreement;
            break;
        case KeyCertificateSign:
            bit = Bit_KeyCertificateSign;
            break;
        case CRLSign:
            bit = Bit_CRLSign;
            break;
        case EncipherOnly:
            bit = Bit_EncipherOnly;
            break;
        case DecipherOnly:
            bit = Bit_DecipherOnly;
            break;
        default:
            break;
        }
        if (bit != -1) {
            if (!keyusage)
                keyusage = ASN1_BIT_STRING_new();
            ASN1_BIT_STRING_set_bit(keyusage, bit, 1);
        }
    }
    if (!keyusage)
        return nullptr;

    X509_EXTENSION *ex = X509V3_EXT_i2d(NID_key_usage, 1, keyusage); // 1 = critical
    ASN1_BIT_STRING_free(keyusage);
    return ex;
}

static Constraints get_cert_key_usage(X509_EXTENSION *ex)
{
    Constraints constraints;
    int         bit_table[9] = {DigitalSignature,
                        NonRepudiation,
                        KeyEncipherment,
                        DataEncipherment,
                        KeyAgreement,
                        KeyCertificateSign,
                        CRLSign,
                        EncipherOnly,
                        DecipherOnly};

    ASN1_BIT_STRING *keyusage = (ASN1_BIT_STRING *)X509V3_EXT_d2i(ex);
    for (int n = 0; n < 9; ++n) {
        if (ASN1_BIT_STRING_get_bit(keyusage, n))
            constraints += ConstraintType((ConstraintTypeKnown)bit_table[n]);
    }
    ASN1_BIT_STRING_free(keyusage);
    return constraints;
}

static X509_EXTENSION *new_cert_ext_key_usage(const Constraints &constraints)
{
    EXTENDED_KEY_USAGE *extkeyusage = nullptr;
    for (int n = 0; n < constraints.count(); ++n) {
        int nid = -1;
        // TODO: don't use known/nid, and instead just use OIDs
        switch (constraints[n].known()) {
        case ServerAuth:
            nid = NID_server_auth;
            break;
        case ClientAuth:
            nid = NID_client_auth;
            break;
        case CodeSigning:
            nid = NID_code_sign;
            break;
        case EmailProtection:
            nid = NID_email_protect;
            break;
        case IPSecEndSystem:
            nid = NID_ipsecEndSystem;
            break;
        case IPSecTunnel:
            nid = NID_ipsecTunnel;
            break;
        case IPSecUser:
            nid = NID_ipsecUser;
            break;
        case TimeStamping:
            nid = NID_time_stamp;
            break;
        case OCSPSigning:
            nid = NID_OCSP_sign;
            break;
        default:
            break;
        }
        if (nid != -1) {
            if (!extkeyusage)
                extkeyusage = sk_ASN1_OBJECT_new_null();
            ASN1_OBJECT *obj = OBJ_nid2obj(nid);
            sk_ASN1_OBJECT_push(extkeyusage, obj);
        }
    }
    if (!extkeyusage)
        return nullptr;

    X509_EXTENSION *ex = X509V3_EXT_i2d(NID_ext_key_usage, 0, extkeyusage); // 0 = not critical
    sk_ASN1_OBJECT_pop_free(extkeyusage, ASN1_OBJECT_free);
    return ex;
}

static Constraints get_cert_ext_key_usage(X509_EXTENSION *ex)
{
    Constraints constraints;

    EXTENDED_KEY_USAGE *extkeyusage = (EXTENDED_KEY_USAGE *)X509V3_EXT_d2i(ex);
    for (int n = 0; n < sk_ASN1_OBJECT_num(extkeyusage); ++n) {
        ASN1_OBJECT *obj = sk_ASN1_OBJECT_value(extkeyusage, n);
        int          nid = OBJ_obj2nid(obj);
        if (nid == NID_undef)
            continue;

        // TODO: don't use known/nid, and instead just use OIDs
        int t = -1;
        switch (nid) {
        case NID_server_auth:
            t = ServerAuth;
            break;
        case NID_client_auth:
            t = ClientAuth;
            break;
        case NID_code_sign:
            t = CodeSigning;
            break;
        case NID_email_protect:
            t = EmailProtection;
            break;
        case NID_ipsecEndSystem:
            t = IPSecEndSystem;
            break;
        case NID_ipsecTunnel:
            t = IPSecTunnel;
            break;
        case NID_ipsecUser:
            t = IPSecUser;
            break;
        case NID_time_stamp:
            t = TimeStamping;
            break;
        case NID_OCSP_sign:
            t = OCSPSigning;
            break;
        };

        if (t == -1)
            continue;

        constraints.append(ConstraintType((ConstraintTypeKnown)t));
    }
    sk_ASN1_OBJECT_pop_free(extkeyusage, ASN1_OBJECT_free);
    return constraints;
}

static X509_EXTENSION *new_cert_policies(const QStringList &policies)
{
    STACK_OF(POLICYINFO) *pols = nullptr;
    for (int n = 0; n < policies.count(); ++n) {
        const QByteArray cs  = policies[n].toLatin1();
        ASN1_OBJECT *    obj = OBJ_txt2obj(cs.data(), 1); // 1 = only accept dotted input
        if (!obj)
            continue;
        if (!pols)
            pols = sk_POLICYINFO_new_null();
        POLICYINFO *pol = POLICYINFO_new();
        pol->policyid   = obj;
        sk_POLICYINFO_push(pols, pol);
    }
    if (!pols)
        return nullptr;

    X509_EXTENSION *ex = X509V3_EXT_i2d(NID_certificate_policies, 0, pols); // 0 = not critical
    sk_POLICYINFO_pop_free(pols, POLICYINFO_free);
    return ex;
}

static QStringList get_cert_policies(X509_EXTENSION *ex)
{
    QStringList out;
    STACK_OF(POLICYINFO) *pols = (STACK_OF(POLICYINFO) *)X509V3_EXT_d2i(ex);
    for (int n = 0; n < sk_POLICYINFO_num(pols); ++n) {
        POLICYINFO *pol = sk_POLICYINFO_value(pols, n);
        QByteArray  buf(128, 0);
        const auto  len = OBJ_obj2txt((char *)buf.data(), buf.size(), pol->policyid, 1); // 1 = only accept dotted input
        if (len > 0)
            out += QString::fromLatin1(buf.left(len));
    }
    sk_POLICYINFO_pop_free(pols, POLICYINFO_free);
    return out;
}

static QByteArray get_cert_subject_key_id(X509_EXTENSION *ex)
{
    ASN1_OCTET_STRING *skid = (ASN1_OCTET_STRING *)X509V3_EXT_d2i(ex);
    const QByteArray   out  = qca_ASN1_STRING_toByteArray(skid);
    ASN1_OCTET_STRING_free(skid);
    return out;
}

// If you get any more crashes in this code, please provide a copy
// of the cert to bradh AT frogmouth.net
static QByteArray get_cert_issuer_key_id(X509_EXTENSION *ex)
{
    AUTHORITY_KEYID *akid = (AUTHORITY_KEYID *)X509V3_EXT_d2i(ex);
    QByteArray       out;
    if (akid->keyid)
        out = qca_ASN1_STRING_toByteArray(akid->keyid);
    AUTHORITY_KEYID_free(akid);
    return out;
}

static Validity convert_verify_error(int err)
{
    // TODO: ErrorExpiredCA
    Validity rc;
    switch (err) {
    case X509_V_ERR_CERT_REJECTED:
        rc = ErrorRejected;
        break;
    case X509_V_ERR_CERT_UNTRUSTED:
        rc = ErrorUntrusted;
        break;
    case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
    case X509_V_ERR_CERT_SIGNATURE_FAILURE:
    case X509_V_ERR_CRL_SIGNATURE_FAILURE:
    case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
    case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
        rc = ErrorSignatureFailed;
        break;
    case X509_V_ERR_INVALID_CA:
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
    case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
        rc = ErrorInvalidCA;
        break;
    case X509_V_ERR_INVALID_PURPOSE: // note: not used by store verify
        rc = ErrorInvalidPurpose;
        break;
    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
    case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
        rc = ErrorSelfSigned;
        break;
    case X509_V_ERR_CERT_REVOKED:
        rc = ErrorRevoked;
        break;
    case X509_V_ERR_PATH_LENGTH_EXCEEDED:
        rc = ErrorPathLengthExceeded;
        break;
    case X509_V_ERR_CERT_NOT_YET_VALID:
    case X509_V_ERR_CERT_HAS_EXPIRED:
    case X509_V_ERR_CRL_NOT_YET_VALID:
    case X509_V_ERR_CRL_HAS_EXPIRED:
    case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
    case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
    case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
    case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
        rc = ErrorExpired;
        break;
    case X509_V_ERR_APPLICATION_VERIFICATION:
    case X509_V_ERR_OUT_OF_MEM:
    case X509_V_ERR_UNABLE_TO_GET_CRL:
    case X509_V_ERR_CERT_CHAIN_TOO_LONG:
    default:
        rc = ErrorValidityUnknown;
        break;
    }
    return rc;
}

EVP_PKEY *qca_d2i_PKCS8PrivateKey(const SecureArray &in, EVP_PKEY **x, pem_password_cb *cb, void *u)
{
    PKCS8_PRIV_KEY_INFO *p8inf;

    // first try unencrypted form
    BIO *bi = BIO_new(BIO_s_mem());
    BIO_write(bi, in.data(), in.size());
    p8inf = d2i_PKCS8_PRIV_KEY_INFO_bio(bi, nullptr);
    BIO_free(bi);
    if (!p8inf) {
        X509_SIG *p8;

        // now try encrypted form
        bi = BIO_new(BIO_s_mem());
        BIO_write(bi, in.data(), in.size());
        p8 = d2i_PKCS8_bio(bi, nullptr);
        BIO_free(bi);
        if (!p8)
            return nullptr;

        // get passphrase
        char psbuf[PEM_BUFSIZE];
        int  klen;
        if (cb)
            klen = cb(psbuf, PEM_BUFSIZE, 0, u);
        else
            klen = PEM_def_callback(psbuf, PEM_BUFSIZE, 0, u);
        if (klen <= 0) {
            PEMerr(PEM_F_D2I_PKCS8PRIVATEKEY_BIO, PEM_R_BAD_PASSWORD_READ);
            X509_SIG_free(p8);
            return nullptr;
        }

        // decrypt it
        p8inf = PKCS8_decrypt(p8, psbuf, klen);
        X509_SIG_free(p8);
        if (!p8inf)
            return nullptr;
    }

    EVP_PKEY *ret = EVP_PKCS82PKEY(p8inf);
    PKCS8_PRIV_KEY_INFO_free(p8inf);
    if (!ret)
        return nullptr;
    if (x) {
        if (*x)
            EVP_PKEY_free(*x);
        *x = ret;
    }
    return ret;
}

class opensslHashContext : public HashContext
{
    Q_OBJECT
public:
    opensslHashContext(const EVP_MD *algorithm, Provider *p, const QString &type)
        : HashContext(p, type)
    {
        m_algorithm = algorithm;
        m_context   = EVP_MD_CTX_new();
        EVP_DigestInit(m_context, m_algorithm);
    }

    opensslHashContext(const opensslHashContext &other)
        : HashContext(other)
    {
        m_algorithm = other.m_algorithm;
        m_context   = EVP_MD_CTX_new();
        EVP_MD_CTX_copy_ex(m_context, other.m_context);
    }

    ~opensslHashContext() override
    {
        EVP_MD_CTX_free(m_context);
    }

    void clear() override
    {
        EVP_MD_CTX_free(m_context);
        m_context = EVP_MD_CTX_new();
        EVP_DigestInit(m_context, m_algorithm);
    }

    void update(const MemoryRegion &a) override
    {
        EVP_DigestUpdate(m_context, (unsigned char *)a.data(), a.size());
    }

    MemoryRegion final() override
    {
        SecureArray a(EVP_MD_size(m_algorithm));
        EVP_DigestFinal(m_context, (unsigned char *)a.data(), nullptr);
        return a;
    }

    Provider::Context *clone() const override
    {
        return new opensslHashContext(*this);
    }

protected:
    const EVP_MD *m_algorithm;
    EVP_MD_CTX *  m_context;
};

class opensslPbkdf1Context : public KDFContext
{
    Q_OBJECT
public:
    opensslPbkdf1Context(const EVP_MD *algorithm, Provider *p, const QString &type)
        : KDFContext(p, type)
    {
        m_algorithm = algorithm;
        m_context   = EVP_MD_CTX_new();
        EVP_DigestInit(m_context, m_algorithm);
    }

    opensslPbkdf1Context(const opensslPbkdf1Context &other)
        : KDFContext(other)
    {
        m_algorithm = other.m_algorithm;
        m_context   = EVP_MD_CTX_new();
        EVP_MD_CTX_copy(m_context, other.m_context);
    }

    ~opensslPbkdf1Context() override
    {
        EVP_MD_CTX_free(m_context);
    }

    Provider::Context *clone() const override
    {
        return new opensslPbkdf1Context(*this);
    }

    SymmetricKey makeKey(const SecureArray &         secret,
                         const InitializationVector &salt,
                         unsigned int                keyLength,
                         unsigned int                iterationCount) override
    {
        /* from RFC2898:
           Steps:

           1. If dkLen > 16 for MD2 and MD5, or dkLen > 20 for SHA-1, output
           "derived key too long" and stop.
        */
        if (keyLength > (unsigned int)EVP_MD_size(m_algorithm)) {
            std::cout << "derived key too long" << std::endl;
            return SymmetricKey();
        }

        /*
          2. Apply the underlying hash function Hash for c iterations to the
          concatenation of the password P and the salt S, then extract
          the first dkLen octets to produce a derived key DK:

          T_1 = Hash (P || S) ,
          T_2 = Hash (T_1) ,
          ...
          T_c = Hash (T_{c-1}) ,
          DK = Tc<0..dkLen-1>
        */
        // calculate T_1
        EVP_DigestUpdate(m_context, (unsigned char *)secret.data(), secret.size());
        EVP_DigestUpdate(m_context, (unsigned char *)salt.data(), salt.size());
        SecureArray a(EVP_MD_size(m_algorithm));
        EVP_DigestFinal(m_context, (unsigned char *)a.data(), nullptr);

        // calculate T_2 up to T_c
        for (unsigned int i = 2; i <= iterationCount; ++i) {
            EVP_DigestInit(m_context, m_algorithm);
            EVP_DigestUpdate(m_context, (unsigned char *)a.data(), a.size());
            EVP_DigestFinal(m_context, (unsigned char *)a.data(), nullptr);
        }

        // shrink a to become DK, of the required length
        a.resize(keyLength);

        /*
          3. Output the derived key DK.
        */
        return a;
    }

    SymmetricKey makeKey(const SecureArray &         secret,
                         const InitializationVector &salt,
                         unsigned int                keyLength,
                         int                         msecInterval,
                         unsigned int *              iterationCount) override
    {
        Q_ASSERT(iterationCount != nullptr);
        QElapsedTimer timer;

        /* from RFC2898:
           Steps:

           1. If dkLen > 16 for MD2 and MD5, or dkLen > 20 for SHA-1, output
           "derived key too long" and stop.
        */
        if (keyLength > (unsigned int)EVP_MD_size(m_algorithm)) {
            std::cout << "derived key too long" << std::endl;
            return SymmetricKey();
        }

        /*
          2. Apply the underlying hash function Hash for M milliseconds
          to the concatenation of the password P and the salt S, incrementing c,
          then extract the first dkLen octets to produce a derived key DK:

          time from M to 0
          T_1 = Hash (P || S) ,
          T_2 = Hash (T_1) ,
          ...
          T_c = Hash (T_{c-1}) ,
          when time = 0: stop,
          DK = Tc<0..dkLen-1>
        */
        // calculate T_1
        EVP_DigestUpdate(m_context, (unsigned char *)secret.data(), secret.size());
        EVP_DigestUpdate(m_context, (unsigned char *)salt.data(), salt.size());
        SecureArray a(EVP_MD_size(m_algorithm));
        EVP_DigestFinal(m_context, (unsigned char *)a.data(), nullptr);

        // calculate T_2 up to T_c
        *iterationCount = 2 - 1; // <- Have to remove 1, unless it computes one
        timer.start();           // ^  time more than the base function
                                 // ^  with the same iterationCount
        while (timer.elapsed() < msecInterval) {
            EVP_DigestInit(m_context, m_algorithm);
            EVP_DigestUpdate(m_context, (unsigned char *)a.data(), a.size());
            EVP_DigestFinal(m_context, (unsigned char *)a.data(), nullptr);
            ++(*iterationCount);
        }

        // shrink a to become DK, of the required length
        a.resize(keyLength);

        /*
          3. Output the derived key DK.
        */
        return a;
    }

protected:
    const EVP_MD *m_algorithm;
    EVP_MD_CTX *  m_context;
};

class opensslPbkdf2Context : public KDFContext
{
    Q_OBJECT
public:
    opensslPbkdf2Context(Provider *p, const QString &type)
        : KDFContext(p, type)
    {
    }

    Provider::Context *clone() const override
    {
        return new opensslPbkdf2Context(*this);
    }

    SymmetricKey makeKey(const SecureArray &         secret,
                         const InitializationVector &salt,
                         unsigned int                keyLength,
                         unsigned int                iterationCount) override
    {
        SecureArray out(keyLength);
        PKCS5_PBKDF2_HMAC_SHA1((char *)secret.data(),
                               secret.size(),
                               (unsigned char *)salt.data(),
                               salt.size(),
                               iterationCount,
                               keyLength,
                               (unsigned char *)out.data());
        return out;
    }

    SymmetricKey makeKey(const SecureArray &         secret,
                         const InitializationVector &salt,
                         unsigned int                keyLength,
                         int                         msecInterval,
                         unsigned int *              iterationCount) override
    {
        Q_ASSERT(iterationCount != nullptr);
        QElapsedTimer timer;
        SecureArray   out(keyLength);

        *iterationCount = 0;
        timer.start();

        // PBKDF2 needs an iterationCount itself, unless PBKDF1.
        // So we need to calculate first the number of iterations for
        // That time interval, then feed the iterationCounts to PBKDF2
        while (timer.elapsed() < msecInterval) {
            PKCS5_PBKDF2_HMAC_SHA1((char *)secret.data(),
                                   secret.size(),
                                   (unsigned char *)salt.data(),
                                   salt.size(),
                                   1,
                                   keyLength,
                                   (unsigned char *)out.data());
            ++(*iterationCount);
        }

        // Now we can directely call makeKey base function,
        // as we now have the iterationCount
        out = makeKey(secret, salt, keyLength, *iterationCount);

        return out;
    }

protected:
};

class opensslHkdfContext : public HKDFContext
{
    Q_OBJECT
public:
    opensslHkdfContext(Provider *p, const QString &type)
        : HKDFContext(p, type)
    {
    }

    Provider::Context *clone() const override
    {
        return new opensslHkdfContext(*this);
    }

    SymmetricKey makeKey(const SecureArray &         secret,
                         const InitializationVector &salt,
                         const InitializationVector &info,
                         unsigned int                keyLength) override
    {
        SecureArray   out(keyLength);
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
        EVP_PKEY_derive_init(pctx);
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256());
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, (const unsigned char *)salt.data(), int(salt.size()));
        EVP_PKEY_CTX_set1_hkdf_key(pctx, (const unsigned char *)secret.data(), int(secret.size()));
        EVP_PKEY_CTX_add1_hkdf_info(pctx, (const unsigned char *)info.data(), int(info.size()));
        size_t outlen = out.size();
        EVP_PKEY_derive(pctx, reinterpret_cast<unsigned char *>(out.data()), &outlen);
        EVP_PKEY_CTX_free(pctx);
        return out;
    }
};

class opensslHMACContext : public MACContext
{
    Q_OBJECT
public:
    opensslHMACContext(const EVP_MD *algorithm, Provider *p, const QString &type)
        : MACContext(p, type)
    {
        m_algorithm = algorithm;
        m_context   = HMAC_CTX_new();
    }

    opensslHMACContext(const opensslHMACContext &other)
        : MACContext(other)
    {
        m_algorithm = other.m_algorithm;
        m_context   = HMAC_CTX_new();
        HMAC_CTX_copy(m_context, other.m_context);
    }

    ~opensslHMACContext() override
    {
        HMAC_CTX_free(m_context);
    }

    void setup(const SymmetricKey &key) override
    {
        HMAC_Init_ex(m_context, key.data(), key.size(), m_algorithm, nullptr);
    }

    KeyLength keyLength() const override
    {
        return anyKeyLength();
    }

    void update(const MemoryRegion &a) override
    {
        HMAC_Update(m_context, (unsigned char *)a.data(), a.size());
    }

    void final(MemoryRegion *out) override
    {
        SecureArray sa(EVP_MD_size(m_algorithm), 0);
        HMAC_Final(m_context, (unsigned char *)sa.data(), nullptr);
        HMAC_CTX_reset(m_context);
        *out = sa;
    }

    Provider::Context *clone() const override
    {
        return new opensslHMACContext(*this);
    }

protected:
    HMAC_CTX *    m_context;
    const EVP_MD *m_algorithm;
};

//----------------------------------------------------------------------------
// EVPKey
//----------------------------------------------------------------------------

// note: this class squelches processing errors, since QCA doesn't care about them
class EVPKey
{
public:
    enum State
    {
        Idle,
        SignActive,
        SignError,
        VerifyActive,
        VerifyError
    };
    EVP_PKEY *  pkey;
    EVP_MD_CTX *mdctx;
    State       state;
    bool        raw_type;
    SecureArray raw;

    EVPKey()
    {
        pkey     = nullptr;
        raw_type = false;
        state    = Idle;
        mdctx    = EVP_MD_CTX_new();
    }

    EVPKey(const EVPKey &from)
    {
        pkey = from.pkey;
        EVP_PKEY_up_ref(pkey);
        raw_type = false;
        state    = Idle;
        mdctx    = EVP_MD_CTX_new();
        EVP_MD_CTX_copy(mdctx, from.mdctx);
    }

    EVPKey &operator=(const EVPKey &from) = delete;

    ~EVPKey()
    {
        reset();
        EVP_MD_CTX_free(mdctx);
    }

    void reset()
    {
        if (pkey)
            EVP_PKEY_free(pkey);
        pkey = nullptr;
        raw.clear();
        raw_type = false;
    }

    void startSign(const EVP_MD *type)
    {
        state = SignActive;
        if (!type) {
            raw_type = true;
            raw.clear();
        } else {
            raw_type = false;
            EVP_MD_CTX_init(mdctx);
            if (!EVP_SignInit_ex(mdctx, type, nullptr))
                state = SignError;
        }
    }

    void startVerify(const EVP_MD *type)
    {
        state = VerifyActive;
        if (!type) {
            raw_type = true;
            raw.clear();
        } else {
            raw_type = false;
            EVP_MD_CTX_init(mdctx);
            if (!EVP_VerifyInit_ex(mdctx, type, nullptr))
                state = VerifyError;
        }
    }

    void update(const MemoryRegion &in)
    {
        if (state == SignActive) {
            if (raw_type)
                raw += in;
            else if (!EVP_SignUpdate(mdctx, in.data(), (unsigned int)in.size()))
                state = SignError;
        } else if (state == VerifyActive) {
            if (raw_type)
                raw += in;
            else if (!EVP_VerifyUpdate(mdctx, in.data(), (unsigned int)in.size()))
                state = VerifyError;
        }
    }

    SecureArray endSign()
    {
        if (state == SignActive) {
            SecureArray  out(EVP_PKEY_size(pkey));
            unsigned int len = out.size();
            if (raw_type) {
                int type = EVP_PKEY_id(pkey);

                if (type == EVP_PKEY_RSA) {
                    const RSA *rsa = EVP_PKEY_get0_RSA(pkey);
                    if (RSA_private_encrypt(raw.size(),
                                            (unsigned char *)raw.data(),
                                            (unsigned char *)out.data(),
                                            (RSA *)rsa,
                                            RSA_PKCS1_PADDING) == -1) {
                        state = SignError;
                        return SecureArray();
                    }
                } else if (type == EVP_PKEY_DSA) {
                    state = SignError;
                    return SecureArray();
                } else {
                    state = SignError;
                    return SecureArray();
                }
            } else {
                if (!EVP_SignFinal(mdctx, (unsigned char *)out.data(), &len, pkey)) {
                    state = SignError;
                    return SecureArray();
                }
            }
            out.resize(len);
            state = Idle;
            return out;
        } else
            return SecureArray();
    }

    bool endVerify(const SecureArray &sig)
    {
        if (state == VerifyActive) {
            if (raw_type) {
                SecureArray out(EVP_PKEY_size(pkey));
                int         len = 0;

                int type = EVP_PKEY_id(pkey);

                if (type == EVP_PKEY_RSA) {
                    const RSA *rsa = EVP_PKEY_get0_RSA(pkey);
                    if ((len = RSA_public_decrypt(sig.size(),
                                                  (unsigned char *)sig.data(),
                                                  (unsigned char *)out.data(),
                                                  (RSA *)rsa,
                                                  RSA_PKCS1_PADDING)) == -1) {
                        state = VerifyError;
                        return false;
                    }
                } else if (type == EVP_PKEY_DSA) {
                    state = VerifyError;
                    return false;
                } else {
                    state = VerifyError;
                    return false;
                }

                out.resize(len);

                if (out != raw) {
                    state = VerifyError;
                    return false;
                }
            } else {
                if (EVP_VerifyFinal(mdctx, (unsigned char *)sig.data(), (unsigned int)sig.size(), pkey) != 1) {
                    state = VerifyError;
                    return false;
                }
            }
            state = Idle;
            return true;
        } else
            return false;
    }
};

//----------------------------------------------------------------------------
// MyDLGroup
//----------------------------------------------------------------------------

// IETF primes from Botan
static const char *IETF_1024_PRIME =
    "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
    "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
    "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
    "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
    "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381"
    "FFFFFFFF FFFFFFFF";

static const char *IETF_2048_PRIME =
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

static const char *IETF_4096_PRIME =
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
static const char *JCE_512_SEED    = "B869C82B 35D70E1B 1FF91B28 E37A62EC DC34409B";
static const int   JCE_512_COUNTER = 123;

static const char *JCE_768_SEED    = "77D0F8C4 DAD15EB8 C4F2F8D6 726CEFD9 6D5BB399";
static const int   JCE_768_COUNTER = 263;

static const char *JCE_1024_SEED    = "8D515589 4229D5E6 89EE01E6 018A237E 2CAE64CD";
static const int   JCE_1024_COUNTER = 92;

static QByteArray dehex(const QByteArray &hex)
{
    QString str;
    for (const char c : hex) {
        if (c != ' ')
            str += QLatin1Char(c);
    }
    return hexToArray(str);
}

static BigInteger decode(const QByteArray &prime)
{
    QByteArray a(1, 0); // 1 byte of zero padding
    a.append(dehex(prime));
    return BigInteger(SecureArray(a));
}

#ifndef OPENSSL_FIPS
static QByteArray decode_seed(const QByteArray &hex_seed)
{
    return dehex(hex_seed);
}
#endif

class DLParams
{
public:
    BigInteger p, q, g;
};

#ifndef OPENSSL_FIPS

static bool make_dlgroup(const QByteArray &seed, int bits, int counter, DLParams *params)
{
    int                                        ret_counter;
    std::unique_ptr<DSA, decltype(DsaDeleter)> dsa(DSA_new(), DsaDeleter);
    if (!dsa)
        return false;

    if (DSA_generate_parameters_ex(
            dsa.get(), bits, (const unsigned char *)seed.data(), seed.size(), &ret_counter, nullptr, nullptr) != 1)
        return false;

    if (ret_counter != counter)
        return false;

    const BIGNUM *bnp, *bnq, *bng;
    DSA_get0_pqg(dsa.get(), &bnp, &bnq, &bng);
    params->p = bn2bi(bnp);
    params->q = bn2bi(bnq);
    params->g = bn2bi(bng);

    return true;
}
#endif

static bool get_dlgroup(const BigInteger &p, const BigInteger &g, DLParams *params)
{
    params->p = p;
    params->q = BigInteger(0);
    params->g = g;
    return true;
}

class DLGroupMaker : public QThread
{
    Q_OBJECT
public:
    DLGroupSet set;
    bool       ok;
    DLParams   params;

    DLGroupMaker(DLGroupSet _set)
    {
        set = _set;
    }

    ~DLGroupMaker() override
    {
        wait();
    }

    void run() override
    {
        switch (set) {
#ifndef OPENSSL_FIPS
        case DSA_512:
            ok = make_dlgroup(decode_seed(JCE_512_SEED), 512, JCE_512_COUNTER, &params);
            break;

        case DSA_768:
            ok = make_dlgroup(decode_seed(JCE_768_SEED), 768, JCE_768_COUNTER, &params);
            break;

        case DSA_1024:
            ok = make_dlgroup(decode_seed(JCE_1024_SEED), 1024, JCE_1024_COUNTER, &params);
            break;
#endif

        case IETF_1024:
            ok = get_dlgroup(decode(IETF_1024_PRIME), 2, &params);
            break;

        case IETF_2048:
            ok = get_dlgroup(decode(IETF_2048_PRIME), 2, &params);
            break;

        case IETF_4096:
            ok = get_dlgroup(decode(IETF_4096_PRIME), 2, &params);
            break;

        default:
            ok = false;
            break;
        }
    }
};

class MyDLGroup : public DLGroupContext
{
    Q_OBJECT
public:
    DLGroupMaker *gm;
    bool          wasBlocking;
    DLParams      params;
    bool          empty;

    MyDLGroup(Provider *p)
        : DLGroupContext(p)
    {
        gm    = nullptr;
        empty = true;
    }

    MyDLGroup(const MyDLGroup &from)
        : DLGroupContext(from.provider())
    {
        gm    = nullptr;
        empty = true;
    }

    ~MyDLGroup() override
    {
        delete gm;
    }

    Provider::Context *clone() const override
    {
        return new MyDLGroup(*this);
    }

    QList<DLGroupSet> supportedGroupSets() const override
    {
        QList<DLGroupSet> list;

        // DSA_* was removed in FIPS specification
        // https://bugzilla.redhat.com/show_bug.cgi?id=1144655
#ifndef OPENSSL_FIPS
        list += DSA_512;
        list += DSA_768;
        list += DSA_1024;
#endif
        list += IETF_1024;
        list += IETF_2048;
        list += IETF_4096;
        return list;
    }

    bool isNull() const override
    {
        return empty;
    }

    void fetchGroup(DLGroupSet set, bool block) override
    {
        params = DLParams();
        empty  = true;

        gm          = new DLGroupMaker(set);
        wasBlocking = block;
        if (block) {
            gm->run();
            gm_finished();
        } else {
            connect(gm, &DLGroupMaker::finished, this, &MyDLGroup::gm_finished);
            gm->start();
        }
    }

    void getResult(BigInteger *p, BigInteger *q, BigInteger *g) const override
    {
        *p = params.p;
        *q = params.q;
        *g = params.g;
    }

private Q_SLOTS:
    void gm_finished()
    {
        bool ok = gm->ok;
        if (ok) {
            params = gm->params;
            empty  = false;
        }

        if (wasBlocking)
            delete gm;
        else
            gm->deleteLater();
        gm = nullptr;

        if (!wasBlocking)
            emit finished();
    }
};

//----------------------------------------------------------------------------
// RSAKey
//----------------------------------------------------------------------------
namespace {
static const auto RsaDeleter = [](RSA *pointer) {
    if (pointer)
        RSA_free((RSA *)pointer);
};

static const auto BnDeleter = [](BIGNUM *pointer) {
    if (pointer)
        BN_free((BIGNUM *)pointer);
};
} // end of anonymous namespace

class RSAKeyMaker : public QThread
{
    Q_OBJECT
public:
    RSA *result;
    int  bits, exp;

    RSAKeyMaker(int _bits, int _exp, QObject *parent = nullptr)
        : QThread(parent)
        , result(nullptr)
        , bits(_bits)
        , exp(_exp)
    {
    }

    ~RSAKeyMaker() override
    {
        wait();
        if (result)
            RSA_free(result);
    }

    void run() override
    {
        std::unique_ptr<RSA, decltype(RsaDeleter)> rsa(RSA_new(), RsaDeleter);
        if (!rsa)
            return;

        std::unique_ptr<BIGNUM, decltype(BnDeleter)> e(BN_new(), BnDeleter);
        if (!e)
            return;

        BN_clear(e.get());
        if (BN_set_word(e.get(), exp) != 1)
            return;

        if (RSA_generate_key_ex(rsa.get(), bits, e.get(), nullptr) == 0) {
            return;
        }

        result = rsa.release();
    }

    RSA *takeResult()
    {
        RSA *rsa = result;
        result   = nullptr;
        return rsa;
    }
};

class RSAKey : public RSAContext
{
    Q_OBJECT
public:
    EVPKey       evp;
    RSAKeyMaker *keymaker;
    bool         wasBlocking;
    bool         sec;

    RSAKey(Provider *p)
        : RSAContext(p)
    {
        keymaker = nullptr;
        sec      = false;
    }

    RSAKey(const RSAKey &from)
        : RSAContext(from.provider())
        , evp(from.evp)
    {
        keymaker = nullptr;
        sec      = from.sec;
    }

    ~RSAKey() override
    {
        delete keymaker;
    }

    Provider::Context *clone() const override
    {
        return new RSAKey(*this);
    }

    bool isNull() const override
    {
        return (evp.pkey ? false : true);
    }

    PKey::Type type() const override
    {
        return PKey::RSA;
    }

    bool isPrivate() const override
    {
        return sec;
    }

    bool canExport() const override
    {
        return true;
    }

    void convertToPublic() override
    {
        if (!sec)
            return;

        // extract the public key into DER format
        const RSA *    rsa_pkey = EVP_PKEY_get0_RSA(evp.pkey);
        int            len      = i2d_RSAPublicKey(rsa_pkey, nullptr);
        SecureArray    result(len);
        unsigned char *p = (unsigned char *)result.data();
        i2d_RSAPublicKey(rsa_pkey, &p);
        p = (unsigned char *)result.data();

        // put the DER public key back into openssl
        evp.reset();
        RSA *rsa = d2i_RSAPublicKey(nullptr, (const unsigned char **)&p, result.size());
        evp.pkey = EVP_PKEY_new();
        EVP_PKEY_assign_RSA(evp.pkey, rsa);
        sec = false;
    }

    int bits() const override
    {
        return EVP_PKEY_bits(evp.pkey);
    }

    int maximumEncryptSize(EncryptionAlgorithm alg) const override
    {
        const RSA *rsa  = EVP_PKEY_get0_RSA(evp.pkey);
        int        size = 0;
        switch (alg) {
        case EME_PKCS1v15:
            size = RSA_size(rsa) - 11 - 1;
            break;
        case EME_PKCS1_OAEP:
            size = RSA_size(rsa) - 41 - 1;
            break;
        case EME_PKCS1v15_SSL:
            size = RSA_size(rsa) - 11 - 1;
            break;
        case EME_NO_PADDING:
            size = RSA_size(rsa) - 1;
            break;
        }

        return size;
    }

    SecureArray encrypt(const SecureArray &in, EncryptionAlgorithm alg) override
    {
        const RSA * rsa = EVP_PKEY_get0_RSA(evp.pkey);
        SecureArray buf = in;
        int         max = maximumEncryptSize(alg);

        if (buf.size() > max)
            buf.resize(max);
        SecureArray result(RSA_size(rsa));

        int pad;
        switch (alg) {
        case EME_PKCS1v15:
            pad = RSA_PKCS1_PADDING;
            break;
        case EME_PKCS1_OAEP:
            pad = RSA_PKCS1_OAEP_PADDING;
            break;
// OPENSSL_VERSION_MAJOR is only defined on openssl > 3.0
// that doesn't have RSA_SSLV23_PADDING so we can use it negatively here
#ifndef OPENSSL_VERSION_MAJOR
        case EME_PKCS1v15_SSL:
            pad = RSA_SSLV23_PADDING;
            break;
#endif
        case EME_NO_PADDING:
            pad = RSA_NO_PADDING;
            break;
        default:
            return SecureArray();
            break;
        }

        int ret;
        if (isPrivate())
            ret = RSA_private_encrypt(
                buf.size(), (unsigned char *)buf.data(), (unsigned char *)result.data(), (RSA *)rsa, pad);
        else
            ret = RSA_public_encrypt(
                buf.size(), (unsigned char *)buf.data(), (unsigned char *)result.data(), (RSA *)rsa, pad);

        if (ret < 0)
            return SecureArray();
        result.resize(ret);

        return result;
    }

    bool decrypt(const SecureArray &in, SecureArray *out, EncryptionAlgorithm alg) override
    {
        const RSA * rsa = EVP_PKEY_get0_RSA(evp.pkey);
        SecureArray result(RSA_size(rsa));
        int         pad;

        switch (alg) {
        case EME_PKCS1v15:
            pad = RSA_PKCS1_PADDING;
            break;
        case EME_PKCS1_OAEP:
            pad = RSA_PKCS1_OAEP_PADDING;
            break;
// OPENSSL_VERSION_MAJOR is only defined on openssl > 3.0
// that doesn't have RSA_SSLV23_PADDING so we can use it negatively here
#ifndef OPENSSL_VERSION_MAJOR
        case EME_PKCS1v15_SSL:
            pad = RSA_SSLV23_PADDING;
            break;
#endif
        case EME_NO_PADDING:
            pad = RSA_NO_PADDING;
            break;
        default:
            return false;
            break;
        }

        int ret;
        if (isPrivate())
            ret = RSA_private_decrypt(
                in.size(), (unsigned char *)in.data(), (unsigned char *)result.data(), (RSA *)rsa, pad);
        else
            ret = RSA_public_decrypt(
                in.size(), (unsigned char *)in.data(), (unsigned char *)result.data(), (RSA *)rsa, pad);

        if (ret < 0)
            return false;
        result.resize(ret);

        *out = result;
        return true;
    }

    void startSign(SignatureAlgorithm alg, SignatureFormat) override
    {
        const EVP_MD *md = nullptr;
        if (alg == EMSA3_SHA1)
            md = EVP_sha1();
        else if (alg == EMSA3_MD5)
            md = EVP_md5();
#ifdef HAVE_OPENSSL_MD2
        else if (alg == EMSA3_MD2)
            md = EVP_md2();
#endif
        else if (alg == EMSA3_RIPEMD160)
            md = EVP_ripemd160();
        else if (alg == EMSA3_SHA224)
            md = EVP_sha224();
        else if (alg == EMSA3_SHA256)
            md = EVP_sha256();
        else if (alg == EMSA3_SHA384)
            md = EVP_sha384();
        else if (alg == EMSA3_SHA512)
            md = EVP_sha512();
        else if (alg == EMSA3_Raw) {
            // md = 0
        }
        evp.startSign(md);
    }

    void startVerify(SignatureAlgorithm alg, SignatureFormat) override
    {
        const EVP_MD *md = nullptr;
        if (alg == EMSA3_SHA1)
            md = EVP_sha1();
        else if (alg == EMSA3_MD5)
            md = EVP_md5();
#ifdef HAVE_OPENSSL_MD2
        else if (alg == EMSA3_MD2)
            md = EVP_md2();
#endif
        else if (alg == EMSA3_RIPEMD160)
            md = EVP_ripemd160();
        else if (alg == EMSA3_SHA224)
            md = EVP_sha224();
        else if (alg == EMSA3_SHA256)
            md = EVP_sha256();
        else if (alg == EMSA3_SHA384)
            md = EVP_sha384();
        else if (alg == EMSA3_SHA512)
            md = EVP_sha512();
        else if (alg == EMSA3_Raw) {
            // md = 0
        }
        evp.startVerify(md);
    }

    void update(const MemoryRegion &in) override
    {
        evp.update(in);
    }

    QByteArray endSign() override
    {
        return evp.endSign().toByteArray();
    }

    bool endVerify(const QByteArray &sig) override
    {
        return evp.endVerify(sig);
    }

    void createPrivate(int bits, int exp, bool block) override
    {
        evp.reset();

        keymaker    = new RSAKeyMaker(bits, exp, !block ? this : nullptr);
        wasBlocking = block;
        if (block) {
            keymaker->run();
            km_finished();
        } else {
            connect(keymaker, &RSAKeyMaker::finished, this, &RSAKey::km_finished);
            keymaker->start();
        }
    }

    void createPrivate(const BigInteger &n,
                       const BigInteger &e,
                       const BigInteger &p,
                       const BigInteger &q,
                       const BigInteger &d) override
    {
        evp.reset();

        RSA *rsa = RSA_new();
        if (RSA_set0_key(rsa, bi2bn(n), bi2bn(e), bi2bn(d)) == 0 || RSA_set0_factors(rsa, bi2bn(p), bi2bn(q)) == 0) {
            // Free BIGNUMS?
            RSA_free(rsa);
            return;
        }

        // When private key has no Public Exponent (e) or Private Exponent (d)
        // need to disable blinding. Otherwise decryption will be broken.
        // http://www.mail-archive.com/openssl-users@openssl.org/msg63530.html
        if (e == BigInteger(0) || d == BigInteger(0))
            RSA_blinding_off(rsa);

        evp.pkey = EVP_PKEY_new();
        EVP_PKEY_assign_RSA(evp.pkey, rsa);
        sec = true;
    }

    void createPublic(const BigInteger &n, const BigInteger &e) override
    {
        evp.reset();

        RSA *rsa = RSA_new();
        if (RSA_set0_key(rsa, bi2bn(n), bi2bn(e), nullptr) == 0) {
            RSA_free(rsa);
            return;
        }

        evp.pkey = EVP_PKEY_new();
        EVP_PKEY_assign_RSA(evp.pkey, rsa);
        sec = false;
    }

    BigInteger n() const override
    {
        const RSA *   rsa = EVP_PKEY_get0_RSA(evp.pkey);
        const BIGNUM *bnn;
        RSA_get0_key(rsa, &bnn, nullptr, nullptr);
        return bn2bi(bnn);
    }

    BigInteger e() const override
    {
        const RSA *   rsa = EVP_PKEY_get0_RSA(evp.pkey);
        const BIGNUM *bne;
        RSA_get0_key(rsa, nullptr, &bne, nullptr);
        return bn2bi(bne);
    }

    BigInteger p() const override
    {
        const RSA *   rsa = EVP_PKEY_get0_RSA(evp.pkey);
        const BIGNUM *bnp;
        RSA_get0_factors(rsa, &bnp, nullptr);
        return bn2bi(bnp);
    }

    BigInteger q() const override
    {
        const RSA *   rsa = EVP_PKEY_get0_RSA(evp.pkey);
        const BIGNUM *bnq;
        RSA_get0_factors(rsa, nullptr, &bnq);
        return bn2bi(bnq);
    }

    BigInteger d() const override
    {
        const RSA *   rsa = EVP_PKEY_get0_RSA(evp.pkey);
        const BIGNUM *bnd;
        RSA_get0_key(rsa, nullptr, nullptr, &bnd);
        return bn2bi(bnd);
    }

private Q_SLOTS:
    void km_finished()
    {
        RSA *rsa = keymaker->takeResult();
        if (wasBlocking)
            delete keymaker;
        else
            keymaker->deleteLater();
        keymaker = nullptr;

        if (rsa) {
            evp.pkey = EVP_PKEY_new();
            EVP_PKEY_assign_RSA(evp.pkey, rsa);
            sec = true;
        }

        if (!wasBlocking)
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
    DLGroup domain;
    DSA *   result;

    DSAKeyMaker(const DLGroup &_domain, QObject *parent = nullptr)
        : QThread(parent)
        , domain(_domain)
        , result(nullptr)
    {
    }

    ~DSAKeyMaker() override
    {
        wait();
        if (result)
            DSA_free(result);
    }

    void run() override
    {
        std::unique_ptr<DSA, decltype(DsaDeleter)> dsa(DSA_new(), DsaDeleter);
        BIGNUM *pne = bi2bn(domain.p()), *qne = bi2bn(domain.q()), *gne = bi2bn(domain.g());

        if (!DSA_set0_pqg(dsa.get(), pne, qne, gne)) {
            return;
        }
        if (!DSA_generate_key(dsa.get())) {
            // OPENSSL_VERSION_MAJOR is only defined in openssl3
#ifdef OPENSSL_VERSION_MAJOR
            // HACK
            // in openssl3 there is an internal flag for "legacy" values
            //      bits < 2048 && seed_len <= 20
            // set in ossl_ffc_params_FIPS186_2_generate (called by DSA_generate_parameters_ex)
            // that we have no way to get or set, so if the bits are smaller than 2048 we generate
            // a dsa from a dummy seed and then override the p/q/g with the ones we want
            // so we can reuse the internal flag
            if (BN_num_bits(pne) < 2048) {
                int dummy;
                dsa.reset(DSA_new());
                if (DSA_generate_parameters_ex(
                        dsa.get(), 512, (const unsigned char *)"THIS_IS_A_DUMMY_SEED", 20, &dummy, nullptr, nullptr) !=
                    1) {
                    return;
                }
                pne = bi2bn(domain.p());
                qne = bi2bn(domain.q());
                gne = bi2bn(domain.g());
                if (!DSA_set0_pqg(dsa.get(), pne, qne, gne)) {
                    return;
                }
                if (!DSA_generate_key(dsa.get())) {
                    return;
                }
            } else {
                return;
            }
#else
            return;
#endif
        }
        result = dsa.release();
    }

    DSA *takeResult()
    {
        DSA *dsa = result;
        result   = nullptr;
        return dsa;
    }
};

// note: DSA doesn't use SignatureAlgorithm, since EMSA1 is always assumed
class DSAKey : public DSAContext
{
    Q_OBJECT
public:
    EVPKey       evp;
    DSAKeyMaker *keymaker;
    bool         wasBlocking;
    bool         transformsig;
    bool         sec;

    DSAKey(Provider *p)
        : DSAContext(p)
    {
        keymaker = nullptr;
        sec      = false;
    }

    DSAKey(const DSAKey &from)
        : DSAContext(from.provider())
        , evp(from.evp)
    {
        keymaker = nullptr;
        sec      = from.sec;
    }

    ~DSAKey() override
    {
        delete keymaker;
    }

    Provider::Context *clone() const override
    {
        return new DSAKey(*this);
    }

    bool isNull() const override
    {
        return (evp.pkey ? false : true);
    }

    PKey::Type type() const override
    {
        return PKey::DSA;
    }

    bool isPrivate() const override
    {
        return sec;
    }

    bool canExport() const override
    {
        return true;
    }

    void convertToPublic() override
    {
        if (!sec)
            return;

        // extract the public key into DER format
        const DSA *    dsa_pkey = EVP_PKEY_get0_DSA(evp.pkey);
        int            len      = i2d_DSAPublicKey(dsa_pkey, nullptr);
        SecureArray    result(len);
        unsigned char *p = (unsigned char *)result.data();
        i2d_DSAPublicKey(dsa_pkey, &p);
        p = (unsigned char *)result.data();

        // put the DER public key back into openssl
        evp.reset();
        DSA *dsa = d2i_DSAPublicKey(nullptr, (const unsigned char **)&p, result.size());
        evp.pkey = EVP_PKEY_new();
        EVP_PKEY_assign_DSA(evp.pkey, dsa);
        sec = false;
    }

    int bits() const override
    {
        return EVP_PKEY_bits(evp.pkey);
    }

    void startSign(SignatureAlgorithm, SignatureFormat format) override
    {
        // openssl native format is DER, so transform otherwise
        if (format != DERSequence)
            transformsig = true;
        else
            transformsig = false;

        evp.startSign(EVP_sha1());
    }

    void startVerify(SignatureAlgorithm, SignatureFormat format) override
    {
        // openssl native format is DER, so transform otherwise
        if (format != DERSequence)
            transformsig = true;
        else
            transformsig = false;

        evp.startVerify(EVP_sha1());
    }

    void update(const MemoryRegion &in) override
    {
        evp.update(in);
    }

    QByteArray endSign() override
    {
        SecureArray out = evp.endSign();
        if (transformsig)
            return dsasig_der_to_raw(out).toByteArray();
        else
            return out.toByteArray();
    }

    bool endVerify(const QByteArray &sig) override
    {
        SecureArray in;
        if (transformsig)
            in = dsasig_raw_to_der(sig);
        else
            in = sig;
        return evp.endVerify(in);
    }

    void createPrivate(const DLGroup &domain, bool block) override
    {
        evp.reset();

        keymaker    = new DSAKeyMaker(domain, !block ? this : nullptr);
        wasBlocking = block;
        if (block) {
            keymaker->run();
            km_finished();
        } else {
            connect(keymaker, &DSAKeyMaker::finished, this, &DSAKey::km_finished);
            keymaker->start();
        }
    }

    void createPrivate(const DLGroup &domain, const BigInteger &y, const BigInteger &x) override
    {
        evp.reset();

        DSA *   dsa        = DSA_new();
        BIGNUM *bnp        = bi2bn(domain.p());
        BIGNUM *bnq        = bi2bn(domain.q());
        BIGNUM *bng        = bi2bn(domain.g());
        BIGNUM *bnpub_key  = bi2bn(y);
        BIGNUM *bnpriv_key = bi2bn(x);

        if (!DSA_set0_pqg(dsa, bnp, bnq, bng) || !DSA_set0_key(dsa, bnpub_key, bnpriv_key)) {
            DSA_free(dsa);
            return;
        }

        evp.pkey = EVP_PKEY_new();
        EVP_PKEY_assign_DSA(evp.pkey, dsa);
        sec = true;
    }

    void createPublic(const DLGroup &domain, const BigInteger &y) override
    {
        evp.reset();

        DSA *   dsa       = DSA_new();
        BIGNUM *bnp       = bi2bn(domain.p());
        BIGNUM *bnq       = bi2bn(domain.q());
        BIGNUM *bng       = bi2bn(domain.g());
        BIGNUM *bnpub_key = bi2bn(y);

        if (!DSA_set0_pqg(dsa, bnp, bnq, bng) || !DSA_set0_key(dsa, bnpub_key, nullptr)) {
            DSA_free(dsa);
            return;
        }

        evp.pkey = EVP_PKEY_new();
        EVP_PKEY_assign_DSA(evp.pkey, dsa);
        sec = false;
    }

    DLGroup domain() const override
    {
        const DSA *   dsa = EVP_PKEY_get0_DSA(evp.pkey);
        const BIGNUM *bnp, *bnq, *bng;
        DSA_get0_pqg(dsa, &bnp, &bnq, &bng);
        return DLGroup(bn2bi(bnp), bn2bi(bnq), bn2bi(bng));
    }

    BigInteger y() const override
    {
        const DSA *   dsa = EVP_PKEY_get0_DSA(evp.pkey);
        const BIGNUM *bnpub_key;
        DSA_get0_key(dsa, &bnpub_key, nullptr);
        return bn2bi(bnpub_key);
    }

    BigInteger x() const override
    {
        const DSA *   dsa = EVP_PKEY_get0_DSA(evp.pkey);
        const BIGNUM *bnpriv_key;
        DSA_get0_key(dsa, nullptr, &bnpriv_key);
        return bn2bi(bnpriv_key);
    }

private Q_SLOTS:
    void km_finished()
    {
        DSA *dsa = keymaker->takeResult();
        if (wasBlocking)
            delete keymaker;
        else
            keymaker->deleteLater();
        keymaker = nullptr;

        if (dsa) {
            evp.pkey = EVP_PKEY_new();
            EVP_PKEY_assign_DSA(evp.pkey, dsa);
            sec = true;
        }

        if (!wasBlocking)
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
    DLGroup domain;
    DH *    result;

    DHKeyMaker(const DLGroup &_domain, QObject *parent = nullptr)
        : QThread(parent)
        , domain(_domain)
        , result(nullptr)
    {
    }

    ~DHKeyMaker() override
    {
        wait();
        if (result)
            DH_free(result);
    }

    void run() override
    {
        DH *    dh  = DH_new();
        BIGNUM *bnp = bi2bn(domain.p());
        BIGNUM *bng = bi2bn(domain.g());
        if (!DH_set0_pqg(dh, bnp, nullptr, bng) || !DH_generate_key(dh)) {
            DH_free(dh);
            return;
        }
        result = dh;
    }

    DH *takeResult()
    {
        DH *dh = result;
        result = nullptr;
        return dh;
    }
};

class DHKey : public DHContext
{
    Q_OBJECT
public:
    EVPKey      evp;
    DHKeyMaker *keymaker;
    bool        wasBlocking;
    bool        sec;

    DHKey(Provider *p)
        : DHContext(p)
    {
        keymaker = nullptr;
        sec      = false;
    }

    DHKey(const DHKey &from)
        : DHContext(from.provider())
        , evp(from.evp)
    {
        keymaker = nullptr;
        sec      = from.sec;
    }

    ~DHKey() override
    {
        delete keymaker;
    }

    Provider::Context *clone() const override
    {
        return new DHKey(*this);
    }

    bool isNull() const override
    {
        return (evp.pkey ? false : true);
    }

    PKey::Type type() const override
    {
        return PKey::DH;
    }

    bool isPrivate() const override
    {
        return sec;
    }

    bool canExport() const override
    {
        return true;
    }

    void convertToPublic() override
    {
        if (!sec)
            return;

        const DH *    orig = EVP_PKEY_get0_DH(evp.pkey);
        DH *          dh   = DH_new();
        const BIGNUM *bnp, *bng, *bnpub_key;
        DH_get0_pqg(orig, &bnp, nullptr, &bng);
        DH_get0_key(orig, &bnpub_key, nullptr);

        DH_set0_key(dh, BN_dup(bnpub_key), nullptr);
        DH_set0_pqg(dh, BN_dup(bnp), nullptr, BN_dup(bng));

        evp.reset();

        evp.pkey = EVP_PKEY_new();
        EVP_PKEY_assign_DH(evp.pkey, dh);
        sec = false;
    }

    int bits() const override
    {
        return EVP_PKEY_bits(evp.pkey);
    }

    SymmetricKey deriveKey(const PKeyBase &theirs) override
    {
        const DH *    dh   = EVP_PKEY_get0_DH(evp.pkey);
        const DH *    them = EVP_PKEY_get0_DH(static_cast<const DHKey *>(&theirs)->evp.pkey);
        const BIGNUM *bnpub_key;
        DH_get0_key(them, &bnpub_key, nullptr);

        SecureArray result(DH_size(dh));
        int         ret = DH_compute_key((unsigned char *)result.data(), bnpub_key, (DH *)dh);
        if (ret <= 0)
            return SymmetricKey();
        result.resize(ret);
        return SymmetricKey(result);
    }

    void createPrivate(const DLGroup &domain, bool block) override
    {
        evp.reset();

        keymaker    = new DHKeyMaker(domain, !block ? this : nullptr);
        wasBlocking = block;
        if (block) {
            keymaker->run();
            km_finished();
        } else {
            connect(keymaker, &DHKeyMaker::finished, this, &DHKey::km_finished);
            keymaker->start();
        }
    }

    void createPrivate(const DLGroup &domain, const BigInteger &y, const BigInteger &x) override
    {
        evp.reset();

        DH *    dh         = DH_new();
        BIGNUM *bnp        = bi2bn(domain.p());
        BIGNUM *bng        = bi2bn(domain.g());
        BIGNUM *bnpub_key  = bi2bn(y);
        BIGNUM *bnpriv_key = bi2bn(x);

        if (!DH_set0_key(dh, bnpub_key, bnpriv_key) || !DH_set0_pqg(dh, bnp, nullptr, bng)) {
            DH_free(dh);
            return;
        }

        evp.pkey = EVP_PKEY_new();
        EVP_PKEY_assign_DH(evp.pkey, dh);
        sec = true;
    }

    void createPublic(const DLGroup &domain, const BigInteger &y) override
    {
        evp.reset();

        DH *    dh        = DH_new();
        BIGNUM *bnp       = bi2bn(domain.p());
        BIGNUM *bng       = bi2bn(domain.g());
        BIGNUM *bnpub_key = bi2bn(y);

        if (!DH_set0_key(dh, bnpub_key, nullptr) || !DH_set0_pqg(dh, bnp, nullptr, bng)) {
            DH_free(dh);
            return;
        }

        evp.pkey = EVP_PKEY_new();
        EVP_PKEY_assign_DH(evp.pkey, dh);
        sec = false;
    }

    DLGroup domain() const override
    {
        const DH *    dh = EVP_PKEY_get0_DH(evp.pkey);
        const BIGNUM *bnp, *bng;
        DH_get0_pqg(dh, &bnp, nullptr, &bng);
        return DLGroup(bn2bi(bnp), bn2bi(bng));
    }

    BigInteger y() const override
    {
        const DH *    dh = EVP_PKEY_get0_DH(evp.pkey);
        const BIGNUM *bnpub_key;
        DH_get0_key(dh, &bnpub_key, nullptr);
        return bn2bi(bnpub_key);
    }

    BigInteger x() const override
    {
        const DH *    dh = EVP_PKEY_get0_DH(evp.pkey);
        const BIGNUM *bnpriv_key;
        DH_get0_key(dh, nullptr, &bnpriv_key);
        return bn2bi(bnpriv_key);
    }

private Q_SLOTS:
    void km_finished()
    {
        DH *dh = keymaker->takeResult();
        if (wasBlocking)
            delete keymaker;
        else
            keymaker->deleteLater();
        keymaker = nullptr;

        if (dh) {
            evp.pkey = EVP_PKEY_new();
            EVP_PKEY_assign_DH(evp.pkey, dh);
            sec = true;
        }

        if (!wasBlocking)
            emit finished();
    }
};

//----------------------------------------------------------------------------
// QCA-based RSA_METHOD
//----------------------------------------------------------------------------

// only supports EMSA3_Raw for now
class QCA_RSA_METHOD
{
public:
    RSAPrivateKey key;

    QCA_RSA_METHOD(const RSAPrivateKey &_key, RSA *rsa)
    {
        key = _key;
        RSA_set_method(rsa, rsa_method());
        RSA_set_app_data(rsa, this);
        BIGNUM *bnn = bi2bn(_key.n());
        BIGNUM *bne = bi2bn(_key.e());

        RSA_set0_key(rsa, bnn, bne, nullptr);
    }

    RSA_METHOD *rsa_method()
    {
        static RSA_METHOD *ops = nullptr;

        if (!ops) {
            ops = RSA_meth_dup(RSA_get_default_method());
            RSA_meth_set_priv_enc(ops, nullptr);      // pkcs11_rsa_encrypt
            RSA_meth_set_priv_dec(ops, rsa_priv_dec); // pkcs11_rsa_encrypt
            RSA_meth_set_sign(ops, nullptr);
            RSA_meth_set_verify(ops, nullptr); // pkcs11_rsa_verify
            RSA_meth_set_finish(ops, rsa_finish);
        }
        return ops;
    }

    static int rsa_priv_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
    {
        QCA::EncryptionAlgorithm algo;

        if (padding == RSA_PKCS1_PADDING) {
            algo = QCA::EME_PKCS1v15;
        } else if (padding == RSA_PKCS1_OAEP_PADDING) {
            algo = QCA::EME_PKCS1_OAEP;
        } else {
            RSAerr(RSA_F_RSA_OSSL_PRIVATE_DECRYPT, RSA_R_UNKNOWN_PADDING_TYPE);
            return -1;
        }

        QCA_RSA_METHOD *self = (QCA_RSA_METHOD *)RSA_get_app_data(rsa);

        QCA::SecureArray input;
        input.resize(flen);
        memcpy(input.data(), from, input.size());

        QCA::SecureArray output;

        if (self->key.decrypt(input, &output, algo)) {
            memcpy(to, output.data(), output.size());
            return output.size();
        }

        // XXX: An error should be set in this case too.
        return -1;
    }

    static int rsa_finish(RSA *rsa)
    {
        QCA_RSA_METHOD *self = (QCA_RSA_METHOD *)RSA_get_app_data(rsa);
        delete self;
        return 1;
    }
};

static RSA *createFromExisting(const RSAPrivateKey &key)
{
    RSA *r = RSA_new();
    new QCA_RSA_METHOD(key, r); // will delete itself on RSA_free
    return r;
}

//----------------------------------------------------------------------------
// MyPKeyContext
//----------------------------------------------------------------------------
class MyPKeyContext : public PKeyContext
{
    Q_OBJECT
public:
    PKeyBase *k;

    MyPKeyContext(Provider *p)
        : PKeyContext(p)
    {
        k = nullptr;
    }

    ~MyPKeyContext() override
    {
        delete k;
    }

    Provider::Context *clone() const override
    {
        MyPKeyContext *c = new MyPKeyContext(*this);
        c->k             = (PKeyBase *)k->clone();
        return c;
    }

    QList<PKey::Type> supportedTypes() const override
    {
        QList<PKey::Type> list;
        list += PKey::RSA;
        list += PKey::DSA;
        list += PKey::DH;
        return list;
    }

    QList<PKey::Type> supportedIOTypes() const override
    {
        QList<PKey::Type> list;
        list += PKey::RSA;
        list += PKey::DSA;
        return list;
    }

    QList<PBEAlgorithm> supportedPBEAlgorithms() const override
    {
        QList<PBEAlgorithm> list;
        list += PBES2_DES_SHA1;
        list += PBES2_TripleDES_SHA1;
        return list;
    }

    PKeyBase *key() override
    {
        return k;
    }

    const PKeyBase *key() const override
    {
        return k;
    }

    void setKey(PKeyBase *key) override
    {
        k = key;
    }

    bool importKey(const PKeyBase *key) override
    {
        Q_UNUSED(key);
        return false;
    }

    EVP_PKEY *get_pkey() const
    {
        PKey::Type t = k->type();
        if (t == PKey::RSA)
            return static_cast<RSAKey *>(k)->evp.pkey;
        else if (t == PKey::DSA)
            return static_cast<DSAKey *>(k)->evp.pkey;
        else
            return static_cast<DHKey *>(k)->evp.pkey;
    }

    PKeyBase *pkeyToBase(EVP_PKEY *pkey, bool sec) const
    {
        PKeyBase *nk        = nullptr;
        int       pkey_type = EVP_PKEY_type(EVP_PKEY_id(pkey));
        if (pkey_type == EVP_PKEY_RSA) {
            RSAKey *c   = new RSAKey(provider());
            c->evp.pkey = pkey;
            c->sec      = sec;
            nk          = c;
        } else if (pkey_type == EVP_PKEY_DSA) {
            DSAKey *c   = new DSAKey(provider());
            c->evp.pkey = pkey;
            c->sec      = sec;
            nk          = c;
        } else if (pkey_type == EVP_PKEY_DH) {
            DHKey *c    = new DHKey(provider());
            c->evp.pkey = pkey;
            c->sec      = sec;
            nk          = c;
        } else {
            EVP_PKEY_free(pkey);
        }
        return nk;
    }

    QByteArray publicToDER() const override
    {
        EVP_PKEY *pkey = get_pkey();

        int pkey_type = EVP_PKEY_type(EVP_PKEY_id(pkey));

        // OpenSSL does not have DH import/export support
        if (pkey_type == EVP_PKEY_DH)
            return QByteArray();

        BIO *bo = BIO_new(BIO_s_mem());
        i2d_PUBKEY_bio(bo, pkey);
        const QByteArray buf = bio2ba(bo);
        return buf;
    }

    QString publicToPEM() const override
    {
        EVP_PKEY *pkey = get_pkey();

        int pkey_type = EVP_PKEY_type(EVP_PKEY_id(pkey));

        // OpenSSL does not have DH import/export support
        if (pkey_type == EVP_PKEY_DH)
            return QString();

        BIO *bo = BIO_new(BIO_s_mem());
        PEM_write_bio_PUBKEY(bo, pkey);
        const QByteArray buf = bio2ba(bo);
        return QString::fromLatin1(buf);
    }

    ConvertResult publicFromDER(const QByteArray &in) override
    {
        delete k;
        k = nullptr;

        BIO *bi = BIO_new(BIO_s_mem());
        BIO_write(bi, in.data(), in.size());
        EVP_PKEY *pkey = d2i_PUBKEY_bio(bi, nullptr);
        BIO_free(bi);

        if (!pkey)
            return ErrorDecode;

        k = pkeyToBase(pkey, false);
        if (k)
            return ConvertGood;
        else
            return ErrorDecode;
    }

    ConvertResult publicFromPEM(const QString &s) override
    {
        delete k;
        k = nullptr;

        const QByteArray in = s.toLatin1();
        BIO *            bi = BIO_new(BIO_s_mem());
        BIO_write(bi, in.data(), in.size());
        EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bi, nullptr, passphrase_cb, nullptr);
        BIO_free(bi);

        if (!pkey)
            return ErrorDecode;

        k = pkeyToBase(pkey, false);
        if (k)
            return ConvertGood;
        else
            return ErrorDecode;
    }

    SecureArray privateToDER(const SecureArray &passphrase, PBEAlgorithm pbe) const override
    {
        // if(pbe == PBEDefault)
        //	pbe = PBES2_TripleDES_SHA1;

        const EVP_CIPHER *cipher = nullptr;
        if (pbe == PBES2_TripleDES_SHA1)
            cipher = EVP_des_ede3_cbc();
        else if (pbe == PBES2_DES_SHA1)
            cipher = EVP_des_cbc();

        if (!cipher)
            return SecureArray();

        EVP_PKEY *pkey      = get_pkey();
        int       pkey_type = EVP_PKEY_type(EVP_PKEY_id(pkey));

        // OpenSSL does not have DH import/export support
        if (pkey_type == EVP_PKEY_DH)
            return SecureArray();

        BIO *bo = BIO_new(BIO_s_mem());
        if (!passphrase.isEmpty())
            i2d_PKCS8PrivateKey_bio(bo, pkey, cipher, nullptr, 0, nullptr, (void *)passphrase.data());
        else
            i2d_PKCS8PrivateKey_bio(bo, pkey, nullptr, nullptr, 0, nullptr, nullptr);
        SecureArray buf = bio2buf(bo);
        return buf;
    }

    QString privateToPEM(const SecureArray &passphrase, PBEAlgorithm pbe) const override
    {
        // if(pbe == PBEDefault)
        //	pbe = PBES2_TripleDES_SHA1;

        const EVP_CIPHER *cipher = nullptr;
        if (pbe == PBES2_TripleDES_SHA1)
            cipher = EVP_des_ede3_cbc();
        else if (pbe == PBES2_DES_SHA1)
            cipher = EVP_des_cbc();

        if (!cipher)
            return QString();

        EVP_PKEY *pkey      = get_pkey();
        int       pkey_type = EVP_PKEY_type(EVP_PKEY_id(pkey));

        // OpenSSL does not have DH import/export support
        if (pkey_type == EVP_PKEY_DH)
            return QString();

        BIO *bo = BIO_new(BIO_s_mem());
        if (!passphrase.isEmpty())
            PEM_write_bio_PKCS8PrivateKey(bo, pkey, cipher, nullptr, 0, nullptr, (void *)passphrase.data());
        else
            PEM_write_bio_PKCS8PrivateKey(bo, pkey, nullptr, nullptr, 0, nullptr, nullptr);
        SecureArray buf = bio2buf(bo);
        return QString::fromLatin1(buf.toByteArray());
    }

    ConvertResult privateFromDER(const SecureArray &in, const SecureArray &passphrase) override
    {
        delete k;
        k = nullptr;

        EVP_PKEY *pkey;
        if (!passphrase.isEmpty())
            pkey = qca_d2i_PKCS8PrivateKey(in, nullptr, nullptr, (void *)passphrase.data());
        else
            pkey = qca_d2i_PKCS8PrivateKey(in, nullptr, passphrase_cb, nullptr);

        if (!pkey)
            return ErrorDecode;

        k = pkeyToBase(pkey, true);
        if (k)
            return ConvertGood;
        else
            return ErrorDecode;
    }

    ConvertResult privateFromPEM(const QString &s, const SecureArray &passphrase) override
    {
        delete k;
        k = nullptr;

        const QByteArray in = s.toLatin1();
        BIO *            bi = BIO_new(BIO_s_mem());
        BIO_write(bi, in.data(), in.size());
        EVP_PKEY *pkey;
        if (!passphrase.isEmpty())
            pkey = PEM_read_bio_PrivateKey(bi, nullptr, nullptr, (void *)passphrase.data());
        else
            pkey = PEM_read_bio_PrivateKey(bi, nullptr, passphrase_cb, nullptr);
        BIO_free(bi);

        if (!pkey)
            return ErrorDecode;

        k = pkeyToBase(pkey, true);
        if (k)
            return ConvertGood;
        else
            return ErrorDecode;
    }
};

//----------------------------------------------------------------------------
// MyCertContext
//----------------------------------------------------------------------------
class X509Item
{
public:
    X509 *    cert;
    X509_REQ *req;
    X509_CRL *crl;

    enum Type
    {
        TypeCert,
        TypeReq,
        TypeCRL
    };

    X509Item()
    {
        cert = nullptr;
        req  = nullptr;
        crl  = nullptr;
    }

    X509Item(const X509Item &from)
    {
        cert  = nullptr;
        req   = nullptr;
        crl   = nullptr;
        *this = from;
    }

    ~X509Item()
    {
        reset();
    }

    X509Item &operator=(const X509Item &from)
    {
        if (this != &from) {
            reset();
            cert = from.cert;
            req  = from.req;
            crl  = from.crl;

            if (cert)
                X509_up_ref(cert);
            if (req) {
                // Not exposed, so copy
                req = X509_REQ_dup(req);
            }
            if (crl)
                X509_CRL_up_ref(crl);
        }

        return *this;
    }

    void reset()
    {
        if (cert) {
            X509_free(cert);
            cert = nullptr;
        }
        if (req) {
            X509_REQ_free(req);
            req = nullptr;
        }
        if (crl) {
            X509_CRL_free(crl);
            crl = nullptr;
        }
    }

    bool isNull() const
    {
        return (!cert && !req && !crl);
    }

    QByteArray toDER() const
    {
        BIO *bo = BIO_new(BIO_s_mem());
        if (cert)
            i2d_X509_bio(bo, cert);
        else if (req)
            i2d_X509_REQ_bio(bo, req);
        else if (crl)
            i2d_X509_CRL_bio(bo, crl);
        const QByteArray buf = bio2ba(bo);
        return buf;
    }

    QString toPEM() const
    {
        BIO *bo = BIO_new(BIO_s_mem());
        if (cert)
            PEM_write_bio_X509(bo, cert);
        else if (req)
            PEM_write_bio_X509_REQ(bo, req);
        else if (crl)
            PEM_write_bio_X509_CRL(bo, crl);
        const QByteArray buf = bio2ba(bo);
        return QString::fromLatin1(buf);
    }

    ConvertResult fromDER(const QByteArray &in, Type t)
    {
        reset();

        BIO *bi = BIO_new(BIO_s_mem());
        BIO_write(bi, in.data(), in.size());

        if (t == TypeCert)
            cert = d2i_X509_bio(bi, nullptr);
        else if (t == TypeReq)
            req = d2i_X509_REQ_bio(bi, nullptr);
        else if (t == TypeCRL)
            crl = d2i_X509_CRL_bio(bi, nullptr);

        BIO_free(bi);

        if (isNull())
            return ErrorDecode;

        return ConvertGood;
    }

    ConvertResult fromPEM(const QString &s, Type t)
    {
        reset();

        const QByteArray in = s.toLatin1();
        BIO *            bi = BIO_new(BIO_s_mem());
        BIO_write(bi, in.data(), in.size());

        if (t == TypeCert)
            cert = PEM_read_bio_X509(bi, nullptr, passphrase_cb, nullptr);
        else if (t == TypeReq)
            req = PEM_read_bio_X509_REQ(bi, nullptr, passphrase_cb, nullptr);
        else if (t == TypeCRL)
            crl = PEM_read_bio_X509_CRL(bi, nullptr, passphrase_cb, nullptr);

        BIO_free(bi);

        if (isNull())
            return ErrorDecode;

        return ConvertGood;
    }
};

// (taken from kdelibs) -- Justin
//
// This code is mostly taken from OpenSSL v0.9.5a
// by Eric Young
QDateTime ASN1_UTCTIME_QDateTime(const ASN1_UTCTIME *tm, int *isGmt)
{
    QDateTime qdt;
    char *    v;
    int       gmt = 0;
    int       i;
    int       y = 0, M = 0, d = 0, h = 0, m = 0, s = 0;
    QDate     qdate;
    QTime     qtime;

    i = tm->length;
    v = (char *)tm->data;

    if (i < 10)
        goto auq_err;
    if (v[i - 1] == 'Z')
        gmt = 1;
    for (i = 0; i < 10; i++)
        if ((v[i] > '9') || (v[i] < '0'))
            goto auq_err;
    y = (v[0] - '0') * 10 + (v[1] - '0');
    if (y < 50)
        y += 100;
    M = (v[2] - '0') * 10 + (v[3] - '0');
    if ((M > 12) || (M < 1))
        goto auq_err;
    d = (v[4] - '0') * 10 + (v[5] - '0');
    h = (v[6] - '0') * 10 + (v[7] - '0');
    m = (v[8] - '0') * 10 + (v[9] - '0');
    if ((v[10] >= '0') && (v[10] <= '9') && (v[11] >= '0') && (v[11] <= '9'))
        s = (v[10] - '0') * 10 + (v[11] - '0');

    // localize the date and display it.
    qdate.setDate(y + 1900, M, d);
    qtime.setHMS(h, m, s);
    qdt.setDate(qdate);
    qdt.setTime(qtime);
    if (gmt)
        qdt.setTimeSpec(Qt::UTC);
auq_err:
    if (isGmt)
        *isGmt = gmt;
    return qdt;
}

class MyCertContext;
static bool sameChain(STACK_OF(X509) * ossl, const QList<const MyCertContext *> &qca);

// TODO: support read/write of multiple info values with the same name
class MyCertContext : public CertContext
{
    Q_OBJECT
public:
    X509Item         item;
    CertContextProps _props;

    MyCertContext(Provider *p)
        : CertContext(p)
    {
        // printf("[%p] ** created\n", this);
    }

    MyCertContext(const MyCertContext &from)
        : CertContext(from)
        , item(from.item)
        , _props(from._props)
    {
        // printf("[%p] ** created as copy (from [%p])\n", this, &from);
    }

    ~MyCertContext() override
    {
        // printf("[%p] ** deleted\n", this);
    }

    Provider::Context *clone() const override
    {
        return new MyCertContext(*this);
    }

    QByteArray toDER() const override
    {
        return item.toDER();
    }

    QString toPEM() const override
    {
        return item.toPEM();
    }

    ConvertResult fromDER(const QByteArray &a) override
    {
        _props          = CertContextProps();
        ConvertResult r = item.fromDER(a, X509Item::TypeCert);
        if (r == ConvertGood)
            make_props();
        return r;
    }

    ConvertResult fromPEM(const QString &s) override
    {
        _props          = CertContextProps();
        ConvertResult r = item.fromPEM(s, X509Item::TypeCert);
        if (r == ConvertGood)
            make_props();
        return r;
    }

    void fromX509(X509 *x)
    {
        X509_up_ref(x);
        item.cert = x;
        make_props();
    }

    bool createSelfSigned(const CertificateOptions &opts, const PKeyContext &priv) override
    {
        _props = CertContextProps();
        item.reset();

        CertificateInfo info = opts.info();

        // Note: removing default constraints, let the app choose these if it wants
        Constraints constraints = opts.constraints();
        // constraints - logic from Botan
        /*Constraints constraints;
        if(opts.isCA())
        {
            constraints += KeyCertificateSign;
            constraints += CRLSign;
        }
        else
            constraints = find_constraints(priv, opts.constraints());*/

        EVP_PKEY *      pk = static_cast<const MyPKeyContext *>(&priv)->get_pkey();
        X509_EXTENSION *ex;

        const EVP_MD *md;
        if (priv.key()->type() == PKey::RSA)
            md = EVP_sha1();
        else if (priv.key()->type() == PKey::DSA)
            md = EVP_sha1();
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
        ASN1_TIME_set(X509_get_notBefore(x), opts.notValidBefore().toSecsSinceEpoch());
        ASN1_TIME_set(X509_get_notAfter(x), opts.notValidAfter().toSecsSinceEpoch());

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
        if (ex) {
            X509_add_ext(x, ex, -1);
            X509_EXTENSION_free(ex);
        }

        // subject alt name
        ex = new_cert_subject_alt_name(info);
        if (ex) {
            X509_add_ext(x, ex, -1);
            X509_EXTENSION_free(ex);
        }

        // key usage
        ex = new_cert_key_usage(constraints);
        if (ex) {
            X509_add_ext(x, ex, -1);
            X509_EXTENSION_free(ex);
        }

        // extended key usage
        ex = new_cert_ext_key_usage(constraints);
        if (ex) {
            X509_add_ext(x, ex, -1);
            X509_EXTENSION_free(ex);
        }

        // policies
        ex = new_cert_policies(opts.policies());
        if (ex) {
            X509_add_ext(x, ex, -1);
            X509_EXTENSION_free(ex);
        }

        // finished
        X509_sign(x, pk, md);

        item.cert = x;
        make_props();
        return true;
    }

    const CertContextProps *props() const override
    {
        // printf("[%p] grabbing props\n", this);
        return &_props;
    }

    bool compare(const CertContext *other) const override
    {
        const CertContextProps *a = &_props;
        const CertContextProps *b = other->props();

        PublicKey    akey, bkey;
        PKeyContext *ac = subjectPublicKey();
        akey.change(ac);
        PKeyContext *bc = other->subjectPublicKey();
        bkey.change(bc);

        // logic from Botan
        if (a->sig != b->sig || a->sigalgo != b->sigalgo || akey != bkey)
            return false;

        if (a->issuer != b->issuer || a->subject != b->subject)
            return false;
        if (a->serial != b->serial || a->version != b->version)
            return false;
        if (a->start != b->start || a->end != b->end)
            return false;

        return true;
    }

    // does a new
    PKeyContext *subjectPublicKey() const override
    {
        MyPKeyContext *kc   = new MyPKeyContext(provider());
        EVP_PKEY *     pkey = X509_get_pubkey(item.cert);
        PKeyBase *     kb   = kc->pkeyToBase(pkey, false);
        kc->setKey(kb);
        return kc;
    }

    bool isIssuerOf(const CertContext *other) const override
    {
        // to check a single issuer, we make a list of 1
        STACK_OF(X509) *untrusted_list = sk_X509_new_null();

        const MyCertContext *our_cc = this;
        X509 *               x      = our_cc->item.cert;
        X509_up_ref(x);
        sk_X509_push(untrusted_list, x);

        const MyCertContext *other_cc = static_cast<const MyCertContext *>(other);
        X509 *               ox       = other_cc->item.cert;

        X509_STORE *store = X509_STORE_new();

        X509_STORE_CTX *ctx = X509_STORE_CTX_new();
        X509_STORE_CTX_init(ctx, store, ox, untrusted_list);

        // we don't care about the verify result here
        X509_verify_cert(ctx);

        // grab the chain, which may not be fully populated
        STACK_OF(X509) *chain = X509_STORE_CTX_get_chain(ctx);

        bool ok = false;

        // chain should be exactly 2 items
        QList<const MyCertContext *> expected;
        expected += other_cc;
        expected += our_cc;
        if (chain && sameChain(chain, expected))
            ok = true;

        // cleanup
        X509_STORE_CTX_free(ctx);
        X509_STORE_free(store);
        sk_X509_pop_free(untrusted_list, X509_free);

        return ok;
    }

    // implemented later because it depends on MyCRLContext
    Validity validate(const QList<CertContext *> &trusted,
                      const QList<CertContext *> &untrusted,
                      const QList<CRLContext *> & crls,
                      UsageMode                   u,
                      ValidateFlags               vf) const override;

    Validity validate_chain(const QList<CertContext *> &chain,
                            const QList<CertContext *> &trusted,
                            const QList<CRLContext *> & crls,
                            UsageMode                   u,
                            ValidateFlags               vf) const override;

    void make_props()
    {
        X509 *           x = item.cert;
        CertContextProps p;

        p.version = X509_get_version(x);

        ASN1_INTEGER *ai = X509_get_serialNumber(x);
        if (ai) {
            char *  rep = i2s_ASN1_INTEGER(nullptr, ai);
            QString str = QString::fromLatin1(rep);
            OPENSSL_free(rep);
            p.serial.fromString(str);
        }

        p.start = ASN1_UTCTIME_QDateTime(X509_get_notBefore(x), nullptr);
        p.end   = ASN1_UTCTIME_QDateTime(X509_get_notAfter(x), nullptr);

        CertificateInfo subject, issuer;

        subject = get_cert_name(X509_get_subject_name(x));
        issuer  = get_cert_name(X509_get_issuer_name(x));

        p.isSelfSigned = (X509_V_OK == X509_check_issued(x, x));

        p.isCA      = false;
        p.pathLimit = 0;
        int pos     = X509_get_ext_by_NID(x, NID_basic_constraints, -1);
        if (pos != -1) {
            X509_EXTENSION *ex = X509_get_ext(x, pos);
            if (ex)
                get_basic_constraints(ex, &p.isCA, &p.pathLimit);
        }

        pos = X509_get_ext_by_NID(x, NID_subject_alt_name, -1);
        if (pos != -1) {
            X509_EXTENSION *ex = X509_get_ext(x, pos);
            if (ex)
                subject.unite(get_cert_alt_name(ex));
        }

        pos = X509_get_ext_by_NID(x, NID_issuer_alt_name, -1);
        if (pos != -1) {
            X509_EXTENSION *ex = X509_get_ext(x, pos);
            if (ex)
                issuer.unite(get_cert_alt_name(ex));
        }

        pos = X509_get_ext_by_NID(x, NID_key_usage, -1);
        if (pos != -1) {
            X509_EXTENSION *ex = X509_get_ext(x, pos);
            if (ex)
                p.constraints = get_cert_key_usage(ex);
        }

        pos = X509_get_ext_by_NID(x, NID_ext_key_usage, -1);
        if (pos != -1) {
            X509_EXTENSION *ex = X509_get_ext(x, pos);
            if (ex)
                p.constraints += get_cert_ext_key_usage(ex);
        }

        pos = X509_get_ext_by_NID(x, NID_certificate_policies, -1);
        if (pos != -1) {
            X509_EXTENSION *ex = X509_get_ext(x, pos);
            if (ex)
                p.policies = get_cert_policies(ex);
        }

        const ASN1_BIT_STRING *signature;

        X509_get0_signature(&signature, nullptr, x);
        if (signature) {
            p.sig = QByteArray(signature->length, 0);
            for (int i = 0; i < signature->length; i++)
                p.sig[i] = signature->data[i];
        }

        switch (X509_get_signature_nid(x)) {
        case NID_sha1WithRSAEncryption:
            p.sigalgo = QCA::EMSA3_SHA1;
            break;
        case NID_md5WithRSAEncryption:
            p.sigalgo = QCA::EMSA3_MD5;
            break;
#ifdef HAVE_OPENSSL_MD2
        case NID_md2WithRSAEncryption:
            p.sigalgo = QCA::EMSA3_MD2;
            break;
#endif
        case NID_ripemd160WithRSA:
            p.sigalgo = QCA::EMSA3_RIPEMD160;
            break;
        case NID_dsaWithSHA1:
            p.sigalgo = QCA::EMSA1_SHA1;
            break;
        case NID_sha224WithRSAEncryption:
            p.sigalgo = QCA::EMSA3_SHA224;
            break;
        case NID_sha256WithRSAEncryption:
            p.sigalgo = QCA::EMSA3_SHA256;
            break;
        case NID_sha384WithRSAEncryption:
            p.sigalgo = QCA::EMSA3_SHA384;
            break;
        case NID_sha512WithRSAEncryption:
            p.sigalgo = QCA::EMSA3_SHA512;
            break;
        default:
            qDebug() << "Unknown signature value: " << X509_get_signature_nid(x);
            p.sigalgo = QCA::SignatureUnknown;
        }

        pos = X509_get_ext_by_NID(x, NID_subject_key_identifier, -1);
        if (pos != -1) {
            X509_EXTENSION *ex = X509_get_ext(x, pos);
            if (ex)
                p.subjectId += get_cert_subject_key_id(ex);
        }

        pos = X509_get_ext_by_NID(x, NID_authority_key_identifier, -1);
        if (pos != -1) {
            X509_EXTENSION *ex = X509_get_ext(x, pos);
            if (ex)
                p.issuerId += get_cert_issuer_key_id(ex);
        }

        // FIXME: super hack
        CertificateOptions opts;
        opts.setInfo(subject);
        p.subject = opts.infoOrdered();
        opts.setInfo(issuer);
        p.issuer = opts.infoOrdered();

        _props = p;
        // printf("[%p] made props: [%s]\n", this, _props.subject[CommonName].toLatin1().data());
    }
};

bool sameChain(STACK_OF(X509) * ossl, const QList<const MyCertContext *> &qca)
{
    if (sk_X509_num(ossl) != qca.count())
        return false;

    for (int n = 0; n < sk_X509_num(ossl); ++n) {
        X509 *a = sk_X509_value(ossl, n);
        X509 *b = qca[n]->item.cert;
        if (X509_cmp(a, b) != 0)
            return false;
    }

    return true;
}

//----------------------------------------------------------------------------
// MyCAContext
//----------------------------------------------------------------------------
// Thanks to Pascal Patry
class MyCAContext : public CAContext
{
    Q_OBJECT
public:
    X509Item       caCert;
    MyPKeyContext *privateKey;

    MyCAContext(Provider *p)
        : CAContext(p)
    {
        privateKey = nullptr;
    }

    MyCAContext(const MyCAContext &from)
        : CAContext(from)
        , caCert(from.caCert)
    {
        privateKey = static_cast<MyPKeyContext *>(from.privateKey->clone());
    }

    ~MyCAContext() override
    {
        delete privateKey;
    }

    CertContext *certificate() const override
    {
        MyCertContext *cert = new MyCertContext(provider());

        cert->fromX509(caCert.cert);
        return cert;
    }

    CertContext *createCertificate(const PKeyContext &pub, const CertificateOptions &opts) const override
    {
        // TODO: implement
        Q_UNUSED(pub)
        Q_UNUSED(opts)
        return nullptr;
    }

    CRLContext *createCRL(const QDateTime &nextUpdate) const override
    {
        // TODO: implement
        Q_UNUSED(nextUpdate)
        return nullptr;
    }

    void setup(const CertContext &cert, const PKeyContext &priv) override
    {
        caCert = static_cast<const MyCertContext &>(cert).item;
        delete privateKey;
        privateKey = nullptr;
        privateKey = static_cast<MyPKeyContext *>(priv.clone());
    }

    CertContext *signRequest(const CSRContext &req, const QDateTime &notValidAfter) const override
    {
        MyCertContext *         cert  = nullptr;
        const EVP_MD *          md    = nullptr;
        X509 *                  x     = nullptr;
        const CertContextProps &props = *req.props();
        CertificateOptions      subjectOpts;
        X509_NAME *             subjectName = nullptr;
        X509_EXTENSION *        ex          = nullptr;

        if (privateKey->key()->type() == PKey::RSA)
            md = EVP_sha1();
        else if (privateKey->key()->type() == PKey::DSA)
            md = EVP_sha1();
        else
            return nullptr;

        cert = new MyCertContext(provider());

        subjectOpts.setInfoOrdered(props.subject);
        subjectName = new_cert_name(subjectOpts.info());

        // create
        x = X509_new();
        X509_set_version(x, 2);

        // serial
        BIGNUM *bn = bi2bn(props.serial);
        BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(x));
        BN_free(bn);

        // validity period
        ASN1_TIME_set(X509_get_notBefore(x), QDateTime::currentDateTimeUtc().toSecsSinceEpoch());
        ASN1_TIME_set(X509_get_notAfter(x), notValidAfter.toSecsSinceEpoch());

        X509_set_pubkey(x, static_cast<const MyPKeyContext *>(req.subjectPublicKey())->get_pkey());
        X509_set_subject_name(x, subjectName);
        X509_set_issuer_name(x, X509_get_subject_name(caCert.cert));

        // subject key id
        ex = new_subject_key_id(x);
        {
            X509_add_ext(x, ex, -1);
            X509_EXTENSION_free(ex);
        }

        // CA mode
        ex = new_basic_constraints(props.isCA, props.pathLimit);
        if (ex) {
            X509_add_ext(x, ex, -1);
            X509_EXTENSION_free(ex);
        }

        // subject alt name
        ex = new_cert_subject_alt_name(subjectOpts.info());
        if (ex) {
            X509_add_ext(x, ex, -1);
            X509_EXTENSION_free(ex);
        }

        // key usage
        ex = new_cert_key_usage(props.constraints);
        if (ex) {
            X509_add_ext(x, ex, -1);
            X509_EXTENSION_free(ex);
        }

        // extended key usage
        ex = new_cert_ext_key_usage(props.constraints);
        if (ex) {
            X509_add_ext(x, ex, -1);
            X509_EXTENSION_free(ex);
        }

        // policies
        ex = new_cert_policies(props.policies);
        if (ex) {
            X509_add_ext(x, ex, -1);
            X509_EXTENSION_free(ex);
        }

        if (!X509_sign(x, privateKey->get_pkey(), md)) {
            X509_free(x);
            delete cert;
            return nullptr;
        }

        cert->fromX509(x);
        X509_free(x);
        return cert;
    }

    CRLContext *
    updateCRL(const CRLContext &crl, const QList<CRLEntry> &entries, const QDateTime &nextUpdate) const override
    {
        // TODO: implement
        Q_UNUSED(crl)
        Q_UNUSED(entries)
        Q_UNUSED(nextUpdate)
        return nullptr;
    }

    Provider::Context *clone() const override
    {
        return new MyCAContext(*this);
    }
};

//----------------------------------------------------------------------------
// MyCSRContext
//----------------------------------------------------------------------------
class MyCSRContext : public CSRContext
{
    Q_OBJECT
public:
    X509Item         item;
    CertContextProps _props;

    MyCSRContext(Provider *p)
        : CSRContext(p)
    {
    }

    MyCSRContext(const MyCSRContext &from)
        : CSRContext(from)
        , item(from.item)
        , _props(from._props)
    {
    }

    Provider::Context *clone() const override
    {
        return new MyCSRContext(*this);
    }

    QByteArray toDER() const override
    {
        return item.toDER();
    }

    QString toPEM() const override
    {
        return item.toPEM();
    }

    ConvertResult fromDER(const QByteArray &a) override
    {
        _props          = CertContextProps();
        ConvertResult r = item.fromDER(a, X509Item::TypeReq);
        if (r == ConvertGood)
            make_props();
        return r;
    }

    ConvertResult fromPEM(const QString &s) override
    {
        _props          = CertContextProps();
        ConvertResult r = item.fromPEM(s, X509Item::TypeReq);
        if (r == ConvertGood)
            make_props();
        return r;
    }

    bool canUseFormat(CertificateRequestFormat f) const override
    {
        if (f == PKCS10)
            return true;
        return false;
    }

    bool createRequest(const CertificateOptions &opts, const PKeyContext &priv) override
    {
        _props = CertContextProps();
        item.reset();

        CertificateInfo info = opts.info();

        // Note: removing default constraints, let the app choose these if it wants
        Constraints constraints = opts.constraints();
        // constraints - logic from Botan
        /*Constraints constraints;
        if(opts.isCA())
        {
            constraints += KeyCertificateSign;
            constraints += CRLSign;
        }
        else
            constraints = find_constraints(priv, opts.constraints());*/

        EVP_PKEY *      pk = static_cast<const MyPKeyContext *>(&priv)->get_pkey();
        X509_EXTENSION *ex;

        const EVP_MD *md;
        if (priv.key()->type() == PKey::RSA)
            md = EVP_sha1();
        else if (priv.key()->type() == PKey::DSA)
            md = EVP_sha1();
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
        const QByteArray cs = opts.challenge().toLatin1();
        if (!cs.isEmpty())
            X509_REQ_add1_attr_by_NID(
                x, NID_pkcs9_challengePassword, MBSTRING_UTF8, (const unsigned char *)cs.data(), -1);

        STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();

        // CA mode
        ex = new_basic_constraints(opts.isCA(), opts.pathLimit());
        if (ex)
            sk_X509_EXTENSION_push(exts, ex);

        // subject alt name
        ex = new_cert_subject_alt_name(info);
        if (ex)
            sk_X509_EXTENSION_push(exts, ex);

        // key usage
        ex = new_cert_key_usage(constraints);
        if (ex)
            sk_X509_EXTENSION_push(exts, ex);

        // extended key usage
        ex = new_cert_ext_key_usage(constraints);
        if (ex)
            sk_X509_EXTENSION_push(exts, ex);

        // policies
        ex = new_cert_policies(opts.policies());
        if (ex)
            sk_X509_EXTENSION_push(exts, ex);

        if (sk_X509_EXTENSION_num(exts) > 0)
            X509_REQ_add_extensions(x, exts);
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

        // finished
        X509_REQ_sign(x, pk, md);

        item.req = x;
        make_props();
        return true;
    }

    const CertContextProps *props() const override
    {
        return &_props;
    }

    bool compare(const CSRContext *other) const override
    {
        const CertContextProps *a = &_props;
        const CertContextProps *b = other->props();

        PublicKey    akey, bkey;
        PKeyContext *ac = subjectPublicKey();
        akey.change(ac);
        PKeyContext *bc = other->subjectPublicKey();
        bkey.change(bc);

        if (a->sig != b->sig || a->sigalgo != b->sigalgo || akey != bkey)
            return false;

        // TODO: Anything else we should compare?

        return true;
    }

    PKeyContext *subjectPublicKey() const override // does a new
    {
        MyPKeyContext *kc   = new MyPKeyContext(provider());
        EVP_PKEY *     pkey = X509_REQ_get_pubkey(item.req);
        PKeyBase *     kb   = kc->pkeyToBase(pkey, false);
        kc->setKey(kb);
        return kc;
    }

    QString toSPKAC() const override
    {
        return QString();
    }

    ConvertResult fromSPKAC(const QString &s) override
    {
        Q_UNUSED(s);
        return ErrorDecode;
    }

    void make_props()
    {
        X509_REQ *       x = item.req;
        CertContextProps p;

        // TODO: QString challenge;

        p.format = PKCS10;

        CertificateInfo subject;

        subject = get_cert_name(X509_REQ_get_subject_name(x));

        STACK_OF(X509_EXTENSION) *exts = X509_REQ_get_extensions(x);

        p.isCA      = false;
        p.pathLimit = 0;
        int pos     = X509v3_get_ext_by_NID(exts, NID_basic_constraints, -1);
        if (pos != -1) {
            X509_EXTENSION *ex = X509v3_get_ext(exts, pos);
            if (ex)
                get_basic_constraints(ex, &p.isCA, &p.pathLimit);
        }

        pos = X509v3_get_ext_by_NID(exts, NID_subject_alt_name, -1);
        if (pos != -1) {
            X509_EXTENSION *ex = X509v3_get_ext(exts, pos);
            if (ex)
                subject.unite(get_cert_alt_name(ex));
        }

        pos = X509v3_get_ext_by_NID(exts, NID_key_usage, -1);
        if (pos != -1) {
            X509_EXTENSION *ex = X509v3_get_ext(exts, pos);
            if (ex)
                p.constraints = get_cert_key_usage(ex);
        }

        pos = X509v3_get_ext_by_NID(exts, NID_ext_key_usage, -1);
        if (pos != -1) {
            X509_EXTENSION *ex = X509v3_get_ext(exts, pos);
            if (ex)
                p.constraints += get_cert_ext_key_usage(ex);
        }

        pos = X509v3_get_ext_by_NID(exts, NID_certificate_policies, -1);
        if (pos != -1) {
            X509_EXTENSION *ex = X509v3_get_ext(exts, pos);
            if (ex)
                p.policies = get_cert_policies(ex);
        }

        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

        const ASN1_BIT_STRING *signature;

        X509_REQ_get0_signature(x, &signature, nullptr);
        if (signature) {
            p.sig = QByteArray(signature->length, 0);
            for (int i = 0; i < signature->length; i++)
                p.sig[i] = signature->data[i];
        }

        switch (X509_REQ_get_signature_nid(x)) {
        case NID_sha1WithRSAEncryption:
            p.sigalgo = QCA::EMSA3_SHA1;
            break;
        case NID_md5WithRSAEncryption:
            p.sigalgo = QCA::EMSA3_MD5;
            break;
#ifdef HAVE_OPENSSL_MD2
        case NID_md2WithRSAEncryption:
            p.sigalgo = QCA::EMSA3_MD2;
            break;
#endif
        case NID_ripemd160WithRSA:
            p.sigalgo = QCA::EMSA3_RIPEMD160;
            break;
        case NID_dsaWithSHA1:
            p.sigalgo = QCA::EMSA1_SHA1;
            break;
        default:
            qDebug() << "Unknown signature value: " << X509_REQ_get_signature_nid(x);
            p.sigalgo = QCA::SignatureUnknown;
        }

        // FIXME: super hack
        CertificateOptions opts;
        opts.setInfo(subject);
        p.subject = opts.infoOrdered();

        _props = p;
    }
};

//----------------------------------------------------------------------------
// MyCRLContext
//----------------------------------------------------------------------------
class MyCRLContext : public CRLContext
{
    Q_OBJECT
public:
    X509Item        item;
    CRLContextProps _props;

    MyCRLContext(Provider *p)
        : CRLContext(p)
    {
    }

    MyCRLContext(const MyCRLContext &from)
        : CRLContext(from)
        , item(from.item)
    {
    }

    Provider::Context *clone() const override
    {
        return new MyCRLContext(*this);
    }

    QByteArray toDER() const override
    {
        return item.toDER();
    }

    QString toPEM() const override
    {
        return item.toPEM();
    }

    ConvertResult fromDER(const QByteArray &a) override
    {
        _props          = CRLContextProps();
        ConvertResult r = item.fromDER(a, X509Item::TypeCRL);
        if (r == ConvertGood)
            make_props();
        return r;
    }

    ConvertResult fromPEM(const QString &s) override
    {
        ConvertResult r = item.fromPEM(s, X509Item::TypeCRL);
        if (r == ConvertGood)
            make_props();
        return r;
    }

    void fromX509(X509_CRL *x)
    {
        X509_CRL_up_ref(x);
        item.crl = x;
        make_props();
    }

    const CRLContextProps *props() const override
    {
        return &_props;
    }

    bool compare(const CRLContext *other) const override
    {
        const CRLContextProps *a = &_props;
        const CRLContextProps *b = other->props();

        if (a->issuer != b->issuer)
            return false;
        if (a->number != b->number)
            return false;
        if (a->thisUpdate != b->thisUpdate)
            return false;
        if (a->nextUpdate != b->nextUpdate)
            return false;
        if (a->revoked != b->revoked)
            return false;
        if (a->sig != b->sig)
            return false;
        if (a->sigalgo != b->sigalgo)
            return false;
        if (a->issuerId != b->issuerId)
            return false;

        return true;
    }

    void make_props()
    {
        X509_CRL *x = item.crl;

        CRLContextProps p;

        CertificateInfo issuer;

        issuer = get_cert_name(X509_CRL_get_issuer(x));

        p.thisUpdate = ASN1_UTCTIME_QDateTime(X509_CRL_get0_lastUpdate(x), nullptr);
        p.nextUpdate = ASN1_UTCTIME_QDateTime(X509_CRL_get0_nextUpdate(x), nullptr);

        STACK_OF(X509_REVOKED) *revokeStack = X509_CRL_get_REVOKED(x);

        for (int i = 0; i < sk_X509_REVOKED_num(revokeStack); ++i) {
            X509_REVOKED *        rev    = sk_X509_REVOKED_value(revokeStack, i);
            BigInteger            serial = bn2bi_free(ASN1_INTEGER_to_BN(X509_REVOKED_get0_serialNumber(rev), nullptr));
            QDateTime             time   = ASN1_UTCTIME_QDateTime(X509_REVOKED_get0_revocationDate(rev), nullptr);
            QCA::CRLEntry::Reason reason = QCA::CRLEntry::Unspecified;
            int                   pos    = X509_REVOKED_get_ext_by_NID(rev, NID_crl_reason, -1);
            if (pos != -1) {
                X509_EXTENSION *ex = X509_REVOKED_get_ext(rev, pos);
                if (ex) {
                    ASN1_ENUMERATED *result = (ASN1_ENUMERATED *)X509V3_EXT_d2i(ex);
                    switch (ASN1_ENUMERATED_get(result)) {
                    case CRL_REASON_UNSPECIFIED:
                        reason = QCA::CRLEntry::Unspecified;
                        break;
                    case CRL_REASON_KEY_COMPROMISE:
                        reason = QCA::CRLEntry::KeyCompromise;
                        break;
                    case CRL_REASON_CA_COMPROMISE:
                        reason = QCA::CRLEntry::CACompromise;
                        break;
                    case CRL_REASON_AFFILIATION_CHANGED:
                        reason = QCA::CRLEntry::AffiliationChanged;
                        break;
                    case CRL_REASON_SUPERSEDED:
                        reason = QCA::CRLEntry::Superseded;
                        break;
                    case CRL_REASON_CESSATION_OF_OPERATION:
                        reason = QCA::CRLEntry::CessationOfOperation;
                        break;
                    case CRL_REASON_CERTIFICATE_HOLD:
                        reason = QCA::CRLEntry::CertificateHold;
                        break;
                    case CRL_REASON_REMOVE_FROM_CRL:
                        reason = QCA::CRLEntry::RemoveFromCRL;
                        break;
                    case CRL_REASON_PRIVILEGE_WITHDRAWN:
                        reason = QCA::CRLEntry::PrivilegeWithdrawn;
                        break;
                    case CRL_REASON_AA_COMPROMISE:
                        reason = QCA::CRLEntry::AACompromise;
                        break;
                    default:
                        reason = QCA::CRLEntry::Unspecified;
                        break;
                    }
                    ASN1_ENUMERATED_free(result);
                }
            }
            CRLEntry thisEntry(serial, time, reason);
            p.revoked.append(thisEntry);
        }

        const ASN1_BIT_STRING *signature;

        X509_CRL_get0_signature(x, &signature, nullptr);
        if (signature) {
            p.sig = QByteArray(signature->length, 0);
            for (int i = 0; i < signature->length; i++)
                p.sig[i] = signature->data[i];
        }

        switch (X509_CRL_get_signature_nid(x)) {
        case NID_sha1WithRSAEncryption:
            p.sigalgo = QCA::EMSA3_SHA1;
            break;
        case NID_md5WithRSAEncryption:
            p.sigalgo = QCA::EMSA3_MD5;
            break;
#ifdef HAVE_OPENSSL_MD2
        case NID_md2WithRSAEncryption:
            p.sigalgo = QCA::EMSA3_MD2;
            break;
#endif
        case NID_ripemd160WithRSA:
            p.sigalgo = QCA::EMSA3_RIPEMD160;
            break;
        case NID_dsaWithSHA1:
            p.sigalgo = QCA::EMSA1_SHA1;
            break;
        case NID_sha224WithRSAEncryption:
            p.sigalgo = QCA::EMSA3_SHA224;
            break;
        case NID_sha256WithRSAEncryption:
            p.sigalgo = QCA::EMSA3_SHA256;
            break;
        case NID_sha384WithRSAEncryption:
            p.sigalgo = QCA::EMSA3_SHA384;
            break;
        case NID_sha512WithRSAEncryption:
            p.sigalgo = QCA::EMSA3_SHA512;
            break;
        default:
            qWarning() << "Unknown signature value: " << X509_CRL_get_signature_nid(x);
            p.sigalgo = QCA::SignatureUnknown;
        }

        int pos = X509_CRL_get_ext_by_NID(x, NID_authority_key_identifier, -1);
        if (pos != -1) {
            X509_EXTENSION *ex = X509_CRL_get_ext(x, pos);
            if (ex)
                p.issuerId += get_cert_issuer_key_id(ex);
        }

        p.number = -1;
        pos      = X509_CRL_get_ext_by_NID(x, NID_crl_number, -1);
        if (pos != -1) {
            X509_EXTENSION *ex = X509_CRL_get_ext(x, pos);
            if (ex) {
                ASN1_INTEGER *result = (ASN1_INTEGER *)X509V3_EXT_d2i(ex);
                p.number             = ASN1_INTEGER_get(result);
                ASN1_INTEGER_free(result);
            }
        }

        // FIXME: super hack
        CertificateOptions opts;
        opts.setInfo(issuer);
        p.issuer = opts.infoOrdered();

        _props = p;
    }
};

//----------------------------------------------------------------------------
// MyCertCollectionContext
//----------------------------------------------------------------------------
class MyCertCollectionContext : public CertCollectionContext
{
    Q_OBJECT
public:
    MyCertCollectionContext(Provider *p)
        : CertCollectionContext(p)
    {
    }

    Provider::Context *clone() const override
    {
        return new MyCertCollectionContext(*this);
    }

    QByteArray toPKCS7(const QList<CertContext *> &certs, const QList<CRLContext *> &crls) const override
    {
        // TODO: implement
        Q_UNUSED(certs);
        Q_UNUSED(crls);
        return QByteArray();
    }

    ConvertResult fromPKCS7(const QByteArray &a, QList<CertContext *> *certs, QList<CRLContext *> *crls) const override
    {
        BIO *bi = BIO_new(BIO_s_mem());
        BIO_write(bi, a.data(), a.size());
        PKCS7 *p7 = d2i_PKCS7_bio(bi, nullptr);
        BIO_free(bi);
        if (!p7)
            return ErrorDecode;

        STACK_OF(X509) *xcerts    = nullptr;
        STACK_OF(X509_CRL) *xcrls = nullptr;

        int i = OBJ_obj2nid(p7->type);
        if (i == NID_pkcs7_signed) {
            xcerts = p7->d.sign->cert;
            xcrls  = p7->d.sign->crl;
        } else if (i == NID_pkcs7_signedAndEnveloped) {
            xcerts = p7->d.signed_and_enveloped->cert;
            xcrls  = p7->d.signed_and_enveloped->crl;
        }

        QList<CertContext *> _certs;
        QList<CRLContext *>  _crls;

        if (xcerts) {
            for (int n = 0; n < sk_X509_num(xcerts); ++n) {
                MyCertContext *cc = new MyCertContext(provider());
                cc->fromX509(sk_X509_value(xcerts, n));
                _certs += cc;
            }
        }
        if (xcrls) {
            for (int n = 0; n < sk_X509_CRL_num(xcrls); ++n) {
                MyCRLContext *cc = new MyCRLContext(provider());
                cc->fromX509(sk_X509_CRL_value(xcrls, n));
                _crls += cc;
            }
        }

        PKCS7_free(p7);

        *certs = _certs;
        *crls  = _crls;

        return ConvertGood;
    }
};

static bool usage_check(const MyCertContext &cc, UsageMode u)
{
    if (cc._props.constraints.isEmpty()) {
        // then any usage is OK
        return true;
    }

    switch (u) {
    case UsageAny:
        return true;
        break;
    case UsageTLSServer:
        return cc._props.constraints.contains(ServerAuth);
        break;
    case UsageTLSClient:
        return cc._props.constraints.contains(ClientAuth);
        break;
    case UsageCodeSigning:
        return cc._props.constraints.contains(CodeSigning);
        break;
    case UsageEmailProtection:
        return cc._props.constraints.contains(EmailProtection);
        break;
    case UsageTimeStamping:
        return cc._props.constraints.contains(TimeStamping);
        break;
    case UsageCRLSigning:
        return cc._props.constraints.contains(CRLSign);
        break;
    default:
        return true;
    }
}

Validity MyCertContext::validate(const QList<CertContext *> &trusted,
                                 const QList<CertContext *> &untrusted,
                                 const QList<CRLContext *> & crls,
                                 UsageMode                   u,
                                 ValidateFlags               vf) const
{
    // TODO
    Q_UNUSED(vf);

    STACK_OF(X509) *trusted_list   = sk_X509_new_null();
    STACK_OF(X509) *untrusted_list = sk_X509_new_null();
    QList<X509_CRL *> crl_list;

    int n;
    for (n = 0; n < trusted.count(); ++n) {
        const MyCertContext *cc = static_cast<const MyCertContext *>(trusted[n]);
        X509 *               x  = cc->item.cert;
        X509_up_ref(x);
        sk_X509_push(trusted_list, x);
    }
    for (n = 0; n < untrusted.count(); ++n) {
        const MyCertContext *cc = static_cast<const MyCertContext *>(untrusted[n]);
        X509 *               x  = cc->item.cert;
        X509_up_ref(x);
        sk_X509_push(untrusted_list, x);
    }
    for (n = 0; n < crls.count(); ++n) {
        const MyCRLContext *cc = static_cast<const MyCRLContext *>(crls[n]);
        X509_CRL *          x  = cc->item.crl;
        X509_CRL_up_ref(x);
        crl_list.append(x);
    }

    const MyCertContext *cc = this;
    X509 *               x  = cc->item.cert;

    // verification happens through a store "context"
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();

    // make a store of crls
    X509_STORE *store = X509_STORE_new();
    for (int n = 0; n < crl_list.count(); ++n)
        X509_STORE_add_crl(store, crl_list[n]);

    // the first initialization handles untrusted certs, crls, and target cert
    X509_STORE_CTX_init(ctx, store, x, untrusted_list);

    // this initializes the trusted certs
    X509_STORE_CTX_trusted_stack(ctx, trusted_list);

    // verify!
    int ret = X509_verify_cert(ctx);
    int err = -1;
    if (!ret)
        err = X509_STORE_CTX_get_error(ctx);

    // cleanup
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);

    sk_X509_pop_free(trusted_list, X509_free);
    sk_X509_pop_free(untrusted_list, X509_free);
    for (int n = 0; n < crl_list.count(); ++n)
        X509_CRL_free(crl_list[n]);

    if (!ret)
        return convert_verify_error(err);

    if (!usage_check(*cc, u))
        return ErrorInvalidPurpose;

    return ValidityGood;
}

Validity MyCertContext::validate_chain(const QList<CertContext *> &chain,
                                       const QList<CertContext *> &trusted,
                                       const QList<CRLContext *> & crls,
                                       UsageMode                   u,
                                       ValidateFlags               vf) const
{
    // TODO
    Q_UNUSED(vf);

    STACK_OF(X509) *trusted_list   = sk_X509_new_null();
    STACK_OF(X509) *untrusted_list = sk_X509_new_null();
    QList<X509_CRL *> crl_list;

    int n;
    for (n = 0; n < trusted.count(); ++n) {
        const MyCertContext *cc = static_cast<const MyCertContext *>(trusted[n]);
        X509 *               x  = cc->item.cert;
        X509_up_ref(x);
        sk_X509_push(trusted_list, x);
    }
    for (n = 1; n < chain.count(); ++n) {
        const MyCertContext *cc = static_cast<const MyCertContext *>(chain[n]);
        X509 *               x  = cc->item.cert;
        X509_up_ref(x);
        sk_X509_push(untrusted_list, x);
    }
    for (n = 0; n < crls.count(); ++n) {
        const MyCRLContext *cc = static_cast<const MyCRLContext *>(crls[n]);
        X509_CRL *          x  = cc->item.crl;
        X509_CRL_up_ref(x);
        crl_list.append(x);
    }

    const MyCertContext *cc = static_cast<const MyCertContext *>(chain[0]);
    X509 *               x  = cc->item.cert;

    // verification happens through a store "context"
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();

    // make a store of crls
    X509_STORE *store = X509_STORE_new();
    for (int n = 0; n < crl_list.count(); ++n)
        X509_STORE_add_crl(store, crl_list[n]);

    // the first initialization handles untrusted certs, crls, and target cert
    X509_STORE_CTX_init(ctx, store, x, untrusted_list);

    // this initializes the trusted certs
    X509_STORE_CTX_trusted_stack(ctx, trusted_list);

    // verify!
    int ret = X509_verify_cert(ctx);
    int err = -1;
    if (!ret)
        err = X509_STORE_CTX_get_error(ctx);

    // grab the chain, which may not be fully populated
    STACK_OF(X509) *xchain = X509_STORE_CTX_get_chain(ctx);

    // make sure the chain is what we expect.  the reason we need to do
    //   this is because I don't think openssl cares about the order of
    //   input.  that is, if there's a chain A<-B<-C, and we input A as
    //   the base cert, with B and C as the issuers, we will get a
    //   successful validation regardless of whether the issuer list is
    //   in the order B,C or C,B.  we don't want an input chain of A,C,B
    //   to be considered correct, so we must account for that here.
    QList<const MyCertContext *> expected;
    for (int n = 0; n < chain.count(); ++n)
        expected += static_cast<const MyCertContext *>(chain[n]);
    if (!xchain || !sameChain(xchain, expected))
        err = ErrorValidityUnknown;

    // cleanup
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);

    sk_X509_pop_free(trusted_list, X509_free);
    sk_X509_pop_free(untrusted_list, X509_free);
    for (int n = 0; n < crl_list.count(); ++n)
        X509_CRL_free(crl_list[n]);

    if (!ret)
        return convert_verify_error(err);

    if (!usage_check(*cc, u))
        return ErrorInvalidPurpose;

    return ValidityGood;
}

class MyPKCS12Context : public PKCS12Context
{
    Q_OBJECT
public:
    MyPKCS12Context(Provider *p)
        : PKCS12Context(p)
    {
    }

    ~MyPKCS12Context() override
    {
    }

    Provider::Context *clone() const override
    {
        return nullptr;
    }

    QByteArray toPKCS12(const QString &                   name,
                        const QList<const CertContext *> &chain,
                        const PKeyContext &               priv,
                        const SecureArray &               passphrase) const override
    {
        if (chain.count() < 1)
            return QByteArray();

        X509 *cert         = static_cast<const MyCertContext *>(chain[0])->item.cert;
        STACK_OF(X509) *ca = sk_X509_new_null();
        if (chain.count() > 1) {
            for (int n = 1; n < chain.count(); ++n) {
                X509 *x = static_cast<const MyCertContext *>(chain[n])->item.cert;
                X509_up_ref(x);
                sk_X509_push(ca, x);
            }
        }
        const MyPKeyContext &pk  = static_cast<const MyPKeyContext &>(priv);
        PKCS12 *             p12 = PKCS12_create(
            (char *)passphrase.data(), (char *)name.toLatin1().data(), pk.get_pkey(), cert, ca, 0, 0, 0, 0, 0);
        sk_X509_pop_free(ca, X509_free);

        if (!p12)
            return QByteArray();

        BIO *bo = BIO_new(BIO_s_mem());
        i2d_PKCS12_bio(bo, p12);
        const QByteArray out = bio2ba(bo);
        return out;
    }

    ConvertResult fromPKCS12(const QByteArray &    in,
                             const SecureArray &   passphrase,
                             QString *             name,
                             QList<CertContext *> *chain,
                             PKeyContext **        priv) const override
    {
        BIO *bi = BIO_new(BIO_s_mem());
        BIO_write(bi, in.data(), in.size());
        PKCS12 *p12 = d2i_PKCS12_bio(bi, nullptr);
        BIO_free(bi);
        if (!p12)
            return ErrorDecode;

        EVP_PKEY *pkey;
        X509 *    cert;
        STACK_OF(X509) *ca = nullptr;
        if (!PKCS12_parse(p12, passphrase.data(), &pkey, &cert, &ca)) {
            PKCS12_free(p12);
            return ErrorDecode;
        }
        PKCS12_free(p12);

        // require private key
        if (!pkey) {
            if (cert)
                X509_free(cert);
            if (ca)
                sk_X509_pop_free(ca, X509_free);
            return ErrorDecode;
        }

        // TODO: require cert

        int   aliasLength;
        char *aliasData = (char *)X509_alias_get0(cert, &aliasLength);
        *name           = QString::fromLatin1(aliasData, aliasLength);

        MyPKeyContext *pk = new MyPKeyContext(provider());
        PKeyBase *     k  = pk->pkeyToBase(pkey, true); // does an EVP_PKEY_free()
        if (!k) {
            delete pk;
            if (cert)
                X509_free(cert);
            if (ca)
                sk_X509_pop_free(ca, X509_free);
            return ErrorDecode;
        }
        pk->k = k;
        *priv = pk;

        QList<CertContext *> certs;
        if (cert) {
            MyCertContext *cc = new MyCertContext(provider());
            cc->fromX509(cert);
            certs.append(cc);
            X509_free(cert);
        }
        if (ca) {
            // TODO: reorder in chain-order?
            // TODO: throw out certs that don't fit the chain?
            for (int n = 0; n < sk_X509_num(ca); ++n) {
                MyCertContext *cc = new MyCertContext(provider());
                cc->fromX509(sk_X509_value(ca, n));
                certs.append(cc);
            }
            sk_X509_pop_free(ca, X509_free);
        }

        // reorder, throw out
        QCA::CertificateChain ch;
        for (int n = 0; n < certs.count(); ++n) {
            QCA::Certificate cert;
            cert.change(certs[n]);
            ch += cert;
        }
        certs.clear();
        ch = ch.complete(QList<QCA::Certificate>());
        for (int n = 0; n < ch.count(); ++n) {
            MyCertContext *cc = (MyCertContext *)ch[n].context();
            certs += (new MyCertContext(*cc));
        }
        ch.clear();

        *chain = certs;
        return ConvertGood;
    }
};

// TODO: test to ensure there is no cert-test lag
static bool ssl_init = false;
class MyTLSContext : public TLSContext
{
    Q_OBJECT
public:
    enum
    {
        Good,
        TryAgain,
        Bad
    };
    enum
    {
        Idle,
        Connect,
        Accept,
        Handshake,
        Active,
        Closing
    };

    bool       serv; // true if we are acting as a server
    int        mode;
    QByteArray sendQueue;
    QByteArray recvQueue;

    CertificateCollection trusted;
    Certificate           cert, peercert; // TODO: support cert chains
    PrivateKey            key;
    QString               targetHostName;

    Result     result_result;
    QByteArray result_to_net;
    int        result_encoded;
    QByteArray result_plain;

    SSL *             ssl;
    const SSL_METHOD *method;
    SSL_CTX *         context;
    BIO *             rbio, *wbio;
    Validity          vr;
    bool              v_eof;

    MyTLSContext(Provider *p)
        : TLSContext(p, QStringLiteral("tls"))
    {
        if (!ssl_init) {
            SSL_library_init();
            SSL_load_error_strings();
            ssl_init = true;
        }

        ssl     = nullptr;
        context = nullptr;
        reset();
    }

    ~MyTLSContext() override
    {
        reset();
    }

    Provider::Context *clone() const override
    {
        return nullptr;
    }

    void reset() override
    {
        if (ssl) {
            SSL_free(ssl);
            ssl = nullptr;
        }
        if (context) {
            SSL_CTX_free(context);
            context = nullptr;
        }

        cert = Certificate();
        key  = PrivateKey();

        sendQueue.resize(0);
        recvQueue.resize(0);
        mode     = Idle;
        peercert = Certificate();
        vr       = ErrorValidityUnknown;
        v_eof    = false;
    }

    // dummy verification function for SSL_set_verify()
    static int ssl_verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
    {
        Q_UNUSED(preverify_ok);
        Q_UNUSED(x509_ctx);

        // don't terminate handshake in case of verification failure
        return 1;
    }

    QStringList supportedCipherSuites(const TLS::Version &version) const override
    {
        OpenSSL_add_ssl_algorithms();
        SSL_CTX *ctx = nullptr;
        switch (version) {
#ifndef OPENSSL_NO_SSL3_METHOD
        case TLS::SSL_v3:
            // Here should be used TLS_client_method() but on Fedora
            // it doesn't return any SSL ciphers.
            ctx = SSL_CTX_new(SSLv3_client_method());
            SSL_CTX_set_min_proto_version(ctx, SSL3_VERSION);
            SSL_CTX_set_max_proto_version(ctx, SSL3_VERSION);
            break;
#endif
        case TLS::TLS_v1:
            ctx = SSL_CTX_new(TLS_client_method());
            SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
            SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
            break;
        case TLS::DTLS_v1:
        default:
            /* should not happen - should be in a "dtls" provider*/
            qWarning("Unexpected enum in cipherSuites");
            ctx = nullptr;
        }
        if (nullptr == ctx)
            return QStringList();

        SSL *ssl = SSL_new(ctx);
        if (nullptr == ssl) {
            SSL_CTX_free(ctx);
            return QStringList();
        }

        STACK_OF(SSL_CIPHER) *sk = SSL_get1_supported_ciphers(ssl);
        QStringList cipherList;
        for (int i = 0; i < sk_SSL_CIPHER_num(sk); ++i) {
            const SSL_CIPHER *thisCipher = sk_SSL_CIPHER_value(sk, i);
            cipherList += QString::fromLatin1(SSL_CIPHER_standard_name(thisCipher));
        }
        sk_SSL_CIPHER_free(sk);

        SSL_free(ssl);
        SSL_CTX_free(ctx);

        return cipherList;
    }

    bool canCompress() const override
    {
        // TODO
        return false;
    }

    bool canSetHostName() const override
    {
        // TODO
        return false;
    }

    int maxSSF() const override
    {
        // TODO
        return 256;
    }

    void setConstraints(int minSSF, int maxSSF) override
    {
        // TODO
        Q_UNUSED(minSSF);
        Q_UNUSED(maxSSF);
    }

    void setConstraints(const QStringList &cipherSuiteList) override
    {
        // TODO
        Q_UNUSED(cipherSuiteList);
    }

    void setup(bool serverMode, const QString &hostName, bool compress) override
    {
        serv = serverMode;
        if (false == serverMode) {
            // client
            targetHostName = hostName;
        }
        Q_UNUSED(compress); // TODO
    }

    void setTrustedCertificates(const CertificateCollection &_trusted) override
    {
        trusted = _trusted;
    }

    void setIssuerList(const QList<CertificateInfoOrdered> &issuerList) override
    {
        Q_UNUSED(issuerList); // TODO
    }

    void setCertificate(const CertificateChain &_cert, const PrivateKey &_key) override
    {
        if (!_cert.isEmpty())
            cert = _cert.primary(); // TODO: take the whole chain
        key = _key;
    }

    void setSessionId(const TLSSessionContext &id) override
    {
        // TODO
        Q_UNUSED(id);
    }

    void shutdown() override
    {
        mode = Closing;
    }

    void start() override
    {
        bool ok;
        if (serv)
            ok = priv_startServer();
        else
            ok = priv_startClient();
        result_result = ok ? Success : Error;

        doResultsReady();
    }

    void update(const QByteArray &from_net, const QByteArray &from_app) override
    {
        if (mode == Active) {
            bool ok = true;
            if (!from_app.isEmpty())
                ok = priv_encode(from_app, &result_to_net, &result_encoded);
            if (ok)
                ok = priv_decode(from_net, &result_plain, &result_to_net);
            result_result = ok ? Success : Error;
        } else if (mode == Closing)
            result_result = priv_shutdown(from_net, &result_to_net);
        else
            result_result = priv_handshake(from_net, &result_to_net);

        // printf("update (from_net=%d, to_net=%d, from_app=%d, to_app=%d)\n", from_net.size(), result_to_net.size(),
        // from_app.size(), result_plain.size());

        doResultsReady();
    }

    bool priv_startClient()
    {
        // serv = false;
        method = SSLv23_client_method();
        if (!init())
            return false;
        mode = Connect;
        return true;
    }

    bool priv_startServer()
    {
        // serv = true;
        method = SSLv23_server_method();
        if (!init())
            return false;
        mode = Accept;
        return true;
    }

    Result priv_handshake(const QByteArray &from_net, QByteArray *to_net)
    {
        if (!from_net.isEmpty())
            BIO_write(rbio, from_net.data(), from_net.size());

        if (mode == Connect) {
            int ret = doConnect();
            if (ret == Good) {
                mode = Handshake;
            } else if (ret == Bad) {
                reset();
                return Error;
            }
        }

        if (mode == Accept) {
            int ret = doAccept();
            if (ret == Good) {
                getCert();
                mode = Active;
            } else if (ret == Bad) {
                reset();
                return Error;
            }
        }

        if (mode == Handshake) {
            int ret = doHandshake();
            if (ret == Good) {
                getCert();
                mode = Active;
            } else if (ret == Bad) {
                reset();
                return Error;
            }
        }

        // process outgoing
        *to_net = readOutgoing();

        if (mode == Active)
            return Success;
        else
            return Continue;
    }

    Result priv_shutdown(const QByteArray &from_net, QByteArray *to_net)
    {
        if (!from_net.isEmpty())
            BIO_write(rbio, from_net.data(), from_net.size());

        int ret = doShutdown();
        if (ret == Bad) {
            reset();
            return Error;
        }

        *to_net = readOutgoing();

        if (ret == Good) {
            mode = Idle;
            return Success;
        } else {
            // mode = Closing;
            return Continue;
        }
    }

    bool priv_encode(const QByteArray &plain, QByteArray *to_net, int *enc)
    {
        if (mode != Active)
            return false;
        sendQueue.append(plain);

        int encoded = 0;
        if (sendQueue.size() > 0) {
            int ret = SSL_write(ssl, sendQueue.data(), sendQueue.size());

            enum
            {
                Good,
                Continue,
                Done,
                Error
            };
            int m;
            if (ret <= 0) {
                int x = SSL_get_error(ssl, ret);
                if (x == SSL_ERROR_WANT_READ || x == SSL_ERROR_WANT_WRITE)
                    m = Continue;
                else if (x == SSL_ERROR_ZERO_RETURN)
                    m = Done;
                else
                    m = Error;
            } else {
                m             = Good;
                encoded       = ret;
                int   newsize = sendQueue.size() - encoded;
                char *r       = sendQueue.data();
                memmove(r, r + encoded, newsize);
                sendQueue.resize(newsize);
            }

            if (m == Done) {
                sendQueue.resize(0);
                v_eof = true;
                return false;
            }
            if (m == Error) {
                sendQueue.resize(0);
                return false;
            }
        }

        *to_net += readOutgoing();
        *enc = encoded;
        return true;
    }

    bool priv_decode(const QByteArray &from_net, QByteArray *plain, QByteArray *to_net)
    {
        if (mode != Active)
            return false;
        if (!from_net.isEmpty())
            BIO_write(rbio, from_net.data(), from_net.size());

        QByteArray a;
        while (!v_eof) {
            a.resize(8192);
            int ret = SSL_read(ssl, a.data(), a.size());
            // printf("SSL_read = %d\n", ret);
            if (ret > 0) {
                if (ret != (int)a.size())
                    a.resize(ret);
                // printf("SSL_read chunk: [%s]\n", qPrintable(arrayToHex(a)));
                recvQueue.append(a);
            } else if (ret <= 0) {
                ERR_print_errors_fp(stdout);
                int x = SSL_get_error(ssl, ret);
                // printf("SSL_read error = %d\n", x);
                if (x == SSL_ERROR_WANT_READ || x == SSL_ERROR_WANT_WRITE)
                    break;
                else if (x == SSL_ERROR_ZERO_RETURN)
                    v_eof = true;
                else
                    return false;
            }
        }

        *plain = recvQueue;
        recvQueue.resize(0);

        // could be outgoing data also
        *to_net += readOutgoing();
        return true;
    }

    bool waitForResultsReady(int msecs) override
    {
        // TODO: for now, all operations block anyway
        Q_UNUSED(msecs);
        return true;
    }

    Result result() const override
    {
        return result_result;
    }

    QByteArray to_net() override
    {
        const QByteArray a = result_to_net;
        result_to_net.clear();
        return a;
    }

    int encoded() const override
    {
        return result_encoded;
    }

    QByteArray to_app() override
    {
        const QByteArray a = result_plain;
        result_plain.clear();
        return a;
    }

    bool eof() const override
    {
        return v_eof;
    }

    bool clientHelloReceived() const override
    {
        // TODO
        return false;
    }

    bool serverHelloReceived() const override
    {
        // TODO
        return false;
    }

    QString hostName() const override
    {
        // TODO
        return QString();
    }

    bool certificateRequested() const override
    {
        // TODO
        return false;
    }

    QList<CertificateInfoOrdered> issuerList() const override
    {
        // TODO
        return QList<CertificateInfoOrdered>();
    }

    SessionInfo sessionInfo() const override
    {
        SessionInfo sessInfo;

        SSL_SESSION *session  = SSL_get0_session(ssl);
        sessInfo.isCompressed = (0 != SSL_SESSION_get_compress_id(session));
        int ssl_version       = SSL_version(ssl);

        if (ssl_version == TLS1_VERSION)
            sessInfo.version = TLS::TLS_v1;
        else if (ssl_version == SSL3_VERSION)
            sessInfo.version = TLS::SSL_v3;
        else if (ssl_version == SSL2_VERSION)
            sessInfo.version = TLS::SSL_v2;
        else {
            qDebug("unexpected version response");
            sessInfo.version = TLS::TLS_v1;
        }

        sessInfo.cipherSuite = QString::fromLatin1(SSL_CIPHER_standard_name(SSL_get_current_cipher(ssl)));

        sessInfo.cipherMaxBits = SSL_get_cipher_bits(ssl, &(sessInfo.cipherBits));

        sessInfo.id = nullptr; // TODO: session resuming

        return sessInfo;
    }

    QByteArray unprocessed() override
    {
        QByteArray a;
        int        size = BIO_pending(rbio);
        if (size <= 0)
            return a;
        a.resize(size);

        int r = BIO_read(rbio, a.data(), size);
        if (r <= 0) {
            a.resize(0);
            return a;
        }
        if (r != size)
            a.resize(r);
        return a;
    }

    Validity peerCertificateValidity() const override
    {
        return vr;
    }

    CertificateChain peerCertificateChain() const override
    {
        // TODO: support whole chain
        CertificateChain chain;
        chain.append(peercert);
        return chain;
    }

    void doResultsReady()
    {
        QMetaObject::invokeMethod(this, "resultsReady", Qt::QueuedConnection);
    }

    bool init()
    {
        context = SSL_CTX_new(method);
        if (!context)
            return false;

        // setup the cert store
        {
            X509_STORE *             store     = SSL_CTX_get_cert_store(context);
            const QList<Certificate> cert_list = trusted.certificates();
            const QList<CRL>         crl_list  = trusted.crls();
            int                      n;
            for (n = 0; n < cert_list.count(); ++n) {
                const MyCertContext *cc = static_cast<const MyCertContext *>(cert_list[n].context());
                X509 *               x  = cc->item.cert;
                // CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509);
                X509_STORE_add_cert(store, x);
            }
            for (n = 0; n < crl_list.count(); ++n) {
                const MyCRLContext *cc = static_cast<const MyCRLContext *>(crl_list[n].context());
                X509_CRL *          x  = cc->item.crl;
                // CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509_CRL);
                X509_STORE_add_crl(store, x);
            }
        }

        ssl = SSL_new(context);
        if (!ssl) {
            SSL_CTX_free(context);
            context = nullptr;
            return false;
        }
        SSL_set_ssl_method(ssl, method); // can this return error?

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
        if (targetHostName.isEmpty() == false) {
            // we have a target
            // this might fail, but we ignore that for now
            char *hostname = targetHostName.toLatin1().data();
            SSL_set_tlsext_host_name(ssl, hostname);
        }
#endif

        // setup the memory bio
        rbio = BIO_new(BIO_s_mem());
        wbio = BIO_new(BIO_s_mem());

        // this passes control of the bios to ssl.  we don't need to free them.
        SSL_set_bio(ssl, rbio, wbio);

        // FIXME: move this to after server hello
        // setup the cert to send
        if (!cert.isNull() && !key.isNull()) {
            PrivateKey nkey = key;

            const PKeyContext *tmp_kc = static_cast<const PKeyContext *>(nkey.context());

            if (!tmp_kc->sameProvider(this)) {
                // fprintf(stderr, "experimental: private key supplied by a different provider\n");

                // make a pkey pointing to the existing private key
                EVP_PKEY *pkey;
                pkey = EVP_PKEY_new();
                EVP_PKEY_assign_RSA(pkey, createFromExisting(nkey.toRSA()));

                // make a new private key object to hold it
                MyPKeyContext *pk = new MyPKeyContext(provider());
                PKeyBase *     k  = pk->pkeyToBase(pkey, true); // does an EVP_PKEY_free()
                pk->k             = k;
                nkey.change(pk);
            }

            const MyCertContext *cc = static_cast<const MyCertContext *>(cert.context());
            const MyPKeyContext *kc = static_cast<const MyPKeyContext *>(nkey.context());

            if (SSL_use_certificate(ssl, cc->item.cert) != 1) {
                SSL_free(ssl);
                SSL_CTX_free(context);
                return false;
            }
            if (SSL_use_PrivateKey(ssl, kc->get_pkey()) != 1) {
                SSL_free(ssl);
                SSL_CTX_free(context);
                return false;
            }
        }

        // request a certificate from the client, if in server mode
        if (serv) {
            SSL_set_verify(ssl, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, ssl_verify_callback);
        }

        return true;
    }

    void getCert()
    {
        // verify the certificate
        Validity code           = ErrorValidityUnknown;
        STACK_OF(X509) *x_chain = SSL_get_peer_cert_chain(ssl);
        // X509 *x = SSL_get_peer_certificate(ssl);
        if (x_chain) {
            CertificateChain chain;

            if (serv) {
                X509 *         x  = SSL_get_peer_certificate(ssl);
                MyCertContext *cc = new MyCertContext(provider());
                cc->fromX509(x);
                Certificate cert;
                cert.change(cc);
                chain += cert;
            }

            for (int n = 0; n < sk_X509_num(x_chain); ++n) {
                X509 *         x  = sk_X509_value(x_chain, n);
                MyCertContext *cc = new MyCertContext(provider());
                cc->fromX509(x);
                Certificate cert;
                cert.change(cc);
                chain += cert;
            }

            peercert = chain.primary();

#ifdef Q_OS_MAC
            code = chain.validate(trusted);
#else
            int ret = SSL_get_verify_result(ssl);
            if (ret == X509_V_OK)
                code = ValidityGood;
            else
                code = convert_verify_error(ret);
#endif
        } else {
            peercert = Certificate();
        }
        vr = code;
    }

    int doConnect()
    {
        int ret = SSL_connect(ssl);
        if (ret < 0) {
            int x = SSL_get_error(ssl, ret);
            if (x == SSL_ERROR_WANT_CONNECT || x == SSL_ERROR_WANT_READ || x == SSL_ERROR_WANT_WRITE)
                return TryAgain;
            else
                return Bad;
        } else if (ret == 0)
            return Bad;
        return Good;
    }

    int doAccept()
    {
        int ret = SSL_accept(ssl);
        if (ret < 0) {
            int x = SSL_get_error(ssl, ret);
            if (x == SSL_ERROR_WANT_CONNECT || x == SSL_ERROR_WANT_READ || x == SSL_ERROR_WANT_WRITE)
                return TryAgain;
            else
                return Bad;
        } else if (ret == 0)
            return Bad;
        return Good;
    }

    int doHandshake()
    {
        int ret = SSL_do_handshake(ssl);
        if (ret < 0) {
            int x = SSL_get_error(ssl, ret);
            if (x == SSL_ERROR_WANT_READ || x == SSL_ERROR_WANT_WRITE)
                return TryAgain;
            else
                return Bad;
        } else if (ret == 0)
            return Bad;
        return Good;
    }

    int doShutdown()
    {
        int ret = SSL_shutdown(ssl);
        if (ret >= 1)
            return Good;
        else {
            if (ret == 0)
                return TryAgain;
            int x = SSL_get_error(ssl, ret);
            if (x == SSL_ERROR_WANT_READ || x == SSL_ERROR_WANT_WRITE)
                return TryAgain;
            return Bad;
        }
    }

    QByteArray readOutgoing()
    {
        QByteArray a;
        int        size = BIO_pending(wbio);
        if (size <= 0)
            return a;
        a.resize(size);

        int r = BIO_read(wbio, a.data(), size);
        if (r <= 0) {
            a.resize(0);
            return a;
        }
        if (r != size)
            a.resize(r);
        return a;
    }
};

class CMSContext : public SMSContext
{
    Q_OBJECT
public:
    CertificateCollection   trustedCerts;
    CertificateCollection   untrustedCerts;
    QList<SecureMessageKey> privateKeys;

    CMSContext(Provider *p)
        : SMSContext(p, QStringLiteral("cms"))
    {
    }

    ~CMSContext() override
    {
    }

    Provider::Context *clone() const override
    {
        return nullptr;
    }

    void setTrustedCertificates(const CertificateCollection &trusted) override
    {
        trustedCerts = trusted;
    }

    void setUntrustedCertificates(const CertificateCollection &untrusted) override
    {
        untrustedCerts = untrusted;
    }

    void setPrivateKeys(const QList<SecureMessageKey> &keys) override
    {
        privateKeys = keys;
    }

    MessageContext *createMessage() override;
};

STACK_OF(X509) * get_pk7_certs(PKCS7 *p7)
{
    int i = OBJ_obj2nid(p7->type);
    if (i == NID_pkcs7_signed)
        return p7->d.sign->cert;
    else if (i == NID_pkcs7_signedAndEnveloped)
        return p7->d.signed_and_enveloped->cert;
    else
        return nullptr;
}

class MyMessageContextThread : public QThread
{
    Q_OBJECT
public:
    SecureMessage::Format   format;
    SecureMessage::SignMode signMode;
    Certificate             cert;
    PrivateKey              key;
    STACK_OF(X509) * other_certs;
    BIO *      bi;
    int        flags;
    PKCS7 *    p7;
    bool       ok;
    QByteArray out, sig;

    MyMessageContextThread(QObject *parent = nullptr)
        : QThread(parent)
        , ok(false)
    {
    }

protected:
    void run() override
    {
        MyCertContext *cc = static_cast<MyCertContext *>(cert.context());
        MyPKeyContext *kc = static_cast<MyPKeyContext *>(key.context());
        X509 *         cx = cc->item.cert;
        EVP_PKEY *     kx = kc->get_pkey();

        p7 = PKCS7_sign(cx, kx, other_certs, bi, flags);

        BIO_free(bi);
        sk_X509_pop_free(other_certs, X509_free);

        if (p7) {
            // printf("good\n");
            BIO *bo;

            // BIO *bo = BIO_new(BIO_s_mem());
            // i2d_PKCS7_bio(bo, p7);
            // PEM_write_bio_PKCS7(bo, p7);
            // SecureArray buf = bio2buf(bo);
            // printf("[%s]\n", buf.data());

            bo = BIO_new(BIO_s_mem());
            if (format == SecureMessage::Binary)
                i2d_PKCS7_bio(bo, p7);
            else // Ascii
                PEM_write_bio_PKCS7(bo, p7);

            if (SecureMessage::Detached == signMode)
                sig = bio2ba(bo);
            else
                out = bio2ba(bo);

            ok = true;
        } else {
            printf("bad here\n");
            ERR_print_errors_fp(stdout);
        }
    }
};

class MyMessageContext : public MessageContext
{
    Q_OBJECT
public:
    CMSContext *            cms;
    SecureMessageKey        signer;
    SecureMessageKeyList    to;
    SecureMessage::SignMode signMode;
    bool                    bundleSigner;
    bool                    smime;
    SecureMessage::Format   format;

    Operation op;
    bool      _finished;

    QByteArray in, out;
    QByteArray sig;
    int        total;

    CertificateChain signerChain;
    int              ver_ret;

    MyMessageContextThread *thread;

    MyMessageContext(CMSContext *_cms, Provider *p)
        : MessageContext(p, QStringLiteral("cmsmsg"))
    {
        cms = _cms;

        total = 0;

        ver_ret = 0;

        thread = nullptr;
    }

    ~MyMessageContext() override
    {
    }

    Provider::Context *clone() const override
    {
        return nullptr;
    }

    bool canSignMultiple() const override
    {
        return false;
    }

    SecureMessage::Type type() const override
    {
        return SecureMessage::CMS;
    }

    void reset() override
    {
    }

    void setupEncrypt(const SecureMessageKeyList &keys) override
    {
        to = keys;
    }

    void setupSign(const SecureMessageKeyList &keys, SecureMessage::SignMode m, bool bundleSigner, bool smime) override
    {
        signer             = keys.first();
        signMode           = m;
        this->bundleSigner = bundleSigner;
        this->smime        = smime;
    }

    void setupVerify(const QByteArray &detachedSig) override
    {
        // TODO
        sig = detachedSig;
    }

    void start(SecureMessage::Format f, Operation op) override
    {
        format    = f;
        _finished = false;

        // TODO: other operations
        // if(op == Sign)
        //{
        this->op = op;
        //}
        // else if(op == Encrypt)
        //{
        //	this->op = op;
        //}
    }

    void update(const QByteArray &in) override
    {
        this->in.append(in);
        total += in.size();
        QMetaObject::invokeMethod(this, "updated", Qt::QueuedConnection);
    }

    QByteArray read() override
    {
        return out;
    }

    int written() override
    {
        int x = total;
        total = 0;
        return x;
    }

    void end() override
    {
        _finished = true;

        // sign
        if (op == Sign) {
            const CertificateChain chain = signer.x509CertificateChain();
            Certificate            cert  = chain.primary();
            QList<Certificate>     nonroots;
            if (chain.count() > 1) {
                for (int n = 1; n < chain.count(); ++n)
                    nonroots.append(chain[n]);
            }
            PrivateKey key = signer.x509PrivateKey();

            const PKeyContext *tmp_kc = static_cast<const PKeyContext *>(key.context());

            if (!tmp_kc->sameProvider(this)) {
                // fprintf(stderr, "experimental: private key supplied by a different provider\n");

                // make a pkey pointing to the existing private key
                EVP_PKEY *pkey;
                pkey = EVP_PKEY_new();
                EVP_PKEY_assign_RSA(pkey, createFromExisting(key.toRSA()));

                // make a new private key object to hold it
                MyPKeyContext *pk = new MyPKeyContext(provider());
                PKeyBase *     k  = pk->pkeyToBase(pkey, true); // does an EVP_PKEY_free()
                pk->k             = k;
                key.change(pk);
            }

            // allow different cert provider.  this is just a
            //   quick hack, enough to please qca-test
            if (!cert.context()->sameProvider(this)) {
                // fprintf(stderr, "experimental: cert supplied by a different provider\n");
                cert = Certificate::fromDER(cert.toDER());
                if (cert.isNull() || !cert.context()->sameProvider(this)) {
                    // fprintf(stderr, "error converting cert\n");
                }
            }

            // MyCertContext *cc = static_cast<MyCertContext *>(cert.context());
            // MyPKeyContext *kc = static_cast<MyPKeyContext *>(key.context());

            // X509 *cx = cc->item.cert;
            // EVP_PKEY *kx = kc->get_pkey();

            STACK_OF(X509) * other_certs;
            BIO *bi;
            int  flags;
            // PKCS7 *p7;

            // nonroots
            other_certs = sk_X509_new_null();
            for (int n = 0; n < nonroots.count(); ++n) {
                X509 *x = static_cast<MyCertContext *>(nonroots[n].context())->item.cert;
                X509_up_ref(x);
                sk_X509_push(other_certs, x);
            }

            // printf("bundling %d other_certs\n", sk_X509_num(other_certs));

            bi = BIO_new(BIO_s_mem());
            BIO_write(bi, in.data(), in.size());

            flags = 0;
            flags |= PKCS7_BINARY;
            if (SecureMessage::Detached == signMode) {
                flags |= PKCS7_DETACHED;
            }
            if (false == bundleSigner)
                flags |= PKCS7_NOCERTS;

            if (thread)
                delete thread;
            thread              = new MyMessageContextThread(this);
            thread->format      = format;
            thread->signMode    = signMode;
            thread->cert        = cert;
            thread->key         = key;
            thread->other_certs = other_certs;
            thread->bi          = bi;
            thread->flags       = flags;
            connect(thread, &MyMessageContextThread::finished, this, &MyMessageContext::thread_finished);
            thread->start();
        } else if (op == Encrypt) {
            // TODO: support multiple recipients
            Certificate target = to.first().x509CertificateChain().primary();

            STACK_OF(X509) * other_certs;
            BIO *  bi;
            int    flags;
            PKCS7 *p7;

            other_certs = sk_X509_new_null();
            X509 *x     = static_cast<MyCertContext *>(target.context())->item.cert;
            X509_up_ref(x);
            sk_X509_push(other_certs, x);

            bi = BIO_new(BIO_s_mem());
            BIO_write(bi, in.data(), in.size());

            flags = 0;
            flags |= PKCS7_BINARY;
            p7 = PKCS7_encrypt(other_certs, bi, EVP_des_ede3_cbc(), flags); // TODO: cipher?

            BIO_free(bi);
            sk_X509_pop_free(other_certs, X509_free);

            if (p7) {
                // FIXME: format
                BIO *bo = BIO_new(BIO_s_mem());
                i2d_PKCS7_bio(bo, p7);
                // PEM_write_bio_PKCS7(bo, p7);
                out = bio2ba(bo);
                PKCS7_free(p7);
            } else {
                printf("bad\n");
                return;
            }
        } else if (op == Verify) {
            // TODO: support non-detached sigs

            BIO *out = BIO_new(BIO_s_mem());
            BIO *bi  = BIO_new(BIO_s_mem());
            if (false == sig.isEmpty()) {
                // We have detached signature
                BIO_write(bi, sig.data(), sig.size());
            } else {
                BIO_write(bi, in.data(), in.size());
            }
            PKCS7 *p7;
            if (format == SecureMessage::Binary)
                p7 = d2i_PKCS7_bio(bi, nullptr);
            else // Ascii
                p7 = PEM_read_bio_PKCS7(bi, nullptr, passphrase_cb, nullptr);
            BIO_free(bi);

            if (!p7) {
                // TODO
                printf("bad1\n");
                QMetaObject::invokeMethod(this, "updated", Qt::QueuedConnection);
                return;
            }

            // intermediates/signers that may not be in the blob
            STACK_OF(X509) *other_certs       = sk_X509_new_null();
            QList<Certificate> untrusted_list = cms->untrustedCerts.certificates();
            const QList<CRL>   untrusted_crls = cms->untrustedCerts.crls(); // we'll use the crls later
            for (int n = 0; n < untrusted_list.count(); ++n) {
                X509 *x = static_cast<MyCertContext *>(untrusted_list[n].context())->item.cert;
                X509_up_ref(x);
                sk_X509_push(other_certs, x);
            }

            // get the possible message signers
            QList<Certificate> signers;
            STACK_OF(X509) *xs = PKCS7_get0_signers(p7, other_certs, 0);
            if (xs) {
                for (int n = 0; n < sk_X509_num(xs); ++n) {
                    MyCertContext *cc = new MyCertContext(provider());
                    cc->fromX509(sk_X509_value(xs, n));
                    Certificate cert;
                    cert.change(cc);
                    // printf("signer: [%s]\n", qPrintable(cert.commonName()));
                    signers.append(cert);
                }
                sk_X509_free(xs);
            }

            // get the rest of the certificates lying around
            QList<Certificate> others;
            xs = get_pk7_certs(p7); // don't free
            if (xs) {
                for (int n = 0; n < sk_X509_num(xs); ++n) {
                    MyCertContext *cc = new MyCertContext(provider());
                    cc->fromX509(sk_X509_value(xs, n));
                    Certificate cert;
                    cert.change(cc);
                    others.append(cert);
                    // printf("other: [%s]\n", qPrintable(cert.commonName()));
                }
            }

            // signer needs to be supplied in the message itself
            //   or via cms->untrustedCerts
            if (signers.isEmpty()) {
                QMetaObject::invokeMethod(this, "updated", Qt::QueuedConnection);
                return;
            }

            // FIXME: handle more than one signer
            CertificateChain chain;
            chain += signers[0];

            // build chain
            chain = chain.complete(others);

            signerChain = chain;

            X509_STORE *             store     = X509_STORE_new();
            const QList<Certificate> cert_list = cms->trustedCerts.certificates();
            QList<CRL>               crl_list  = cms->trustedCerts.crls();
            for (int n = 0; n < cert_list.count(); ++n) {
                // printf("trusted: [%s]\n", qPrintable(cert_list[n].commonName()));
                const MyCertContext *cc = static_cast<const MyCertContext *>(cert_list[n].context());
                X509 *               x  = cc->item.cert;
                // CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509);
                X509_STORE_add_cert(store, x);
            }
            for (int n = 0; n < crl_list.count(); ++n) {
                const MyCRLContext *cc = static_cast<const MyCRLContext *>(crl_list[n].context());
                X509_CRL *          x  = cc->item.crl;
                // CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509_CRL);
                X509_STORE_add_crl(store, x);
            }
            // add these crls also
            crl_list = untrusted_crls;
            for (int n = 0; n < crl_list.count(); ++n) {
                const MyCRLContext *cc = static_cast<const MyCRLContext *>(crl_list[n].context());
                X509_CRL *          x  = cc->item.crl;
                // CRYPTO_add(&x->references, 1, CRYPTO_LOCK_X509_CRL);
                X509_STORE_add_crl(store, x);
            }

            int ret;
            if (!sig.isEmpty()) {
                // Detached signMode
                bi = BIO_new(BIO_s_mem());
                BIO_write(bi, in.data(), in.size());
                ret = PKCS7_verify(p7, other_certs, store, bi, nullptr, 0);
                BIO_free(bi);
            } else {
                ret = PKCS7_verify(p7, other_certs, store, nullptr, out, 0);
                // qDebug() << "Verify: " << ret;
            }
            // if(!ret)
            //	ERR_print_errors_fp(stdout);
            sk_X509_pop_free(other_certs, X509_free);
            X509_STORE_free(store);
            PKCS7_free(p7);

            ver_ret = ret;
            // TODO

            QMetaObject::invokeMethod(this, "updated", Qt::QueuedConnection);
        } else if (op == Decrypt) {
            bool ok = false;
            for (int n = 0; n < cms->privateKeys.count(); ++n) {
                CertificateChain chain = cms->privateKeys[n].x509CertificateChain();
                Certificate      cert  = chain.primary();
                PrivateKey       key   = cms->privateKeys[n].x509PrivateKey();

                MyCertContext *cc = static_cast<MyCertContext *>(cert.context());
                MyPKeyContext *kc = static_cast<MyPKeyContext *>(key.context());

                X509 *    cx = cc->item.cert;
                EVP_PKEY *kx = kc->get_pkey();

                BIO *bi = BIO_new(BIO_s_mem());
                BIO_write(bi, in.data(), in.size());
                PKCS7 *p7 = d2i_PKCS7_bio(bi, nullptr);
                BIO_free(bi);

                if (!p7) {
                    // TODO
                    printf("bad1\n");
                    return;
                }

                BIO *bo  = BIO_new(BIO_s_mem());
                int  ret = PKCS7_decrypt(p7, kx, cx, bo, 0);
                PKCS7_free(p7);
                if (!ret)
                    continue;

                ok  = true;
                out = bio2ba(bo);
                break;
            }

            if (!ok) {
                // TODO
                printf("bad2\n");
                return;
            }
        }
    }

    bool finished() const override
    {
        return _finished;
    }

    bool waitForFinished(int msecs) override
    {
        // TODO
        Q_UNUSED(msecs);

        if (thread) {
            thread->wait();
            getresults();
        }
        return true;
    }

    bool success() const override
    {
        // TODO
        return true;
    }

    SecureMessage::Error errorCode() const override
    {
        // TODO
        return SecureMessage::ErrorUnknown;
    }

    QByteArray signature() const override
    {
        return sig;
    }

    QString hashName() const override
    {
        // TODO
        return QStringLiteral("sha1");
    }

    SecureMessageSignatureList signers() const override
    {
        // only report signers for verify
        if (op != Verify)
            return SecureMessageSignatureList();

        SecureMessageKey key;
        if (!signerChain.isEmpty())
            key.setX509CertificateChain(signerChain);

        // TODO/FIXME !!! InvalidSignature might be used here even
        //   if the signature is just fine, and the key is invalid
        //   (we need to use InvalidKey instead).

        Validity vr = ErrorValidityUnknown;
        if (!signerChain.isEmpty())
            vr = signerChain.validate(cms->trustedCerts, cms->untrustedCerts.crls());

        SecureMessageSignature::IdentityResult ir;
        if (vr == ValidityGood)
            ir = SecureMessageSignature::Valid;
        else
            ir = SecureMessageSignature::InvalidKey;

        if (!ver_ret)
            ir = SecureMessageSignature::InvalidSignature;

        SecureMessageSignature s(ir, vr, key, QDateTime::currentDateTime());

        // TODO
        return SecureMessageSignatureList() << s;
    }

    void getresults()
    {
        sig = thread->sig;
        out = thread->out;
    }

private Q_SLOTS:
    void thread_finished()
    {
        getresults();
        emit updated();
    }
};

MessageContext *CMSContext::createMessage()
{
    return new MyMessageContext(this, provider());
}

class opensslCipherContext : public CipherContext
{
    Q_OBJECT
public:
    opensslCipherContext(const EVP_CIPHER *algorithm, const int pad, Provider *p, const QString &type)
        : CipherContext(p, type)
    {
        m_cryptoAlgorithm = algorithm;
        m_context         = EVP_CIPHER_CTX_new();
        EVP_CIPHER_CTX_init(m_context);
        m_pad  = pad;
        m_type = type;
    }

    opensslCipherContext(const opensslCipherContext &other)
        : CipherContext(other)
    {
        m_cryptoAlgorithm = other.m_cryptoAlgorithm;
        m_context         = EVP_CIPHER_CTX_new();
        EVP_CIPHER_CTX_copy(m_context, other.m_context);
        m_direction = other.m_direction;
        m_pad       = other.m_pad;
        m_type      = other.m_type;
        m_tag       = other.m_tag;
    }

    ~opensslCipherContext() override
    {
        EVP_CIPHER_CTX_cleanup(m_context);
        EVP_CIPHER_CTX_free(m_context);
    }

    void setup(Direction dir, const SymmetricKey &key, const InitializationVector &iv, const AuthTag &tag) override
    {
        m_tag       = tag;
        m_direction = dir;
        if ((m_cryptoAlgorithm == EVP_des_ede3()) && (key.size() == 16)) {
            // this is really a two key version of triple DES.
            m_cryptoAlgorithm = EVP_des_ede();
        }
        if (Encode == m_direction) {
            EVP_EncryptInit_ex(m_context, m_cryptoAlgorithm, nullptr, nullptr, nullptr);
            EVP_CIPHER_CTX_set_key_length(m_context, key.size());
            if (m_type.endsWith(QLatin1String("gcm")) || m_type.endsWith(QLatin1String("ccm"))) {
                int parameter = m_type.endsWith(QLatin1String("gcm")) ? EVP_CTRL_GCM_SET_IVLEN : EVP_CTRL_CCM_SET_IVLEN;
                EVP_CIPHER_CTX_ctrl(m_context, parameter, iv.size(), nullptr);
            }
            EVP_EncryptInit_ex(
                m_context, nullptr, nullptr, (const unsigned char *)(key.data()), (const unsigned char *)(iv.data()));
        } else {
            EVP_DecryptInit_ex(m_context, m_cryptoAlgorithm, nullptr, nullptr, nullptr);
            EVP_CIPHER_CTX_set_key_length(m_context, key.size());
            if (m_type.endsWith(QLatin1String("gcm")) || m_type.endsWith(QLatin1String("ccm"))) {
                int parameter = m_type.endsWith(QLatin1String("gcm")) ? EVP_CTRL_GCM_SET_IVLEN : EVP_CTRL_CCM_SET_IVLEN;
                EVP_CIPHER_CTX_ctrl(m_context, parameter, iv.size(), nullptr);
            }
            EVP_DecryptInit_ex(
                m_context, nullptr, nullptr, (const unsigned char *)(key.data()), (const unsigned char *)(iv.data()));
        }

        EVP_CIPHER_CTX_set_padding(m_context, m_pad);
    }

    Provider::Context *clone() const override
    {
        return new opensslCipherContext(*this);
    }

    int blockSize() const override
    {
        return EVP_CIPHER_CTX_block_size(m_context);
    }

    AuthTag tag() const override
    {
        return m_tag;
    }

    bool update(const SecureArray &in, SecureArray *out) override
    {
        // This works around a problem in OpenSSL, where it asserts if
        // there is nothing to encrypt.
        if (0 == in.size())
            return true;

        out->resize(in.size() + blockSize());
        int resultLength;
        if (Encode == m_direction) {
            if (0 ==
                EVP_EncryptUpdate(
                    m_context, (unsigned char *)out->data(), &resultLength, (unsigned char *)in.data(), in.size())) {
                return false;
            }
        } else {
            if (0 ==
                EVP_DecryptUpdate(
                    m_context, (unsigned char *)out->data(), &resultLength, (unsigned char *)in.data(), in.size())) {
                return false;
            }
        }
        out->resize(resultLength);
        return true;
    }

    bool final(SecureArray *out) override
    {
        out->resize(blockSize());
        int resultLength;
        if (Encode == m_direction) {
            if (0 == EVP_EncryptFinal_ex(m_context, (unsigned char *)out->data(), &resultLength)) {
                return false;
            }
            if (m_tag.size() && (m_type.endsWith(QLatin1String("gcm")) || m_type.endsWith(QLatin1String("ccm")))) {
                int parameter = m_type.endsWith(QLatin1String("gcm")) ? EVP_CTRL_GCM_GET_TAG : EVP_CTRL_CCM_GET_TAG;
                if (0 == EVP_CIPHER_CTX_ctrl(m_context, parameter, m_tag.size(), (unsigned char *)m_tag.data())) {
                    return false;
                }
            }
        } else {
            if (m_tag.size() && (m_type.endsWith(QLatin1String("gcm")) || m_type.endsWith(QLatin1String("ccm")))) {
                int parameter = m_type.endsWith(QLatin1String("gcm")) ? EVP_CTRL_GCM_SET_TAG : EVP_CTRL_CCM_SET_TAG;
                if (0 == EVP_CIPHER_CTX_ctrl(m_context, parameter, m_tag.size(), m_tag.data())) {
                    return false;
                }
            }
            if (0 == EVP_DecryptFinal_ex(m_context, (unsigned char *)out->data(), &resultLength)) {
                return false;
            }
        }
        out->resize(resultLength);
        return true;
    }

    // Change cipher names
    KeyLength keyLength() const override
    {
        if (m_type.left(4) == QLatin1String("des-")) {
            return KeyLength(8, 8, 1);
        } else if (m_type.left(6) == QLatin1String("aes128")) {
            return KeyLength(16, 16, 1);
        } else if (m_type.left(6) == QLatin1String("aes192")) {
            return KeyLength(24, 24, 1);
        } else if (m_type.left(6) == QLatin1String("aes256")) {
            return KeyLength(32, 32, 1);
        } else if (m_type.left(5) == QLatin1String("cast5")) {
            return KeyLength(5, 16, 1);
        } else if (m_type.left(8) == QLatin1String("blowfish")) {
            // Don't know - TODO
            return KeyLength(1, 32, 1);
        } else if (m_type.left(9) == QLatin1String("tripledes")) {
            return KeyLength(16, 24, 1);
        } else {
            return KeyLength(0, 1, 1);
        }
    }

protected:
    EVP_CIPHER_CTX *  m_context;
    const EVP_CIPHER *m_cryptoAlgorithm;
    Direction         m_direction;
    int               m_pad;
    QString           m_type;
    AuthTag           m_tag;
};

static QStringList all_hash_types()
{
    QStringList list;
    list += QStringLiteral("sha1");
#ifdef HAVE_OPENSSL_SHA0
    list += QStringLiteral("sha0");
#endif
    list += QStringLiteral("ripemd160");
#ifdef HAVE_OPENSSL_MD2
    list += QStringLiteral("md2");
#endif
    list += QStringLiteral("md4");
    list += QStringLiteral("md5");
#ifdef SHA224_DIGEST_LENGTH
    list += QStringLiteral("sha224");
#endif
#ifdef SHA256_DIGEST_LENGTH
    list += QStringLiteral("sha256");
#endif
#ifdef SHA384_DIGEST_LENGTH
    list += QStringLiteral("sha384");
#endif
#ifdef SHA512_DIGEST_LENGTH
    list += QStringLiteral("sha512");
#endif
#ifdef OBJ_whirlpool
    list += QStringLiteral("whirlpool");
#endif
    return list;
}

static QStringList all_cipher_types()
{
    QStringList list;
    list += QStringLiteral("aes128-ecb");
    list += QStringLiteral("aes128-cfb");
    list += QStringLiteral("aes128-cbc");
    list += QStringLiteral("aes128-cbc-pkcs7");
    list += QStringLiteral("aes128-ofb");
#ifdef HAVE_OPENSSL_AES_CTR
    list += QStringLiteral("aes128-ctr");
#endif
#ifdef HAVE_OPENSSL_AES_GCM
    list += QStringLiteral("aes128-gcm");
#endif
#ifdef HAVE_OPENSSL_AES_CCM
    list += QStringLiteral("aes128-ccm");
#endif
    list += QStringLiteral("aes192-ecb");
    list += QStringLiteral("aes192-cfb");
    list += QStringLiteral("aes192-cbc");
    list += QStringLiteral("aes192-cbc-pkcs7");
    list += QStringLiteral("aes192-ofb");
#ifdef HAVE_OPENSSL_AES_CTR
    list += QStringLiteral("aes192-ctr");
#endif
#ifdef HAVE_OPENSSL_AES_GCM
    list += QStringLiteral("aes192-gcm");
#endif
#ifdef HAVE_OPENSSL_AES_CCM
    list += QStringLiteral("aes192-ccm");
#endif
    list += QStringLiteral("aes256-ecb");
    list += QStringLiteral("aes256-cbc");
    list += QStringLiteral("aes256-cbc-pkcs7");
    list += QStringLiteral("aes256-cfb");
    list += QStringLiteral("aes256-ofb");
#ifdef HAVE_OPENSSL_AES_CTR
    list += QStringLiteral("aes256-ctr");
#endif
#ifdef HAVE_OPENSSL_AES_GCM
    list += QStringLiteral("aes256-gcm");
#endif
#ifdef HAVE_OPENSSL_AES_CCM
    list += QStringLiteral("aes256-ccm");
#endif
    list += QStringLiteral("blowfish-ecb");
    list += QStringLiteral("blowfish-cbc-pkcs7");
    list += QStringLiteral("blowfish-cbc");
    list += QStringLiteral("blowfish-cfb");
    list += QStringLiteral("blowfish-ofb");
    list += QStringLiteral("tripledes-ecb");
    list += QStringLiteral("tripledes-cbc");
    list += QStringLiteral("des-ecb");
    list += QStringLiteral("des-ecb-pkcs7");
    list += QStringLiteral("des-cbc");
    list += QStringLiteral("des-cbc-pkcs7");
    list += QStringLiteral("des-cfb");
    list += QStringLiteral("des-ofb");
    list += QStringLiteral("cast5-ecb");
    list += QStringLiteral("cast5-cbc");
    list += QStringLiteral("cast5-cbc-pkcs7");
    list += QStringLiteral("cast5-cfb");
    list += QStringLiteral("cast5-ofb");
    return list;
}

static QStringList all_mac_types()
{
    QStringList list;
    list += QStringLiteral("hmac(md5)");
    list += QStringLiteral("hmac(sha1)");
#ifdef SHA224_DIGEST_LENGTH
    list += QStringLiteral("hmac(sha224)");
#endif
#ifdef SHA256_DIGEST_LENGTH
    list += QStringLiteral("hmac(sha256)");
#endif
#ifdef SHA384_DIGEST_LENGTH
    list += QStringLiteral("hmac(sha384)");
#endif
#ifdef SHA512_DIGEST_LENGTH
    list += QStringLiteral("hmac(sha512)");
#endif
    list += QStringLiteral("hmac(ripemd160)");
    return list;
}

class opensslInfoContext : public InfoContext
{
    Q_OBJECT
public:
    opensslInfoContext(Provider *p)
        : InfoContext(p)
    {
    }

    Provider::Context *clone() const override
    {
        return new opensslInfoContext(*this);
    }

    QStringList supportedHashTypes() const override
    {
        return all_hash_types();
    }

    QStringList supportedCipherTypes() const override
    {
        return all_cipher_types();
    }

    QStringList supportedMACTypes() const override
    {
        return all_mac_types();
    }
};

class opensslRandomContext : public RandomContext
{
    Q_OBJECT
public:
    opensslRandomContext(QCA::Provider *p)
        : RandomContext(p)
    {
    }

    Context *clone() const override
    {
        return new opensslRandomContext(*this);
    }

    QCA::SecureArray nextBytes(int size) override
    {
        QCA::SecureArray buf(size);
        int              r;
        // FIXME: loop while we don't have enough random bytes.
        while (true) {
            r = RAND_bytes((unsigned char *)(buf.data()), size);
            if (r == 1)
                break; // success
        }
        return buf;
    }
};

}

using namespace opensslQCAPlugin;

class opensslProvider : public Provider
{
public:
    bool openssl_initted;

    opensslProvider()
    {
        openssl_initted = false;
    }

    void init() override
    {
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();

// OPENSSL_VERSION_MAJOR is only defined in openssl3
#ifdef OPENSSL_VERSION_MAJOR
        /* Load Multiple providers into the default (NULL) library context */
        OSSL_PROVIDER *legacy = OSSL_PROVIDER_load(NULL, "legacy");
        if (legacy == NULL) {
            printf("Failed to load Legacy provider\n");
            exit(EXIT_FAILURE);
        }
        OSSL_PROVIDER *deflt = OSSL_PROVIDER_load(NULL, "default");
        if (deflt == NULL) {
            printf("Failed to load Default provider\n");
            OSSL_PROVIDER_unload(legacy);
            exit(EXIT_FAILURE);
        }
#endif

        // seed the RNG if it's not seeded yet
        if (RAND_status() == 0) {
            std::srand(time(nullptr));
            char buf[128];
            for (char &n : buf)
                n = std::rand();
            RAND_seed(buf, 128);
        }

        openssl_initted = true;
    }

    ~opensslProvider() override
    {
        // FIXME: ?  for now we never deinit, in case other libs/code
        //   are using openssl
        /*if(!openssl_initted)
            return;
        // todo: any other shutdown?
        EVP_cleanup();
        //ENGINE_cleanup();
        CRYPTO_cleanup_all_ex_data();
        ERR_remove_state(0);
        ERR_free_strings();*/
    }

    int qcaVersion() const override
    {
        return QCA_VERSION;
    }

    QString name() const override
    {
        return QStringLiteral("qca-ossl");
    }

    QString credit() const override
    {
        return QStringLiteral(
            "This product includes cryptographic software "
            "written by Eric Young (eay@cryptsoft.com)");
    }

    QStringList features() const override
    {
        QStringList list;
        list += QStringLiteral("random");
        list += all_hash_types();
        list += all_mac_types();
        list += all_cipher_types();
#ifdef HAVE_OPENSSL_MD2
        list += QStringLiteral("pbkdf1(md2)");
#endif
        list += QStringLiteral("pbkdf1(sha1)");
        list += QStringLiteral("pbkdf2(sha1)");
        list += QStringLiteral("hkdf(sha256)");
        list += QStringLiteral("pkey");
        list += QStringLiteral("dlgroup");
        list += QStringLiteral("rsa");
        list += QStringLiteral("dsa");
        list += QStringLiteral("dh");
        list += QStringLiteral("cert");
        list += QStringLiteral("csr");
        list += QStringLiteral("crl");
        list += QStringLiteral("certcollection");
        list += QStringLiteral("pkcs12");
        list += QStringLiteral("tls");
        list += QStringLiteral("cms");
        list += QStringLiteral("ca");

        return list;
    }

    Context *createContext(const QString &type) override
    {
        // OpenSSL_add_all_digests();
        if (type == QLatin1String("random"))
            return new opensslRandomContext(this);
        else if (type == QLatin1String("info"))
            return new opensslInfoContext(this);
        else if (type == QLatin1String("sha1"))
            return new opensslHashContext(EVP_sha1(), this, type);
#ifdef HAVE_OPENSSL_SHA0
        else if (type == QLatin1String("sha0"))
            return new opensslHashContext(EVP_sha(), this, type);
#endif
        else if (type == QLatin1String("ripemd160"))
            return new opensslHashContext(EVP_ripemd160(), this, type);
#ifdef HAVE_OPENSSL_MD2
        else if (type == QLatin1String("md2"))
            return new opensslHashContext(EVP_md2(), this, type);
#endif
        else if (type == QLatin1String("md4"))
            return new opensslHashContext(EVP_md4(), this, type);
        else if (type == QLatin1String("md5"))
            return new opensslHashContext(EVP_md5(), this, type);
#ifdef SHA224_DIGEST_LENGTH
        else if (type == QLatin1String("sha224"))
            return new opensslHashContext(EVP_sha224(), this, type);
#endif
#ifdef SHA256_DIGEST_LENGTH
        else if (type == QLatin1String("sha256"))
            return new opensslHashContext(EVP_sha256(), this, type);
#endif
#ifdef SHA384_DIGEST_LENGTH
        else if (type == QLatin1String("sha384"))
            return new opensslHashContext(EVP_sha384(), this, type);
#endif
#ifdef SHA512_DIGEST_LENGTH
        else if (type == QLatin1String("sha512"))
            return new opensslHashContext(EVP_sha512(), this, type);
#endif
#ifdef OBJ_whirlpool
        else if (type == QLatin1String("whirlpool"))
            return new opensslHashContext(EVP_whirlpool(), this, type);
#endif
        else if (type == QLatin1String("pbkdf1(sha1)"))
            return new opensslPbkdf1Context(EVP_sha1(), this, type);
#ifdef HAVE_OPENSSL_MD2
        else if (type == QLatin1String("pbkdf1(md2)"))
            return new opensslPbkdf1Context(EVP_md2(), this, type);
#endif
        else if (type == QLatin1String("pbkdf2(sha1)"))
            return new opensslPbkdf2Context(this, type);
        else if (type == QLatin1String("hkdf(sha256)"))
            return new opensslHkdfContext(this, type);
        else if (type == QLatin1String("hmac(md5)"))
            return new opensslHMACContext(EVP_md5(), this, type);
        else if (type == QLatin1String("hmac(sha1)"))
            return new opensslHMACContext(EVP_sha1(), this, type);
#ifdef SHA224_DIGEST_LENGTH
        else if (type == QLatin1String("hmac(sha224)"))
            return new opensslHMACContext(EVP_sha224(), this, type);
#endif
#ifdef SHA256_DIGEST_LENGTH
        else if (type == QLatin1String("hmac(sha256)"))
            return new opensslHMACContext(EVP_sha256(), this, type);
#endif
#ifdef SHA384_DIGEST_LENGTH
        else if (type == QLatin1String("hmac(sha384)"))
            return new opensslHMACContext(EVP_sha384(), this, type);
#endif
#ifdef SHA512_DIGEST_LENGTH
        else if (type == QLatin1String("hmac(sha512)"))
            return new opensslHMACContext(EVP_sha512(), this, type);
#endif
        else if (type == QLatin1String("hmac(ripemd160)"))
            return new opensslHMACContext(EVP_ripemd160(), this, type);
        else if (type == QLatin1String("aes128-ecb"))
            return new opensslCipherContext(EVP_aes_128_ecb(), 0, this, type);
        else if (type == QLatin1String("aes128-cfb"))
            return new opensslCipherContext(EVP_aes_128_cfb(), 0, this, type);
        else if (type == QLatin1String("aes128-cbc"))
            return new opensslCipherContext(EVP_aes_128_cbc(), 0, this, type);
        else if (type == QLatin1String("aes128-cbc-pkcs7"))
            return new opensslCipherContext(EVP_aes_128_cbc(), 1, this, type);
        else if (type == QLatin1String("aes128-ofb"))
            return new opensslCipherContext(EVP_aes_128_ofb(), 0, this, type);
#ifdef HAVE_OPENSSL_AES_CTR
        else if (type == QLatin1String("aes128-ctr"))
            return new opensslCipherContext(EVP_aes_128_ctr(), 0, this, type);
#endif
#ifdef HAVE_OPENSSL_AES_GCM
        else if (type == QLatin1String("aes128-gcm"))
            return new opensslCipherContext(EVP_aes_128_gcm(), 0, this, type);
#endif
#ifdef HAVE_OPENSSL_AES_CCM
        else if (type == QLatin1String("aes128-ccm"))
            return new opensslCipherContext(EVP_aes_128_ccm(), 0, this, type);
#endif
        else if (type == QLatin1String("aes192-ecb"))
            return new opensslCipherContext(EVP_aes_192_ecb(), 0, this, type);
        else if (type == QLatin1String("aes192-cfb"))
            return new opensslCipherContext(EVP_aes_192_cfb(), 0, this, type);
        else if (type == QLatin1String("aes192-cbc"))
            return new opensslCipherContext(EVP_aes_192_cbc(), 0, this, type);
        else if (type == QLatin1String("aes192-cbc-pkcs7"))
            return new opensslCipherContext(EVP_aes_192_cbc(), 1, this, type);
        else if (type == QLatin1String("aes192-ofb"))
            return new opensslCipherContext(EVP_aes_192_ofb(), 0, this, type);
#ifdef HAVE_OPENSSL_AES_CTR
        else if (type == QLatin1String("aes192-ctr"))
            return new opensslCipherContext(EVP_aes_192_ctr(), 0, this, type);
#endif
#ifdef HAVE_OPENSSL_AES_GCM
        else if (type == QLatin1String("aes192-gcm"))
            return new opensslCipherContext(EVP_aes_192_gcm(), 0, this, type);
#endif
#ifdef HAVE_OPENSSL_AES_CCM
        else if (type == QLatin1String("aes192-ccm"))
            return new opensslCipherContext(EVP_aes_192_ccm(), 0, this, type);
#endif
        else if (type == QLatin1String("aes256-ecb"))
            return new opensslCipherContext(EVP_aes_256_ecb(), 0, this, type);
        else if (type == QLatin1String("aes256-cfb"))
            return new opensslCipherContext(EVP_aes_256_cfb(), 0, this, type);
        else if (type == QLatin1String("aes256-cbc"))
            return new opensslCipherContext(EVP_aes_256_cbc(), 0, this, type);
        else if (type == QLatin1String("aes256-cbc-pkcs7"))
            return new opensslCipherContext(EVP_aes_256_cbc(), 1, this, type);
        else if (type == QLatin1String("aes256-ofb"))
            return new opensslCipherContext(EVP_aes_256_ofb(), 0, this, type);
#ifdef HAVE_OPENSSL_AES_CTR
        else if (type == QLatin1String("aes256-ctr"))
            return new opensslCipherContext(EVP_aes_256_ctr(), 0, this, type);
#endif
#ifdef HAVE_OPENSSL_AES_GCM
        else if (type == QLatin1String("aes256-gcm"))
            return new opensslCipherContext(EVP_aes_256_gcm(), 0, this, type);
#endif
#ifdef HAVE_OPENSSL_AES_CCM
        else if (type == QLatin1String("aes256-ccm"))
            return new opensslCipherContext(EVP_aes_256_ccm(), 0, this, type);
#endif
        else if (type == QLatin1String("blowfish-ecb"))
            return new opensslCipherContext(EVP_bf_ecb(), 0, this, type);
        else if (type == QLatin1String("blowfish-cfb"))
            return new opensslCipherContext(EVP_bf_cfb(), 0, this, type);
        else if (type == QLatin1String("blowfish-ofb"))
            return new opensslCipherContext(EVP_bf_ofb(), 0, this, type);
        else if (type == QLatin1String("blowfish-cbc"))
            return new opensslCipherContext(EVP_bf_cbc(), 0, this, type);
        else if (type == QLatin1String("blowfish-cbc-pkcs7"))
            return new opensslCipherContext(EVP_bf_cbc(), 1, this, type);
        else if (type == QLatin1String("tripledes-ecb"))
            return new opensslCipherContext(EVP_des_ede3(), 0, this, type);
        else if (type == QLatin1String("tripledes-cbc"))
            return new opensslCipherContext(EVP_des_ede3_cbc(), 0, this, type);
        else if (type == QLatin1String("des-ecb"))
            return new opensslCipherContext(EVP_des_ecb(), 0, this, type);
        else if (type == QLatin1String("des-ecb-pkcs7"))
            return new opensslCipherContext(EVP_des_ecb(), 1, this, type);
        else if (type == QLatin1String("des-cbc"))
            return new opensslCipherContext(EVP_des_cbc(), 0, this, type);
        else if (type == QLatin1String("des-cbc-pkcs7"))
            return new opensslCipherContext(EVP_des_cbc(), 1, this, type);
        else if (type == QLatin1String("des-cfb"))
            return new opensslCipherContext(EVP_des_cfb(), 0, this, type);
        else if (type == QLatin1String("des-ofb"))
            return new opensslCipherContext(EVP_des_ofb(), 0, this, type);
        else if (type == QLatin1String("cast5-ecb"))
            return new opensslCipherContext(EVP_cast5_ecb(), 0, this, type);
        else if (type == QLatin1String("cast5-cbc"))
            return new opensslCipherContext(EVP_cast5_cbc(), 0, this, type);
        else if (type == QLatin1String("cast5-cbc-pkcs7"))
            return new opensslCipherContext(EVP_cast5_cbc(), 1, this, type);
        else if (type == QLatin1String("cast5-cfb"))
            return new opensslCipherContext(EVP_cast5_cfb(), 0, this, type);
        else if (type == QLatin1String("cast5-ofb"))
            return new opensslCipherContext(EVP_cast5_ofb(), 0, this, type);
        else if (type == QLatin1String("pkey"))
            return new MyPKeyContext(this);
        else if (type == QLatin1String("dlgroup"))
            return new MyDLGroup(this);
        else if (type == QLatin1String("rsa"))
            return new RSAKey(this);
        else if (type == QLatin1String("dsa"))
            return new DSAKey(this);
        else if (type == QLatin1String("dh"))
            return new DHKey(this);
        else if (type == QLatin1String("cert"))
            return new MyCertContext(this);
        else if (type == QLatin1String("csr"))
            return new MyCSRContext(this);
        else if (type == QLatin1String("crl"))
            return new MyCRLContext(this);
        else if (type == QLatin1String("certcollection"))
            return new MyCertCollectionContext(this);
        else if (type == QLatin1String("pkcs12"))
            return new MyPKCS12Context(this);
        else if (type == QLatin1String("tls"))
            return new MyTLSContext(this);
        else if (type == QLatin1String("cms"))
            return new CMSContext(this);
        else if (type == QLatin1String("ca"))
            return new MyCAContext(this);
        return nullptr;
    }
};

class opensslPlugin : public QObject, public QCAPlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "com.affinix.qca.Plugin/1.0")
    Q_INTERFACES(QCAPlugin)
public:
    Provider *createProvider() override
    {
        return new opensslProvider;
    }
};

#include "qca-ossl.moc"
