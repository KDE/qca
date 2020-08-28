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

#include "certcontext.h"

#include "pkeycontext.h"
#include "utils.h"

#include <QDebug>

namespace opensslQCAPlugin {

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

// (taken from kdelibs) -- Justin
//
// This code is mostly taken from OpenSSL v0.9.5a
// by Eric Young
static QDateTime ASN1_UTCTIME_QDateTime(const ASN1_UTCTIME *asn1_tm)
{
    struct tm t;
    ASN1_TIME_to_tm(asn1_tm, &t);
    return QDateTime(QDate(1900 + t.tm_year, t.tm_mon + 1, t.tm_mday), QTime(t.tm_hour, t.tm_min, t.tm_sec), Qt::UTC);
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

static void try_get_name_item_by_oid(X509_NAME *name, const QString &oidText, const CertificateInfoType &t,
                                     CertificateInfo *info)
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
        const QList<QString>                       emails = info.values(Email);
        QMapIterator<CertificateInfoType, QString> it(p9_info);
        while (it.hasNext()) {
            it.next();
            if (!emails.contains(it.value()))
                info.insert(Email, it.value());
        }
    }

    return info;
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

static QByteArray ipaddress_string_to_bytes(const QString &) { return QByteArray(4, 0); }

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
    int         bit_table[9] = { DigitalSignature,   NonRepudiation, KeyEncipherment, DataEncipherment, KeyAgreement,
                         KeyCertificateSign, CRLSign,        EncipherOnly,    DecipherOnly };

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
        OBJ_obj2txt((char *)buf.data(), buf.size(), pol->policyid, 1); // 1 = only accept dotted input
        out += QString::fromLatin1(buf);
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

MyCertContext::MyCertContext(Provider *p) : CertContext(p)
{
    // printf("[%p] ** created\n", this);
}

MyCertContext::MyCertContext(const MyCertContext &from) : CertContext(from), item(from.item), _props(from._props)
{
    // printf("[%p] ** created as copy (from [%p])\n", this, &from);
}

MyCertContext::~MyCertContext()
{
    // printf("[%p] ** deleted\n", this);
}

Provider::Context *MyCertContext::clone() const { return new MyCertContext(*this); }

QByteArray MyCertContext::toDER() const { return item.toDER(); }

QString MyCertContext::toPEM() const { return item.toPEM(); }

ConvertResult MyCertContext::fromDER(const QByteArray &a)
{
    _props          = CertContextProps();
    ConvertResult r = item.fromDER(a, X509Item::TypeCert);
    if (r == ConvertGood)
        make_props();
    return r;
}

ConvertResult MyCertContext::fromPEM(const QString &s)
{
    _props          = CertContextProps();
    ConvertResult r = item.fromPEM(s, X509Item::TypeCert);
    if (r == ConvertGood)
        make_props();
    return r;
}

void MyCertContext::fromX509(X509 *x)
{
    X509_up_ref(x);
    item.cert = x;
    make_props();
}

bool MyCertContext::createSelfSigned(const CertificateOptions &opts, const PKeyContext &priv)
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

const CertContextProps *MyCertContext::props() const
{
    // printf("[%p] grabbing props\n", this);
    return &_props;
}

bool MyCertContext::compare(const CertContext *other) const
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

PKeyContext *MyCertContext::subjectPublicKey() const
{
    MyPKeyContext *kc   = new MyPKeyContext(provider());
    EVP_PKEY *     pkey = X509_get_pubkey(item.cert);
    PKeyBase *     kb   = kc->pkeyToBase(pkey, false);
    kc->setKey(kb);
    return kc;
}

bool MyCertContext::isIssuerOf(const CertContext *other) const
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

void MyCertContext::make_props()
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

    p.start = ASN1_UTCTIME_QDateTime(X509_get0_notBefore(x));
    p.end   = ASN1_UTCTIME_QDateTime(X509_get0_notAfter(x));
    // qDebug() << p.start << " - " << p.end;

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
    case NID_ecdsa_with_SHA384:
        p.sigalgo = QCA::EMSA3_SHA384;
        break;
    case NID_ecdsa_with_SHA256:
        p.sigalgo = QCA::EMSA3_SHA256;
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
    // printf("[%p] made props: [%s]\n", this, qPrintable(_props.subject[CommonName].value()));
}

X509Item::X509Item()
{
    cert = nullptr;
    req  = nullptr;
    crl  = nullptr;
}

X509Item::X509Item(const X509Item &from)
{
    cert  = nullptr;
    req   = nullptr;
    crl   = nullptr;
    *this = from;
}

X509Item::~X509Item() { reset(); }

X509Item &X509Item::operator=(const X509Item &from)
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

void X509Item::reset()
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

bool X509Item::isNull() const { return (!cert && !req && !crl); }

QByteArray X509Item::toDER() const
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

QString X509Item::toPEM() const
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

ConvertResult X509Item::fromDER(const QByteArray &in, X509Item::Type t)
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

ConvertResult X509Item::fromPEM(const QString &s, X509Item::Type t)
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

Validity MyCertContext::validate(const QList<CertContext *> &trusted, const QList<CertContext *> &untrusted,
                                 const QList<CRLContext *> &crls, UsageMode u, ValidateFlags vf) const
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

Validity MyCertContext::validate_chain(const QList<CertContext *> &chain, const QList<CertContext *> &trusted,
                                       const QList<CRLContext *> &crls, UsageMode u, ValidateFlags vf) const
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

// ---------------------------------------------------------------------
// MyCRLContext
// ---------------------------------------------------------------------
MyCRLContext::MyCRLContext(Provider *p) : CRLContext(p) { }

MyCRLContext::MyCRLContext(const MyCRLContext &from) : CRLContext(from), item(from.item) { }

Provider::Context *MyCRLContext::clone() const { return new MyCRLContext(*this); }

QByteArray MyCRLContext::toDER() const { return item.toDER(); }

QString MyCRLContext::toPEM() const { return item.toPEM(); }

ConvertResult MyCRLContext::fromDER(const QByteArray &a)
{
    _props          = CRLContextProps();
    ConvertResult r = item.fromDER(a, X509Item::TypeCRL);
    if (r == ConvertGood)
        make_props();
    return r;
}

ConvertResult MyCRLContext::fromPEM(const QString &s)
{
    ConvertResult r = item.fromPEM(s, X509Item::TypeCRL);
    if (r == ConvertGood)
        make_props();
    return r;
}

void MyCRLContext::fromX509(X509_CRL *x)
{
    X509_CRL_up_ref(x);
    item.crl = x;
    make_props();
}

const CRLContextProps *MyCRLContext::props() const { return &_props; }

bool MyCRLContext::compare(const CRLContext *other) const
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

void MyCRLContext::make_props()
{
    X509_CRL *x = item.crl;

    CRLContextProps p;

    CertificateInfo issuer;

    issuer = get_cert_name(X509_CRL_get_issuer(x));

    p.thisUpdate = ASN1_UTCTIME_QDateTime(X509_CRL_get0_lastUpdate(x));
    p.nextUpdate = ASN1_UTCTIME_QDateTime(X509_CRL_get0_nextUpdate(x));

    STACK_OF(X509_REVOKED) *revokeStack = X509_CRL_get_REVOKED(x);

    for (int i = 0; i < sk_X509_REVOKED_num(revokeStack); ++i) {
        X509_REVOKED *        rev    = sk_X509_REVOKED_value(revokeStack, i);
        BigInteger            serial = bn2bi_free(ASN1_INTEGER_to_BN(X509_REVOKED_get0_serialNumber(rev), nullptr));
        QDateTime             time   = ASN1_UTCTIME_QDateTime(X509_REVOKED_get0_revocationDate(rev));
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

//----------------------------------------------------------------------------
// MyCAContext
//----------------------------------------------------------------------------
MyCAContext::MyCAContext(Provider *p) : CAContext(p) { privateKey = nullptr; }

MyCAContext::MyCAContext(const MyCAContext &from) : CAContext(from), caCert(from.caCert)
{
    privateKey = static_cast<MyPKeyContext *>(from.privateKey->clone());
}

MyCAContext::~MyCAContext() { delete privateKey; }

CertContext *MyCAContext::certificate() const
{
    MyCertContext *cert = new MyCertContext(provider());

    cert->fromX509(caCert.cert);
    return cert;
}

CertContext *MyCAContext::createCertificate(const PKeyContext &pub, const CertificateOptions &opts) const
{
    // TODO: implement
    Q_UNUSED(pub)
    Q_UNUSED(opts)
    return nullptr;
}

CRLContext *MyCAContext::createCRL(const QDateTime &nextUpdate) const
{
    // TODO: implement
    Q_UNUSED(nextUpdate)
    return nullptr;
}

void MyCAContext::setup(const CertContext &cert, const PKeyContext &priv)
{
    caCert = static_cast<const MyCertContext &>(cert).item;
    delete privateKey;
    privateKey = nullptr;
    privateKey = static_cast<MyPKeyContext *>(priv.clone());
}

CertContext *MyCAContext::signRequest(const CSRContext &req, const QDateTime &notValidAfter) const
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
    ASN1_TIME_set(X509_get_notBefore(x), QDateTime::currentDateTimeUtc().toTime_t());
    ASN1_TIME_set(X509_get_notAfter(x), notValidAfter.toTime_t());

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

CRLContext *MyCAContext::updateCRL(const CRLContext &crl, const QList<CRLEntry> &entries,
                                   const QDateTime &nextUpdate) const
{
    // TODO: implement
    Q_UNUSED(crl)
    Q_UNUSED(entries)
    Q_UNUSED(nextUpdate)
    return nullptr;
}

Provider::Context *MyCAContext::clone() const { return new MyCAContext(*this); }

//----------------------------------------------------------------------------
// MyCSRContext
//----------------------------------------------------------------------------
MyCSRContext::MyCSRContext(Provider *p) : CSRContext(p) { }

MyCSRContext::MyCSRContext(const MyCSRContext &from) : CSRContext(from), item(from.item), _props(from._props) { }

Provider::Context *MyCSRContext::clone() const { return new MyCSRContext(*this); }

QByteArray MyCSRContext::toDER() const { return item.toDER(); }

QString MyCSRContext::toPEM() const { return item.toPEM(); }

ConvertResult MyCSRContext::fromDER(const QByteArray &a)
{
    _props          = CertContextProps();
    ConvertResult r = item.fromDER(a, X509Item::TypeReq);
    if (r == ConvertGood)
        make_props();
    return r;
}

ConvertResult MyCSRContext::fromPEM(const QString &s)
{
    _props          = CertContextProps();
    ConvertResult r = item.fromPEM(s, X509Item::TypeReq);
    if (r == ConvertGood)
        make_props();
    return r;
}

bool MyCSRContext::canUseFormat(CertificateRequestFormat f) const
{
    if (f == PKCS10)
        return true;
    return false;
}

bool MyCSRContext::createRequest(const CertificateOptions &opts, const PKeyContext &priv)
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
        X509_REQ_add1_attr_by_NID(x, NID_pkcs9_challengePassword, MBSTRING_UTF8, (const unsigned char *)cs.data(), -1);

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

const CertContextProps *MyCSRContext::props() const { return &_props; }

bool MyCSRContext::compare(const CSRContext *other) const
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

PKeyContext *MyCSRContext::subjectPublicKey() const // does a new
{
    MyPKeyContext *kc   = new MyPKeyContext(provider());
    EVP_PKEY *     pkey = X509_REQ_get_pubkey(item.req);
    PKeyBase *     kb   = kc->pkeyToBase(pkey, false);
    kc->setKey(kb);
    return kc;
}

QString MyCSRContext::toSPKAC() const { return QString(); }

ConvertResult MyCSRContext::fromSPKAC(const QString &s)
{
    Q_UNUSED(s);
    return ErrorDecode;
}

void MyCSRContext::make_props()
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

}
