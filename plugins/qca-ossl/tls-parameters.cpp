/*
 * Copyright (C) 2020
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

#include <QString>

#define QS(str) QStringLiteral(str)

namespace opensslQCAPlugin {

QString tlsCipherIdToString(unsigned long cipherID)
{
	switch (cipherID & 0xFFFF) {
	case 0x0000: return QS("TLS_NULL_WITH_NULL_NULL"); break; // RFC5246
	case 0x0001: return QS("TLS_RSA_WITH_NULL_MD5"); break; // RFC5246
	case 0x0002: return QS("TLS_RSA_WITH_NULL_SHA"); break; // RFC5246
	case 0x0003: return QS("TLS_RSA_EXPORT_WITH_RC4_40_MD5"); break; // RFC4346 RFC6347
	case 0x0004: return QS("TLS_RSA_WITH_RC4_128_MD5"); break; // RFC5246 RFC6347
	case 0x0005: return QS("TLS_RSA_WITH_RC4_128_SHA"); break; // RFC5246 RFC6347
	case 0x0006: return QS("TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"); break; // RFC4346
	case 0x0007: return QS("TLS_RSA_WITH_IDEA_CBC_SHA"); break; // RFC5469
	case 0x0008: return QS("TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"); break; // RFC4346
	case 0x0009: return QS("TLS_RSA_WITH_DES_CBC_SHA"); break; // RFC5469
	case 0x000A: return QS("TLS_RSA_WITH_3DES_EDE_CBC_SHA"); break; // RFC5246
	case 0x000B: return QS("TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA"); break; // RFC4346
	case 0x000C: return QS("TLS_DH_DSS_WITH_DES_CBC_SHA"); break; // RFC5469
	case 0x000D: return QS("TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA"); break; // RFC5246
	case 0x000E: return QS("TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA"); break; // RFC4346
	case 0x000F: return QS("TLS_DH_RSA_WITH_DES_CBC_SHA"); break; // RFC5469
	case 0x0010: return QS("TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA"); break; // RFC5246
	case 0x0011: return QS("TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"); break; // RFC4346
	case 0x0012: return QS("TLS_DHE_DSS_WITH_DES_CBC_SHA"); break; // RFC5469
	case 0x0013: return QS("TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"); break; // RFC5246
	case 0x0014: return QS("TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"); break; // RFC4346
	case 0x0015: return QS("TLS_DHE_RSA_WITH_DES_CBC_SHA"); break; // RFC5469
	case 0x0016: return QS("TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"); break; // RFC5246
	case 0x0017: return QS("TLS_DH_anon_EXPORT_WITH_RC4_40_MD5"); break; // RFC4346 RFC6347
	case 0x0018: return QS("TLS_DH_anon_WITH_RC4_128_MD5"); break; // RFC5246 RFC6347
	case 0x0019: return QS("TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA"); break; // RFC4346
	case 0x001A: return QS("TLS_DH_anon_WITH_DES_CBC_SHA"); break; // RFC5469
	case 0x001B: return QS("TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"); break; // RFC5246
	case 0x001E: return QS("TLS_KRB5_WITH_DES_CBC_SHA"); break; // RFC2712
	case 0x001F: return QS("TLS_KRB5_WITH_3DES_EDE_CBC_SHA"); break; // RFC2712
	case 0x0020: return QS("TLS_KRB5_WITH_RC4_128_SHA"); break; // RFC2712 RFC6347
	case 0x0021: return QS("TLS_KRB5_WITH_IDEA_CBC_SHA"); break; // RFC2712
	case 0x0022: return QS("TLS_KRB5_WITH_DES_CBC_MD5"); break; // RFC2712
	case 0x0023: return QS("TLS_KRB5_WITH_3DES_EDE_CBC_MD5"); break; // RFC2712
	case 0x0024: return QS("TLS_KRB5_WITH_RC4_128_MD5"); break; // RFC2712 RFC6347
	case 0x0025: return QS("TLS_KRB5_WITH_IDEA_CBC_MD5"); break; // RFC2712
	case 0x0026: return QS("TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA"); break; // RFC2712
	case 0x0027: return QS("TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA"); break; // RFC2712
	case 0x0028: return QS("TLS_KRB5_EXPORT_WITH_RC4_40_SHA"); break; // RFC2712 RFC6347
	case 0x0029: return QS("TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5"); break; // RFC2712
	case 0x002A: return QS("TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5"); break; // RFC2712
	case 0x002B: return QS("TLS_KRB5_EXPORT_WITH_RC4_40_MD5"); break; // RFC2712 RFC6347
	case 0x002C: return QS("TLS_PSK_WITH_NULL_SHA"); break; // RFC4785
	case 0x002D: return QS("TLS_DHE_PSK_WITH_NULL_SHA"); break; // RFC4785
	case 0x002E: return QS("TLS_RSA_PSK_WITH_NULL_SHA"); break; // RFC4785
	case 0x002F: return QS("TLS_RSA_WITH_AES_128_CBC_SHA"); break; // RFC5246
	case 0x0030: return QS("TLS_DH_DSS_WITH_AES_128_CBC_SHA"); break; // RFC5246
	case 0x0031: return QS("TLS_DH_RSA_WITH_AES_128_CBC_SHA"); break; // RFC5246
	case 0x0032: return QS("TLS_DHE_DSS_WITH_AES_128_CBC_SHA"); break; // RFC5246
	case 0x0033: return QS("TLS_DHE_RSA_WITH_AES_128_CBC_SHA"); break; // RFC5246
	case 0x0034: return QS("TLS_DH_anon_WITH_AES_128_CBC_SHA"); break; // RFC5246
	case 0x0035: return QS("TLS_RSA_WITH_AES_256_CBC_SHA"); break; // RFC5246
	case 0x0036: return QS("TLS_DH_DSS_WITH_AES_256_CBC_SHA"); break; // RFC5246
	case 0x0037: return QS("TLS_DH_RSA_WITH_AES_256_CBC_SHA"); break; // RFC5246
	case 0x0038: return QS("TLS_DHE_DSS_WITH_AES_256_CBC_SHA"); break; // RFC5246
	case 0x0039: return QS("TLS_DHE_RSA_WITH_AES_256_CBC_SHA"); break; // RFC5246
	case 0x003A: return QS("TLS_DH_anon_WITH_AES_256_CBC_SHA"); break; // RFC5246
	case 0x003B: return QS("TLS_RSA_WITH_NULL_SHA256"); break; // RFC5246
	case 0x003C: return QS("TLS_RSA_WITH_AES_128_CBC_SHA256"); break; // RFC5246
	case 0x003D: return QS("TLS_RSA_WITH_AES_256_CBC_SHA256"); break; // RFC5246
	case 0x003E: return QS("TLS_DH_DSS_WITH_AES_128_CBC_SHA256"); break; // RFC5246
	case 0x003F: return QS("TLS_DH_RSA_WITH_AES_128_CBC_SHA256"); break; // RFC5246
	case 0x0040: return QS("TLS_DHE_DSS_WITH_AES_128_CBC_SHA256"); break; // RFC5246
	case 0x0041: return QS("TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"); break; // RFC5932
	case 0x0042: return QS("TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA"); break; // RFC5932
	case 0x0043: return QS("TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA"); break; // RFC5932
	case 0x0044: return QS("TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA"); break; // RFC5932
	case 0x0045: return QS("TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA"); break; // RFC5932
	case 0x0046: return QS("TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA"); break; // RFC5932
	case 0x0067: return QS("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"); break; // RFC5246
	case 0x0068: return QS("TLS_DH_DSS_WITH_AES_256_CBC_SHA256"); break; // RFC5246
	case 0x0069: return QS("TLS_DH_RSA_WITH_AES_256_CBC_SHA256"); break; // RFC5246
	case 0x006A: return QS("TLS_DHE_DSS_WITH_AES_256_CBC_SHA256"); break; // RFC5246
	case 0x006B: return QS("TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"); break; // RFC5246
	case 0x006C: return QS("TLS_DH_anon_WITH_AES_128_CBC_SHA256"); break; // RFC5246
	case 0x006D: return QS("TLS_DH_anon_WITH_AES_256_CBC_SHA256"); break; // RFC5246
	case 0x0084: return QS("TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"); break; // RFC5932
	case 0x0085: return QS("TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA"); break; // RFC5932
	case 0x0086: return QS("TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA"); break; // RFC5932
	case 0x0087: return QS("TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA"); break; // RFC5932
	case 0x0088: return QS("TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA"); break; // RFC5932
	case 0x0089: return QS("TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA"); break; // RFC5932
	case 0x008A: return QS("TLS_PSK_WITH_RC4_128_SHA"); break; // RFC4279 RFC6347
	case 0x008B: return QS("TLS_PSK_WITH_3DES_EDE_CBC_SHA"); break; // RFC4279
	case 0x008C: return QS("TLS_PSK_WITH_AES_128_CBC_SHA"); break; // RFC4279
	case 0x008D: return QS("TLS_PSK_WITH_AES_256_CBC_SHA"); break; // RFC4279
	case 0x008E: return QS("TLS_DHE_PSK_WITH_RC4_128_SHA"); break; // RFC4279 RFC6347
	case 0x008F: return QS("TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA"); break; // RFC4279
	case 0x0090: return QS("TLS_DHE_PSK_WITH_AES_128_CBC_SHA"); break; // RFC4279
	case 0x0091: return QS("TLS_DHE_PSK_WITH_AES_256_CBC_SHA"); break; // RFC4279
	case 0x0092: return QS("TLS_RSA_PSK_WITH_RC4_128_SHA"); break; // RFC4279 RFC6347
	case 0x0093: return QS("TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA"); break; // RFC4279
	case 0x0094: return QS("TLS_RSA_PSK_WITH_AES_128_CBC_SHA"); break; // RFC4279
	case 0x0095: return QS("TLS_RSA_PSK_WITH_AES_256_CBC_SHA"); break; // RFC4279
	case 0x0096: return QS("TLS_RSA_WITH_SEED_CBC_SHA"); break; // RFC4162
	case 0x0097: return QS("TLS_DH_DSS_WITH_SEED_CBC_SHA"); break; // RFC4162
	case 0x0098: return QS("TLS_DH_RSA_WITH_SEED_CBC_SHA"); break; // RFC4162
	case 0x0099: return QS("TLS_DHE_DSS_WITH_SEED_CBC_SHA"); break; // RFC4162
	case 0x009A: return QS("TLS_DHE_RSA_WITH_SEED_CBC_SHA"); break; // RFC4162
	case 0x009B: return QS("TLS_DH_anon_WITH_SEED_CBC_SHA"); break; // RFC4162
	case 0x009C: return QS("TLS_RSA_WITH_AES_128_GCM_SHA256"); break; // RFC5288
	case 0x009D: return QS("TLS_RSA_WITH_AES_256_GCM_SHA384"); break; // RFC5288
	case 0x009E: return QS("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"); break; // RFC5288
	case 0x009F: return QS("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"); break; // RFC5288
	case 0x00A0: return QS("TLS_DH_RSA_WITH_AES_128_GCM_SHA256"); break; // RFC5288
	case 0x00A1: return QS("TLS_DH_RSA_WITH_AES_256_GCM_SHA384"); break; // RFC5288
	case 0x00A2: return QS("TLS_DHE_DSS_WITH_AES_128_GCM_SHA256"); break; // RFC5288
	case 0x00A3: return QS("TLS_DHE_DSS_WITH_AES_256_GCM_SHA384"); break; // RFC5288
	case 0x00A4: return QS("TLS_DH_DSS_WITH_AES_128_GCM_SHA256"); break; // RFC5288
	case 0x00A5: return QS("TLS_DH_DSS_WITH_AES_256_GCM_SHA384"); break; // RFC5288
	case 0x00A6: return QS("TLS_DH_anon_WITH_AES_128_GCM_SHA256"); break; // RFC5288
	case 0x00A7: return QS("TLS_DH_anon_WITH_AES_256_GCM_SHA384"); break; // RFC5288
	case 0x00A8: return QS("TLS_PSK_WITH_AES_128_GCM_SHA256"); break; // RFC5487
	case 0x00A9: return QS("TLS_PSK_WITH_AES_256_GCM_SHA384"); break; // RFC5487
	case 0x00AA: return QS("TLS_DHE_PSK_WITH_AES_128_GCM_SHA256"); break; // RFC5487
	case 0x00AB: return QS("TLS_DHE_PSK_WITH_AES_256_GCM_SHA384"); break; // RFC5487
	case 0x00AC: return QS("TLS_RSA_PSK_WITH_AES_128_GCM_SHA256"); break; // RFC5487
	case 0x00AD: return QS("TLS_RSA_PSK_WITH_AES_256_GCM_SHA384"); break; // RFC5487
	case 0x00AE: return QS("TLS_PSK_WITH_AES_128_CBC_SHA256"); break; // RFC5487
	case 0x00AF: return QS("TLS_PSK_WITH_AES_256_CBC_SHA384"); break; // RFC5487
	case 0x00B0: return QS("TLS_PSK_WITH_NULL_SHA256"); break; // RFC5487
	case 0x00B1: return QS("TLS_PSK_WITH_NULL_SHA384"); break; // RFC5487
	case 0x00B2: return QS("TLS_DHE_PSK_WITH_AES_128_CBC_SHA256"); break; // RFC5487
	case 0x00B3: return QS("TLS_DHE_PSK_WITH_AES_256_CBC_SHA384"); break; // RFC5487
	case 0x00B4: return QS("TLS_DHE_PSK_WITH_NULL_SHA256"); break; // RFC5487
	case 0x00B5: return QS("TLS_DHE_PSK_WITH_NULL_SHA384"); break; // RFC5487
	case 0x00B6: return QS("TLS_RSA_PSK_WITH_AES_128_CBC_SHA256"); break; // RFC5487
	case 0x00B7: return QS("TLS_RSA_PSK_WITH_AES_256_CBC_SHA384"); break; // RFC5487
	case 0x00B8: return QS("TLS_RSA_PSK_WITH_NULL_SHA256"); break; // RFC5487
	case 0x00B9: return QS("TLS_RSA_PSK_WITH_NULL_SHA384"); break; // RFC5487
	case 0x00BA: return QS("TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256"); break; // RFC5932
	case 0x00BB: return QS("TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256"); break; // RFC5932
	case 0x00BC: return QS("TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256"); break; // RFC5932
	case 0x00BD: return QS("TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256"); break; // RFC5932
	case 0x00BE: return QS("TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"); break; // RFC5932
	case 0x00BF: return QS("TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256"); break; // RFC5932
	case 0x00C0: return QS("TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256"); break; // RFC5932
	case 0x00C1: return QS("TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256"); break; // RFC5932
	case 0x00C2: return QS("TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256"); break; // RFC5932
	case 0x00C3: return QS("TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256"); break; // RFC5932
	case 0x00C4: return QS("TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256"); break; // RFC5932
	case 0x00C5: return QS("TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256"); break; // RFC5932
	case 0x00C6: return QS("TLS_SM4_GCM_SM3"); break; // draft-yang-tls-tls13-sm-suites
	case 0x00C7: return QS("TLS_SM4_CCM_SM3"); break; // draft-yang-tls-tls13-sm-suites
	case 0x00FF: return QS("TLS_EMPTY_RENEGOTIATION_INFO_SCSV"); break; // RFC5746
	case 0x1301: return QS("TLS_AES_128_GCM_SHA256"); break; // RFC8446
	case 0x1302: return QS("TLS_AES_256_GCM_SHA384"); break; // RFC8446
	case 0x1303: return QS("TLS_CHACHA20_POLY1305_SHA256"); break; // RFC8446
	case 0x1304: return QS("TLS_AES_128_CCM_SHA256"); break; // RFC8446
	case 0x1305: return QS("TLS_AES_128_CCM_8_SHA256"); break; // RFC8446 IESG Action 2018-08-16
	case 0x5600: return QS("TLS_FALLBACK_SCSV"); break; // RFC7507
	case 0xC001: return QS("TLS_ECDH_ECDSA_WITH_NULL_SHA"); break; // RFC8422
	case 0xC002: return QS("TLS_ECDH_ECDSA_WITH_RC4_128_SHA"); break; // RFC8422 RFC6347
	case 0xC003: return QS("TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"); break; // RFC8422
	case 0xC004: return QS("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA"); break; // RFC8422
	case 0xC005: return QS("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA"); break; // RFC8422
	case 0xC006: return QS("TLS_ECDHE_ECDSA_WITH_NULL_SHA"); break; // RFC8422
	case 0xC007: return QS("TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"); break; // RFC8422 RFC6347
	case 0xC008: return QS("TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"); break; // RFC8422
	case 0xC009: return QS("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"); break; // RFC8422
	case 0xC00A: return QS("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"); break; // RFC8422
	case 0xC00B: return QS("TLS_ECDH_RSA_WITH_NULL_SHA"); break; // RFC8422
	case 0xC00C: return QS("TLS_ECDH_RSA_WITH_RC4_128_SHA"); break; // RFC8422 RFC6347
	case 0xC00D: return QS("TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA"); break; // RFC8422
	case 0xC00E: return QS("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA"); break; // RFC8422
	case 0xC00F: return QS("TLS_ECDH_RSA_WITH_AES_256_CBC_SHA"); break; // RFC8422
	case 0xC010: return QS("TLS_ECDHE_RSA_WITH_NULL_SHA"); break; // RFC8422
	case 0xC011: return QS("TLS_ECDHE_RSA_WITH_RC4_128_SHA"); break; // RFC8422 RFC6347
	case 0xC012: return QS("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"); break; // RFC8422
	case 0xC013: return QS("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"); break; // RFC8422
	case 0xC014: return QS("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"); break; // RFC8422
	case 0xC015: return QS("TLS_ECDH_anon_WITH_NULL_SHA"); break; // RFC8422
	case 0xC016: return QS("TLS_ECDH_anon_WITH_RC4_128_SHA"); break; // RFC8422 RFC6347
	case 0xC017: return QS("TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA"); break; // RFC8422
	case 0xC018: return QS("TLS_ECDH_anon_WITH_AES_128_CBC_SHA"); break; // RFC8422
	case 0xC019: return QS("TLS_ECDH_anon_WITH_AES_256_CBC_SHA"); break; // RFC8422
	case 0xC01A: return QS("TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA"); break; // RFC5054
	case 0xC01B: return QS("TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA"); break; // RFC5054
	case 0xC01C: return QS("TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA"); break; // RFC5054
	case 0xC01D: return QS("TLS_SRP_SHA_WITH_AES_128_CBC_SHA"); break; // RFC5054
	case 0xC01E: return QS("TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA"); break; // RFC5054
	case 0xC01F: return QS("TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA"); break; // RFC5054
	case 0xC020: return QS("TLS_SRP_SHA_WITH_AES_256_CBC_SHA"); break; // RFC5054
	case 0xC021: return QS("TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA"); break; // RFC5054
	case 0xC022: return QS("TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA"); break; // RFC5054
	case 0xC023: return QS("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"); break; // RFC5289
	case 0xC024: return QS("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"); break; // RFC5289
	case 0xC025: return QS("TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256"); break; // RFC5289
	case 0xC026: return QS("TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"); break; // RFC5289
	case 0xC027: return QS("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"); break; // RFC5289
	case 0xC028: return QS("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"); break; // RFC5289
	case 0xC029: return QS("TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256"); break; // RFC5289
	case 0xC02A: return QS("TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384"); break; // RFC5289
	case 0xC02B: return QS("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"); break; // RFC5289
	case 0xC02C: return QS("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"); break; // RFC5289
	case 0xC02D: return QS("TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256"); break; // RFC5289
	case 0xC02E: return QS("TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"); break; // RFC5289
	case 0xC02F: return QS("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"); break; // RFC5289
	case 0xC030: return QS("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"); break; // RFC5289
	case 0xC031: return QS("TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256"); break; // RFC5289
	case 0xC032: return QS("TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"); break; // RFC5289
	case 0xC033: return QS("TLS_ECDHE_PSK_WITH_RC4_128_SHA"); break; // RFC5489 RFC6347
	case 0xC034: return QS("TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA"); break; // RFC5489
	case 0xC035: return QS("TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA"); break; // RFC5489
	case 0xC036: return QS("TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA"); break; // RFC5489
	case 0xC037: return QS("TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256"); break; // RFC5489
	case 0xC038: return QS("TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384"); break; // RFC5489
	case 0xC039: return QS("TLS_ECDHE_PSK_WITH_NULL_SHA"); break; // RFC5489
	case 0xC03A: return QS("TLS_ECDHE_PSK_WITH_NULL_SHA256"); break; // RFC5489
	case 0xC03B: return QS("TLS_ECDHE_PSK_WITH_NULL_SHA384"); break; // RFC5489
	case 0xC03C: return QS("TLS_RSA_WITH_ARIA_128_CBC_SHA256"); break; // RFC6209
	case 0xC03D: return QS("TLS_RSA_WITH_ARIA_256_CBC_SHA384"); break; // RFC6209
	case 0xC03E: return QS("TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256"); break; // RFC6209
	case 0xC03F: return QS("TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384"); break; // RFC6209
	case 0xC040: return QS("TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256"); break; // RFC6209
	case 0xC041: return QS("TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384"); break; // RFC6209
	case 0xC042: return QS("TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256"); break; // RFC6209
	case 0xC043: return QS("TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384"); break; // RFC6209
	case 0xC044: return QS("TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256"); break; // RFC6209
	case 0xC045: return QS("TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384"); break; // RFC6209
	case 0xC046: return QS("TLS_DH_anon_WITH_ARIA_128_CBC_SHA256"); break; // RFC6209
	case 0xC047: return QS("TLS_DH_anon_WITH_ARIA_256_CBC_SHA384"); break; // RFC6209
	case 0xC048: return QS("TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256"); break; // RFC6209
	case 0xC049: return QS("TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384"); break; // RFC6209
	case 0xC04A: return QS("TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256"); break; // RFC6209
	case 0xC04B: return QS("TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384"); break; // RFC6209
	case 0xC04C: return QS("TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256"); break; // RFC6209
	case 0xC04D: return QS("TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384"); break; // RFC6209
	case 0xC04E: return QS("TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256"); break; // RFC6209
	case 0xC04F: return QS("TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384"); break; // RFC6209
	case 0xC050: return QS("TLS_RSA_WITH_ARIA_128_GCM_SHA256"); break; // RFC6209
	case 0xC051: return QS("TLS_RSA_WITH_ARIA_256_GCM_SHA384"); break; // RFC6209
	case 0xC052: return QS("TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256"); break; // RFC6209
	case 0xC053: return QS("TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384"); break; // RFC6209
	case 0xC054: return QS("TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256"); break; // RFC6209
	case 0xC055: return QS("TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384"); break; // RFC6209
	case 0xC056: return QS("TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256"); break; // RFC6209
	case 0xC057: return QS("TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384"); break; // RFC6209
	case 0xC058: return QS("TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256"); break; // RFC6209
	case 0xC059: return QS("TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384"); break; // RFC6209
	case 0xC05A: return QS("TLS_DH_anon_WITH_ARIA_128_GCM_SHA256"); break; // RFC6209
	case 0xC05B: return QS("TLS_DH_anon_WITH_ARIA_256_GCM_SHA384"); break; // RFC6209
	case 0xC05C: return QS("TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256"); break; // RFC6209
	case 0xC05D: return QS("TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384"); break; // RFC6209
	case 0xC05E: return QS("TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256"); break; // RFC6209
	case 0xC05F: return QS("TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384"); break; // RFC6209
	case 0xC060: return QS("TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256"); break; // RFC6209
	case 0xC061: return QS("TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384"); break; // RFC6209
	case 0xC062: return QS("TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256"); break; // RFC6209
	case 0xC063: return QS("TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384"); break; // RFC6209
	case 0xC064: return QS("TLS_PSK_WITH_ARIA_128_CBC_SHA256"); break; // RFC6209
	case 0xC065: return QS("TLS_PSK_WITH_ARIA_256_CBC_SHA384"); break; // RFC6209
	case 0xC066: return QS("TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256"); break; // RFC6209
	case 0xC067: return QS("TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384"); break; // RFC6209
	case 0xC068: return QS("TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256"); break; // RFC6209
	case 0xC069: return QS("TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384"); break; // RFC6209
	case 0xC06A: return QS("TLS_PSK_WITH_ARIA_128_GCM_SHA256"); break; // RFC6209
	case 0xC06B: return QS("TLS_PSK_WITH_ARIA_256_GCM_SHA384"); break; // RFC6209
	case 0xC06C: return QS("TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256"); break; // RFC6209
	case 0xC06D: return QS("TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384"); break; // RFC6209
	case 0xC06E: return QS("TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256"); break; // RFC6209
	case 0xC06F: return QS("TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384"); break; // RFC6209
	case 0xC070: return QS("TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256"); break; // RFC6209
	case 0xC071: return QS("TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384"); break; // RFC6209
	case 0xC072: return QS("TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"); break; // RFC6367
	case 0xC073: return QS("TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"); break; // RFC6367
	case 0xC074: return QS("TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256"); break; // RFC6367
	case 0xC075: return QS("TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384"); break; // RFC6367
	case 0xC076: return QS("TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256"); break; // RFC6367
	case 0xC077: return QS("TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384"); break; // RFC6367
	case 0xC078: return QS("TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256"); break; // RFC6367
	case 0xC079: return QS("TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384"); break; // RFC6367
	case 0xC07A: return QS("TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256"); break; // RFC6367
	case 0xC07B: return QS("TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384"); break; // RFC6367
	case 0xC07C: return QS("TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256"); break; // RFC6367
	case 0xC07D: return QS("TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384"); break; // RFC6367
	case 0xC07E: return QS("TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256"); break; // RFC6367
	case 0xC07F: return QS("TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384"); break; // RFC6367
	case 0xC080: return QS("TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256"); break; // RFC6367
	case 0xC081: return QS("TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384"); break; // RFC6367
	case 0xC082: return QS("TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256"); break; // RFC6367
	case 0xC083: return QS("TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384"); break; // RFC6367
	case 0xC084: return QS("TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256"); break; // RFC6367
	case 0xC085: return QS("TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384"); break; // RFC6367
	case 0xC086: return QS("TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256"); break; // RFC6367
	case 0xC087: return QS("TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384"); break; // RFC6367
	case 0xC088: return QS("TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256"); break; // RFC6367
	case 0xC089: return QS("TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384"); break; // RFC6367
	case 0xC08A: return QS("TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256"); break; // RFC6367
	case 0xC08B: return QS("TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384"); break; // RFC6367
	case 0xC08C: return QS("TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256"); break; // RFC6367
	case 0xC08D: return QS("TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384"); break; // RFC6367
	case 0xC08E: return QS("TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256"); break; // RFC6367
	case 0xC08F: return QS("TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384"); break; // RFC6367
	case 0xC090: return QS("TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256"); break; // RFC6367
	case 0xC091: return QS("TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384"); break; // RFC6367
	case 0xC092: return QS("TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256"); break; // RFC6367
	case 0xC093: return QS("TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384"); break; // RFC6367
	case 0xC094: return QS("TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256"); break; // RFC6367
	case 0xC095: return QS("TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384"); break; // RFC6367
	case 0xC096: return QS("TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"); break; // RFC6367
	case 0xC097: return QS("TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"); break; // RFC6367
	case 0xC098: return QS("TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256"); break; // RFC6367
	case 0xC099: return QS("TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384"); break; // RFC6367
	case 0xC09A: return QS("TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256"); break; // RFC6367
	case 0xC09B: return QS("TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384"); break; // RFC6367
	case 0xC09C: return QS("TLS_RSA_WITH_AES_128_CCM"); break; // RFC6655
	case 0xC09D: return QS("TLS_RSA_WITH_AES_256_CCM"); break; // RFC6655
	case 0xC09E: return QS("TLS_DHE_RSA_WITH_AES_128_CCM"); break; // RFC6655
	case 0xC09F: return QS("TLS_DHE_RSA_WITH_AES_256_CCM"); break; // RFC6655
	case 0xC0A0: return QS("TLS_RSA_WITH_AES_128_CCM_8"); break; // RFC6655
	case 0xC0A1: return QS("TLS_RSA_WITH_AES_256_CCM_8"); break; // RFC6655
	case 0xC0A2: return QS("TLS_DHE_RSA_WITH_AES_128_CCM_8"); break; // RFC6655
	case 0xC0A3: return QS("TLS_DHE_RSA_WITH_AES_256_CCM_8"); break; // RFC6655
	case 0xC0A4: return QS("TLS_PSK_WITH_AES_128_CCM"); break; // RFC6655
	case 0xC0A5: return QS("TLS_PSK_WITH_AES_256_CCM"); break; // RFC6655
	case 0xC0A6: return QS("TLS_DHE_PSK_WITH_AES_128_CCM"); break; // RFC6655
	case 0xC0A7: return QS("TLS_DHE_PSK_WITH_AES_256_CCM"); break; // RFC6655
	case 0xC0A8: return QS("TLS_PSK_WITH_AES_128_CCM_8"); break; // RFC6655
	case 0xC0A9: return QS("TLS_PSK_WITH_AES_256_CCM_8"); break; // RFC6655
	case 0xC0AA: return QS("TLS_PSK_DHE_WITH_AES_128_CCM_8"); break; // RFC6655
	case 0xC0AB: return QS("TLS_PSK_DHE_WITH_AES_256_CCM_8"); break; // RFC6655
	case 0xC0AC: return QS("TLS_ECDHE_ECDSA_WITH_AES_128_CCM"); break; // RFC7251
	case 0xC0AD: return QS("TLS_ECDHE_ECDSA_WITH_AES_256_CCM"); break; // RFC7251
	case 0xC0AE: return QS("TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8"); break; // RFC7251
	case 0xC0AF: return QS("TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8"); break; // RFC7251
	case 0xC0B0: return QS("TLS_ECCPWD_WITH_AES_128_GCM_SHA256"); break; // RFC8492
	case 0xC0B1: return QS("TLS_ECCPWD_WITH_AES_256_GCM_SHA384"); break; // RFC8492
	case 0xC0B2: return QS("TLS_ECCPWD_WITH_AES_128_CCM_SHA256"); break; // RFC8492
	case 0xC0B3: return QS("TLS_ECCPWD_WITH_AES_256_CCM_SHA384"); break; // RFC8492
	case 0xC0B4: return QS("TLS_SHA256_SHA256"); break; // draft-camwinget-tls-ts13-macciphersuites
	case 0xC0B5: return QS("TLS_SHA384_SHA384"); break; // draft-camwinget-tls-ts13-macciphersuites
	case 0xC100: return QS("TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC"); break; // draft-smyshlyaev-tls12-gost-suites
	case 0xC101: return QS("TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC"); break; // draft-smyshlyaev-tls12-gost-suites
	case 0xC102: return QS("TLS_GOSTR341112_256_WITH_28147_CNT_IMIT"); break; // draft-smyshlyaev-tls12-gost-suites
	case 0xC103: return QS("TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L"); break; // draft-smyshlyaev-tls13-gost-suites
	case 0xC104: return QS("TLS_GOSTR341112_256_WITH_MAGMA_MGM_L"); break; // draft-smyshlyaev-tls13-gost-suites
	case 0xC105: return QS("TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S"); break; // draft-smyshlyaev-tls13-gost-suites
	case 0xC106: return QS("TLS_GOSTR341112_256_WITH_MAGMA_MGM_S"); break; // draft-smyshlyaev-tls13-gost-suites
	case 0xCCA8: return QS("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"); break; // RFC7905
	case 0xCCA9: return QS("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"); break; // RFC7905
	case 0xCCAA: return QS("TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"); break; // RFC7905
	case 0xCCAB: return QS("TLS_PSK_WITH_CHACHA20_POLY1305_SHA256"); break; // RFC7905
	case 0xCCAC: return QS("TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256"); break; // RFC7905
	case 0xCCAD: return QS("TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256"); break; // RFC7905
	case 0xCCAE: return QS("TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256"); break; // RFC7905
	case 0xD001: return QS("TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256"); break; // RFC8442
	case 0xD002: return QS("TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384"); break; // RFC8442
	case 0xD003: return QS("TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256"); break; // RFC8442
	case 0xD005: return QS("TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256"); break; // RFC8442
	default: return QS("TLS algo to be added: 0x%1").arg(cipherID & 0xffff, 0, 16); break;
	}
}

}
