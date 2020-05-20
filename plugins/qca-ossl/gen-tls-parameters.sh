#!/usr/bin/env bash

# Copyright (C) 2020  Ivan Romanov <drizt72@zoho.eu>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA

src="$PWD/$1"
cd $(dirname "$0")

if [ -z "$1" ]; then
    echo "Usage gen-tls-parameters.sh tls-parameters.csv"
    echo ""
    echo "tls-parameters.csv can be downloaded from https://www.iana.org/assignments/tls-parameters/"
    echo "in TLS Cipher Suites section."
    exit 0
fi

regex_tls_1_3='RFC8446|RFC8492|RFC8701'

ciphers="$(cat $src |
    grep -e '^"0x[0-9A-F]\{2\},0x[0-9A-F]\{2\}"' |
    sed -e '/^"0x[0-9A-F]\{2\},0x[0-9A-F]\{2\}",\(Reserved\|Unassigned\)/d' |
    sed -e 's/^"0x\([0-9A-F]\{2\}\),0x\([0-9A-F]\{2\}\)",\([^,]\+\),[YN],[YN],\[\(.*\)]\r\?$/\tcase 0x\1\2: return QS("\3"); \/\/ \4/' |
    sed -e 's/]\[/ /g')"

file=tls-parameters.cpp

cat > $file <<EOF
/*
 * Copyright (C) `date +"%Y"`
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

#include "qca_securelayer.h"

#include <QString>

#define QS(str) QStringLiteral(str)

namespace opensslQCAPlugin {

QString cipherIdToStringTLS1_3(unsigned long cipherID)
{
	switch (cipherID & 0xFFFF) {
$(echo "$ciphers" | grep -E "$regex_tls_1_3")
	default: return QS("TLS 1.3 algo to be added: 0x%1").arg(cipherID & 0xffff, 0, 16);
	}
}

QString cipherIdToStringTLS(const QCA::TLS::Version version, unsigned long cipherID)
{
	if (QCA::TLS::TLS_v1_3 == version) {
		return cipherIdToStringTLS1_3(cipherID);
	}
	switch (cipherID & 0xFFFF) {
$(echo "$ciphers" | grep -vE "$regex_tls_1_3")
	default: return QS("TLS algo to be added: 0x%1").arg(cipherID & 0xffff, 0, 16);
	}
}

}
EOF
