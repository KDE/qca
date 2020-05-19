#!/usr/bin/bash

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

if [ -z "$1" ]; then
    echo "Usage gen-tls-parameters.sh tls-parameters.csv"
    echo ""
    echo "tls-parameters.csv can be downloaded from https://www.iana.org/assignments/tls-parameters/"
    echo "in TLS Cipher Suites section."
    exit 0
fi

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

#include <QString>

#define QS(str) QStringLiteral(str)

namespace opensslQCAPlugin {

QString tlsCipherIdToString(unsigned long cipherID)
{
	switch (cipherID & 0xFFFF) {
EOF

cat $1 | \
    grep -e '^"0x[0-9A-F]\{2\},0x[0-9A-F]\{2\}"' | \
    sed -e '/^"0x[0-9A-F]\{2\},0x[0-9A-F]\{2\}",\(Reserved\|Unassigned\)/d' | \
    sed -e 's/^"0x\([0-9A-F]\{2\}\),0x\([0-9A-F]\{2\}\)",\([^,]\+\),[YN],[YN],\[\(.*\)]\r\?$/\tcase 0x\1\2: return QS("\3"); break; \/\/ \4/' | \
    sed -e 's/]\[/ /g' >> $file

cat >> $file <<EOF
	default: return QS("TLS algo to be added: 0x%1").arg(cipherID & 0xffff, 0, 16); break;
	}
}

}
EOF
