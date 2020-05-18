#!/usr/bin/bash

if [ -z "$1" ]; then
    echo "Usage gen-tls-parameters.sh tls-parameters.csv"
    exit 0
fi

file=tls-parameters.cpp

cat > $file <<EOF
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
