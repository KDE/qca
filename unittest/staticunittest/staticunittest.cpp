/*
 * staticunittest.cpp - Qt Cryptographic Architecture
 * Copyright (C) 2004 Brad Hards <bradh@frogmouth.net>
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

#include"qca.h"
#include<stdio.h>

int main(int argc, char **argv)
{
	QCA::init();

	QByteArray test(10);
	test.fill('a');

	if (QString("61616161616161616161") == QCA::arrayToHex(test) ) {
		printf ("arrayToHex passed\n");
	} else {
		printf ("arrayToHex FAILED\n");
		printf ("expected: 61616161616161616161\n");
		printf ("     got: %s\n", QCA::arrayToHex(test).latin1() );
	}

	test.fill('b');
	test[7] = 0x00;

	if (QCA::hexToArray(QString("62626262626262006262") ) == test ) {
		printf ("hexToArray passed\n");
	} else {
		printf ("hexToArray FAILED\n");
	}
	return 0;
}

