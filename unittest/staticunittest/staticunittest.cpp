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

