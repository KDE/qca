#include"qca.h"
#include<stdio.h>

int main(int argc, char **argv)
{
	QCA::init();
	QCString cs = (argc >= 2) ? argv[1] : "hello";

	if(!QCA::isSupported(QCA::CAP_SHA1))
		printf("SHA1 not supported!\n");
	else {
		QString result = QCA::SHA1::hashToString(cs);
		printf("sha1(\"%s\") = [%s]\n", cs.data(), result.latin1());
	}

	if(!QCA::isSupported(QCA::CAP_MD5))
		printf("MD5 not supported!\n");
	else {
		QString result = QCA::MD5::hashToString(cs);
		printf("md5(\"%s\") = [%s]\n", cs.data(), result.latin1());
	}

	return 0;
}

