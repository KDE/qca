#include"qca.h"

int main(int argc, char **argv)
{
	QCA::init();
	if(!QCA::isSupported(QCA::CAP_SHA1)) {
		printf("SHA1 not supported!\n");
		return 1;
	}

	QCString cs = (argc >= 2) ? argv[1] : "hello";
	QString result = QCA::SHA1::hashToString(cs);
	printf("sha1(\"%s\") = [%s]\n", cs.data(), result.latin1());

	return 0;
}

