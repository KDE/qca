#include "tlssocket.h"

int main(int argc, char **argv)
{
	QCoreApplication qapp(argc, argv);

	TLSSocket socket;
	socket.connectToHostEncrypted("www.paypal.com", 443);
	socket.write("GET / HTTP/1.0\r\n\r\n");
	while(socket.waitForReadyRead())
		printf("%s", socket.readAll().data());

	return 0;
}
