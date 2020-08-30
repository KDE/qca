/*
 Copyright (C) 2020 Sergey Ilinykh <rion4ik@gmail.com>

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
 AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "dtlssocket.h"

#include <QCoreApplication>
#include <QHostAddress>

int main(int argc, char **argv)
{
    QCA::Initializer init;
    QCoreApplication qapp(argc, argv);
    QCA::logger()->setLevel(QCA::Logger::Debug);
    QCA::logger()->registerLogDevice(new SimpleLogger(&qapp));

    if (qapp.arguments().contains(QLatin1String("-s"))) {
        auto server = new DTLSServer(&qapp);
        server->start(QHostAddress::LocalHost, 9753);
        QObject::connect(server, &DTLSServer::sessionReady, [](DTLSSocket *socket) {
            QObject::connect(socket, &DTLSSocket::readyRead, [socket]() {
                auto data = socket->readDatagram();
                qDebug("got %s. sending reply", data.data());
                socket->writeDatagram("reply");
            });
        });
        qDebug("DTLS server started");

    } else {
        auto client = new DTLSSocket(&qapp);
        QObject::connect(client, &DTLSSocket::connected, [client]() { client->writeDatagram("Hello world"); });
        QObject::connect(client, &DTLSSocket::readyRead, [client]() {
            auto data = client->readDatagram();
            qDebug("got reply: %s", data.data());
        });
        client->connectToServer(QHostAddress::LocalHost, 9753);
    }

    return qapp.exec();
}
