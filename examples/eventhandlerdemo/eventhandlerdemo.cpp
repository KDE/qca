/*
 Copyright (C) 2007 Brad Hards <bradh@frogmouth.net>

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

// QtCrypto has the declarations for all of QCA
#include <QtCrypto>

#include <QCoreApplication>

#include <iostream>

/**
   We need a class on the client side to handle password requests.
*/
class ClientPassphraseHandler: public QObject
{
    Q_OBJECT
public:
    ClientPassphraseHandler(QObject *parent = 0) : QObject( parent )
    {
        // When the PasswordAsker or TokenAsker needs to interact
        // with the user, it raises a signal. We connect that to a
        // local slot to get the required information.
        connect( &m_handler, SIGNAL( eventReady(int, const QCA::Event &) ),
                 SLOT( my_eventReady(int, const QCA::Event &) ) );

        // Now that we are set up, we can start the EventHandler. Nothing
        // will happen if you don't call this method.
        m_handler.start();
    }

private slots:
    // This slot gets called when the provider needs a token inserted,
    // or to get a passphrase / password / PIN.
    void my_eventReady(int id, const QCA::Event &event)
    {
        // We can sanity check the event
        if ( event.isNull() ) {
            return;
        }

        // Events can be associated with a a keystore or a file/bytearray
        // You can tell which by looking at the Source
        if ( event.source() == QCA::Event::KeyStore ) {
            std::cout << "Event is associated with a key store operation" << std::endl;
        } else if ( event.source() == QCA::Event::Data ) {
            std::cout << "Event is associated with a file or some other data" << std::endl;
            // if the event comes from a file type operation, you can get the
            // name / label using fileName()
            std::cout << "   Filename: " << qPrintable( event.fileName() ) << std::endl;
        } else {
            std::cout << "Unexpected Source for Event" << std::endl;
        }

        // There are different kinds of events.
        if ( event.type() == QCA::Event::Token ) {
            // You would typically ask the user to insert the token here
            std::cout << "Request for token" << std::endl;
            // we just fake it for this demo.
            m_handler.tokenOkay( id );
            // you could use m_handler.reject( id ) to refuse the token request

        } else if ( event.type() == QCA::Event::Password ) {
            std::cout << "Request for password, passphrase or PIN" << std::endl;
            // and within the Password type, we have a few different styles.
            if ( event.passwordStyle() == QCA::Event::StylePassword ) {
                std::cout << "   [Password request]" << std::endl;
            } else if ( event.passwordStyle() == QCA::Event::StylePassphrase ) {
                std::cout << "   [Passphrase request]" << std::endl;
            } else if ( event.passwordStyle() == QCA::Event::StylePIN ){
                std::cout << "   [PIN request]" << std::endl;
            } else {
                std::cout << "   [unexpect request style]" << std::endl;
            }
            // You would typically request the password/PIN/passphrase.
            // again, we just fake it.
            m_handler.submitPassword( id,  QCA::SecureArray( "hello" ) );

        } else {
            std::cout << "Unexpected event type" << std::endl;
        }
    }
private:
    QCA::EventHandler m_handler;

};

void asker_procedure();

class AskerThread : public QThread
{
    Q_OBJECT
protected:
    virtual void run()
    {
        asker_procedure();
    }
};

int main(int argc, char **argv)
{
    // the Initializer object sets things up, and
    // also does cleanup when it goes out of scope
    QCA::Initializer init;

    QCoreApplication exampleApp(argc, argv);

    ClientPassphraseHandler cph;

    // handler and asker cannot occur in the same thread
    AskerThread askerThread;
    QObject::connect(&askerThread, SIGNAL(finished()), &exampleApp, SLOT(quit()));
    askerThread.start();

    exampleApp.exec();
    return 0;
}

void asker_procedure()
{
    QCA::PasswordAsker pwAsker;

    pwAsker.ask( QCA::Event::StylePassword, "foo.tmp",  0 );

    pwAsker.waitForResponse();

    std::cout << "Password was: " << pwAsker.password().toByteArray().data() << std::endl;

    std::cout << std::endl << "Now do token:" << std::endl;

    QCA::TokenAsker tokenAsker;

    tokenAsker.ask( QCA::KeyStoreInfo( QCA::KeyStore::SmartCard, "Token Id", "Token Name" ), QCA::KeyStoreEntry(), 0 );

    tokenAsker.waitForResponse();

    if ( tokenAsker.accepted() ) {
        std::cout << "Token was accepted" << std::endl;
    } else {
        std::cout << "Token was not accepted" << std::endl;
    }
}

#include "eventhandlerdemo.moc"
