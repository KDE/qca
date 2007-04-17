/*
 Copyright (C) 2003 Justin Karneges <justin@affinix.com>
 Copyright (C) 2005-2006 Brad Hards <bradh@frogmouth.net>

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


#include <QtCrypto>

#include <QCoreApplication>
#include <QDebug>

int main(int argc, char** argv)
{
    // the Initializer object sets things up, and
    // also does cleanup when it goes out of scope
    QCA::Initializer init;

    QCoreApplication app(argc, argv);

    // We need to ensure that we have certificate handling support
    if ( !QCA::isSupported( "cert" ) ) {
	qWarning() << "Sorry, no PKI certificate support";
    	return 1;
    }

    // Read in a public key cert
    // you could also build this using the fromPEMFile() method
    QCA::Certificate pubCert( "User.pem" );
    if ( pubCert.isNull() ) {
	qWarning() << "Sorry, could not import public key certificate";
	return 1;
    }
    // We are building the certificate into a SecureMessageKey object, via a
    // CertificateChain
    QCA::SecureMessageKey secMsgKey;
    QCA::CertificateChain chain;
    chain += pubCert;
    secMsgKey.setX509CertificateChain( chain );

    // build up a SecureMessage object, based on our public key certificate
    if ( !QCA::isSupported( "cms" ) ) {
	qWarning() << "Sorry, no CMS support";
    	return 1;
    }
    QCA::CMS cms;
    QCA::SecureMessage msg(&cms);
    msg.setRecipient(secMsgKey);

    // Some plain text - we use the first command line argument if provided
    QByteArray plainText = (argc >= 2) ? argv[1] : "What do ya want for nuthin'";

    // Now use the SecureMessage object to encrypt the plain text.
    msg.startEncrypt();
    msg.update(plainText);
    msg.end();
    // I think it is reasonable to wait for 1 second for this
    msg.waitForFinished(1000);

    // check to see if it worked
    if(!msg.success())
    {
	qWarning() << "Error encrypting: " << msg.errorCode();
	return 1;
    }

    // get the result
    QByteArray cipherText = msg.read();
    QCA::Base64 enc;
    qDebug() << "'" << plainText.data() << "' encrypts to (in base 64): ";
    qDebug() << enc.arrayToString( cipherText );
    qDebug() << "Message uses" << msg.hashName() << "hashing algorithm";
    qDebug();

    // Show we can decrypt it with the private key

    // Read in a private key
    QCA::PrivateKey privKey;
    QCA::ConvertResult convRes;
    QCA::SecureArray passPhrase = "start";
    privKey = QCA::PrivateKey::fromPEMFile( "Userkey.pem", passPhrase, &convRes );
    if ( convRes != QCA::ConvertGood ) {
	qWarning() << "Sorry, could not import Private Key";
	return 1;
    }

    QCA::SecureMessageKey secMsgKey2;
    // needed?
    secMsgKey2.setX509CertificateChain( chain );
    secMsgKey2.setX509PrivateKey(privKey);
    QCA::SecureMessageKeyList privKeyList;
    privKeyList += secMsgKey2;

    // build up a SecureMessage object, based on the private key
    // you could re-use the existing QCA::CMS object (cms), but
    // this example simulates encryption and one end, and decryption
    // at the other
    QCA::CMS anotherCms;
    anotherCms.setPrivateKeys( privKeyList );

    QCA::SecureMessage msg2( &anotherCms );

    msg2.startDecrypt();
    msg2.update( cipherText );
    msg2.end();

    // I think it is reasonable to wait for 1 second for this
    msg2.waitForFinished(1000);

    // check to see if it worked
    if(!msg2.success())
    {
	qWarning() << "Error encrypting: " << msg2.errorCode();
	return 1;
    }

    QCA::SecureArray plainTextResult = msg2.read();

    qDebug() << enc.arrayToString( cipherText )
	     << " (in base 64) decrypts to: "
	     << plainTextResult.data();

    if (msg2.wasSigned()) {
	qDebug() << "Message was signed at "
		 << msg2.signer().timestamp();
    } else {
	qDebug() << "Message was not signed";
    }

    qDebug() << "Message used" << msg2.hashName() << "hashing algorithm";

    qDebug();

    // Now we want to try a signature
    QByteArray text("Got your message");

    // Re-use the CMS and SecureMessageKeyList objects from the decrypt...
    QCA::SecureMessage signing( &anotherCms );
    signing.setSigners(privKeyList);

    signing.startSign(QCA::SecureMessage::Detached);
    signing.update(text);
    signing.end();

    // I think it is reasonable to wait for 1 second for this
    signing.waitForFinished(1000);

    // check to see if it worked
    if(!signing.success())
    {
	qWarning() << "Error signing: " << signing.errorCode();
	return 1;
    }

    // get the result
    QByteArray signature = signing.signature();

    qDebug() << "'" << text.data() << "', signature (converted to base 64), is: ";
    qDebug() << enc.arrayToString( signature );
    qDebug() << "Message uses" << signing.hashName() << "hashing algorithm";
    qDebug();


    // Now we go back to the first CMS, and re-use that.
    QCA::SecureMessage verifying( &cms );

    // You have to pass the signature to startVerify(),
    // and the message to update()
    verifying.startVerify(signature);
    verifying.update(text);
    verifying.end();

    verifying.waitForFinished(1000);

    // check to see if it worked
    if(!verifying.success())
    {
	qWarning() << "Error verifying: " << verifying.errorCode();
	return 1;
    }

    QCA::SecureMessageSignature sign;
    sign = verifying.signer();
    // todo: dump some data out about the signer

    if(verifying.verifySuccess())
    {
	qDebug() << "Message verified";
    } else {
	qDebug() << "Message failed to verify:" << verifying.errorCode();
    }

    return 0;
}

