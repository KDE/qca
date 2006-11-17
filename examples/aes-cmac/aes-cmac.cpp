/*
 Copyright (C) 2006 Brad Hards <bradh@frogmouth.net>

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

class AESCMACContext : public QCA::MACContext
{
public:
    AESCMACContext(QCA::Provider *p) : QCA::MACContext(p, "cmac(aes)")
    {
    }

    ~AESCMACContext()
    {
    }


    // Helper to left shift an arbitrary length array
    // This is heavily based on the example in the I-D.
    QSecureArray leftShift(const QSecureArray &array)
    {
	// We create an output of the same size as the input
	QSecureArray out(array.size());
	// We handle one byte at a time - this is the high bit
	// from the previous byte.
	int overflow = 0;

	// work through each byte.
	for (int i = array.size() -1; i >= 0; --i) {
	    // do the left shift on this byte.
	    out[i] = array[i] << 1;
	    // make the low bit on this byte be the high bit
	    // from the previous byte.
	    out[i] |= overflow;
	    // save the high bit for next time
	    overflow = (array[i] & 0x80) ? 1 : 0;
	}
	return out;
    }


    // Helper to XOR two arrays - must be same length
    QSecureArray xorArray(const QSecureArray &array1,
			  const QSecureArray &array2)
    {
	if (array1.size() != array2.size())
	    // empty array
	    return QSecureArray();

	QSecureArray result(array1.size());

	for (int i = 0; i < array1.size(); ++i)
	    result[i] = array1[i] ^ array2[i];

	return result;
    }


    void setup(const QCA::SymmetricKey &key)
    {
	// We might not have a real key, since this can get called
	// from the constructor.
	if (key.size() == 0)
	    return;

	m_key = key;
	// Generate the subkeys
	QSecureArray const_Zero(16);
	QSecureArray const_Rb(16);
	const_Rb[15] = 0x87;

	m_X = const_Zero;
	m_residual = QSecureArray();

	// Figure 2.2, step 1.
	QCA::Cipher aesObj(QString("aes128"),
			   QCA::Cipher::ECB, QCA::Cipher::DefaultPadding,
			   QCA::Encode, key);
	QSecureArray L = aesObj.process(const_Zero);

	// Figure 2.2, step 2
	if (0 == (L[0] & 0x80))
	    m_k1 = leftShift(L);
	else
	    m_k1 = xorArray(leftShift(L), const_Rb);

	// Figure 2.2, step 3
	if (0 == (m_k1[0] & 0x80))
	    m_k2 = leftShift(m_k1);
	else
	    m_k2 = xorArray(leftShift(m_k1), const_Rb);
    }

    Context *clone() const
    {
        return new AESCMACContext(*this);
    }

    void clear()
    {
	setup(m_key);
    }

    QCA::KeyLength keyLength() const
    {
        return QCA::KeyLength(16, 16, 1);
    }

    // This is a bit different to the way the I-D does it,
    // to allow for multiple update() calls.
    void update(const QSecureArray &a)
    {
	QSecureArray bytesToProcess = m_residual + a;
	int blockNum;
	// note that we don't want to do the last full block here, because
	// it needs special treatment in final().
	for (blockNum = 0; blockNum < ((bytesToProcess.size()-1)/16); ++blockNum) {
	    // copy a block of data
	    QSecureArray thisBlock(16);
	    for (int yalv = 0; yalv < 16; ++yalv)
		thisBlock[yalv] = bytesToProcess[blockNum*16 + yalv];

	    m_Y = xorArray(m_X, thisBlock);

	    QCA::Cipher aesObj(QString("aes128"),
			       QCA::Cipher::ECB, QCA::Cipher::DefaultPadding,
			       QCA::Encode, m_key);
	    m_X = aesObj.process(m_Y);
	}
	// This can be between 1 and 16
	int numBytesLeft = bytesToProcess.size() - 16*blockNum;
	// we copy the left over part
	m_residual.resize(numBytesLeft);
	for(int yalv = 0; yalv < numBytesLeft; ++yalv)
	    m_residual[yalv] = bytesToProcess[blockNum*16 + yalv];
    }

    void final( QSecureArray *out)
    {
	QSecureArray lastBlock;
	int numBytesLeft = m_residual.size();

	if ( numBytesLeft != 16 ) {
	    // no full block, so we have to pad.
	    m_residual.resize(16);
	    m_residual[numBytesLeft] = 0x80;
	    lastBlock = xorArray(m_residual, m_k2);
	} else {
	    // this is a full block - no padding
	    lastBlock = xorArray(m_residual, m_k1);
	}
	m_Y = xorArray(m_X, lastBlock);
	QCA::Cipher aesObj(QString("aes128"),
			   QCA::Cipher::ECB, QCA::Cipher::DefaultPadding,
			   QCA::Encode, m_key);
	*out = aesObj.process(m_Y);

    }

protected:
    // first subkey
    QSecureArray m_k1;
    // second subkey
    QSecureArray m_k2;
    // main key
    QSecureArray m_key;

    // state
    QSecureArray m_X;
    QSecureArray m_Y;

    // partial block that we can't do yet
    QSecureArray m_residual;
};

class ClientSideProvider : public QCA::Provider
{
public:
        int version() const
        {
                return QCA_VERSION;
        }

        QString name() const
        {
                return "exampleClientSideProvider";
        }

        QStringList features() const
        {
                QStringList list;
                list += "cmac(aes)";
		// you can add more features in here, if you have some.
                return list;
        }

        Provider::Context *createContext(const QString &type)
        {
	    if(type == "cmac(aes)")
		return new AESCMACContext(this);
	    // else if (type == some other feature)
	    //  return some other context.
	    else
		return 0;
        }
};


// AES CMAC is a Message Authentication Code based on a block cipher
// instead of the more normal keyed hash.
// See RFC 4493 "The AES-CMAC Algorithm"
class AES_CMAC: public QCA::MessageAuthenticationCode
{
public:
    AES_CMAC(const QCA::SymmetricKey &key = QCA::SymmetricKey(),
	     const QString &provider = QString()):
	QCA::MessageAuthenticationCode( "cmac(aes)", key, provider)
    {}
};


int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    qDebug() << "This example shows AES CMAC";

    // the Initializer object sets things up, and
    // also does cleanup when it goes out of scope
    QCA::Initializer init;

    qDebug() << "Completed initialisation";

    if( ! QCA::isSupported("aes128-ecb") ) {
	qDebug() << "AES not supported!";
    }

    if ( QCA::insertProvider(new ClientSideProvider, 0) )
	qDebug() << "Inserted our provider";
    else
	qDebug() << "our provider could not be added";

    // We should check AES CMAC is supported before using it.
    if( ! QCA::isSupported("cmac(aes)") ) {
	qDebug() << "AES CMAC not supported!";
    } else {
	// create the required object
	AES_CMAC cmacObject;

	// create the key
	QCA::SymmetricKey key(QCA::hexToArray("2b7e151628aed2a6abf7158809cf4f3c"));

	// set the MAC to use the key
	cmacObject.setup(key);

	QSecureArray message = QCA::hexToArray("6bc1bee22e409f96e93d7e117393172a"
					       "ae2d8a571e03ac9c9eb76fac45af8e51"
					       "30c81c46a35ce411e5fbc1191a0a52ef"
					       "f69f2445df4f9b17ad2b417be66c3710");
	QSecureArray message1(message);
	message1.resize(0);
	qDebug();
	qDebug() << "Message1: " << QCA::arrayToHex(message1);
	qDebug() << "Expecting:  bb1d6929e95937287fa37d129b756746";
	qDebug() << "AES-CMAC: " << QCA::arrayToHex(cmacObject.process(message1));

	cmacObject.clear();
	QSecureArray message2(message);
	message2.resize(16);
	qDebug();
	qDebug() << "Message2: " << QCA::arrayToHex(message2);
	qDebug() << "Expecting:  070a16b46b4d4144f79bdd9dd04a287c";
	qDebug() << "AES-CMAC: " << QCA::arrayToHex(cmacObject.process(message2));

	cmacObject.clear();
	QSecureArray message3(message);
	message3.resize(40);
	qDebug();
	qDebug() << "Message3: " << QCA::arrayToHex(message3);
	qDebug() << "Expecting:  dfa66747de9ae63030ca32611497c827";
	qDebug() << "AES-CMAC  " << QCA::arrayToHex(cmacObject.process(message3));

	cmacObject.clear();
	QSecureArray message4(message);
	message4.resize(64);
	qDebug();
	qDebug() << "Message4: " << QCA::arrayToHex(message4);
	qDebug() << "Expecting:  51f0bebf7e3b9d92fc49741779363cfe";
	qDebug() << "AES-CMAC: " << QCA::arrayToHex(cmacObject.process(message4));
    }

    return 0;
}

