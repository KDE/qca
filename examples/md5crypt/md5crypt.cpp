/*
  Copyright (C) 2007 Carlo Todeschini - Metarete s.r.l. <info@metarete.it>

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

/*
  Algorithm inspired by Vladimir Silva's "Secure Java apps on Linux using
  MD5 crypt" article
  (http://www-128.ibm.com/developerworks/linux/library/l-md5crypt/)
*/

#include <QtCrypto>
#include <QCoreApplication>
#include <QtDebug>
#include <stdio.h>

QString to64 ( long v , int size )
{

    // Character set of the encrypted password: A-Za-z0-9./
    QString itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    QString result;

    while ( --size >= 0 )
    {
        result.append ( itoa64.at ( ( int )( v & 0x3f ) ) );
        v = v >> 6;
    }

    return result;

}


int byte2unsigned ( int byteValue )
{

    int integerToReturn;
    integerToReturn = (int) byteValue & 0xff;
    return integerToReturn;

}

QString qca_md5crypt( const QCA::SecureArray &password, const QCA::SecureArray &salt )
{
    QCA::SecureArray finalState, magic_string = "$1$";

    // The md5crypt algorithm uses two separate hashes
    QCA::Hash hash1( "md5" );
    QCA::Hash hash2( "md5" );

    // MD5 Hash #1: pwd, magic string and salt
    hash1.update ( password );
    hash1.update ( magic_string );
    hash1.update ( salt );

    // MD5 Hash #2: password, salt, password
    hash2.update ( password );
    hash2.update ( salt );
    hash2.update ( password );

    finalState = hash2.final();

    // Two sets of transformations based on the length of the password
    for ( int i = password.size() ; i > 0 ; i -= 16 )
    {
        // Update hash1 from offset value (i > 16 ? 16 : i)
        hash1.update( finalState.toByteArray().left(i > 16 ? 16 : i));
    }

    // Clear array bits
    finalState.fill( 0 );

    for ( int i = password.size() ; i != 0 ; i = i >> 1 )
    {
        if ( ( i & 1 ) != 0 )
        {
            hash1.update( finalState.toByteArray().left ( 1 ) );
        }
        else
        {
            hash1.update( password.toByteArray().left ( 1 ) );
        }
    }

    finalState = hash1.final();

    // Now build a 1000 entry dictionary...
    for ( int i = 0 ; i < 1000 ; i++ )
    {

        hash2.clear();

        if ((i & 1) != 0)
        {
            hash2.update ( password );
        }
        else
        {
            hash2.update ( finalState.toByteArray().left( 16 ));
        }

        if ((i % 3) != 0)
        {
            hash2.update ( salt );
        }

        if ((i % 7) != 0)
        {
            hash2.update ( password );
        }

        if ((i & 1) != 0)
        {
            hash2.update ( finalState.toByteArray().left( 16 ) );
        }
        else
        {
            hash2.update ( password );
        }

        finalState = hash2.final();
    }

    // Create an output string
    // Salt is part of the encoded password ($1$<string>$)
    QString encodedString;

    encodedString.append ( magic_string.toByteArray() );
    encodedString.append ( salt.toByteArray() );
    encodedString.append ( "$" );

    long l;

    l = ( byte2unsigned (finalState.toByteArray().at(0) ) << 16 |
          ( byte2unsigned (finalState.toByteArray().at(6)) ) << 8 |
          byte2unsigned (finalState.toByteArray().at(12)) );
    encodedString.append ( to64 (l, 4) );

    l = ( byte2unsigned (finalState.toByteArray().at(1)) << 16 |
          ( byte2unsigned (finalState.toByteArray().at(7))) << 8 |
          byte2unsigned (finalState.toByteArray().at(13)) );
    encodedString.append ( to64 (l, 4) );

    l = ( byte2unsigned (finalState.toByteArray().at(2)) << 16 |
          ( byte2unsigned (finalState.toByteArray().at(8))) << 8 |
          byte2unsigned (finalState.toByteArray().at(14)) );
    encodedString.append ( to64 (l, 4) );

    l = ( byte2unsigned (finalState.toByteArray().at(3)) << 16 |
          ( byte2unsigned (finalState.toByteArray().at(9))) << 8 |
          byte2unsigned (finalState.toByteArray().at(15)) );
    encodedString.append ( to64 (l, 4) );

    l = ( byte2unsigned (finalState.toByteArray().at(4)) << 16 |
          ( byte2unsigned (finalState.toByteArray().at(10))) << 8 |
          byte2unsigned (finalState.toByteArray().at(5)) );
    encodedString.append ( to64 (l, 4) );

    l = byte2unsigned (finalState.toByteArray().at(11));
    encodedString.append ( to64 (l, 2) );

    return encodedString;
}

int main(int argc, char **argv)
{

    // the Initializer object sets things up, and
    // also does cleanup when it goes out of scope
    QCA::Initializer init;

    QCoreApplication app ( argc, argv );

    QCA::SecureArray password, salt;

    if ( argc < 3 )
    {
        printf ( "Usage: %s password salt (salt without $1$)\n" , argv[0] );
        return 1;
    }

    password.append( argv[1] );

    salt.append( argv[2] );

    // must always check that an algorithm is supported before using it
    if( !QCA::isSupported( "md5" ) )
        printf ("MD5 hash not supported!\n");
    else
    {
        QString result = qca_md5crypt( password, salt );

        printf ("md5crypt     [ %s , %s ] = '%s'\n" , password.data(), salt.data() , qPrintable(result) );

        // this is equivalent if you have GNU libc 2.0
        // printf( "GNU md5crypt [ %s , %s ] = '%s'\n",  password.data(), salt.data(), crypt( password.data(), ( "$1$"+salt ).data() ) );
    }

    return 0;
}




