
//Added by the Qt porting tool:
#include <QTextStream>

/*
 * Copyright (C)  2004  Zack Rusin <zack@kde.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "qtester.h"


#include <qvariant.h>
#include <qtextstream.h>

QTester::QTester( QObject *parent )
    : QObject( parent ), m_tests( 0 )
{
}

void QTester::check( const char *file, int line, const char *str,
                     const QVariant &result, const QVariant &expectedResult,
		     bool expectedFailure)
{
    if ( result != expectedResult ) {
        QString error;
        QTextStream ts( &error, QIODevice::WriteOnly );
        ts << file << "["<< line <<"]:"
           <<" failed on \""<<  str <<"\""
           << "\n\t\t result = "
           << result.toString()
           << ", expected = "<< expectedResult.toString();
	if ( expectedFailure ) {
	    m_xfailList.append( error );
	} else {
	    m_errorList.append( error );
 	}
    } else {
	// then the test passed, but we want to record it if 
	// we were expecting a failure
	if (expectedFailure) {
	    QString error;
	    QTextStream ts( &error, QIODevice::WriteOnly );
	    ts << file << "["<< line <<"]:"
	       <<" unexpectedly passed on \""
	       <<  str <<"\"";
	    m_xpassList.append( error );
	}
    }
    ++m_tests;
}

// #include "qtester.moc"
