/**
 * tester.h
 *
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
#ifndef TESTER_H
#define TESTER_H

#include <kdebug.h>
#include <qstringlist.h>

#define CHECK( x, y ) check( __FILE__, __LINE__, #x, x, y, false )
#define XFAIL( x, y ) check( __FILE__, __LINE__, #x, x, y, true )
#define SKIP( x ) skip( __FILE__, __LINE__, #x )

class Tester
{
public:
    Tester()
        : m_tests( 0 )
    {}
    virtual ~Tester() {}

public:
    virtual void allTests() = 0;

public:
    int testsFinished() const {
        return m_tests;
    }

    int testsFailed() const {
        return m_errorList.count();
    }

    int testsXFail() const {
	return m_xfailList.count();
    }

    int testsXPass() const {
	return m_xpassList.count();
    }

    int testsSkipped() const {
	return m_skipList.count();
    }

    QStringList errorList() const {
        return m_errorList;
    }

    QStringList xfailList() const {
	return m_xfailList;
    }

    QStringList xpassList() const {
	return m_xpassList;
    }

    QStringList skipList() const {
	return m_skipList;
    }

    void skip( const char *file, int line, QString msg )
    {
	QString skipEntry;
	QTextStream ts( &skipEntry, IO_WriteOnly );
	ts << file << "["<< line <<"]: " << msg;
	m_skipList.append( skipEntry );

	++m_tests;
    }

protected:
    template<typename T>
    void check( const char *file, int line, const char *str,
                const T  &result, const T &expectedResult,
		bool expectedFailure )
    {
	if ( result != expectedResult ) {
            QString error;
            QTextStream ts( &error, IO_WriteOnly );
            ts << file << "["<< line <<"]:"
               <<" failed on \""<<  str <<"\""
               << "\n\t\t result = '"
               << result
               << "', expected = '"<< expectedResult<<"'";
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
		QTextStream ts( &error, IO_WriteOnly );
		ts << file << "["<< line <<"]:"
		   <<" unexpectedly passed on \""
		   <<  str <<"\"";
		m_xpassList.append( error );
	    }
	}
	++m_tests;
    }

private:
    QStringList m_errorList;
    QStringList m_xfailList;
    QStringList m_xpassList;
    QStringList m_skipList;
    int m_tests;
};

#endif
