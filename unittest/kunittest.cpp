/**
 * kunittest.cpp
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
#include "kunittest.h"

#include "staticunittest.h"
#include "hashunittest.h"
#include "bigintunittest.h"
#include "securearrayunittest.h"

#include "qtester.h"
#include "tester.h"

#include <qapplication.h>
#include <qtimer.h>

#include <iostream>
using namespace std;

void KUnitTest::registerTests()
{
    ADD_TEST( StaticUnitTest );
    ADD_TEST( HashUnitTest );
    ADD_TEST( BigIntUnitTest );
    ADD_TEST( SecureArrayUnitTest );
}

KUnitTest::KUnitTest()
{
    QTimer::singleShot( 0, this, SLOT(checkRun()) );

    m_tests.setAutoDelete( TRUE );
    m_qtests.setAutoDelete( TRUE );

    registerTests();
}

void KUnitTest::checkRun()
{
    if ( m_qtests.isEmpty() )
        qApp->exit();
}

int KUnitTest::runTests()
{
    int result = 0;
    int globalSteps = 0;
    int globalPasses = 0;
    int globalFails = 0;
    int globalXFails = 0;
    int globalXPasses = 0;
    int globalSkipped = 0;

    cout << "# Running normal tests... #" << endl << endl;
    QAsciiDictIterator<Tester> it( m_tests );

    for( ; it.current(); ++it ) {
        Tester* test = it.current();
        test->allTests();
        QStringList errorList = test->errorList();
        QStringList xfailList = test->xfailList();
	QStringList xpassList = test->xpassList();
	QStringList skipList = test->skipList();
	cout << it.currentKey() << " - ";
	if ( !errorList.empty() || !xfailList.empty() ) {
            ++result;
	    int numPass = test->testsFinished() - ( test->testsFailed() + test->testsXFail() );
	    globalSteps += test->testsFinished();
	    globalPasses += numPass;
	    int numFail = test->testsFailed() + test->testsXFail();
	    globalFails += numFail;
	    int numXFail = test->testsXFail();
	    globalXFails += numXFail;
	    globalXPasses += test->testsXPass();

	    cout << numPass << " test" << ( ( 1 == numPass )?"":"s") << " passed ";
	    if ( 0 < test->testsXPass() ) {
		cout << "(" << test->testsXPass() << " unexpected pass" << ( ( 1 == test->testsXPass() )?"":"es") << ")";
	    }
            cout << ", " << numFail << " test" << ( ( 1 == numFail )?"":"s") << " failed";
	    if ( 0 < numXFail  ) {
		cout << " (" << numXFail << " expected failure" << ( ( 1 == numXFail )?"":"s") << ")";
	    }
	    cout  << endl;

	    if ( 0 < test->testsXPass() ) {
		cout << "    Unexpected pass" << ( ( 1 == test->testsXPass() )?"":"es") << ":" << endl;
		for ( QStringList::Iterator itr = xpassList.begin(); itr != xpassList.end(); ++itr ) {
		    cout << "\t" << (*itr).latin1() << endl;
		}
	    }
	    if ( !errorList.empty() ) {
		cout << "    Unexpected failure" << ( ( 1 == test->testsFailed() )?"":"s") << ":" << endl;
		for ( QStringList::Iterator itr = errorList.begin(); itr != errorList.end(); ++itr ) {
		    cout << "\t" << (*itr).latin1() << endl;
		}
	    }
	    if ( 0 < numXFail ) {
		cout << "    Expected failure" << ( ( 1 == numXFail)?"":"s") << ":" << endl;
		for ( QStringList::Iterator itr = xfailList.begin(); itr != xfailList.end(); ++itr ) {
		    cout << "\t" << (*itr).latin1() << endl;
		}
	    }
        } else {
	    // then we are dealing with no failures, but perhaps some skipped
	    int numSkipped = test->testsSkipped();
	    int numPass = test->testsFinished() - numSkipped;

            cout << numPass << " test" << ((1 == numPass)?",":"s, all") << " passed";
	    globalPasses += numPass;
	    globalSkipped += numSkipped;
	    globalSteps += test->testsFinished();

	    if ( 0 < test->testsXPass() ) {
		cout << " (" << test->testsXPass() << " unexpected pass" << ( ( 1 == test->testsXPass() )?"":"es") << ")";
		globalXPasses += test->testsXPass();
	    }
	    if ( 0 < numSkipped ) {
		cout << "; also " << numSkipped << " skipped";
	    }	
	    cout << endl;
	    if ( 0 < test->testsXPass() ) {
		cout << "    Unexpected pass" << ( ( 1 == test->testsXPass() )?"":"es") << ":" << endl;
		for ( QStringList::Iterator itr = xpassList.begin(); itr != xpassList.end(); ++itr ) {
		    cout << "\t" << (*itr).latin1() << endl;
		}
	    }
	    if ( 0 < numSkipped ) {
		cout << "    Skipped test" << ( ( 1 == numSkipped )?"":"s") << ":" << endl;
		for ( QStringList::Iterator itr = skipList.begin(); itr != skipList.end(); ++itr ) {
		    cout << "\t" << (*itr).latin1() << endl;
		}
	    }
	}
	cout << endl;
    }

    cout << "# Done with normal tests:" << endl;
    cout << "  Total test cases: " << m_tests.count() << endl;
    cout << "  Total test steps                                 : " << globalSteps << endl;
    cout << "    Total passed test steps (including unexpected) : " << globalPasses << endl;
    cout << "      Total unexpected passed test steps           :  " << globalXPasses << endl;
    cout << "    Total failed test steps (including expected)   :  " << globalFails << endl;
    cout << "      Total expected failed test steps             :  " << globalXFails << endl;
    cout << "    Total skipped test steps                       :  " << globalSkipped << endl;

    return result;
}

void KUnitTest::addTester( QTester *test )
{
    m_qtests.insert( test, test );
    connect( test, SIGNAL(destroyed(QObject*)),
             SLOT(qtesterDone(QObject* )) );
}

void KUnitTest::qtesterDone( QObject *obj )
{
    m_qtests.remove( obj );
    if ( m_qtests.isEmpty() )
        qApp->quit();
}

// #include "kunittest.moc"
