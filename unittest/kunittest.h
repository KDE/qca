/**
 * kunittest.h
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
#ifndef KUNITTEST_H
#define KUNITTEST_H

#include "qtester.h"
#include "tester.h"

#include <qobject.h>
#include <qasciidict.h>
#include <qptrdict.h>

#define ADD_TEST(x) addTester( #x, new x )
#define ADD_QTEST(x) addTester( new x )

class KUnitTest : public QObject
{
    Q_OBJECT
public:
    KUnitTest();

    int runTests();
public:
    void addTester( const char *name, Tester* test )
    {
        m_tests.insert( name, test );
    }
    void addTester( QTester *test );

private slots:
    void qtesterDone( QObject *obj );
    void checkRun();

private:
    void registerTests();

private:
    QAsciiDict<Tester> m_tests;
    QPtrDict<QTester> m_qtests;
    int globalTests;
    int globalPasses;
    int globalFails;
    int globalXFails;
    int globalXPasses;
    int globalSkipped;
};

#endif
