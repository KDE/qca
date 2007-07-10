/**
 * Copyright (C)  2007  Brad Hards <bradh@frogmouth.net>
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

#include <QtCrypto>
#include <QtTest/QtTest>

class PipeUnitTest : public QObject
{
  Q_OBJECT

private slots:
    void initTestCase();
    void cleanupTestCase();
    void createPipeWithInsecureMemory();
    void createPipeWithSecureMemory();
    void readWrite();
private:
    QCA::Initializer* m_init;
};

void PipeUnitTest::initTestCase()
{
    m_init = new QCA::Initializer;
#include "../fixpaths.include"
}

void PipeUnitTest::cleanupTestCase()
{
    QCA::unloadAllPlugins();
    delete m_init;
}

void PipeUnitTest::createPipeWithInsecureMemory()
{
    QCA::QPipe pipe1;
    // we haven't created the pipe yet, so it shouldn't be valid
    QCOMPARE( pipe1.readEnd().isValid(), false );
    QCOMPARE( pipe1.writeEnd().isValid(), false );

    pipe1.create(); // insecure memory used
    QVERIFY( pipe1.readEnd().isValid() );
    QVERIFY( pipe1.readEnd().type() == QCA::QPipeDevice::Read );
    QVERIFY( pipe1.writeEnd().isValid() );
    QVERIFY( pipe1.writeEnd().type() == QCA::QPipeDevice::Write );

    pipe1.reset();
    QCOMPARE( pipe1.readEnd().isValid(), false );
    QCOMPARE( pipe1.writeEnd().isValid(), false );
}

void PipeUnitTest::createPipeWithSecureMemory()
{
    QCA::QPipe pipe1;
    // we haven't created the pipe yet, so it shouldn't be valid
    QCOMPARE( pipe1.readEnd().isValid(), false );
    QCOMPARE( pipe1.writeEnd().isValid(), false );

    pipe1.create( true ); // secure memory used
    QVERIFY( pipe1.readEnd().isValid() );
    QVERIFY( pipe1.readEnd().type() == QCA::QPipeDevice::Read );
    QVERIFY( pipe1.writeEnd().isValid() );
    QVERIFY( pipe1.writeEnd().type() == QCA::QPipeDevice::Write );

    pipe1.reset();
    QCOMPARE( pipe1.readEnd().isValid(), false );
    QCOMPARE( pipe1.writeEnd().isValid(), false );
}

void PipeUnitTest::readWrite()
{
    QCA::QPipe pipe1;
    QByteArray testData1( "Down the" );
    QByteArray testData2( "pipe!" );

    pipe1.create();
    QVERIFY( pipe1.writeEnd().isValid() );
    QVERIFY( pipe1.readEnd().isValid() );

    // enable the pipe ends for read/write
    pipe1.writeEnd().enable();
    pipe1.readEnd().enable();

    pipe1.writeEnd().write( testData1 );
    // QTest::qWait(1);
    QCoreApplication::processEvents();
    QCoreApplication::processEvents();
    QByteArray out1 = pipe1.readEnd().read(); // read all...
    QCOMPARE( testData1, out1 );

    pipe1.writeEnd().write( testData1 ); // put it back in
    QCoreApplication::processEvents();
    QCoreApplication::processEvents();
    QCOMPARE( pipe1.readEnd().bytesAvailable(), testData1.size() );
    pipe1.writeEnd().write( testData2 );
    QCoreApplication::processEvents();
    QCoreApplication::processEvents();
    QCOMPARE( pipe1.readEnd().bytesAvailable(), testData1.size() + testData2.size() );
    

}
QTEST_MAIN(PipeUnitTest)

#include "pipeunittest.moc"
