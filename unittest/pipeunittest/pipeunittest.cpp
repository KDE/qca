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

#ifdef QT_STATICPLUGIN
#include "import_plugins.h"
#endif

class PipeUnitTest : public QObject
{
  Q_OBJECT

private slots:
    void initTestCase();
    void cleanupTestCase();
    void createPipeWithInsecureMemory();
    void createPipeWithSecureMemory();
    void readWrite();
    void readWriteSecure();
    void signalTests();
    void signalTestsSecure();
private:
    QCA::Initializer* m_init;
};

void PipeUnitTest::initTestCase()
{
    m_init = new QCA::Initializer;
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
    QTest::qWait(1); // process events
    QTest::qWait(1); // process events
    QByteArray out1 = pipe1.readEnd().read(); // read all...
    QCOMPARE( testData1, out1 );

    pipe1.writeEnd().write( testData1 ); // put it back in
    QTest::qWait(1); // process events
    QCOMPARE( pipe1.readEnd().bytesAvailable(), testData1.size() );

    pipe1.writeEnd().write( testData2 ); // add some more data
    QTest::qWait(1); // process events
    QCOMPARE( pipe1.readEnd().bytesAvailable(), testData1.size() + testData2.size() );
    QByteArray thisRead = pipe1.readEnd().read(1);
    QCOMPARE( thisRead, QByteArray("D") );
    thisRead = pipe1.readEnd().read(3);
    QCOMPARE( thisRead, QByteArray("own") );
    thisRead = pipe1.readEnd().read();
    QCOMPARE( thisRead, QByteArray(" thepipe!") );
}

void PipeUnitTest::readWriteSecure()
{
    QCA::QPipe pipe1;
    QCA::SecureArray testData1( "Down the" );
    QCA::SecureArray testData2( " secure pipe!" );

    pipe1.create(true);
    QVERIFY( pipe1.writeEnd().isValid() );
    QVERIFY( pipe1.readEnd().isValid() );

    // enable the pipe ends for read/write
    pipe1.writeEnd().enable();
    pipe1.readEnd().enable();

    pipe1.writeEnd().writeSecure( testData1 );
    QTest::qWait(1); // process events
    QTest::qWait(1); // process events
    QCA::SecureArray out1 = pipe1.readEnd().readSecure(); // read all...
    QCOMPARE( testData1, out1 );

    pipe1.writeEnd().writeSecure( testData1 ); // put it back in
    QTest::qWait(1); // process events
    QCOMPARE( pipe1.readEnd().bytesAvailable(), testData1.size() );

    pipe1.writeEnd().writeSecure( testData2 ); // add some more data
    QTest::qWait(1); // process events
    QCOMPARE( pipe1.readEnd().bytesAvailable(), testData1.size() + testData2.size() );
    QCA::SecureArray thisRead = pipe1.readEnd().readSecure(1);
    QCOMPARE( thisRead, QCA::SecureArray("D") );
    thisRead = pipe1.readEnd().readSecure(3);
    QCOMPARE( thisRead, QCA::SecureArray("own") );
    thisRead = pipe1.readEnd().readSecure();
    QCOMPARE( thisRead, QCA::SecureArray(" the secure pipe!") );
}

void PipeUnitTest::signalTests()
{
    QCA::QPipe* pipe = new QCA::QPipe;
    pipe->create();
    
    QVERIFY( pipe->writeEnd().isValid() );
    pipe->writeEnd().enable();
    QVERIFY( pipe->readEnd().isValid() );
    pipe->readEnd().enable();

    QSignalSpy readyReadSpy( &(pipe->readEnd()), SIGNAL( readyRead() ) );
    QVERIFY( readyReadSpy.isValid() );
    QSignalSpy bytesWrittenSpy( &(pipe->writeEnd()), SIGNAL( bytesWritten(int) ) );
    QVERIFY( bytesWrittenSpy.isValid() );
    QSignalSpy closedWriteSpy( &(pipe->writeEnd()), SIGNAL( closed() ) );
    QVERIFY( closedWriteSpy.isValid() );
    QSignalSpy closedReadSpy( &(pipe->readEnd()), SIGNAL( closed() ) );
    QVERIFY( closedReadSpy.isValid() );

    QCOMPARE( readyReadSpy.count(), 0 );
    QCOMPARE( bytesWrittenSpy.count(), 0 );
    QCOMPARE( closedWriteSpy.count(), 0 );
    QCOMPARE( closedReadSpy.count(), 0 );

    QByteArray data("Far better, it is, to dare mighty things");
    pipe->writeEnd().write( data );
    QTest::qWait(1);
    QTest::qWait(1);
    QCOMPARE( readyReadSpy.count(), 1 );
    QCOMPARE( bytesWrittenSpy.count(), 1 );    
    // this pulls out the first argument to the first signal as an integer
    QCOMPARE( bytesWrittenSpy.takeFirst().at(0).toInt(), data.size() );
    QCOMPARE( pipe->readEnd().bytesAvailable(), data.size() );

    QCOMPARE( closedWriteSpy.count(), 0 );
    QCOMPARE( closedReadSpy.count(), 0 );
 
    pipe->readEnd().close();
    QTest::qWait(1);
    QCOMPARE( closedWriteSpy.count(), 0 );
    QCOMPARE( closedReadSpy.count(), 1 );
    pipe->writeEnd().close();
    QTest::qWait(1);
    QCOMPARE( closedWriteSpy.count(), 1 );
    QCOMPARE( closedReadSpy.count(), 1 );
}

void PipeUnitTest::signalTestsSecure()
{
    QCA::QPipe* pipe = new QCA::QPipe;
    pipe->create(true);
    
    QVERIFY( pipe->writeEnd().isValid() );
    pipe->writeEnd().enable();
    QVERIFY( pipe->readEnd().isValid() );
    pipe->readEnd().enable();

    QSignalSpy readyReadSpy( &(pipe->readEnd()), SIGNAL( readyRead() ) );
    QVERIFY( readyReadSpy.isValid() );
    QSignalSpy bytesWrittenSpy( &(pipe->writeEnd()), SIGNAL( bytesWritten(int) ) );
    QVERIFY( bytesWrittenSpy.isValid() );
    QSignalSpy closedWriteSpy( &(pipe->writeEnd()), SIGNAL( closed() ) );
    QVERIFY( closedWriteSpy.isValid() );
    QSignalSpy closedReadSpy( &(pipe->readEnd()), SIGNAL( closed() ) );
    QVERIFY( closedReadSpy.isValid() );

    QCOMPARE( readyReadSpy.count(), 0 );
    QCOMPARE( bytesWrittenSpy.count(), 0 );
    QCOMPARE( closedWriteSpy.count(), 0 );
    QCOMPARE( closedReadSpy.count(), 0 );

    QCA::SecureArray data("Far better, it is, to dare mighty things");
    pipe->writeEnd().writeSecure( data );
    QTest::qWait(1);
    QTest::qWait(1);
    QCOMPARE( readyReadSpy.count(), 1 );
    QCOMPARE( bytesWrittenSpy.count(), 1 );    
    // this pulls out the first argument to the first signal as an integer
    QCOMPARE( bytesWrittenSpy.takeFirst().at(0).toInt(), data.size() );
    QCOMPARE( pipe->readEnd().bytesAvailable(), data.size() );

    QCOMPARE( closedWriteSpy.count(), 0 );
    QCOMPARE( closedReadSpy.count(), 0 );
 
    pipe->readEnd().close();
    QTest::qWait(1);
    QCOMPARE( closedWriteSpy.count(), 0 );
    QCOMPARE( closedReadSpy.count(), 1 );
    pipe->writeEnd().close();
    QTest::qWait(1);
    QCOMPARE( closedWriteSpy.count(), 1 );
    QCOMPARE( closedReadSpy.count(), 1 );
}

QTEST_MAIN(PipeUnitTest)

#include "pipeunittest.moc"
