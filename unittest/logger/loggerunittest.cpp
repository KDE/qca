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

class LoggerUnitTest : public QObject
{
  Q_OBJECT

private slots:
    void initTestCase();
    void cleanupTestCase();
    void basicSetup();
    void logText1();
    void logText2();
    void logBlob();
    void logLevel();
private:
    QCA::Initializer* m_init;
};

class NullLogger : public QCA::AbstractLogDevice
{
public:
    NullLogger() : QCA::AbstractLogDevice( "null logger" )
    {}

    ~NullLogger()
    {}
};

class LastLogger : public QCA::AbstractLogDevice
{
public:
    LastLogger() : QCA::AbstractLogDevice( "last logger" )
    {}

    ~LastLogger()
    {}

    void logTextMessage( const QString &message, enum QCA::Logger::Severity severity )
    {
        m_lastMessage = message;
        m_messageSeverity = severity;
    }

    QString lastMessage() const
    {
        return m_lastMessage;
    }

    void logBinaryMessage( const QByteArray &blob, enum QCA::Logger::Severity severity )
    {
        m_lastBlob = blob;
        m_blobSeverity = severity;
    }

    QByteArray lastBlob() const
    {
        return m_lastBlob;
    }

    QCA::Logger::Severity lastMessageSeverity() const
    {
        return m_messageSeverity;
    }

    QCA::Logger::Severity lastBlobSeverity() const
    {
        return m_blobSeverity;
    }

private:
    QString m_lastMessage;
    QByteArray m_lastBlob;
    QCA::Logger::Severity m_messageSeverity;
    QCA::Logger::Severity m_blobSeverity;
};

void LoggerUnitTest::initTestCase()
{
    m_init = new QCA::Initializer;
}

void LoggerUnitTest::cleanupTestCase()
{
    QCA::unloadAllPlugins();
    delete m_init;
}

void LoggerUnitTest::basicSetup()
{
    QCA::Logger *logSystem = QCA::logger();

    QCOMPARE( logSystem->currentLogDevices().count(), 0 );

    logSystem->setLevel (QCA::Logger::Debug);
    QCOMPARE( logSystem->level (), QCA::Logger::Debug );

    NullLogger *nullLogger = new NullLogger;

    logSystem->registerLogDevice( nullLogger );
    QCOMPARE( logSystem->currentLogDevices().count(), 1 );
    QVERIFY( logSystem->currentLogDevices().contains( "null logger" ) );
    logSystem->unregisterLogDevice( "null logger" );
    QCOMPARE( logSystem->currentLogDevices().count(), 0 );

    delete nullLogger;
}

void LoggerUnitTest::logText1()
{
    QCA::Logger *logSystem = QCA::logger();

    logSystem->logTextMessage( "Sending with no recipients" );

    LastLogger *lastlogger = new LastLogger;
    logSystem->registerLogDevice( lastlogger );
    QCOMPARE( logSystem->currentLogDevices().count(), 1 );
    QVERIFY( logSystem->currentLogDevices().contains( "last logger" ) );

    logSystem->logTextMessage( "Sending to system, checking for log device" );
    QCOMPARE( lastlogger->lastMessage(),
              QString( "Sending to system, checking for log device" ) );
    QCOMPARE( lastlogger->lastMessageSeverity(),  QCA::Logger::Information );

    logSystem->logTextMessage( "Sending at Error severity", QCA::Logger::Error );
    QCOMPARE( lastlogger->lastMessage(),
              QString( "Sending at Error severity" ) );
    QCOMPARE( lastlogger->lastMessageSeverity(),  QCA::Logger::Error );

    LastLogger *lastlogger2 = new LastLogger;
    logSystem->registerLogDevice( lastlogger2 );
    QCOMPARE( logSystem->currentLogDevices().count(), 2 );
    QVERIFY( logSystem->currentLogDevices().contains( "last logger" ) );

    logSystem->logTextMessage( "Sending to system, checking for two log devices" );
    QCOMPARE( lastlogger->lastMessage(),
              QString( "Sending to system, checking for two log devices" ) );
    QCOMPARE( lastlogger->lastMessageSeverity(),  QCA::Logger::Information );
    QCOMPARE( lastlogger2->lastMessage(),
              QString( "Sending to system, checking for two log devices" ) );
    QCOMPARE( lastlogger2->lastMessageSeverity(),  QCA::Logger::Information );

    logSystem->unregisterLogDevice( "last logger" ); // this will remove them both

    QCOMPARE( logSystem->currentLogDevices().count(), 0 );

    delete lastlogger;
    delete lastlogger2;
}


// same as above, but use convenience routine.
void LoggerUnitTest::logText2()
{
    QCA_logTextMessage ( "Sending with no recipients", QCA::Logger::Notice );

    LastLogger *lastlogger = new LastLogger;

    QCA::Logger *logSystem = QCA::logger();
    logSystem->registerLogDevice( lastlogger );
    QCOMPARE( logSystem->currentLogDevices().count(), 1 );
    QVERIFY( logSystem->currentLogDevices().contains( "last logger" ) );

    QCA_logTextMessage ( "Sending to system, checking for log device", QCA::Logger::Information );
    QCOMPARE( lastlogger->lastMessage(),
              QString( "Sending to system, checking for log device" ) );
    QCOMPARE( lastlogger->lastMessageSeverity(),  QCA::Logger::Information );

    QCA_logTextMessage ( "Sending at Error severity", QCA::Logger::Error );
    QCOMPARE( lastlogger->lastMessage(),
              QString( "Sending at Error severity" ) );
    QCOMPARE( lastlogger->lastMessageSeverity(),  QCA::Logger::Error );

    LastLogger *lastlogger2 = new LastLogger;
    logSystem->registerLogDevice( lastlogger2 );
    QCOMPARE( logSystem->currentLogDevices().count(), 2 );
    QVERIFY( logSystem->currentLogDevices().contains( "last logger" ) );

    QCA_logTextMessage ( "Sending to system, checking for two log devices", QCA::Logger::Information );
    QCOMPARE( lastlogger->lastMessage(),
              QString( "Sending to system, checking for two log devices" ) );
    QCOMPARE( lastlogger->lastMessageSeverity(),  QCA::Logger::Information );
    QCOMPARE( lastlogger2->lastMessage(),
              QString( "Sending to system, checking for two log devices" ) );
    QCOMPARE( lastlogger2->lastMessageSeverity(),  QCA::Logger::Information );

    logSystem->unregisterLogDevice( "last logger" ); // this will remove them both

    QCOMPARE( logSystem->currentLogDevices().count(), 0 );

    delete lastlogger;
    delete lastlogger2;
}

void LoggerUnitTest::logBlob()
{
    QCA::Logger *logSystem = QCA::logger();

    QCOMPARE( logSystem->currentLogDevices().count(), 0 );

    QByteArray test( "abcd\x34" );
    logSystem->logBinaryMessage( test );

    LastLogger *lastlogger = new LastLogger;
    logSystem->registerLogDevice( lastlogger );
    QCOMPARE( logSystem->currentLogDevices().count(), 1 );
    QVERIFY( logSystem->currentLogDevices().contains( "last logger" ) );

    logSystem->logBinaryMessage( test );
    QCOMPARE( lastlogger->lastBlob(), test );
    QCOMPARE( lastlogger->lastBlobSeverity(),  QCA::Logger::Information );

    logSystem->logBinaryMessage( test, QCA::Logger::Critical );
    QCOMPARE( lastlogger->lastBlob(), test );
    QCOMPARE( lastlogger->lastBlobSeverity(),  QCA::Logger::Critical );

    LastLogger *lastlogger2 = new LastLogger;
    logSystem->registerLogDevice( lastlogger2 );
    QCOMPARE( logSystem->currentLogDevices().count(), 2 );
    QVERIFY( logSystem->currentLogDevices().contains( "last logger" ) );

    test += test;
    logSystem->logBinaryMessage(  test );
    QCOMPARE( lastlogger->lastBlob(), test );
    QCOMPARE( lastlogger->lastBlobSeverity(),  QCA::Logger::Information );
    QCOMPARE( lastlogger2->lastBlob(), test );
    QCOMPARE( lastlogger2->lastBlobSeverity(),  QCA::Logger::Information );

    logSystem->unregisterLogDevice( "last logger" ); // this will remove them both

    QCOMPARE( logSystem->currentLogDevices().count(), 0 );
    delete lastlogger;
    delete lastlogger2;

}

void LoggerUnitTest::logLevel()
{
    QCA::Logger *logSystem = QCA::logger();

    LastLogger *lastlogger = new LastLogger;
    logSystem->registerLogDevice( lastlogger );

    logSystem->setLevel (QCA::Logger::Error);
    QCOMPARE( logSystem->level (), QCA::Logger::Error );

    QCA_logTextMessage ( "Sending to system, checking that it is filtered out", QCA::Logger::Information );
    QEXPECT_FAIL("", "Should fail", Continue);
    QCOMPARE( lastlogger->lastMessage(),
              QString( "Sending to system, checking that it is filtered out" ) );

    QCA_logTextMessage ( "Sending to system, checking that it is not filtered out", QCA::Logger::Error );
    QCOMPARE( lastlogger->lastMessage(),
              QString( "Sending to system, checking that it is not filtered out" ) );

    logSystem->setLevel (QCA::Logger::Debug);

    delete lastlogger;
}

QTEST_MAIN(LoggerUnitTest)

#include "loggerunittest.moc"
