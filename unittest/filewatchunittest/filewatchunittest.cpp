/**
 * Copyright (C) 2006  Brad Hards <bradh@frogmouth.net>
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
#include "filewatchunittest.h"

#ifdef QT_STATICPLUGIN
#include "import_plugins.h"
#endif

void FileWatchUnitTest::initTestCase()
{
    m_init = new QCA::Initializer;
}

void FileWatchUnitTest::cleanupTestCase()
{
    delete m_init;
}

void FileWatchUnitTest::filewatchTest()
{
    QWARN("Unittest will take about 1 minute. Please wait.");

    QCA::FileWatch watcher;
    QCOMPARE( watcher.fileName(), QString() );

    QSignalSpy spy( &watcher, SIGNAL(changed()) );
    QVERIFY( spy.isValid() );
    QCOMPARE( spy.count(), 0 );

    QTemporaryFile *tempFile = new QTemporaryFile;

    tempFile->open();

    watcher.setFileName( tempFile->fileName() );
    QCOMPARE( watcher.fileName(), tempFile->fileName() );
    QTest::qWait(7000);
    QCOMPARE( spy.count(), 0 );
    tempFile->close();
    QTest::qWait(7000);
    QCOMPARE( spy.count(), 0 );

    tempFile->open();
    tempFile->write("foo");
    tempFile->flush();
    QTest::qWait(7000);
    QCOMPARE( spy.count(), 1 );

    tempFile->close();
    QTest::qWait(7000);

    QCOMPARE( spy.count(), 1 );

    tempFile->open();
    tempFile->write("foo");
    tempFile->flush();
    QTest::qWait(7000);
    QCOMPARE( spy.count(), 2 );

    tempFile->write("bar");
    tempFile->flush();
    QTest::qWait(7000);
    QCOMPARE( spy.count(), 3 );

    tempFile->close();
    QTest::qWait(7000);

    QCOMPARE( spy.count(), 3 );

    delete tempFile;
    QTest::qWait(7000);
    QCOMPARE( spy.count(), 4 );
    
}

QTEST_MAIN(FileWatchUnitTest)
