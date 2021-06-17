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

#include <limits>

#ifdef QT_STATICPLUGIN
#include "import_plugins.h"
#endif

class TestClass1 : public QObject
{
    Q_OBJECT

public:
    TestClass1() {};
    TestClass1(const TestClass1 &)
        : QObject(nullptr) {};

public Q_SLOTS:
    void    voidMethod() {};
    QString qstringMethod()
    {
        return QString();
    };
    bool boolMethod(const QString &)
    {
        return true;
    };
    QString returnArg(const QString &s)
    {
        return s;
    };
    QByteArray returnArg(const QByteArray &a)
    {
        return a;
    };
    QString returnRepeatArg(const QString &s)
    {
        return QString(s + s);
    };
    QString tenArgs(const QString &s, int, int, int, int, int, int, int, int, int)
    {
        return QString(s);
    };
    QString elevenArgs(const QString &s, int, int, int, int, int, int, int, int, int, int)
    {
        return QString(s);
    };
};

Q_DECLARE_METATYPE(TestClass1)

class MetaTypeUnitTest : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void initTestCase();
    void cleanupTestCase();
    void returnTypeTest();
    void invokeMethodTest();

private:
    QCA::Initializer *m_init;
};

void MetaTypeUnitTest::initTestCase()
{
    m_init = new QCA::Initializer;
}

void MetaTypeUnitTest::cleanupTestCase()
{
    QCA::unloadAllPlugins();
    delete m_init;
}

void MetaTypeUnitTest::returnTypeTest()
{
    TestClass1        testClass1;
    QList<QByteArray> args;

#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    // returns a null type name because that is what void does...
    QCOMPARE(QMetaType::Void, QCA::methodReturnType(testClass1.metaObject(), QByteArray("voidMethod"), args));
    QCOMPARE(QMetaType::QString, QCA::methodReturnType(testClass1.metaObject(), QByteArray("qstringMethod"), args));

    // returns a null type, because args don't match
    QCOMPARE(QMetaType::UnknownType, QCA::methodReturnType(testClass1.metaObject(), QByteArray("boolMethod"), args));

    args << "QString";
    QCOMPARE(QMetaType::QString, QCA::methodReturnType(testClass1.metaObject(), QByteArray("returnArg"), args));
    QCOMPARE(QMetaType::Bool, QCA::methodReturnType(testClass1.metaObject(), QByteArray("boolMethod"), args));
    args.clear();

    args << "QByteArray";
    QCOMPARE(QMetaType::QByteArray, QCA::methodReturnType(testClass1.metaObject(), QByteArray("returnArg"), args));
    args.clear();

    args << "QString"
         << "int"
         << "int"
         << "int"
         << "int"
         << "int"
         << "int"
         << "int"
         << "int";

    // wrong number of arguments - has 9, needs 10
    QCOMPARE(QMetaType::UnknownType, QCA::methodReturnType(testClass1.metaObject(), QByteArray("tenArgs"), args));

    // match
    args << "int";
    QCOMPARE(QMetaType::QString, QCA::methodReturnType(testClass1.metaObject(), QByteArray("tenArgs"), args));

    args << "int";
    QCOMPARE(QMetaType::QString, QCA::methodReturnType(testClass1.metaObject(), QByteArray("elevenArgs"), args));
#else
    // returns a null type name because that is what void does...
    QCOMPARE(QByteArray("void"), QCA::methodReturnType(testClass1.metaObject(), QByteArray("voidMethod"), args));
    QCOMPARE(QByteArray("QString"), QCA::methodReturnType(testClass1.metaObject(), QByteArray("qstringMethod"), args));

    // returns a null type, because args don't match
    QCOMPARE(QByteArray(""), QCA::methodReturnType(testClass1.metaObject(), QByteArray("boolMethod"), args));

    args << "QString";
    QCOMPARE(QByteArray("QString"), QCA::methodReturnType(testClass1.metaObject(), QByteArray("returnArg"), args));
    QCOMPARE(QByteArray("bool"), QCA::methodReturnType(testClass1.metaObject(), QByteArray("boolMethod"), args));
    args.clear();

    args << "QByteArray";
    QCOMPARE(QByteArray("QByteArray"), QCA::methodReturnType(testClass1.metaObject(), QByteArray("returnArg"), args));
    args.clear();

    args << "QString"
         << "int"
         << "int"
         << "int"
         << "int"
         << "int"
         << "int"
         << "int"
         << "int";

    // wrong number of arguments - has 9, needs 10
    QCOMPARE(QByteArray(""), QCA::methodReturnType(testClass1.metaObject(), QByteArray("tenArgs"), args));

    // match
    args << "int";
    QCOMPARE(QByteArray("QString"), QCA::methodReturnType(testClass1.metaObject(), QByteArray("tenArgs"), args));

    args << "int";
    QCOMPARE(QByteArray("QString"), QCA::methodReturnType(testClass1.metaObject(), QByteArray("elevenArgs"), args));
#endif
}

void MetaTypeUnitTest::invokeMethodTest()
{
    TestClass1 * testClass1 = new TestClass1;
    QVariantList args;

    bool ret;
    ret = QCA::invokeMethodWithVariants(testClass1, QByteArray("voidMethod"), args, nullptr);
    QVERIFY(ret);

    ret = QCA::invokeMethodWithVariants(testClass1, QByteArray("noSuchMethod"), args, nullptr);
    QVERIFY(ret == false);

    QVariant stringRes;
    ret = QCA::invokeMethodWithVariants(testClass1, QByteArray("qstringMethod"), args, &stringRes);
    QVERIFY(ret);
    QVERIFY(stringRes.isValid());

    QVariant result(false);
    QString  fakeArg;
    args << fakeArg;
    ret = QCA::invokeMethodWithVariants(testClass1, QByteArray("boolMethod"), args, &result);
    QVERIFY(ret);
    QCOMPARE(result.toBool(), true);

    result = QByteArray();
    args.clear();
    QByteArray myArray("array");
    args << myArray;
    ret = QCA::invokeMethodWithVariants(testClass1, QByteArray("returnArg"), args, &result);
    QVERIFY(ret);
    QCOMPARE(result.toByteArray(), myArray);

    result = QString();
    args.clear();
    QString myString = QStringLiteral("test words");
    args << myString;
    ret = QCA::invokeMethodWithVariants(testClass1, QByteArray("returnArg"), args, &result);
    QVERIFY(ret);
    QCOMPARE(result.toString(), myString);

    ret = QCA::invokeMethodWithVariants(testClass1, QByteArray("returnRepeatArg"), args, &result);
    QVERIFY(ret);
    QCOMPARE(result.toString(), QString(myString + myString));

    // 9 arguments - no matching method
    result = QStringLiteral("unchanged");
    args << 0 << 0 << 0 << 0 << 0 << 0 << 0 << 0;
    ret = QCA::invokeMethodWithVariants(testClass1, QByteArray("tenArgs"), args, &result);
    QVERIFY(ret == false);
    QCOMPARE(result.toString(), QStringLiteral("unchanged"));

    // 10 args
    args << 0;
    ret = QCA::invokeMethodWithVariants(testClass1, QByteArray("tenArgs"), args, &result);
    QVERIFY(ret);
    QCOMPARE(result.toString(), myString);

    // 11 args
    result = QStringLiteral("unchanged");
    args << 0;
    ret = QCA::invokeMethodWithVariants(testClass1, QByteArray("elevenArgs"), args, &result);
    QVERIFY(ret == false);
    QCOMPARE(result.toString(), QStringLiteral("unchanged"));

    delete testClass1;
}

QTEST_MAIN(MetaTypeUnitTest)

#include "metatype.moc"
