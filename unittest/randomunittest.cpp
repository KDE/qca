/**
 * randomunittest.cpp
 *
 * Copyright (C)  2004  Brad Hards <bradh@frogmouth.net>
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
#include "randomunittest.h"
#include "qca.h"

RandomUnitTest::RandomUnitTest()
    : Tester()
{

}

void RandomUnitTest::allTests()
{
    QCA::Initializer init;

    QCA::Random randObject;
    CHECK( randObject.nextByte() == randObject.nextByte(), false );
    CHECK( QCA::Random().nextByte() == QCA::Random().nextByte(), false );
    CHECK( randObject.nextBytes(4) == randObject.nextBytes(4), false );
    CHECK( randObject.randomChar() == randObject.randomChar(), false );
    CHECK( QCA::Random().randomChar() == QCA::Random().randomChar(), false );
    CHECK( QCA::Random().randomInt() == QCA::Random().randomInt(), false );
    CHECK( QCA::Random().randomArray(3) == QCA::Random().randomArray(3), false );

}

