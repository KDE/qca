/**
 * base64unittest.cpp
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
#include "base64unittest.h"
#include <QtCrypto>

Base64UnitTest::Base64UnitTest()
    : Tester()
{

}


struct base64TestStruct {
    QString raw;
    QString encoded;
} base64TestValues[] = {
    { "31", "4d513d3d" },
    { "235c91", "49317952" },
    { "4142634452313236", "51554a6a524649784d6a593d" },
    { "241bb300a3989a620659", "4a42757a414b4f596d6d494757513d3d" },
    { "31323537374343666671333435337836", "4d5449314e7a644451325a6d63544d304e544e344e673d3d" },
    { "60e8e5ebb1a5eac95a01ec7f8796b2dce471", "594f6a6c3637476c36736c614165782f68356179334f5278" },
    { "31346d354f33313333372c31274d754e7354307050346231333a29", "4d5452744e55387a4d544d7a4e7977784a303131546e4e554d4842514e4749784d7a6f70" },
    { "", "" },
    { 0, 0 }
};

void Base64UnitTest::allTests()
{
    QCA::Initializer init;

    QCA::Base64 base64Object;
    QSecureArray encoded;
    for (int n = 0; base64TestValues[n].raw; n++) {
	encoded = base64Object.encode(QCA::hexToArray(base64TestValues[n].raw));
	CHECK( QCA::arrayToHex(encoded), base64TestValues[n].encoded);
	encoded = base64Object.decode(QCA::hexToArray(base64TestValues[n].encoded));
	CHECK( QCA::arrayToHex(encoded), base64TestValues[n].raw);
    }
}

