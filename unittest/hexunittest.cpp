/**
 * hexunittest.cpp
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
#include "hexunittest.h"
#include <QtCrypto>

HexUnitTest::HexUnitTest()
    : Tester()
{

}


struct hexTestStruct {
    QString raw;
    QString encoded;
} hexTestValues[] = {
  { "abcd", "61626364" },
  { "ABCD", "41424344" },
  { "", "" },
  { "abcddef", "61626364646566" },
  { "\0", "" },   // Empty QString.
  { "\a", "07" }, // BEL
  { "\b", "08" }, // BS
  { "\t", "09" }, // HT
  { "\n", "0a" }, // LF
  { "\v", "0b" }, // VT
  { "\f", "0c" }, // FF
  { "\r", "0d" }, // CR
  { 0, 0 }
};

void HexUnitTest::allTests()
{
    QCA::Initializer init;

    QCA::Hex hexObject;
    QString result;
    for (int n = 0; hexTestValues[n].raw; n++) {
      result = hexObject.encodeString(hexTestValues[n].raw);
      CHECK( result, hexTestValues[n].encoded);
      result = hexObject.decodeString(hexTestValues[n].encoded);
      CHECK( result, hexTestValues[n].raw);
    }

    // test incremental updates
    hexObject.setup(QCA::Encode);
    hexObject.clear();
    QSecureArray result1 = hexObject.update(QSecureArray("ab"));
    CHECK( hexObject.ok(), true );
    CHECK( result1[0], '6' );
    CHECK( result1[1], '1' );
    CHECK( result1[2], '6' );
    CHECK( result1[3], '2' );
    QSecureArray result2 = hexObject.update(QSecureArray("cd"));
    CHECK( hexObject.ok(), true );
    CHECK( result2[0], '6' );
    CHECK( result2[1], '3' );
    CHECK( result2[2], '6' );
    CHECK( result2[3], '4' );
    CHECK( QSecureArray(), hexObject.final() );
    CHECK( hexObject.ok(), true );

    //test broken input
    hexObject.setup(QCA::Decode);
    hexObject.clear();
    hexObject.update(QSecureArray("-="));
    CHECK(hexObject.ok(), false);
}

