/**
 * cipherunittest.cpp
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
#include "cipherunittest.h"
#include <QtCrypto>

struct cipherTestValues {
    QCString plaintext;
    QCString ciphertext;
    QCString key;
};

struct cipherIVTestValues {
    QCString plaintext;
    QCString ciphertext;
    QCString key;
    QCString iv;
};

// These are from the Botan test suite
static struct cipherTestValues aes128ecbTestValues[] = {


    { "506812a45f08c889b97f5980038b8359",
      "d8f532538289ef7d06b506a4fd5be9c9",
      "00010203050607080a0b0c0d0f101112" },

    { "5c6d71ca30de8b8b00549984d2ec7d4b",
      "59ab30f4d4ee6e4ff9907ef65b1fb68c",
      "14151617191a1b1c1e1f202123242526" },

    { "53f3f4c64f8616e4e7c56199f48f21f6",
      "bf1ed2fcb2af3fd41443b56d85025cb1",
      "28292a2b2d2e2f30323334353738393a" },

    { "a1eb65a3487165fb0f1c27ff9959f703",
      "7316632d5c32233edcb0780560eae8b2",
      "3c3d3e3f41424344464748494b4c4d4e" },

    { "3553ecf0b1739558b08e350a98a39bfa",
      "408c073e3e2538072b72625e68b8364b",
      "50515253555657585a5b5c5d5f606162" },

    { "67429969490b9711ae2b01dc497afde8",
      "e1f94dfa776597beaca262f2f6366fea",
      "64656667696a6b6c6e6f707173747576" },

    { "93385c1f2aec8bed192f5a8e161dd508",
      "f29e986c6a1c27d7b29ffd7ee92b75f1",
      "78797a7b7d7e7f80828384858788898a" },

    { "3e23b3bc065bcc152407e23896d77783",
      "1959338344e945670678a5d432c90b93",
      "54555657595a5b5c5e5f606163646566" },

    { "79f0fba002be1744670e7e99290d8f52",
      "e49bddd2369b83ee66e6c75a1161b394",
      "68696a6b6d6e6f70727374757778797a" },

    { "da23fe9d5bd63e1d72e3dafbe21a6c2a",
      "d3388f19057ff704b70784164a74867d",
      "7c7d7e7f81828384868788898b8c8d8e" },

    { "e3f5698ba90b6a022efd7db2c7e6c823",
      "23aa03e2d5e4cd24f3217e596480d1e1",
      "a4a5a6a7a9aaabacaeafb0b1b3b4b5b6" },

    { "bdc2691d4f1b73d2700679c3bcbf9c6e",
      "c84113d68b666ab2a50a8bdb222e91b9",
      "e0e1e2e3e5e6e7e8eaebecedeff0f1f2" },

    { "ba74e02093217ee1ba1b42bd5624349a",
      "ac02403981cd4340b507963db65cb7b6",
      "08090a0b0d0e0f10121314151718191a" },

    { "b5c593b5851c57fbf8b3f57715e8f680",
      "8d1299236223359474011f6bf5088414",
      "6c6d6e6f71727374767778797b7c7d7e" },

    { 0, 0, 0 }
};

// These are from the Botan test suite
static struct cipherIVTestValues aes128cbcTestValues[] = {


    { "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
      "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7",
      "2b7e151628aed2a6abf7158809cf4f3c",
      "000102030405060708090a0b0c0d0e0f" },

    { 0, 0, 0, 0 }
};


// These are from the Botan test suite
static struct cipherIVTestValues aes128cfbTestValues[] = {

    { "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
      "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b26751f67a3cbb140b1808cf187a4f4dfc04b05357c5d1c0eeac4c66f9ff7f2e6",
      "2b7e151628aed2a6abf7158809cf4f3c",
      "000102030405060708090a0b0c0d0e0f" },

    { 0, 0, 0, 0 }
};

// These are from the Botan test suite
static struct cipherTestValues aes192ecbTestValues[] = {

    { "fec1c04f529bbd17d8cecfcc4718b17f",
      "62564c738f3efe186e1a127a0c4d3c61",
      "4a4b4c4d4f50515254555657595a5b5c5e5f606163646566" },
    { "32df99b431ed5dc5acf8caf6dc6ce475", 
      "07805aa043986eb23693e23bef8f3438",
      "68696a6b6d6e6f70727374757778797a7c7d7e7f81828384" },
    { "7fdc2b746f3f665296943b83710d1f82",
      "df0b4931038bade848dee3b4b85aa44b", 
      "868788898b8c8d8e90919293959697989a9b9c9d9fa0a1a2" },
    { "8fba1510a3c5b87e2eaa3f7a91455ca2", 
      "592d5fded76582e4143c65099309477c", 
      "a4a5a6a7a9aaabacaeafb0b1b3b4b5b6b8b9babbbdbebfc0" },
    { "2c9b468b1c2eed92578d41b0716b223b", 
      "c9b8d6545580d3dfbcdd09b954ed4e92", 
      "c2c3c4c5c7c8c9cacccdcecfd1d2d3d4d6d7d8d9dbdcddde" },
    { "0a2bbf0efc6bc0034f8a03433fca1b1a", 
      "5dccd5d6eb7c1b42acb008201df707a0", 
      "e0e1e2e3e5e6e7e8eaebecedeff0f1f2f4f5f6f7f9fafbfc" },
    { "25260e1f31f4104d387222e70632504b", 
      "a2a91682ffeb6ed1d34340946829e6f9", 
      "fefe01010304050608090a0b0d0e0f10121314151718191a" },
    { "c527d25a49f08a5228d338642ae65137", 
      "e45d185b797000348d9267960a68435d", 
      "1c1d1e1f21222324262728292b2c2d2e3031323335363738" },
    { "3b49fc081432f5890d0e3d87e884a69e", 
      "45e060dae5901cda8089e10d4f4c246b", 
      "3a3b3c3d3f40414244454647494a4b4c4e4f505153545556" },
    { "d173f9ed1e57597e166931df2754a083", 
      "f6951afacc0079a369c71fdcff45df50", 
      "58595a5b5d5e5f60626364656768696a6c6d6e6f71727374" },
    { "8c2b7cafa5afe7f13562daeae1adede0", 
      "9e95e00f351d5b3ac3d0e22e626ddad6", 
      "767778797b7c7d7e80818283858687888a8b8c8d8f909192" },
    { "aaf4ec8c1a815aeb826cab741339532c", 
      "9cb566ff26d92dad083b51fdc18c173c", 
      "94959697999a9b9c9e9fa0a1a3a4a5a6a8a9aaabadaeafb0" },
    { "40be8c5d9108e663f38f1a2395279ecf", 
      "c9c82766176a9b228eb9a974a010b4fb", 
      "d0d1d2d3d5d6d7d8dadbdcdddfe0e1e2e4e5e6e7e9eaebec" },
    { "0c8ad9bc32d43e04716753aa4cfbe351", 
      "d8e26aa02945881d5137f1c1e1386e88", 
      "2a2b2c2d2f30313234353637393a3b3c3e3f404143444546" },
    { "1407b1d5f87d63357c8dc7ebbaebbfee",
      "c0e024ccd68ff5ffa4d139c355a77c55",
      "48494a4b4d4e4f50525354555758595a5c5d5e5f61626364" },
    { 0, 0, 0 }
};

static struct cipherIVTestValues aes192cbcTestValues[] = {

    { "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
      "4f021db243bc633d7178183a9fa071e8b4d9ada9ad7dedf4e5e738763f69145a571b242012fb7ae07fa9baac3df102e008b0e27988598881d920a9e64f5615cd",
      "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
      "000102030405060708090a0b0c0d0e0f" },
    { 0, 0, 0, 0 }
};

// These are from the Botan test suite
static struct cipherIVTestValues aes192cfbTestValues[] = {

    { "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
      "cdc80d6fddf18cab34c25909c99a417467ce7f7f81173621961a2b70171d3d7a2e1e8a1dd59b88b1c8e60fed1efac4c9c05f9f9ca9834fa042ae8fba584b09ff",
      "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
      "000102030405060708090a0b0c0d0e0f" },

    { 0, 0, 0, 0 }
};


// These are from the Botan test suite
static struct cipherTestValues aes256ecbTestValues[] = {
    { "e51aa0b135dba566939c3b6359a980c5",
      "8cd9423dfc459e547155c5d1d522e540",
      "e0e1e2e3e5e6e7e8eaebecedeff0f1f2f4f5f6f7f9fafbfcfefe010103040506" },

    { "069a007fc76a459f98baf917fedf9521",
      "080e9517eb1677719acf728086040ae3",
      "08090a0b0d0e0f10121314151718191a1c1d1e1f21222324262728292b2c2d2e" },

    { "726165c1723fbcf6c026d7d00b091027",
      "7c1700211a3991fc0ecded0ab3e576b0",
      "30313233353637383a3b3c3d3f40414244454647494a4b4c4e4f505153545556" },
    
    { "d7c544de91d55cfcde1f84ca382200ce",
      "dabcbcc855839251db51e224fbe87435",
      "58595a5b5d5e5f60626364656768696a6c6d6e6f71727374767778797b7c7d7e" },
    
    { "fed3c9a161b9b5b2bd611b41dc9da357",
      "68d56fad0406947a4dd27a7448c10f1d",
      "80818283858687888a8b8c8d8f90919294959697999a9b9c9e9fa0a1a3a4a5a6" },
    
    { "4f634cdc6551043409f30b635832cf82",
      "da9a11479844d1ffee24bbf3719a9925",
      "a8a9aaabadaeafb0b2b3b4b5b7b8b9babcbdbebfc1c2c3c4c6c7c8c9cbcccdce" },
    
    { "109ce98db0dfb36734d9f3394711b4e6",
      "5e4ba572f8d23e738da9b05ba24b8d81",
      "d0d1d2d3d5d6d7d8dadbdcdddfe0e1e2e4e5e6e7e9eaebeceeeff0f1f3f4f5f6" },
    
    { "4ea6dfaba2d8a02ffdffa89835987242",
      "a115a2065d667e3f0b883837a6e903f8",
      "70717273757677787a7b7c7d7f80818284858687898a8b8c8e8f909193949596" },

    { "5ae094f54af58e6e3cdbf976dac6d9ef",
      "3e9e90dc33eac2437d86ad30b137e66e",
      "98999a9b9d9e9fa0a2a3a4a5a7a8a9aaacadaeafb1b2b3b4b6b7b8b9bbbcbdbe" },
    
    { "764d8e8e0f29926dbe5122e66354fdbe",
      "01ce82d8fbcdae824cb3c48e495c3692",
      "c0c1c2c3c5c6c7c8cacbcccdcfd0d1d2d4d5d6d7d9dadbdcdedfe0e1e3e4e5e6" },
    
    { "3f0418f888cdf29a982bf6b75410d6a9",
      "0c9cff163ce936faaf083cfd3dea3117",
      "e8e9eaebedeeeff0f2f3f4f5f7f8f9fafcfdfeff01020304060708090b0c0d0e" },
    
    { "e4a3e7cb12cdd56aa4a75197a9530220",
      "5131ba9bd48f2bba85560680df504b52",
      "10111213151617181a1b1c1d1f20212224252627292a2b2c2e2f303133343536" },
    
    { "211677684aac1ec1a160f44c4ebf3f26",
      "9dc503bbf09823aec8a977a5ad26ccb2",
      "38393a3b3d3e3f40424344454748494a4c4d4e4f51525354565758595b5c5d5e" },
    
    { "d21e439ff749ac8f18d6d4b105e03895",
      "9a6db0c0862e506a9e397225884041d7",
      "60616263656667686a6b6c6d6f70717274757677797a7b7c7e7f808183848586" },
    
    { "d9f6ff44646c4725bd4c0103ff5552a7",
      "430bf9570804185e1ab6365fc6a6860c",
      "88898a8b8d8e8f90929394959798999a9c9d9e9fa1a2a3a4a6a7a8a9abacadae" },
    
    { "0b1256c2a00b976250cfc5b0c37ed382",
      "3525ebc02f4886e6a5a3762813e8ce8a",
      "b0b1b2b3b5b6b7b8babbbcbdbfc0c1c2c4c5c6c7c9cacbcccecfd0d1d3d4d5d6" },
    
    { "b056447ffc6dc4523a36cc2e972a3a79",
      "07fa265c763779cce224c7bad671027b",
      "d8d9dadbdddedfe0e2e3e4e5e7e8e9eaecedeeeff1f2f3f4f6f7f8f9fbfcfdfe" },
    
    { "5e25ca78f0de55802524d38da3fe4456",
      "e8b72b4e8be243438c9fff1f0e205872",
      "00010203050607080a0b0c0d0f10111214151617191a1b1c1e1f202123242526" },
    
    { "a5bcf4728fa5eaad8567c0dc24675f83",
      "109d4f999a0e11ace1f05e6b22cbcb50",
      "28292a2b2d2e2f30323334353738393a3c3d3e3f41424344464748494b4c4d4e" },
    
    { "814e59f97ed84646b78b2ca022e9ca43",
      "45a5e8d4c3ed58403ff08d68a0cc4029",
      "50515253555657585a5b5c5d5f60616264656667696a6b6c6e6f707173747576" },
    
    { "15478beec58f4775c7a7f5d4395514d7",
      "196865964db3d417b6bd4d586bcb7634",
      "78797a7b7d7e7f80828384858788898a8c8d8e8f91929394969798999b9c9d9e" },
    
    { 0, 0, 0 }
};

static struct cipherIVTestValues aes256cbcTestValues[] = {

    { "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
      "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b",
      "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
      "000102030405060708090a0b0c0d0e0f" },

    { 0, 0, 0, 0 }
};

// These are from the Botan test suite
static struct cipherIVTestValues aes256cfbTestValues[] = {

    { "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
      "dc7e84bfda79164b7ecd8486985d386039ffed143b28b1c832113c6331e5407bdf10132415e54b92a13ed0a8267ae2f975a385741ab9cef82031623d55b1e471",
      "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
      "000102030405060708090a0b0c0d0e0f" },

    { 0, 0, 0, 0 }
};

// These are from the Botan test suite
static struct cipherTestValues blowfishTestValues[] = {

  { "0000000000000000", "245946885754369a", "0123456789abcdef" },
  { "0000000000000000", "4ef997456198dd78", "0000000000000000" },
  { "0000000000000000", "f21e9a77b71c49bc", "ffffffffffffffff" },
  { "004bd6ef09176062", "452031c1e4fada8e", "584023641aba6176" },
  { "0123456789abcdef", "0aceab0fc6a0a28d", "fedcba9876543210" },
  { "0123456789abcdef", "7d0cc630afda1ec7", "1111111111111111" },
  { "0123456789abcdef", "a790795108ea3cae", "1f1f1f1f0e0e0e0e" },
  { "0123456789abcdef", "c39e072d9fac631d", "e0fee0fef1fef1fe" },
  { "0123456789abcdef", "fa34ec4847b268b2", "0101010101010101" },
  { "01a1d6d039776742", "59c68245eb05282b", "7ca110454a1a6e57" },
  { "0248d43806f67172", "1730e5778bea1da4", "07a1133e4a0b2686" },
  { "02fe55778117f12a", "cf9c5d7a4986adb5", "49e95d6d4ca229bf" },
  { "059b5e0851cf143a", "48f4d0884c379918", "0113b970fd34f2ce" },
  { "072d43a077075292", "7a8e7bfa937e89a3", "4fb05e1515ab73a7" },
  { "0756d8e0774761d2", "432193b78951fc98", "0170f175468fb5e6" },
  { "1000000000000001", "7d856f9a613063f2", "3000000000000000" },
  { "1111111111111111", "2466dd878b963c9d", "1111111111111111" },
  { "1111111111111111", "61f9c3802281b096", "0123456789abcdef" },
  { "164d5e404f275232", "5f99d04f5b163969", "37d06bb516cb7546" },
  { "1d9d5c5018f728c2", "d1abb290658bc778", "018310dc409b26d6" },
  { "26955f6835af609a", "d887e0393c2da6e3", "04689104c2fd3b2f" },
  { "305532286d6f295a", "55cb3774d13ef201", "1c587f1c13924fef" },
  { "3bdd119049372802", "2eedda93ffd39c79", "07a7137045da2a16" },
  { "42fd443059577fa2", "353882b109ce8f1a", "04b915ba43feb5b6" },
  { "437540c8698f3cfa", "53c55f9cb49fc019", "49793ebc79b3258f" },
  { "480d39006ee762f2", "7555ae39f59b87bd", "025816164629b007" },
  { "51454b582ddf440a", "a25e7856cf2651eb", "3849674c2602319e" },
  { "5cd54ca83def57da", "b1b8cc0b250f09a0", "0131d9619dc1376e" },
  { "6b056e18759f5cca", "4a057a3b24d3977b", "1f08260d1ac2465e" },
  { "762514b829bf486a", "13f04154d69d1ae5", "43297fad38e373fe" },
  { "ffffffffffffffff", "014933e0cdaff6e4", "0000000000000000" },
  { "ffffffffffffffff", "51866fd5b85ecb8a", "ffffffffffffffff" },
  { "ffffffffffffffff", "6b5c5a9c5d9e0a5a", "fedcba9876543210" },
  { "0123456789abcdef1111111111111111", "7d0cc630afda1ec72466dd878b963c9d", "1111111111111111" },
  { "fedcba9876543210", "cc91732b8022f684", "57686f206973204a6f686e2047616c743f" },
  { "424c4f5746495348", "324ed0fef413a203", "6162636465666768696a6b6c6d6e6f707172737475767778797a" },
  { "fedcba9876543210", "f9ad597c49db005e", "f0" },
  { "fedcba9876543210", "e91d21c1d961a6d6", "f0e1" },
  { "fedcba9876543210", "e9c2b70a1bc65cf3", "f0e1d2" },
  { "fedcba9876543210", "be1e639408640f05", "f0e1d2c3" },
  { "fedcba9876543210", "b39e44481bdb1e6e", "f0e1d2c3b4" },
  { "fedcba9876543210", "9457aa83b1928c0d", "f0e1d2c3b4a5" },
  { "fedcba9876543210", "8bb77032f960629d", "f0e1d2c3b4a596" },
  { "fedcba9876543210", "e87a244e2cc85e82", "f0e1d2c3b4a59687" },
  { "fedcba9876543210", "15750e7a4f4ec577", "f0e1d2c3b4a5968778" },
  { "fedcba9876543210", "122ba70b3ab64ae0", "f0e1d2c3b4a596877869" },
  { "fedcba9876543210", "3a833c9affc537f6", "f0e1d2c3b4a5968778695a" },
  { "fedcba9876543210", "9409da87a90f6bf2", "f0e1d2c3b4a5968778695a4b" },
  { "fedcba9876543210", "884f80625060b8b4", "f0e1d2c3b4a5968778695a4b3c" },
  { "fedcba9876543210", "1f85031c19e11968", "f0e1d2c3b4a5968778695a4b3c2d" },
  { "fedcba9876543210", "79d9373a714ca34f", "f0e1d2c3b4a5968778695a4b3c2d1e" },
  { "fedcba9876543210", "93142887ee3be15c", "f0e1d2c3b4a5968778695a4b3c2d1e0f" },
  { "fedcba9876543210", "03429e838ce2d14b", "f0e1d2c3b4a5968778695a4b3c2d1e0f00" },
  { "fedcba9876543210", "a4299e27469ff67b", "f0e1d2c3b4a5968778695a4b3c2d1e0f0011" },
  { "fedcba9876543210", "afd5aed1c1bc96a8", "f0e1d2c3b4a5968778695a4b3c2d1e0f001122" },
  { "fedcba9876543210", "10851c0e3858da9f", "f0e1d2c3b4a5968778695a4b3c2d1e0f00112233" },
  { "fedcba9876543210", "e6f51ed79b9db21f", "f0e1d2c3b4a5968778695a4b3c2d1e0f0011223344" },
  { "fedcba9876543210", "64a6e14afd36b46f", "f0e1d2c3b4a5968778695a4b3c2d1e0f001122334455" },
  { "fedcba9876543210", "80c7d7d45a5479ad", "f0e1d2c3b4a5968778695a4b3c2d1e0f00112233445566" },
  { "fedcba9876543210", "05044b62fa52d080", "f0e1d2c3b4a5968778695a4b3c2d1e0f0011223344556677" },
  { 0, 0, 0 }
};

// These are from the Botan test suite
static struct cipherTestValues tripledesTestValues[] = {
// Botan includes these, but the key length is wrong. Beats me.
//  { "0123456789abcde7", "7f1d0a77826b8aff", "123456789abcdeffedcba9876543210" },
//  { "4e6f772069732074", "3fa40e8a984d4815", "123456789abcdef0123456789abcdef" },
//  { "42fd443059577fa2", "af37fb421f8c4095", "4b915ba43feb5b604b915ba43feb5b6" },

    { "42fd443059577fa2", "af37fb421f8c4095", "04b915ba43feb5b604b915ba43feb5b604b915ba43feb5b6" },
    { "736f6d6564617461", "18d748e563620572", "0123456789abcdef5555555555555555fedcba9876543210" },
    { "7371756967676c65", "c07d2a0fa566fa30", "0352020767208217860287665908219864056abdfea93457" },
    { "0123456789abcde7", "de0b7c06ae5e0ed5", "0123456789abcdeffedcba987654321089abcdef01234567" },
    { "0123456789abcde7", "7f1d0a77826b8aff", "0123456789abcdeffedcba98765432100123456789abcdef" },
    { "4115e551299a5c4b", "f7a0822fc310686c", "1ef743a68d629f68a5e3136c36ad7953a835cf849bb4ec3c" },
    { "d5ab44e0fe46e1b5", "02aed9bf72eca222", "b7d560be49c3936728ef0bf57b602d2eb7e5c631dd7f753e" },
    { "b4077dfdb721d88c", "f76aba838b1c4372", "d2d98706e9ab867647d244bdcdbcd5ef8b4dbc9cf4f35493" },
    { "890e98ab385fa1a1", "187087c77790c3b2", "153b963004101d12683e8f87116001b8c5526475510b5036" },
    { "02d5da6d5f247cd2", "89fc7df1e7913163", "45e4275dccc5d8b5a27993c16d9960ca939c023e2763216a" },
    { "5af9e5a3525e3f7d", "8fcc7a8bc337e484", "f6c2474b33934ea76e6c841d9b1e86e37189095a895a3e5a" },
    { "12864dde8e694bd1", "5b4dde8f000a5a9b", "5b4f6d3185efbae97d58ed9cc75e2bae655d2cefb2dd09cd" },
    { "0123456789abcde7", "c95744256a5ed31d", "0123456789abcdef0123456789abcdef0123456789abcdef" },
    { "68652074696d6520", "6a271787ab8883f9", "0123456789abcdef0123456789abcdef0123456789abcdef" },
    { "4e6f772069732074", "3fa40e8a984d4815", "0123456789abcdef0123456789abcdef0123456789abcdef" },
    { 0, 0, 0 }
};

// These are from the Botan test suite
static struct cipherTestValues desTestValues[] = {
  { "059b5e0851cf143a", "86a560f10ec6d85b", "0113b970fd34f2ce" },
  { "4e6f772069732074", "3fa40e8a984d4815", "0123456789abcdef" },
  { "666f7220616c6c20", "893d51ec4b563b53", "0123456789abcdef" },
  { "68652074696d6520", "6a271787ab8883f9", "0123456789abcdef" },
  { "5cd54ca83def57da", "7a389d10354bd271", "0131d9619dc1376e" },
  { "0756d8e0774761d2", "0cd3da020021dc09", "0170f175468fb5e6" },
  { "1d9d5c5018f728c2", "5f4c038ed12b2e41", "018310dc409b26d6" },
  { "480d39006ee762f2", "a1f9915541020b56", "025816164629b007" },
  { "26955f6835af609a", "5c513c9c4886c088", "04689104c2fd3b2f" },
  { "42fd443059577fa2", "af37fb421f8c4095", "04b915ba43feb5b6" },
  { "0248d43806f67172", "868ebb51cab4599a", "07a1133e4a0b2686" },
  { "3bdd119049372802", "dfd64a815caf1a0f", "07a7137045da2a16" },
  { "16393bcdd6560506", "9966adcfc53bf968", "0a3fddc8350aff39" },
  { "dc7fc6cf0358ecc0", "a47a7485661f7085", "10dd6dcd5c89e151" },
  { "305532286d6f295a", "63fac0d034d9f793", "1c587f1c13924fef" },
  { "f786d02413c574fc", "54c160d369f62ae3", "1eb00767bdee584e" },
  { "6b056e18759f5cca", "ef1bf03e5dfa575a", "1f08260d1ac2465e" },
  { "905ea29aeea26e07", "2292e9aebee6a4b6", "28ee445d8a21c534" },
  { "164d5e404f275232", "0a2aeeae3ff4ab77", "37d06bb516cb7546" },
  { "51454b582ddf440a", "7178876e01f19b2a", "3849674c2602319e" },
  { "68ff9d6068c71513", "84595f5b9d046132", "3cde816ef9ef8edb" },
  { "762514b829bf486a", "ea676b2cb7db2b7a", "43297fad38e373fe" },
  { "437540c8698f3cfa", "6fbf1cafcffd0556", "49793ebc79b3258f" },
  { "02fe55778117f12a", "5a6b612cc26cce4a", "49e95d6d4ca229bf" },
  { "1f508a50adb3d6e2", "470204969876604a", "4bb53ecfefb38dde" },
  { "072d43a077075292", "2f22e49bab7ca1ac", "4fb05e1515ab73a7" },
  { "004bd6ef09176062", "88bf0db6d70dee56", "584023641aba6176" },
  { "5aa1d62806ae0ead", "6db0f280fef2b564", "5f2b51f59e781d9c" },
  { "7e1b1c6776833772", "eb11cd3c72f7e90e", "699c920d7ce1e0b1" },
  { "5dbfb47c5f471136", "9c8b904d4d772be7", "7ac2fdeee4c79746" },
  { "01a1d6d039776742", "690f5b0d9a26939b", "7ca110454a1a6e57" },
  { "4de2f0926cf598d7", "ba107655991df529", "7fc92c3098ecf14a" },
  { "f45e6819e3108559", "f0c76ba556283b2f", "9ab645e268430854" },
  { "51d4eaaac6d76553", "bf3c6e8fd15ba861", "a6b0ae88f980011a" },
  { "6a89626ea8038511", "1067b36913cbcc47", "bafebafafeaeeaff" },
  { "7b0313c0d3a866f9", "e49e15e4f46f10e9", "bb2420b5fee5a6a1" },
  { "9d4a44aefce79965", "77b2ecc9278e9714", "bebafbeabaffeaaf" },
  { "59bcdfc253424cb5", "0a50abbbcd07061a", "c38c6f20230d9ed5" },
  { "d6c059a85ee2b13e", "25977533635beb5b", "c6f974504d954c7e" },
  { "f9e4821dfcaa5466", "48ec3a79399e9a00", "cb959b7ffd94f734" },
  { "35e8554bad60fb29", "993a3af0bc0d77a4", "cfb23034323cd19a" },
  { "9f97210d75b7e6df", "4729e3396e57ae4e", "d4d861035745f2c8" },
  { "ffffffffffffffff", "b5ce4f28fdeb21e8", "e36972fc4bec7587" },
  { "323837024123c918", "7f28bf28adfa1cf0", "e91a71a7ed5eb0ef" },
  { "37dfe527086af0a0", "5f53c6c87760256e", "ebbbbaebfbbefaba" },
  { "20678f45b5b8ac00", "7cc8ecf2638cc808", "ebbeeeaebbbbffff" },
  { "78481ed0c5a7c93e", "4ca3a08300ea6afc", "fbeaffeeffeeabab" },
  { "e2ccd415ac25412a", "bd85b3b659ab7276", "fd8a675c0ed08301" },
  // weak key
  { "cccc5bdfd9029507", "da57553d7d55775f", "ffffffffffffffff" },
  { "0000000000000000", "23083a3ca70dd027", "d5d44ff720683d0d" },
  { "0100000000000000", "6f353e3388abe2ef", "d5d44ff720683d0d" },
  //weak keys till next comment.
  { "95f8a5e5dd31d900", "8000000000000000", "0101010101010101" },
  { "95f8a5e5dd31d900", "8000000000000000", "0000000000000000" },
  { "dd7f121ca5015619", "4000000000000000", "0101010101010101" },
  { "2e8653104f3834ea", "2000000000000000", "0101010101010101" },
  { "4bd388ff6cd81d4f", "1000000000000000", "0101010101010101" },
  { "20b9e767b2fb1456", "0800000000000000", "0101010101010101" },
  { "20b9e767b2fb1456", "0800000000000000", "0001010101010100" },
  { "55579380d77138ef", "0400000000000000", "0101010101010101" },
  { "6cc5defaaf04512f", "0200000000000000", "0101010101010101" },
  { "0d9f279ba5d87260", "0100000000000000", "0101010101010101" },
  { "d9031b0271bd5a0a", "0080000000000000", "0101010101010101" },
  { "424250b37c3dd951", "0040000000000000", "0101010101010101" },
  { "b8061b7ecd9a21e5", "0020000000000000", "0101010101010101" },
  { "f15d0f286b65bd28", "0010000000000000", "0101010101010101" },
  { "add0cc8d6e5deba1", "0008000000000000", "0101010101010101" },
  { "e6d5f82752ad63d1", "0004000000000000", "0101010101010101" },
  { "ecbfe3bd3f591a5e", "0002000000000000", "0101010101010101" },
  { "f356834379d165cd", "0001000000000000", "0101010101010101" },
  { "2b9f982f20037fa9", "0000800000000000", "0101010101010101" },
  { "889de068a16f0be6", "0000400000000000", "0101010101010101" },
  { "e19e275d846a1298", "0000200000000000", "0101010101010101" },
  { "329a8ed523d71aec", "0000100000000000", "0101010101010101" },
  { "e7fce22557d23c97", "0000080000000000", "0101010101010101" },
  { "12a9f5817ff2d65d", "0000040000000000", "0101010101010101" },
  { "a484c3ad38dc9c19", "0000020000000000", "0101010101010101" },
  { "fbe00a8a1ef8ad72", "0000010000000000", "0101010101010101" },
  { "750d079407521363", "0000008000000000", "0101010101010101" },
  { "64feed9c724c2faf", "0000004000000000", "0101010101010101" },
  { "f02b263b328e2b60", "0000002000000000", "0101010101010101" },
  { "9d64555a9a10b852", "0000001000000000", "0101010101010101" },
  { "d106ff0bed5255d7", "0000000800000000", "0101010101010101" },
  { "e1652c6b138c64a5", "0000000400000000", "0101010101010101" },
  { "e428581186ec8f46", "0000000200000000", "0101010101010101" },
  { "aeb5f5ede22d1a36", "0000000100000000", "0101010101010101" },
  { "e943d7568aec0c5c", "0000000080000000", "0101010101010101" },
  { "df98c8276f54b04b", "0000000040000000", "0101010101010101" },
  { "b160e4680f6c696f", "0000000020000000", "0101010101010101" },
  { "fa0752b07d9c4ab8", "0000000010000000", "0101010101010101" },
  { "ca3a2b036dbc8502", "0000000008000000", "0101010101010101" },
  { "5e0905517bb59bcf", "0000000004000000", "0101010101010101" },
  { "814eeb3b91d90726", "0000000002000000", "0101010101010101" },
  { "4d49db1532919c9f", "0000000001000000", "0101010101010101" },
  { "25eb5fc3f8cf0621", "0000000000800000", "0101010101010101" },
  { "ab6a20c0620d1c6f", "0000000000400000", "0101010101010101" },
  { "79e90dbc98f92cca", "0000000000200000", "0101010101010101" },
  { "866ecedd8072bb0e", "0000000000100000", "0101010101010101" },
  { "8b54536f2f3e64a8", "0000000000080000", "0101010101010101" },
  { "ea51d3975595b86b", "0000000000040000", "0101010101010101" },
  { "caffc6ac4542de31", "0000000000020000", "0101010101010101" },
  { "8dd45a2ddf90796c", "0000000000010000", "0101010101010101" },
  { "1029d55e880ec2d0", "0000000000008000", "0101010101010101" },
  { "5d86cb23639dbea9", "0000000000004000", "0101010101010101" },
  { "1d1ca853ae7c0c5f", "0000000000002000", "0101010101010101" },
  { "ce332329248f3228", "0000000000001000", "0101010101010101" },
  { "8405d1abe24fb942", "0000000000000800", "0101010101010101" },
  { "e643d78090ca4207", "0000000000000400", "0101010101010101" },
  { "48221b9937748a23", "0000000000000200", "0101010101010101" },
  { "dd7c0bbd61fafd54", "0000000000000100", "0101010101010101" },
  { "2fbc291a570db5c4", "0000000000000080", "0101010101010101" },
  { "e07c30d7e4e26e12", "0000000000000040", "0101010101010101" },
  { "0953e2258e8e90a1", "0000000000000020", "0101010101010101" },
  { "5b711bc4ceebf2ee", "0000000000000010", "0101010101010101" },
  { "cc083f1e6d9e85f6", "0000000000000008", "0101010101010101" },
  { "d2fd8867d50d2dfe", "0000000000000004", "0101010101010101" },
  { "06e7ea22ce92708f", "0000000000000002", "0101010101010101" },
  { "166b40b44aba4bd6", "0000000000000001", "0101010101010101" },
  { "0000000000000000", "95a8d72813daa94d", "8001010101010101" },
  { "0000000000000000", "0eec1487dd8c26d5", "4001010101010101" },
  { "0000000000000000", "7ad16ffb79c45926", "2001010101010101" },
  { "0000000000000000", "d3746294ca6a6cf3", "1001010101010101" },
  { "0000000000000000", "809f5f873c1fd761", "0801010101010101" },
  { "0000000000000000", "c02faffec989d1fc", "0401010101010101" },
  { "0000000000000000", "4615aa1d33e72f10", "0201010101010101" },
  { "0000000000000000", "2055123350c00858", "0180010101010101" },
  { "0000000000000000", "df3b99d6577397c8", "0140010101010101" },
  { "0000000000000000", "31fe17369b5288c9", "0120010101010101" },
  { "0000000000000000", "dfdd3cc64dae1642", "0110010101010101" },
  { "0000000000000000", "178c83ce2b399d94", "0108010101010101" },
  { "0000000000000000", "50f636324a9b7f80", "0104010101010101" },
  { "0000000000000000", "a8468ee3bc18f06d", "0102010101010101" },
  { "0000000000000000", "a2dc9e92fd3cde92", "0101800101010101" },
  { "0000000000000000", "cac09f797d031287", "0101400101010101" },
  { "0000000000000000", "90ba680b22aeb525", "0101200101010101" },
  { "0000000000000000", "ce7a24f350e280b6", "0101100101010101" },
  { "0000000000000000", "882bff0aa01a0b87", "0101080101010101" },
  { "0000000000000000", "25610288924511c2", "0101040101010101" },
  { "0000000000000000", "c71516c29c75d170", "0101020101010101" },
  { "0000000000000000", "5199c29a52c9f059", "0101018001010101" },
  { "0000000000000000", "c22f0a294a71f29f", "0101014001010101" },
  { "0000000000000000", "ee371483714c02ea", "0101012001010101" },
  { "0000000000000000", "a81fbd448f9e522f", "0101011001010101" },
  { "0000000000000000", "4f644c92e192dfed", "0101010801010101" },
  { "0000000000000000", "1afa9a66a6df92ae", "0101010401010101" },
  { "0000000000000000", "b3c1cc715cb879d8", "0101010201010101" },
  { "0000000000000000", "19d032e64ab0bd8b", "0101010180010101" },
  { "0000000000000000", "3cfaa7a7dc8720dc", "0101010140010101" },
  { "0000000000000000", "b7265f7f447ac6f3", "0101010120010101" },
  { "0000000000000000", "9db73b3c0d163f54", "0101010110010101" },
  { "0000000000000000", "8181b65babf4a975", "0101010108010101" },
  { "0000000000000000", "93c9b64042eaa240", "0101010104010101" },
  { "0000000000000000", "5570530829705592", "0101010102010101" },
  { "0000000000000000", "8638809e878787a0", "0101010101800101" },
  { "0000000000000000", "41b9a79af79ac208", "0101010101400101" },
  { "0000000000000000", "7a9be42f2009a892", "0101010101200101" },
  { "0000000000000000", "29038d56ba6d2745", "0101010101100101" },
  { "0000000000000000", "5495c6abf1e5df51", "0101010101080101" },
  { "0000000000000000", "ae13dbd561488933", "0101010101040101" },
  { "0000000000000000", "024d1ffa8904e389", "0101010101020101" },
  { "0000000000000000", "d1399712f99bf02e", "0101010101018001" },
  { "0000000000000000", "14c1d7c1cffec79e", "0101010101014001" },
  { "0000000000000000", "1de5279dae3bed6f", "0101010101012001" },
  { "0000000000000000", "e941a33f85501303", "0101010101011001" },
  { "0000000000000000", "da99dbbc9a03f379", "0101010101010801" },
  { "0000000000000000", "b7fc92f91d8e92e9", "0101010101010401" },
  { "0000000000000000", "ae8e5caa3ca04e85", "0101010101010201" },
  { "0000000000000000", "9cc62df43b6eed74", "0101010101010180" },
  { "0000000000000000", "d863dbb5c59a91a0", "0101010101010140" },
  { "0000000000000000", "a1ab2190545b91d7", "0101010101010120" },
  { "0000000000000000", "0875041e64c570f7", "0101010101010110" },
  { "0000000000000000", "5a594528bebef1cc", "0101010101010108" },
  { "0000000000000000", "fcdb3291de21f0c0", "0101010101010104" },
  { "0000000000000000", "869efd7f9f265a09", "0101010101010102" },
  //end of weak keys
  { "0000000000000000", "88d55e54f54c97b4", "1046913489980131" },
  { "0000000000000000", "0c0cc00c83ea48fd", "1007103489988020" },
  { "0000000000000000", "83bc8ef3a6570183", "10071034c8980120" },
  { "0000000000000000", "df725dcad94ea2e9", "1046103489988020" },
  { "0000000000000000", "e652b53b550be8b0", "1086911519190101" },
  { "0000000000000000", "af527120c485cbb0", "1086911519580101" },
  { "0000000000000000", "0f04ce393db926d5", "5107b01519580101" },
  { "0000000000000000", "c9f00ffc74079067", "1007b01519190101" },
  { "0000000000000000", "7cfd82a593252b4e", "3107915498080101" },
  { "0000000000000000", "cb49a2f9e91363e3", "3107919498080101" },
  { "0000000000000000", "00b588be70d23f56", "10079115b9080140" },
  { "0000000000000000", "406a9a6ab43399ae", "3107911598090140" },
  { "0000000000000000", "6cb773611dca9ada", "1007d01589980101" },
  { "0000000000000000", "67fd21c17dbb5d70", "9107911589980101" },
  { "0000000000000000", "9592cb4110430787", "9107d01589190101" },
  { "0000000000000000", "a6b7ff68a318ddd3", "1007d01598980120" },
  { "0000000000000000", "4d102196c914ca16", "1007940498190101" },
  { "0000000000000000", "2dfa9f4573594965", "0107910491190401" },
  { "0000000000000000", "b46604816c0e0774", "0107910491190101" },
  { "0000000000000000", "6e7e6221a4f34e87", "0107940491190401" },
  { "0000000000000000", "aa85e74643233199", "19079210981a0101" },
  { "0000000000000000", "2e5a19db4d1962d6", "1007911998190801" },
  { "0000000000000000", "23a866a809d30894", "10079119981a0801" },
  { "0000000000000000", "d812d961f017d320", "1007921098190101" },
  { "0000000000000000", "055605816e58608f", "100791159819010b" },
  { "0000000000000000", "abd88e8b1b7716f1", "1004801598190101" },
  { "0000000000000000", "537ac95be69da1e1", "1004801598190102" },
  { "0000000000000000", "aed0f6ae3c25cdd8", "1004801598190108" },
  { "0000000000000000", "b3e35a5ee53e7b8d", "1002911598100104" },
  { "0000000000000000", "61c79c71921a2ef8", "1002911598190104" },
  { "0000000000000000", "e2f5728f0995013c", "1002911598100201" },
  { "0000000000000000", "1aeac39a61f0a464", "1002911698100101" },
  { "059b5e0851cf143a", "86a560f10ec6d85b", "0113b970fd34f2ce" },
  { "4e6f772069732074", "3fa40e8a984d4815", "0123456789abcdef" },
  { 0, 0, 0 }
};


CipherUnitTest::CipherUnitTest()
    : Tester()
{
}

void CipherUnitTest::allTests()
{
    QCA::Initializer init;

    if (!QCA::isSupported("aes128") )
	SKIP("AES128 not supported!");
    else {
	QCA::SymmetricKey key1(QCA::hexToArray( "00010203050607080A0B0C0D0F101112" ) );
	QCA::AES128 cipherObj1(QCA::Cipher::ECB, QCA::Encode, key1, QCA::InitializationVector(), QCA::Cipher::NoPadding );
	QSecureArray inter = cipherObj1.update( QCA::hexToArray( "506812A45F08C889B97F5980038B8359" ) );
	CHECK( QCA::arrayToHex( inter ), QString( "d8f532538289ef7d06b506a4fd5be9c9") );
	CHECK( QCA::arrayToHex( cipherObj1.final() ), QString( "" ) );

	CHECK( cipherObj1.blockSize(), (unsigned)16 );

	// From the NIST rijndael-vals.zip set, see ecb_iv.txt
	QCA::SymmetricKey key2(QCA::hexToArray( "000102030405060708090A0B0C0D0E0F" ) );
	QCA::AES128 cipherObj2(QCA::Cipher::ECB, QCA::Encode, key2, QCA::InitializationVector(), QCA::Cipher::NoPadding );
	CHECK( QCA::arrayToHex( cipherObj2.update( QCA::hexToArray( "000102030405060708090A0B0C0D0E0F" ) ) ),
	       QString( "0a940bb5416ef045f1c39458c653ea5a" ) );
	CHECK( QCA::arrayToHex( cipherObj2.final() ), QString( "" ) );

	// From the NIST rijndael-vals.zip set, see ecb_iv.txt
	QCA::AES128 cipherObj3(QCA::Cipher::ECB, QCA::Decode, key2, QCA::InitializationVector(), QCA::Cipher::NoPadding );
	CHECK( QCA::arrayToHex( cipherObj3.update( QCA::hexToArray( "0A940BB5416EF045F1C39458C653EA5A" ) ) ),
	       QString("000102030405060708090a0b0c0d0e0f" ) );
	CHECK( QCA::arrayToHex( cipherObj3.final() ), QString( "" ) );

	// From FIPS-197 Annex C.1
	QCA::AES128 cipherObj4(QCA::Cipher::ECB, QCA::Encode, key2, QCA::InitializationVector(), QCA::Cipher::NoPadding );
	CHECK( QCA::arrayToHex( cipherObj4.update( QCA::hexToArray( "00112233445566778899aabbccddeeff" ) ) ),
	       QString("69c4e0d86a7b0430d8cdb78070b4c55a" ) );
	CHECK( QCA::arrayToHex( cipherObj4.final() ), QString( "" ) );

	// From FIPS-197 Annex C.1
	QCA::AES128 cipherObj5(QCA::Cipher::ECB, QCA::Decode, key2, QCA::InitializationVector(), QCA::Cipher::NoPadding );

	CHECK( QCA::arrayToHex( cipherObj5.update( QCA::hexToArray( "69c4e0d86a7b0430d8cdb78070b4c55a" ) ) ),
	       QString( "00112233445566778899aabbccddeeff" ) );
	CHECK( QCA::arrayToHex( cipherObj5.final() ), QString( "" ) );

	for (int n = 0; aes128ecbTestValues[n].plaintext; n++) {
	    QCA::SymmetricKey key( QCA::hexToArray( aes128ecbTestValues[n].key ) );
	    QCA::AES128 forwardCipher( QCA::Cipher::ECB, QCA::Encode, key, QCA::InitializationVector(), QCA::Cipher::NoPadding );
	    CHECK( QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( aes128ecbTestValues[n].plaintext ) ) ),
		   QString( aes128ecbTestValues[n].ciphertext ) );
	    CHECK( forwardCipher.ok(), true );
	    CHECK( QCA::arrayToHex( forwardCipher.final() ), QString( "" ) );
	    CHECK( forwardCipher.ok(), true );

	    QCA::AES128 reverseCipher( QCA::Cipher::ECB, QCA::Decode, key, QCA::InitializationVector(), QCA::Cipher::NoPadding );

	    CHECK( QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( aes128ecbTestValues[n].ciphertext ) ) ),
		   QString( aes128ecbTestValues[n].plaintext ) );
	    CHECK( reverseCipher.ok(), true );
	    CHECK( QCA::arrayToHex( reverseCipher.final() ), QString( "" ) );
	    CHECK( reverseCipher.ok(), true );
        }

	for (int n = 0; aes128cbcTestValues[n].plaintext; n++) {
	    QCA::SymmetricKey key( QCA::hexToArray( aes128cbcTestValues[n].key ) );
	    QCA::InitializationVector iv( QCA::hexToArray( aes128cbcTestValues[n].iv ) );
	    QCA::AES128 forwardCipher( QCA::Cipher::CBC, QCA::Encode, key, iv, QCA::Cipher::NoPadding );
	    CHECK( QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( aes128cbcTestValues[n].plaintext ) ) ),
		   QString( aes128cbcTestValues[n].ciphertext ) );
	    CHECK( forwardCipher.ok(), true );
	    CHECK( QCA::arrayToHex( forwardCipher.final() ), QString( "" ) );
	    CHECK( forwardCipher.ok(), true );

	    QCA::AES128 reverseCipher( QCA::Cipher::CBC, QCA::Decode, key, iv, QCA::Cipher::NoPadding );

	    CHECK( QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( aes128cbcTestValues[n].ciphertext ) ) ),
		   QString( aes128cbcTestValues[n].plaintext ) );
	    CHECK( reverseCipher.ok(), true );
	    CHECK( QCA::arrayToHex( reverseCipher.final() ), QString( "" ) );
	    CHECK( reverseCipher.ok(), true );
        }

	for (int n = 0; aes128cfbTestValues[n].plaintext; n++) {
	    QCA::SymmetricKey key( QCA::hexToArray( aes128cfbTestValues[n].key ) );
	    QCA::InitializationVector iv( QCA::hexToArray( aes128cfbTestValues[n].iv ) );
	    QCA::AES128 forwardCipher( QCA::Cipher::CFB, QCA::Encode, key, iv, QCA::Cipher::NoPadding );
	    CHECK( QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( aes128cfbTestValues[n].plaintext ) ) ),
		   QString( aes128cfbTestValues[n].ciphertext ) );
	    CHECK( forwardCipher.ok(), true );
	    CHECK( QCA::arrayToHex( forwardCipher.final() ), QString( "" ) );
	    CHECK( forwardCipher.ok(), true );

	    QCA::AES128 reverseCipher( QCA::Cipher::CFB, QCA::Decode, key, iv, QCA::Cipher::NoPadding );

	    CHECK( QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( aes128cfbTestValues[n].ciphertext ) ) ),
		   QString( aes128cfbTestValues[n].plaintext ) );
	    CHECK( reverseCipher.ok(), true );
	    CHECK( QCA::arrayToHex( reverseCipher.final() ), QString( "" ) );
	    CHECK( reverseCipher.ok(), true );
        }
    }

    if (!QCA::isSupported("aes192") )
	SKIP("AES192 not supported!");
    else {
	// FIPS 197, Appendix C.2
	QCA::SymmetricKey key1(QCA::hexToArray( "000102030405060708090A0B0C0D0E0F1011121314151617" ) );
	QCA::AES192 cipherObj1(QCA::Cipher::ECB, QCA::Encode, key1, QCA::InitializationVector(), QCA::Cipher::NoPadding );
	QSecureArray data1 = QCA::hexToArray( "00112233445566778899AABBCCDDEEFF" );
	CHECK( QCA::arrayToHex( cipherObj1.update( data1 ) ), QString( "dda97ca4864cdfe06eaf70a0ec0d7191") );
	CHECK( cipherObj1.ok(), true );
	CHECK( QCA::arrayToHex( cipherObj1.final() ), QString( "" ) );
	CHECK( cipherObj1.ok(), true );

	CHECK( cipherObj1.blockSize(), (unsigned)16 );

	QCA::AES192 cipherObj2(QCA::Cipher::ECB, QCA::Decode, key1, QCA::InitializationVector(), QCA::Cipher::NoPadding );

	CHECK( QCA::arrayToHex(	cipherObj2.update( QCA::hexToArray( "dda97ca4864cdfe06eaf70a0ec0d7191") ) ),
	       QString( "00112233445566778899aabbccddeeff" ) );
	CHECK( cipherObj2.ok(), true );
	CHECK( QCA::arrayToHex( cipherObj2.final() ), QString( "" ) );
	CHECK( cipherObj2.ok(), true );

	for (int n = 0; aes192ecbTestValues[n].plaintext; n++) {
	    QCA::SymmetricKey key( QCA::hexToArray( aes192ecbTestValues[n].key ) );
	    QCA::AES192 forwardCipher( QCA::Cipher::ECB, QCA::Encode, key, QCA::InitializationVector(), QCA::Cipher::NoPadding );
	    CHECK( QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( aes192ecbTestValues[n].plaintext ) ) ),
		   QString( aes192ecbTestValues[n].ciphertext ) );
	    CHECK( forwardCipher.ok(), true );
	    CHECK( QCA::arrayToHex( forwardCipher.final() ), QString( "" ) );
	    CHECK( forwardCipher.ok(), true );

	    QCA::AES192 reverseCipher( QCA::Cipher::ECB, QCA::Decode, key, QCA::InitializationVector(), QCA::Cipher::NoPadding );

	    CHECK( QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( aes192ecbTestValues[n].ciphertext ) ) ),
		   QString( aes192ecbTestValues[n].plaintext ) );
	    CHECK( reverseCipher.ok(), true );
	    CHECK( QCA::arrayToHex( reverseCipher.final() ), QString( "" ) );
	    CHECK( reverseCipher.ok(), true );
        }

	for (int n = 0; aes192cbcTestValues[n].plaintext; n++) {
	    QCA::SymmetricKey key( QCA::hexToArray( aes192cbcTestValues[n].key ) );
	    QCA::InitializationVector iv( QCA::hexToArray( aes192cbcTestValues[n].iv ) );
	    QCA::AES192 forwardCipher( QCA::Cipher::CBC, QCA::Encode, key, iv, QCA::Cipher::NoPadding );
	    CHECK( QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( aes192cbcTestValues[n].plaintext ) ) ),
		   QString( aes192cbcTestValues[n].ciphertext ) );
	    CHECK( forwardCipher.ok(), true );
	    CHECK( QCA::arrayToHex( forwardCipher.final() ), QString( "" ) );
	    CHECK( forwardCipher.ok(), true );

	    QCA::AES192 reverseCipher( QCA::Cipher::CBC, QCA::Decode, key, iv, QCA::Cipher::NoPadding );

	    CHECK( QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( aes192cbcTestValues[n].ciphertext ) ) ),
		   QString( aes192cbcTestValues[n].plaintext ) );
	    CHECK( reverseCipher.ok(), true );
	    CHECK( QCA::arrayToHex( reverseCipher.final() ), QString( "" ) );
	    CHECK( reverseCipher.ok(), true );
        }

	for (int n = 0; aes192cfbTestValues[n].plaintext; n++) {
	    QCA::SymmetricKey key( QCA::hexToArray( aes192cfbTestValues[n].key ) );
	    QCA::InitializationVector iv( QCA::hexToArray( aes192cfbTestValues[n].iv ) );
	    QCA::AES192 forwardCipher( QCA::Cipher::CFB, QCA::Encode, key, iv, QCA::Cipher::NoPadding );
	    CHECK( QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( aes192cfbTestValues[n].plaintext ) ) ),
		   QString( aes192cfbTestValues[n].ciphertext ) );
	    CHECK( forwardCipher.ok(), true );
	    CHECK( QCA::arrayToHex( forwardCipher.final() ), QString( "" ) );
	    CHECK( forwardCipher.ok(), true );

	    QCA::AES192 reverseCipher( QCA::Cipher::CFB, QCA::Decode, key, iv, QCA::Cipher::NoPadding );

	    CHECK( QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( aes192cfbTestValues[n].ciphertext ) ) ),
		   QString( aes192cfbTestValues[n].plaintext ) );
	    CHECK( reverseCipher.ok(), true );
	    CHECK( QCA::arrayToHex( reverseCipher.final() ), QString( "" ) );
	    CHECK( reverseCipher.ok(), true );
        }
    }


    if (!QCA::isSupported("aes256") )
	SKIP("AES256 not supported!");
    else {
	// FIPS 197, Appendix C.3
	QCA::SymmetricKey key1(QCA::hexToArray( "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F" ) );
	QCA::AES256 cipherObj1(QCA::Cipher::ECB, QCA::Encode, key1, QCA::InitializationVector(), QCA::Cipher::NoPadding );
	QSecureArray data1 = QCA::hexToArray( "00112233445566778899AABBCCDDEEFF" );
	CHECK( QCA::arrayToHex( cipherObj1.update( data1 ) ), QString( "8ea2b7ca516745bfeafc49904b496089") );
	CHECK( cipherObj1.ok(), true );
	CHECK( QCA::arrayToHex( cipherObj1.final() ), QString( "" ) );
	CHECK( cipherObj1.ok(), true );

	CHECK( cipherObj1.blockSize(), (unsigned)16 );

	QCA::AES256 cipherObj2(QCA::Cipher::ECB, QCA::Decode, key1, QCA::InitializationVector(), QCA::Cipher::NoPadding );
	CHECK( QCA::arrayToHex( cipherObj2.update( QCA::hexToArray( "8EA2B7CA516745BFEAFC49904B496089") ) ),
	       QString( "00112233445566778899aabbccddeeff" ) );
	CHECK( cipherObj2.ok(), true );
	CHECK( QCA::arrayToHex( cipherObj2.final() ), QString( "" ) );
	CHECK( cipherObj2.ok(), true );

	for (int n = 0; aes256ecbTestValues[n].plaintext; n++) {
	    QCA::SymmetricKey key( QCA::hexToArray( aes256ecbTestValues[n].key ) );
	    QCA::AES256 forwardCipher( QCA::Cipher::ECB, QCA::Encode, key, QCA::InitializationVector(), QCA::Cipher::NoPadding );
	    CHECK( QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( aes256ecbTestValues[n].plaintext ) ) ),
		   QString( aes256ecbTestValues[n].ciphertext ) );
	    CHECK( forwardCipher.ok(), true );
	    CHECK( QCA::arrayToHex( forwardCipher.final() ), QString( "" ) );
	    CHECK( forwardCipher.ok(), true );

	    QCA::AES256 reverseCipher( QCA::Cipher::ECB, QCA::Decode, key, QCA::InitializationVector(), QCA::Cipher::NoPadding );

	    CHECK( QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( aes256ecbTestValues[n].ciphertext ) ) ),
		   QString( aes256ecbTestValues[n].plaintext ) );
	    CHECK( reverseCipher.ok(), true );
	    CHECK( QCA::arrayToHex( reverseCipher.final() ), QString( "" ) );
	    CHECK( reverseCipher.ok(), true );
        }

	for (int n = 0; aes256cbcTestValues[n].plaintext; n++) {
	    QCA::SymmetricKey key( QCA::hexToArray( aes256cbcTestValues[n].key ) );
	    QCA::InitializationVector iv( QCA::hexToArray( aes256cfbTestValues[n].iv ) );
	    QCA::AES256 forwardCipher( QCA::Cipher::CBC, QCA::Encode, key, iv, QCA::Cipher::NoPadding );
	    CHECK( QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( aes256cbcTestValues[n].plaintext ) ) ),
		   QString( aes256cbcTestValues[n].ciphertext ) );
	    CHECK( forwardCipher.ok(), true );
	    CHECK( QCA::arrayToHex( forwardCipher.final() ), QString( "" ) );
	    CHECK( forwardCipher.ok(), true );

	    QCA::AES256 reverseCipher( QCA::Cipher::CBC, QCA::Decode, key, iv, QCA::Cipher::NoPadding );

	    CHECK( QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( aes256cbcTestValues[n].ciphertext ) ) ),
		   QString( aes256cbcTestValues[n].plaintext ) );
	    CHECK( reverseCipher.ok(), true );
	    CHECK( QCA::arrayToHex( reverseCipher.final() ), QString( "" ) );
	    CHECK( reverseCipher.ok(), true );
        }

	for (int n = 0; aes256cfbTestValues[n].plaintext; n++) {
	    QCA::SymmetricKey key( QCA::hexToArray( aes256cfbTestValues[n].key ) );
	    QCA::InitializationVector iv( QCA::hexToArray( aes256cfbTestValues[n].iv ) );
	    QCA::AES256 forwardCipher( QCA::Cipher::CFB, QCA::Encode, key, iv, QCA::Cipher::NoPadding );
	    CHECK( QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( aes256cfbTestValues[n].plaintext ) ) ),
		   QString( aes256cfbTestValues[n].ciphertext ) );
	    CHECK( forwardCipher.ok(), true );
	    CHECK( QCA::arrayToHex( forwardCipher.final() ), QString( "" ) );
	    CHECK( forwardCipher.ok(), true );

	    QCA::AES256 reverseCipher( QCA::Cipher::CFB, QCA::Decode, key, iv, QCA::Cipher::NoPadding );

	    CHECK( QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( aes256cfbTestValues[n].ciphertext ) ) ),
		   QString( aes256cfbTestValues[n].plaintext ) );
	    CHECK( reverseCipher.ok(), true );
	    CHECK( QCA::arrayToHex( reverseCipher.final() ), QString( "" ) );
	    CHECK( reverseCipher.ok(), true );
        }
    }

    if (!QCA::isSupported("tripledes") )
	SKIP("Triple DES not supported!");
    else {
	QCA::TripleDES cipherObj1( QCA::Cipher::ECB, QCA::Encode, QCA::SymmetricKey( 24 ) );
	CHECK( cipherObj1.keyLength().minimum(), 24 );
	CHECK( cipherObj1.keyLength().maximum(), 24 );
	CHECK( cipherObj1.blockSize(), (unsigned)8 );

	for (int n = 0; tripledesTestValues[n].plaintext; n++) {
	    QCA::SymmetricKey key( QCA::hexToArray( tripledesTestValues[n].key ) );
	    QCA::TripleDES forwardCipher( QCA::Cipher::ECB, QCA::Encode, key, QCA::InitializationVector(), QCA::Cipher::NoPadding );
	    CHECK( QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( tripledesTestValues[n].plaintext ) ) ),
		   QString( tripledesTestValues[n].ciphertext ) );
	    CHECK( forwardCipher.ok(), true );
	    CHECK( QCA::arrayToHex( forwardCipher.final() ), QString( "" ) );
	    CHECK( forwardCipher.ok(), true );

	    QCA::TripleDES reverseCipher( QCA::Cipher::ECB, QCA::Decode, key, QCA::InitializationVector(), QCA::Cipher::NoPadding );

	    CHECK( QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( tripledesTestValues[n].ciphertext ) ) ),
		   QString( tripledesTestValues[n].plaintext ) );
	    CHECK( reverseCipher.ok(), true );
	    CHECK( QCA::arrayToHex( reverseCipher.final() ), QString( "" ) );
	    CHECK( reverseCipher.ok(), true );
        }
    }

    if (!QCA::isSupported("des") )
	SKIP("DES not supported!");
    else {
	QCA::DES cipherObj1( QCA::Cipher::ECB, QCA::Encode, QCA::SymmetricKey( 8 ) );
	CHECK( cipherObj1.keyLength().minimum(), 8 );
	CHECK( cipherObj1.keyLength().maximum(), 8 );
	CHECK( cipherObj1.blockSize(), (unsigned)8 );

	for (int n = 0; desTestValues[n].plaintext; n++) {
	    QCA::SymmetricKey key( QCA::hexToArray( desTestValues[n].key ) );
	    QCA::DES forwardCipher( QCA::Cipher::ECB, QCA::Encode, key, QCA::InitializationVector(), QCA::Cipher::NoPadding );
	    CHECK( QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( desTestValues[n].plaintext ) ) ),
		   QString( desTestValues[n].ciphertext ) );
	    CHECK( forwardCipher.ok(), true );
	    CHECK( QCA::arrayToHex( forwardCipher.final() ), QString( "" ) );
	    CHECK( forwardCipher.ok(), true );

	    QCA::DES reverseCipher( QCA::Cipher::ECB, QCA::Decode, key, QCA::InitializationVector(), QCA::Cipher::NoPadding );

	    CHECK( QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( desTestValues[n].ciphertext ) ) ),
		   QString( desTestValues[n].plaintext ) );
	    CHECK( reverseCipher.ok(), true );
	    CHECK( QCA::arrayToHex( reverseCipher.final() ), QString( "" ) );
	    CHECK( reverseCipher.ok(), true );
        }
    }

    if (!QCA::isSupported("blowfish") )
	SKIP("Blowfish not supported!");
    else {
	QCA::BlowFish cipherObj1( QCA::Cipher::ECB, QCA::Encode, QCA::SymmetricKey( 16 ) );
	CHECK( cipherObj1.blockSize(), (unsigned)8 );

	for (int n = 0; blowfishTestValues[n].plaintext; n++) {
	    QCA::SymmetricKey key( QCA::hexToArray( blowfishTestValues[n].key ) );
	    QCA::BlowFish forwardCipher( QCA::Cipher::ECB, QCA::Encode, key, QCA::InitializationVector(), QCA::Cipher::NoPadding );
	    CHECK( QCA::arrayToHex( forwardCipher.update( QCA::hexToArray( blowfishTestValues[n].plaintext ) ) ),
		   QString( blowfishTestValues[n].ciphertext ) );
	    CHECK( forwardCipher.ok(), true );
	    CHECK( QCA::arrayToHex( forwardCipher.final() ), QString( "" ) );
	    CHECK( forwardCipher.ok(), true );

	    QCA::BlowFish reverseCipher( QCA::Cipher::ECB, QCA::Decode, key, QCA::InitializationVector(), QCA::Cipher::NoPadding );

	    CHECK( QCA::arrayToHex( reverseCipher.update( QCA::hexToArray( blowfishTestValues[n].ciphertext ) ) ),
		   QString( blowfishTestValues[n].plaintext ) );
	    CHECK( reverseCipher.ok(), true );
	    CHECK( QCA::arrayToHex( reverseCipher.final() ), QString( "" ) );
	    CHECK( reverseCipher.ok(), true );
        }
    }
}

