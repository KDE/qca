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
#include "qca.h"

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

CipherUnitTest::CipherUnitTest()
    : Tester()
{
}

void CipherUnitTest::allTests()
{
    QCA::Initializer init;

    if (!QCA::isSupported("aes128") )
	SKIP("AES128 not supported!\n");
    else {
	QCA::SymmetricKey key1(QCA::hexToArray( "00010203050607080A0B0C0D0F101112" ) );
	QCA::AES128 cipherObj1(QCA::Cipher::ECB, QCA::Encode, key1, QCA::InitializationVector(), false );
	QSecureArray inter = cipherObj1.update( QCA::hexToArray( "506812A45F08C889B97F5980038B8359" ) );
	CHECK( QCA::arrayToHex( inter ), QString( "d8f532538289ef7d06b506a4fd5be9c9") );
	CHECK( QCA::arrayToHex( cipherObj1.final() ), QString( "d8f532538289ef7d06b506a4fd5be9c9") );

	CHECK( cipherObj1.blockSize(), 16 );

	// From the NIST rijndael-vals.zip set, see ecb_iv.txt
	QCA::SymmetricKey key2(QCA::hexToArray( "000102030405060708090A0B0C0D0E0F" ) );
	QCA::AES128 cipherObj2(QCA::Cipher::ECB, QCA::Encode, key2, QCA::InitializationVector(), false );
	QSecureArray ct2r1 = cipherObj2.update( QCA::hexToArray( "000102030405060708090A0B0C0D0E0F" ) );
	CHECK( QCA::arrayToHex( ct2r1 ), QString("0a940bb5416ef045f1c39458c653ea5a" ) );
	CHECK( QCA::arrayToHex( cipherObj2.final() ), QString("0a940bb5416ef045f1c39458c653ea5a" ) );

	// From the NIST rijndael-vals.zip set, see ecb_iv.txt
	QCA::AES128 cipherObj3(QCA::Cipher::ECB, QCA::Decode, key2, QCA::InitializationVector(), false );
	cipherObj3.update( QCA::hexToArray( "0A940BB5416EF045F1C39458C653EA5A" ) );
	CHECK( QCA::arrayToHex( cipherObj3.final() ), QString("000102030405060708090a0b0c0d0e0f" ) );

	// From FIPS-197 Annex C.1
	QCA::AES128 cipherObj4(QCA::Cipher::ECB, QCA::Encode, key2, QCA::InitializationVector(), false );
	cipherObj4.update( QCA::hexToArray( "00112233445566778899aabbccddeeff" ) );
	CHECK( QCA::arrayToHex( cipherObj4.final() ), QString("69c4e0d86a7b0430d8cdb78070b4c55a" ) );

	// From FIPS-197 Annex C.1
	QCA::AES128 cipherObj5(QCA::Cipher::ECB, QCA::Decode, key2, QCA::InitializationVector(), false );
	cipherObj5.update( QCA::hexToArray( "69c4e0d86a7b0430d8cdb78070b4c55a" ) );
	CHECK( QCA::arrayToHex( cipherObj5.final() ), QString( "00112233445566778899aabbccddeeff" ) );

	for (int n = 0; aes128ecbTestValues[n].plaintext; n++) {
	    QCA::SymmetricKey key( QCA::hexToArray( aes128ecbTestValues[n].key ) );
	    QCA::AES128 forwardCipher( QCA::Cipher::ECB, QCA::Encode, key );
	    forwardCipher.update( QCA::hexToArray( aes128ecbTestValues[n].plaintext ) );
	    CHECK( QCA::arrayToHex( forwardCipher.final() ), QString( aes128ecbTestValues[n].ciphertext ) );

	    QCA::AES128 reverseCipher( QCA::Cipher::ECB, QCA::Decode, key );
	    reverseCipher.update( QCA::hexToArray( aes128ecbTestValues[n].ciphertext ) );
	    CHECK( QCA::arrayToHex( reverseCipher.final() ), QString( aes128ecbTestValues[n].plaintext ) );
        }

	for (int n = 0; aes128ecbTestValues[n].plaintext; n++) {
	    QCA::SymmetricKey key( QCA::hexToArray( aes128ecbTestValues[n].key ) );
	    QCA::AES128 forwardCipher( QCA::Cipher::ECB, QCA::Encode, key );
	    forwardCipher.update( QCA::hexToArray( aes128ecbTestValues[n].plaintext ) );
	    CHECK( QCA::arrayToHex( forwardCipher.final() ), QString( aes128ecbTestValues[n].ciphertext ) );

	    QCA::AES128 reverseCipher( QCA::Cipher::ECB, QCA::Decode, key );
	    reverseCipher.update( QCA::hexToArray( aes128ecbTestValues[n].ciphertext ) );
	    CHECK( QCA::arrayToHex( reverseCipher.final() ), QString( aes128ecbTestValues[n].plaintext ) );
        }

	for (int n = 0; aes128cbcTestValues[n].plaintext; n++) {
	    QCA::SymmetricKey key( QCA::hexToArray( aes128cbcTestValues[n].key ) );
	    QCA::InitializationVector iv( QCA::hexToArray( aes128cbcTestValues[n].iv ) );
	    QCA::AES128 forwardCipher( QCA::Cipher::CBC, QCA::Encode, key, iv );
	    forwardCipher.update( QCA::hexToArray( aes128cbcTestValues[n].plaintext ) );
	    CHECK( QCA::arrayToHex( forwardCipher.final() ), QString( aes128cbcTestValues[n].ciphertext ) );

	    QCA::AES128 reverseCipher( QCA::Cipher::CBC, QCA::Decode, key, iv );
	    reverseCipher.update( QCA::hexToArray( aes128cbcTestValues[n].ciphertext ) );
	    CHECK( QCA::arrayToHex( reverseCipher.final() ), QString( aes128cbcTestValues[n].plaintext ) );
        }

	for (int n = 0; aes128cfbTestValues[n].plaintext; n++) {
	    QCA::SymmetricKey key( QCA::hexToArray( aes128cfbTestValues[n].key ) );
	    QCA::InitializationVector iv( QCA::hexToArray( aes128cfbTestValues[n].iv ) );
	    QCA::AES128 forwardCipher( QCA::Cipher::CFB, QCA::Encode, key, iv );
	    forwardCipher.update( QCA::hexToArray( aes128cfbTestValues[n].plaintext ) );
	    CHECK( QCA::arrayToHex( forwardCipher.final() ), QString( aes128cfbTestValues[n].ciphertext ) );

	    QCA::AES128 reverseCipher( QCA::Cipher::CFB, QCA::Decode, key, iv );
	    reverseCipher.update( QCA::hexToArray( aes128cfbTestValues[n].ciphertext ) );
	    CHECK( QCA::arrayToHex( reverseCipher.final() ), QString( aes128cfbTestValues[n].plaintext ) );
        }
    }

    if (!QCA::isSupported("aes192") )
	SKIP("AES192 not supported!\n");
    else {
	// FIPS 197, Appendix C.2
	QCA::SymmetricKey key1(QCA::hexToArray( "000102030405060708090A0B0C0D0E0F1011121314151617" ) );
	QCA::AES192 cipherObj1(QCA::Cipher::ECB, QCA::Encode, key1, QCA::InitializationVector(), false );
	QSecureArray data1 = QCA::hexToArray( "00112233445566778899AABBCCDDEEFF" );
	cipherObj1.update( data1 );
	CHECK( QCA::arrayToHex( cipherObj1.final() ), QString( "dda97ca4864cdfe06eaf70a0ec0d7191") );

	CHECK( cipherObj1.blockSize(), 16 );

	QCA::AES192 cipherObj2(QCA::Cipher::ECB, QCA::Decode, key1, QCA::InitializationVector(), false );
	cipherObj2.update( QCA::hexToArray( "dda97ca4864cdfe06eaf70a0ec0d7191") );
	CHECK( QCA::arrayToHex( cipherObj2.final() ), QString( "00112233445566778899aabbccddeeff" ) );

	for (int n = 0; aes192ecbTestValues[n].plaintext; n++) {
	    QCA::SymmetricKey key( QCA::hexToArray( aes192ecbTestValues[n].key ) );
	    QCA::AES192 forwardCipher( QCA::Cipher::ECB, QCA::Encode, key );
	    forwardCipher.update( QCA::hexToArray( aes192ecbTestValues[n].plaintext ) );
	    CHECK( QCA::arrayToHex( forwardCipher.final() ), QString( aes192ecbTestValues[n].ciphertext ) );

	    QCA::AES192 reverseCipher( QCA::Cipher::ECB, QCA::Decode, key );
	    reverseCipher.update( QCA::hexToArray( aes192ecbTestValues[n].ciphertext ) );
	    CHECK( QCA::arrayToHex( reverseCipher.final() ), QString( aes192ecbTestValues[n].plaintext ) );
        }

	for (int n = 0; aes192cbcTestValues[n].plaintext; n++) {
	    QCA::SymmetricKey key( QCA::hexToArray( aes192cbcTestValues[n].key ) );
	    QCA::InitializationVector iv( QCA::hexToArray( aes192cbcTestValues[n].iv ) );
	    QCA::AES192 forwardCipher( QCA::Cipher::CBC, QCA::Encode, key, iv );
	    forwardCipher.update( QCA::hexToArray( aes192cbcTestValues[n].plaintext ) );
	    CHECK( QCA::arrayToHex( forwardCipher.final() ), QString( aes192cbcTestValues[n].ciphertext ) );

	    QCA::AES192 reverseCipher( QCA::Cipher::CBC, QCA::Decode, key, iv );
	    reverseCipher.update( QCA::hexToArray( aes192cbcTestValues[n].ciphertext ) );
	    CHECK( QCA::arrayToHex( reverseCipher.final() ), QString( aes192cbcTestValues[n].plaintext ) );
        }

	for (int n = 0; aes192cfbTestValues[n].plaintext; n++) {
	    QCA::SymmetricKey key( QCA::hexToArray( aes192cfbTestValues[n].key ) );
	    QCA::InitializationVector iv( QCA::hexToArray( aes192cfbTestValues[n].iv ) );
	    QCA::AES192 forwardCipher( QCA::Cipher::CFB, QCA::Encode, key, iv );
	    forwardCipher.update( QCA::hexToArray( aes192cfbTestValues[n].plaintext ) );
	    CHECK( QCA::arrayToHex( forwardCipher.final() ), QString( aes192cfbTestValues[n].ciphertext ) );

	    QCA::AES192 reverseCipher( QCA::Cipher::CFB, QCA::Decode, key, iv );
	    reverseCipher.update( QCA::hexToArray( aes192cfbTestValues[n].ciphertext ) );
	    CHECK( QCA::arrayToHex( reverseCipher.final() ), QString( aes192cfbTestValues[n].plaintext ) );
        }
    }


    if (!QCA::isSupported("aes256") )
	SKIP("AES256 not supported!\n");
    else {
	// FIPS 197, Appendix C.3
	QCA::SymmetricKey key1(QCA::hexToArray( "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F" ) );
	QCA::AES256 cipherObj1(QCA::Cipher::ECB, QCA::Encode, key1, QCA::InitializationVector(), false );
	QSecureArray data1 = QCA::hexToArray( "00112233445566778899AABBCCDDEEFF" );
	cipherObj1.update( data1 );
	CHECK( QCA::arrayToHex( cipherObj1.final() ), QString( "8ea2b7ca516745bfeafc49904b496089") );

	CHECK( cipherObj1.blockSize(), 16 );

	QCA::AES256 cipherObj2(QCA::Cipher::ECB, QCA::Decode, key1, QCA::InitializationVector(), false );
	cipherObj2.update( QCA::hexToArray( "8EA2B7CA516745BFEAFC49904B496089") );
	CHECK( QCA::arrayToHex( cipherObj2.final() ), QString( "00112233445566778899aabbccddeeff" ) );

	for (int n = 0; aes256ecbTestValues[n].plaintext; n++) {
	    QCA::SymmetricKey key( QCA::hexToArray( aes256ecbTestValues[n].key ) );
	    QCA::AES256 forwardCipher( QCA::Cipher::ECB, QCA::Encode, key );
	    forwardCipher.update( QCA::hexToArray( aes256ecbTestValues[n].plaintext ) );
	    CHECK( QCA::arrayToHex( forwardCipher.final() ), QString( aes256ecbTestValues[n].ciphertext ) );

	    QCA::AES256 reverseCipher( QCA::Cipher::ECB, QCA::Decode, key );
	    reverseCipher.update( QCA::hexToArray( aes256ecbTestValues[n].ciphertext ) );
	    CHECK( QCA::arrayToHex( reverseCipher.final() ), QString( aes256ecbTestValues[n].plaintext ) );
        }

	for (int n = 0; aes256cbcTestValues[n].plaintext; n++) {
	    QCA::SymmetricKey key( QCA::hexToArray( aes256cbcTestValues[n].key ) );
	    QCA::InitializationVector iv( QCA::hexToArray( aes256cbcTestValues[n].iv ) );
	    QCA::AES256 forwardCipher( QCA::Cipher::CBC, QCA::Encode, key, iv );
	    forwardCipher.update( QCA::hexToArray( aes256cbcTestValues[n].plaintext ) );
	    CHECK( QCA::arrayToHex( forwardCipher.final() ), QString( aes256cbcTestValues[n].ciphertext ) );

	    QCA::AES256 reverseCipher( QCA::Cipher::CBC, QCA::Decode, key, iv );
	    reverseCipher.update( QCA::hexToArray( aes256cbcTestValues[n].ciphertext ) );
	    CHECK( QCA::arrayToHex( reverseCipher.final() ), QString( aes256cbcTestValues[n].plaintext ) );
        }

	for (int n = 0; aes256cfbTestValues[n].plaintext; n++) {
	    QCA::SymmetricKey key( QCA::hexToArray( aes256cfbTestValues[n].key ) );
	    QCA::InitializationVector iv( QCA::hexToArray( aes256cfbTestValues[n].iv ) );
	    QCA::AES256 forwardCipher( QCA::Cipher::CFB, QCA::Encode, key, iv );
	    forwardCipher.update( QCA::hexToArray( aes256cfbTestValues[n].plaintext ) );
	    CHECK( QCA::arrayToHex( forwardCipher.final() ), QString( aes256cfbTestValues[n].ciphertext ) );

	    QCA::AES256 reverseCipher( QCA::Cipher::CFB, QCA::Decode, key, iv );
	    reverseCipher.update( QCA::hexToArray( aes256cfbTestValues[n].ciphertext ) );
	    CHECK( QCA::arrayToHex( reverseCipher.final() ), QString( aes256cfbTestValues[n].plaintext ) );
        }

    }

    if (!QCA::isSupported("tripledes") )
	SKIP("Triple DES not supported!\n");
    else {
	QCA::TripleDES cipherObj1( QCA::Cipher::ECB, QCA::Encode, QCA::SymmetricKey( 24 ) );
	CHECK( cipherObj1.keyLength().minimum(), 24 );
	CHECK( cipherObj1.keyLength().maximum(), 24 );
	CHECK( cipherObj1.blockSize(), 8 );

	for (int n = 0; tripledesTestValues[n].plaintext; n++) {
	    QCA::SymmetricKey key( QCA::hexToArray( tripledesTestValues[n].key ) );
	    QCA::TripleDES forwardCipher( QCA::Cipher::ECB, QCA::Encode, key );
	    forwardCipher.update( QCA::hexToArray( tripledesTestValues[n].plaintext ) );
	    CHECK( QCA::arrayToHex( forwardCipher.final() ), QString( tripledesTestValues[n].ciphertext ) );

	    QCA::TripleDES reverseCipher( QCA::Cipher::ECB, QCA::Decode, key );
	    reverseCipher.update( QCA::hexToArray( tripledesTestValues[n].ciphertext ) );
	    CHECK( QCA::arrayToHex( reverseCipher.final() ), QString( tripledesTestValues[n].plaintext ) );
        }
    }

    if (!QCA::isSupported("blowfish") )
	SKIP("Blowfish not supported!\n");
    else {
	QCA::BlowFish cipherObj1( QCA::Cipher::ECB, QCA::Encode, QCA::SymmetricKey( 16 ) );
	CHECK( cipherObj1.blockSize(), 8 );

	for (int n = 0; blowfishTestValues[n].plaintext; n++) {
	    QCA::SymmetricKey key( QCA::hexToArray( blowfishTestValues[n].key ) );
	    QCA::BlowFish forwardCipher( QCA::Cipher::ECB, QCA::Encode, key );
	    forwardCipher.update( QCA::hexToArray( blowfishTestValues[n].plaintext ) );
	    CHECK( QCA::arrayToHex( forwardCipher.final() ), QString( blowfishTestValues[n].ciphertext ) );

	    QCA::BlowFish reverseCipher( QCA::Cipher::ECB, QCA::Decode, key );
	    reverseCipher.update( QCA::hexToArray( blowfishTestValues[n].ciphertext ) );
	    CHECK( QCA::arrayToHex( reverseCipher.final() ), QString( blowfishTestValues[n].plaintext ) );
        }
    }
}

