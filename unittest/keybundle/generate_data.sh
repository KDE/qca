#!/bin/sh
# Generate CA key + certificate
openssl req -x509 -newkey rsa:4096 -keyout RootCA2key.pem -out RootCA2cert.pem -sha256 -days 3650 -nodes -subj "/C=de/O=InsecureTestCertificate/CN=For Tests Only next generation/emailAddress=insecure@test.insecure"
# Generate user key + certificate, signed by ^
openssl req -x509 -CA RootCA2cert.pem -CAkey RootCA2key.pem -newkey rsa:4096 -keyout user2goodkey.pem -out user2goodcert.pem -sha256 -days 3650 -nodes -subj "/C=de/O=InsecureTestCertificate/CN=For Tests Only next generation/emailAddress=insecure@test.insecure"
# Put ^ into a pkcs#12 file
openssl pkcs12 -export -inkey user2goodkey.pem -in user2goodcert.pem -out user2good.p12 -password pass:start
# Same for the server
openssl req -x509 -CA RootCA2cert.pem -CAkey RootCA2key.pem -newkey rsa:4096 -keyout servergood2key.pem -out servergood2cert.pem -sha256 -days 3650 -nodes -subj "/C=de/O=InsecureTestCertificate/CN=For Tests Only next generation/emailAddress=insecure@test.insecure"
openssl pkcs12 -export -inkey servergood2key.pem -in servergood2cert.pem -out servergood2.p12 -password pass:start
# Remove unneeded intermediate files
rm servergood2cert.pem servergood2key.pem
