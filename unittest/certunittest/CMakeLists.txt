ENABLE_TESTING()

set(certunittest_bin_SRCS certunittest.cpp)

MY_AUTOMOC( certunittest_bin_SRCS )

add_executable(certunittest ${certunittest_bin_SRCS} )

target_link_libraries( certunittest ${QCA_LIB_NAME} ${QT_QTTEST_LIBRARY})

FOREACH( testFileName RootCAcert.pem 76.pem altname.pem csr1.pem 
	 GoodCACRL.pem ov-root-ca-cert.crt User.pem QcaTestClientCert.pem xmppcert.pem 
	 Server.pem QcaTestServerCert.pem xmppcert.pem newreq.pem
	 QualitySSLIntermediateCA.crt QcaTestRootCert.pem Test_CRL.crl
	 RAIZ2007_CERTIFICATE_AND_CRL_SIGNING_SHA256.crt )
   CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/certs/${testFileName} ${CMAKE_CURRENT_BINARY_DIR}/certs/${testFileName} COPYONLY)
ENDFOREACH( testFileName )

ADD_TEST(Certificate ${EXECUTABLE_OUTPUT_PATH}/certunittest)
