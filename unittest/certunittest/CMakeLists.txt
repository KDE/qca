ENABLE_TESTING()

set(certunittest_bin_SRCS certunittest.cpp)

MY_AUTOMOC( certunittest_bin_SRCS )

add_executable(certunittest ${certunittest_bin_SRCS} )

target_link_libraries( certunittest qca ${QT_QTTEST_LIBRARY})

FOREACH( testFileName RootCAcert.pem 76.pem altname.pem csr1.pem 
	 GoodCACRL.pem ov-root-ca-cert.crt User.pem user2goodcert.pem xmppcert.pem 
	 Server.pem servergood2cert.pem xmppcert.pem newreq.pem
	 QualitySSLIntermediateCA.crt RootCA2cert.pem Test_CRL.crl )
   CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/certs/${testFileName} ${CMAKE_CURRENT_BINARY_DIR}/certs/${testFileName} COPYONLY)
ENDFOREACH( testFileName )

ADD_TEST(Certificate ${EXECUTABLE_OUTPUT_PATH}/certunittest)
