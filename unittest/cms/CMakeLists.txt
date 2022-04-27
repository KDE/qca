ENABLE_TESTING()

set(cms_bin_SRCS cms.cpp)

add_executable(cms ${cms_bin_SRCS} )

target_link_qca_test_libraries(cms)
#Remove once we stop supporting openssl < 1.1.1i
target_link_libraries(cms OpenSSL::SSL OpenSSL::Crypto)

FOREACH( testFileName QcaTestRootCert.pem QcaTestClientCert.pem  QcaTestClientKey.pem )
   CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/${testFileName} ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${testFileName} COPYONLY)
ENDFOREACH( testFileName )

add_qca_test(cms "CryptographicMessageSyntax")
