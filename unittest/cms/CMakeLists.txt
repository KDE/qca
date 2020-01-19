ENABLE_TESTING()

set(cms_bin_SRCS cms.cpp)

add_executable(cms ${cms_bin_SRCS} )

target_link_qca_test_libraries(cms)

FOREACH( testFileName QcaTestRootCert.pem QcaTestClientCert.pem  QcaTestClientKey.pem )
   CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/${testFileName} ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${testFileName} COPYONLY)
ENDFOREACH( testFileName )

add_qca_test(cms "CryptographicMessageSyntax")
