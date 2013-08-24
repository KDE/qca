ENABLE_TESTING()

set(cms_bin_SRCS cms.cpp)

MY_AUTOMOC( cms_bin_SRCS )

add_executable(cms ${cms_bin_SRCS} )

target_link_libraries( cms ${QCA_LIB_NAME} ${QT_QTTEST_LIBRARY})

FOREACH( testFileName QcaTestRootCert.pem QcaTestClientCert.pem  QcaTestClientKey.pem )
   CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/${testFileName} ${CMAKE_CURRENT_BINARY_DIR}/${testFileName} COPYONLY)
ENDFOREACH( testFileName )

ADD_TEST(CryptographicMessageSyntax ${EXECUTABLE_OUTPUT_PATH}/cms)
