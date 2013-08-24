ENABLE_TESTING()

set(pgpunittest_bin_SRCS pgpunittest.cpp)  

MY_AUTOMOC( pgpunittest_bin_SRCS )

add_executable(pgpunittest ${pgpunittest_bin_SRCS} )

target_link_libraries( pgpunittest ${QCA_LIB_NAME} ${QT_QTTEST_LIBRARY} )

FOREACH( testFileName pubring.gpg secring.gpg trustdb.gpg )
   CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/keys1/${testFileName} ${CMAKE_CURRENT_BINARY_DIR}/keys1/${testFileName} COPYONLY)
ENDFOREACH( testFileName )

FOREACH( testFileName pubring.gpg trustdb.gpg )
   CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/keys2/${testFileName} ${CMAKE_CURRENT_BINARY_DIR}/keys2/${testFileName} COPYONLY)
ENDFOREACH( testFileName )

FOREACH( testFileName pubring.gpg secring.gpg trustdb.gpg )
   CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/keys3/${testFileName} ${CMAKE_CURRENT_BINARY_DIR}/keys3/${testFileName} COPYONLY)
ENDFOREACH( testFileName )

ADD_TEST(PGP ${EXECUTABLE_OUTPUT_PATH}/pgpunittest)
