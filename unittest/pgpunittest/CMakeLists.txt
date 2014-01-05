ENABLE_TESTING()

set(pgpunittest_bin_SRCS pgpunittest.cpp)  

MY_AUTOMOC( pgpunittest_bin_SRCS )

add_executable(pgpunittest ${pgpunittest_bin_SRCS} )

target_link_qca_test_libraries(pgpunittest)

file(MAKE_DIRECTORY
  ${CMAKE_CURRENT_BINARY_DIR}/keys1_work
  ${CMAKE_CURRENT_BINARY_DIR}/keys2_work
  ${CMAKE_CURRENT_BINARY_DIR}/keys3_work)

FOREACH( testFileName pubring.gpg secring.gpg trustdb.gpg )
   CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/keys1/${testFileName} ${CMAKE_CURRENT_BINARY_DIR}/keys1_work/${testFileName} COPYONLY)
ENDFOREACH( testFileName )

FOREACH( testFileName pubring.gpg trustdb.gpg )
   CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/keys2/${testFileName} ${CMAKE_CURRENT_BINARY_DIR}/keys2_work/${testFileName} COPYONLY)
ENDFOREACH( testFileName )

FOREACH( testFileName pubring.gpg secring.gpg trustdb.gpg )
   CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/keys3/${testFileName} ${CMAKE_CURRENT_BINARY_DIR}/keys3_work/${testFileName} COPYONLY)
ENDFOREACH( testFileName )

ADD_TEST(PGP ${EXECUTABLE_OUTPUT_PATH}/pgpunittest)
