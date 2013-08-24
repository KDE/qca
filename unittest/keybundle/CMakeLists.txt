ENABLE_TESTING()

set(keybundleunittest_bin_SRCS keybundle.cpp)  

MY_AUTOMOC( keybundleunittest_bin_SRCS )

add_executable( keybundle ${keybundleunittest_bin_SRCS} )

target_link_libraries( keybundle ${QCA_LIB_NAME} ${QT_QTTEST_LIBRARY})


FOREACH( testFileName RootCA2cert.pem  servergood2.p12  
	 user2goodcert.pem  user2goodkey.pem  user2good.p12 )
   CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/${testFileName} ${CMAKE_CURRENT_BINARY_DIR}/${testFileName} COPYONLY)
ENDFOREACH( testFileName )

ADD_TEST(KeyBundle ${EXECUTABLE_OUTPUT_PATH}/keybundle)
