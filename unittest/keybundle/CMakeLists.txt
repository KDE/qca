ENABLE_TESTING()

set(keybundleunittest_bin_SRCS keybundle.cpp)  

add_executable( keybundle ${keybundleunittest_bin_SRCS} )

target_link_qca_test_libraries(keybundle)

FOREACH( testFileName RootCA2cert.pem  servergood2.p12  
	 user2goodcert.pem  user2goodkey.pem  user2good.p12 )
   CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/${testFileName} ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${testFileName} COPYONLY)
ENDFOREACH( testFileName )

add_qca_test(keybundle "KeyBundle")
