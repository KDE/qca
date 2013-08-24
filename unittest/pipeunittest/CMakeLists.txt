ENABLE_TESTING()

set(pipeunittest_bin_SRCS pipeunittest.cpp)  

MY_AUTOMOC( pipeunittest_bin_SRCS )

add_executable( pipeunittest ${pipeunittest_bin_SRCS} )

target_link_libraries( pipeunittest ${QCA_LIB_NAME} ${QT_QTTEST_LIBRARY})

# ADD_TEST(QPipe ${EXECUTABLE_OUTPUT_PATH}/pipeunittest)
