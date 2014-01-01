ENABLE_TESTING()

set(loggerunittest_bin_SRCS loggerunittest.cpp)  

MY_AUTOMOC( loggerunittest_bin_SRCS )

add_executable(loggerunittest ${loggerunittest_bin_SRCS} )

target_link_qca_test_libraries(loggerunittest)

ADD_TEST(Logger ${EXECUTABLE_OUTPUT_PATH}/loggerunittest)
