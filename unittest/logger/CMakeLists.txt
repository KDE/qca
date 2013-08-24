ENABLE_TESTING()

set(loggerunittest_bin_SRCS loggerunittest.cpp)  

MY_AUTOMOC( loggerunittest_bin_SRCS )

add_executable(loggerunittest ${loggerunittest_bin_SRCS} )

target_link_libraries( loggerunittest ${QCA_LIB_NAME} ${QT_QTTEST_LIBRARY})

ADD_TEST(Logger ${EXECUTABLE_OUTPUT_PATH}/loggerunittest)
