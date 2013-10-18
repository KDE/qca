ENABLE_TESTING()

set( filewatchunittest_bin_SRCS filewatchunittest.cpp)  

MY_AUTOMOC( filewatchunittest_bin_SRCS )

add_executable( filewatchunittest ${filewatchunittest_bin_SRCS} )

target_link_libraries( filewatchunittest ${QCA_LIB_NAME} ${QT_QTTEST_LIBRARY})

ADD_TEST(FileWatch ${EXECUTABLE_OUTPUT_PATH}/filewatchunittest)

