ENABLE_TESTING()

set(macunittest_bin_SRCS macunittest.cpp)  

MY_AUTOMOC( macunittest_bin_SRCS )

add_executable( macunittest ${macunittest_bin_SRCS} )

target_link_libraries( macunittest ${QCA_LIB_NAME} ${QT_QTTEST_LIBRARY})

ADD_TEST(MessageAuthenticationCode ${EXECUTABLE_OUTPUT_PATH}/macunittest)
