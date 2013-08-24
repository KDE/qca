ENABLE_TESTING()

set(securearrayunittest_bin_SRCS securearrayunittest.cpp)  

MY_AUTOMOC( securearrayunittest_bin_SRCS )

add_executable( securearrayunittest ${securearrayunittest_bin_SRCS} )

target_link_libraries( securearrayunittest ${QCA_LIB_NAME} ${QT_QTTEST_LIBRARY})

ADD_TEST(SecureArray ${EXECUTABLE_OUTPUT_PATH}/securearrayunittest)
