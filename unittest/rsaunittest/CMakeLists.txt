ENABLE_TESTING()

set(rsaunittest_bin_SRCS rsaunittest.cpp)  

MY_AUTOMOC( rsaunittest_bin_SRCS )

add_executable(rsaunittest ${rsaunittest_bin_SRCS} )

target_link_libraries( rsaunittest ${QCA_LIB_NAME} ${QT_QTTEST_LIBRARY})

ADD_TEST(RSA ${EXECUTABLE_OUTPUT_PATH}/rsaunittest)
