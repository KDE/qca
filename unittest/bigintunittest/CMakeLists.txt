ENABLE_TESTING()

set(bigintunittest_bin_SRCS bigintunittest.cpp)  

MY_AUTOMOC( bigintunittest_bin_SRCS )

add_executable(bigintunittest ${bigintunittest_bin_SRCS} )

target_link_libraries( bigintunittest ${QCA_LIB_NAME} ${QT_QTTEST_LIBRARY})

ADD_TEST("BigInteger" ${EXECUTABLE_OUTPUT_PATH}/bigintunittest)
