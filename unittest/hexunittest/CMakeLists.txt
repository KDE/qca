ENABLE_TESTING()

set(hexunittest_bin_SRCS hexunittest.cpp)  

MY_AUTOMOC( hexunittest_bin_SRCS )

add_executable( hexunittest ${hexunittest_bin_SRCS} )

target_link_libraries( hexunittest qca ${QT_QTTEST_LIBRARY})

ADD_TEST(HexadecimalConversion ${EXECUTABLE_OUTPUT_PATH}/hexunittest)
