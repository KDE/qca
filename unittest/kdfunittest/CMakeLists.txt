ENABLE_TESTING()

set( kdfunittest_bin_SRCS kdfunittest.cpp)  

MY_AUTOMOC( kdfunittest_bin_SRCS )

add_executable( kdfunittest ${kdfunittest_bin_SRCS} )

target_link_libraries( kdfunittest ${QCA_LIB_NAME} ${QT_QTTEST_LIBRARY})

ADD_TEST(KeyDerivationFunction ${EXECUTABLE_OUTPUT_PATH}/kdfunittest)
