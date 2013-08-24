ENABLE_TESTING()

set(tlsunittest_bin_SRCS tlsunittest.cpp)  

MY_AUTOMOC( tlsunittest_bin_SRCS )

add_executable(tlsunittest ${tlsunittest_bin_SRCS} )

target_link_libraries( tlsunittest ${QCA_LIB_NAME} ${QT_QTTEST_LIBRARY})

ADD_TEST(TransportLayerSecurity ${EXECUTABLE_OUTPUT_PATH}/tlsunittest)
