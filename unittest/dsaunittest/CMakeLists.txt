ENABLE_TESTING()

set( dsaunittest_bin_SRCS dsaunittest.cpp)  

MY_AUTOMOC( dsaunittest_bin_SRCS )

add_executable( dsaunittest ${dsaunittest_bin_SRCS} )

target_link_libraries( dsaunittest ${QCA_LIB_NAME} ${QT_QTTEST_LIBRARY})

ADD_TEST(DigitalSignatureAlgorithm ${EXECUTABLE_OUTPUT_PATH}/dsaunittest)

