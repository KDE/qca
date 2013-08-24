ENABLE_TESTING()

set( keygenunittest_bin_SRCS keygenunittest.cpp)  

MY_AUTOMOC( keygenunittest_bin_SRCS )

add_executable( keygenunittest ${keygenunittest_bin_SRCS} )

target_link_libraries( keygenunittest ${QCA_LIB_NAME} ${QT_QTTEST_LIBRARY})

ADD_TEST(KeyGeneration ${EXECUTABLE_OUTPUT_PATH}/keygenunittest)
