ENABLE_TESTING()

set(staticunittest_bin_SRCS staticunittest.cpp)  

MY_AUTOMOC( staticunittest_bin_SRCS )

add_executable( staticunittest ${staticunittest_bin_SRCS} )

target_link_libraries( staticunittest ${QCA_LIB_NAME} ${QT_QTTEST_LIBRARY})

ADD_TEST(StaticFunctions ${EXECUTABLE_OUTPUT_PATH}/staticunittest)

