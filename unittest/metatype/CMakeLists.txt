ENABLE_TESTING()

set(metatype_bin_SRCS metatype.cpp)  

MY_AUTOMOC( metatype_bin_SRCS )

add_executable( metatypeunittest ${metatype_bin_SRCS} )

target_link_libraries( metatypeunittest ${QCA_LIB_NAME} ${QT_QTTEST_LIBRARY})

ADD_TEST(MetaTypeUnittest ${EXECUTABLE_OUTPUT_PATH}/metatypeunittest)
