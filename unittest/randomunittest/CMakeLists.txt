ENABLE_TESTING()

set(randomunittest_bin_SRCS randomunittest.cpp)  

MY_AUTOMOC( randomunittest_bin_SRCS )

add_executable( randomunittest ${randomunittest_bin_SRCS} )

target_link_libraries( randomunittest ${QCA_LIB_NAME} ${QT_QTTEST_LIBRARY})

ADD_TEST(RandomNumberGeneration ${EXECUTABLE_OUTPUT_PATH}/randomunittest)
