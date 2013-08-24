ENABLE_TESTING()

set(keylengthunittest_bin_SRCS keylengthunittest.cpp)  

MY_AUTOMOC( keylengthunittest_bin_SRCS )

add_executable( keylengthunittest ${keylengthunittest_bin_SRCS} )

target_link_libraries( keylengthunittest ${QCA_LIB_NAME} ${QT_QTTEST_LIBRARY})

ADD_TEST(KeyLength ${EXECUTABLE_OUTPUT_PATH}/keylengthunittest)
