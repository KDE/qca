ENABLE_TESTING()

set(symmetrickeyunittest_bin_SRCS symmetrickeyunittest.cpp)  

MY_AUTOMOC( symmetrickeyunittest_bin_SRCS )

add_executable( symmetrickeyunittest ${symmetrickeyunittest_bin_SRCS} )

target_link_libraries( symmetrickeyunittest qca ${QT_QTTEST_LIBRARY})

ADD_TEST(SymmetricKey ${EXECUTABLE_OUTPUT_PATH}/symmetrickeyunittest)
