ENABLE_TESTING()

set(veloxunittest_bin_SRCS veloxunittest.cpp)  

MY_AUTOMOC( veloxunittest_bin_SRCS )

add_executable(veloxunittest ${veloxunittest_bin_SRCS} )

target_link_libraries( veloxunittest ${QCA_LIB_NAME} ${QT_QTTEST_LIBRARY} ${QT_QTNETWORK_LIBRARY} )

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/root.crt ${CMAKE_CURRENT_BINARY_DIR}/root.crt COPYONLY)

# this will almost always fail.
# ADD_TEST(ServerNameIndication ${EXECUTABLE_OUTPUT_PATH}/veloxunittest)
