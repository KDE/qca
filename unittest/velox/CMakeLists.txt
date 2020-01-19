find_package(Qt5 REQUIRED Network)

ENABLE_TESTING()

set(veloxunittest_bin_SRCS veloxunittest.cpp)  

add_executable(veloxunittest ${veloxunittest_bin_SRCS} )

target_link_qca_test_libraries(veloxunittest)
target_link_libraries(veloxunittest Qt5::Network)

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/root.crt ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/root.crt COPYONLY)

# this will almost always fail.
# add_qca_test(veloxunittest "ServerNameIndication")
