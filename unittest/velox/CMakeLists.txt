find_package(Qt${QT_MAJOR_VERSION} COMPONENTS Network REQUIRED)

ENABLE_TESTING()

set(veloxunittest_bin_SRCS veloxunittest.cpp)  

add_executable(veloxunittest ${veloxunittest_bin_SRCS} )

target_link_qca_test_libraries(veloxunittest)
target_link_libraries(veloxunittest Qt${QT_MAJOR_VERSION}::Network)

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/root.crt ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/root.crt COPYONLY)

# this will almost always fail.
# add_qca_test(veloxunittest "ServerNameIndication")
