if(QT6)
  find_package(Qt6 COMPONENTS Network REQUIRED)
else()
  find_package(Qt5 REQUIRED Network)
endif()

ENABLE_TESTING()

set(veloxunittest_bin_SRCS veloxunittest.cpp)  

add_executable(veloxunittest ${veloxunittest_bin_SRCS} )

target_link_qca_test_libraries(veloxunittest)
if(QT6)
  target_link_libraries(veloxunittest Qt6::Network)
else()
  target_link_libraries(veloxunittest Qt5::Network)
endif()

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/root.crt ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/root.crt COPYONLY)

# this will almost always fail.
# add_qca_test(veloxunittest "ServerNameIndication")
