set(hashunittest_bin_SRCS hashunittest.cpp)  

MY_AUTOMOC( hashunittest_bin_SRCS )

add_executable( hashunittest ${hashunittest_bin_SRCS} )

target_link_libraries( hashunittest qca ${QT_QTTEST_LIBRARY})

CONFIGURE_FILE(${CMAKE_CURRENT_SOURCE_DIR}/data/empty ${CMAKE_CURRENT_BINARY_DIR}/data/empty COPYONLY)

