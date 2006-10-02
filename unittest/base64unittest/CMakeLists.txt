set(base64unittest_bin_SRCS base64unittest.cpp)  

QT4_GENERATE_MOC(${CMAKE_CURRENT_SOURCE_DIR}/base64unittest.h ${CMAKE_CURRENT_BINARY_DIR}/base64unittest.moc)

MACRO_ADD_FILE_DEPENDENCIES(base64unittest.cpp ${CMAKE_CURRENT_BINARY_DIR}/base64unittest.moc)

#MY_AUTOMOC( base64unittest_bin_SRCS )

add_executable(base64unittest ${base64unittest_bin_SRCS} )

target_link_libraries( base64unittest qca ${QT_QTTEST_LIBRARY} ${QT_QTGUI_LIBRARY})

