project(qcatool)

set(qcatool_moc_SRCS main.cpp)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

MY_AUTOMOC( qcatool_moc_SRCS )

set(qcatool_bin_SRCS ${qcatool_moc_SRCS})

add_executable(${QCA_TOOL_NAME} ${qcatool_bin_SRCS})

target_link_libraries( ${QCA_TOOL_NAME} ${QCA_LIB_NAME} ${QT_QTCORE_LIBRARY})

install(TARGETS ${QCA_TOOL_NAME} DESTINATION "${QCA_BINARY_INSTALL_DIR}")
