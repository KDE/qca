project(qcatool)

set(qcatool_moc_SRCS main.cpp)

MY_AUTOMOC( qcatool_moc_SRCS )

set(qcatool_bin_SRCS ${qcatool_moc_SRCS})

add_executable(${QCA_TOOL_NAME} ${qcatool_bin_SRCS})

target_link_qca_libraries(${QCA_TOOL_NAME})

install(TARGETS ${QCA_TOOL_NAME} DESTINATION "${QCA_BINARY_INSTALL_DIR}")
