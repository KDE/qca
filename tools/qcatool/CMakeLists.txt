project(qcatool)

set(qcatool_moc_SRCS main.cpp)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

MY_AUTOMOC( qcatool_moc_SRCS )

set(qcatool_bin_SRCS ${qcatool_moc_SRCS})

if(QCA_LIB_SUFFIX)
  set(QCATOOL_NAME qcatool-${QCA_LIB_SUFFIX})
else(QCA_LIB_SUFFIX)
  set(QCATOOL_NAME qcatool)
endif(QCA_LIB_SUFFIX)

add_executable(${QCATOOL_NAME} ${qcatool_bin_SRCS})

target_link_libraries( ${QCATOOL_NAME} ${QCA_LIB_NAME} ${QT_QTCORE_LIBRARY})

install(TARGETS ${QCATOOL_NAME} DESTINATION "${QCA_BINARY_INSTALL_DIR}")
