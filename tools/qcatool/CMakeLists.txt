project(qcatool2)

set(qcatool2_moc_SRCS main.cpp)

MY_AUTOMOC( qcatool2_moc_SRCS )

set(qcatool2_bin_SRCS ${qcatool2_moc_SRCS})  

if(QCA_LIB_SUFFIX)
  set(QCATOOL_NAME qcatool2-${QCA_LIB_SUFFIX})
else(QCA_LIB_SUFFIX)
  set(QCATOOL_NAME qcatool2)
endif(QCA_LIB_SUFFIX)

add_executable(${QCATOOL_NAME} ${qcatool2_bin_SRCS})

target_link_libraries( ${QCATOOL_NAME} ${QCA_LIB_NAME} ${QT_QTCORE_LIBRARY})

install(TARGETS ${QCATOOL_NAME} DESTINATION "${QCA_BINARY_INSTALL_DIR}")
