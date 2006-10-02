project(qcatool)

set(qcatool_moc_SRCS main.cpp)

MY_AUTOMOC( qcatool_moc_SRCS )

set(qcatool_bin_SRCS ${qcatool_moc_SRCS})  

add_executable(qcatool ${qcatool_bin_SRCS})

target_link_libraries( qcatool qca ${QT_QTGUI_LIBRARY})
