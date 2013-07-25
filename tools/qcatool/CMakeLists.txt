project(qcatool2)

set(qcatool2_moc_SRCS main.cpp)

MY_AUTOMOC( qcatool2_moc_SRCS )

set(qcatool2_bin_SRCS ${qcatool2_moc_SRCS})  

add_executable(qcatool2 ${qcatool2_bin_SRCS})

target_link_libraries( qcatool2 qca ${QT_QTCORE_LIBRARY})

install(TARGETS qcatool2 DESTINATION bin)
