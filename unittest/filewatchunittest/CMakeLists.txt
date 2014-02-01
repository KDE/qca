ENABLE_TESTING()

set(SOURCES "filewatchunittest.cpp")
qt4_wrap_cpp(SOURCES "filewatchunittest.h")

add_executable( filewatchunittest ${SOURCES})

target_link_qca_test_libraries(filewatchunittest)

add_qca_test(filewatchunittest "FileWatch")
