ENABLE_TESTING()

add_executable(loggerunittest loggerunittest.cpp )

target_link_qca_test_libraries(loggerunittest)

add_qca_test(loggerunittest "Logger")
