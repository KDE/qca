project(mozcerts)

set(mozcerts_bin_SRCS main.cpp)  
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

add_executable(${MOZCERTS_NAME} ${mozcerts_bin_SRCS})

target_link_libraries( ${MOZCERTS_NAME} ${QCA_LIB_NAME} ${QT_QTGUI_LIBRARY})

install(TARGETS ${MOZCERTS_NAME} DESTINATION "${QCA_BINARY_INSTALL_DIR}")
