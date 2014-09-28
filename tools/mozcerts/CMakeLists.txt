project(mozcerts)

set(mozcerts_bin_SRCS main.cpp)  

add_executable(${MOZCERTS_NAME} ${mozcerts_bin_SRCS})

target_link_qca_libraries(${MOZCERTS_NAME})

if(NOT DEVELOPER_MODE)
  install(TARGETS ${MOZCERTS_NAME} DESTINATION "${QCA_BINARY_INSTALL_DIR}")
  install_pdb(${MOZCERTS_NAME} ${QCA_BINARY_INSTALL_DIR})
endif()
