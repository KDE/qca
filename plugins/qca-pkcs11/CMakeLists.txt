# qca-pkcs11

if(WITH_pkcs11_PLUGIN STREQUAL "yes")
  find_package(OpenSSL REQUIRED)
  find_package(Pkcs11Helper REQUIRED)
else()
  find_package(OpenSSL)
  find_package(Pkcs11Helper)
endif()

if(OPENSSL_FOUND AND PKCS11H_FOUND)
  enable_plugin("pkcs11")
  set(QCA_PKCS11_SOURCES qca-pkcs11.cpp)

  add_library(qca-pkcs11 ${PLUGIN_TYPE} ${QCA_PKCS11_SOURCES})

  if(APPLE AND ${PLUGIN_TYPE} STREQUAL "MODULE")
    set_property(TARGET qca-pkcs11 PROPERTY SUFFIX ".dylib")
  endif()

  add_definitions(${PKCS11H_CFLAGS_OTHER})
  include_directories(${PKCS11H_INCLUDE_DIRS})
  if(QT6)
    target_link_libraries(qca-pkcs11 Qt6::Core)
  else()
    target_link_libraries(qca-pkcs11 Qt5::Core)
  endif()
  target_link_libraries(qca-pkcs11 ${QCA_LIB_NAME})
  target_link_libraries(qca-pkcs11 ${PKCS11H_LDFLAGS})
  if (WIN32)
    target_link_libraries(qca-pkcs11 pkcs11-helper.dll)
  endif()

  if(NOT DEVELOPER_MODE)
    install(TARGETS qca-pkcs11
            LIBRARY DESTINATION "${QCA_CRYPTO_INSTALL_DIR}"
            ARCHIVE DESTINATION "${QCA_CRYPTO_INSTALL_DIR}"
            RUNTIME DESTINATION "${QCA_CRYPTO_INSTALL_DIR}")

    install_pdb(qca-pkcs11 ${QCA_CRYPTO_INSTALL_DIR})
  endif()
else()
  disable_plugin("pkcs11")
endif()
