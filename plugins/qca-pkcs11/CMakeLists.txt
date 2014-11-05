# qca-pkcs11

if(WITH_pkcs11_PLUGIN STREQUAL "yes")
  find_package(OpenSSL REQUIRED)
  find_package(Pkcs11Helper REQUIRED)
else(WITH_pkcs11_PLUGIN STREQUAL "yes")
  find_package(OpenSSL)
  find_package(Pkcs11Helper)
endif(WITH_pkcs11_PLUGIN STREQUAL "yes")

if(OPENSSL_FOUND AND PKCS11H_FOUND)
  enable_plugin("pkcs11")
  set(QCA_PKCS11_SOURCES qca-pkcs11.cpp)
  my_automoc( QCA_PKCS11_SOURCES )

  add_library(qca-pkcs11 ${PLUGIN_TYPE} ${QCA_PKCS11_SOURCES})

  if(APPLE AND ${PLUGIN_TYPE} STREQUAL "MODULE")
    set_property(TARGET qca-pkcs11 PROPERTY SUFFIX ".dylib")
  endif()

  add_definitions(${PKCS11H_CFLAGS_OTHER})
  include_directories(${PKCS11H_INCLUDE_DIRS})
  target_link_libraries(qca-pkcs11 ${QT_QTCORE_LIBRARY})
  target_link_libraries(qca-pkcs11 ${QCA_LIB_NAME})
  target_link_libraries(qca-pkcs11 ${PKCS11H_LDFLAGS})
  if (WIN32)
    target_link_libraries(qca-pkcs11 pkcs11-helper.dll)
  endif(WIN32)

  if(NOT DEVELOPER_MODE)
    install(TARGETS qca-pkcs11
            LIBRARY DESTINATION "${QCA_CRYPTO_INSTALL_DIR}"
            ARCHIVE DESTINATION "${QCA_CRYPTO_INSTALL_DIR}"
            RUNTIME DESTINATION "${QCA_CRYPTO_INSTALL_DIR}")

    install_pdb(qca-pkcs11 ${QCA_CRYPTO_INSTALL_DIR})
  endif()
else(OPENSSL_FOUND AND PKCS11H_FOUND)
  disable_plugin("pkcs11")
endif(OPENSSL_FOUND AND PKCS11H_FOUND)
