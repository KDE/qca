# QCA OSSL

if(WITH_ossl_PLUGIN STREQUAL "yes")
  find_package(OpenSSL REQUIRED)
else(WITH_ossl_PLUGIN STREQUAL "yes")
  find_package(OpenSSL)
endif(WITH_ossl_PLUGIN STREQUAL "yes")

if(OPENSSL_FOUND)
  enable_plugin("ossl")

  include(CheckFunctionExists)
  set(CMAKE_REQUIRED_LIBRARIES ${OPENSSL_LIBRARIES})
  check_function_exists(EVP_md2 HAVE_OPENSSL_MD2)
  if(HAVE_OPENSSL_MD2)
    add_definitions(-DHAVE_OPENSSL_MD2)
  else(HAVE_OPENSSL_MD2)
    message(WARNING "qca-ossl will be compiled without MD2 digest algorithm support")
  endif(HAVE_OPENSSL_MD2)

  check_function_exists(EVP_aes_128_ctr HAVE_OPENSSL_AES_CTR)
  if(HAVE_OPENSSL_AES_CTR)
    add_definitions(-DHAVE_OPENSSL_AES_CTR)
  else(HAVE_OPENSSL_AES_CTR)
    message(WARNING "qca-ossl will be compiled without AES CTR mode encryption support")
  endif(HAVE_OPENSSL_AES_CTR)

  check_function_exists(EVP_aes_128_gcm HAVE_OPENSSL_AES_GCM)
  if(HAVE_OPENSSL_AES_GCM)
    add_definitions(-DHAVE_OPENSSL_AES_GCM)
  else()
    message(WARNING "qca-ossl will be compiled without AES GCM mode encryption support")
  endif()

  check_function_exists(EVP_aes_128_ccm HAVE_OPENSSL_AES_CCM)
  if(HAVE_OPENSSL_AES_CCM)
    add_definitions(-DHAVE_OPENSSL_AES_CCM)
  else()
    message(WARNING "qca-ossl will be compiled without AES CCM mode encryption support")
  endif()

  check_function_exists(EVP_sha HAVE_OPENSSL_SHA0)
  if(HAVE_OPENSSL_SHA0)
    add_definitions(-DHAVE_OPENSSL_SHA0)
  else(HAVE_OPENSSL_SHA0)
    message(WARNING "qca-ossl will be compiled without SHA-0 digest algorithm support")
  endif(HAVE_OPENSSL_SHA0)

  set(QCA_OSSL_SOURCES qca-ossl.cpp)

  my_automoc( QCA_OSSL_SOURCES )

  add_library(qca-ossl ${PLUGIN_TYPE} ${QCA_OSSL_SOURCES})

  if(APPLE AND ${PLUGIN_TYPE} STREQUAL "MODULE")
    set_property(TARGET qca-ossl PROPERTY SUFFIX ".dylib")
  endif()

  target_link_libraries(qca-ossl ${QT_QTCORE_LIBRARY})
  target_link_libraries(qca-ossl ${QCA_LIB_NAME})
  target_link_libraries(qca-ossl OpenSSL::SSL OpenSSL::Crypto)

  if(NOT DEVELOPER_MODE)
    install(TARGETS qca-ossl
            LIBRARY DESTINATION "${QCA_CRYPTO_INSTALL_DIR}"
            ARCHIVE DESTINATION "${QCA_CRYPTO_INSTALL_DIR}"
            RUNTIME DESTINATION "${QCA_CRYPTO_INSTALL_DIR}")

    install_pdb(qca-ossl ${QCA_CRYPTO_INSTALL_DIR})
  endif()

  else(OPENSSL_FOUND)
  disable_plugin("ossl")
endif(OPENSSL_FOUND)
