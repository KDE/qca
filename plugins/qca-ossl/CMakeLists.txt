# QCA OSSL

if(WITH_ossl_PLUGIN STREQUAL "yes")
  find_package(OpenSSL 1.1.1 REQUIRED)
else()
  find_package(OpenSSL 1.1.1)
endif()

option(OSSL3_NO_LEGACY "Disable algorithms in the legacy provider of OpenSSL 3" OFF)
if(OSSL3_NO_LEGACY)
  add_definitions(-DOPENSSL3_NO_LEGACY)
endif()

if(OPENSSL_FOUND)
  enable_plugin("ossl")

  include(CheckFunctionExists)
  set(CMAKE_REQUIRED_LIBRARIES ${OPENSSL_LIBRARIES})

  check_function_exists(EVP_aes_128_ctr HAVE_OPENSSL_AES_CTR)
  if(HAVE_OPENSSL_AES_CTR)
    add_definitions(-DHAVE_OPENSSL_AES_CTR)
  else()
    message(WARNING "qca-ossl will be compiled without AES CTR mode encryption support")
  endif()

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

  set(QCA_OSSL_SOURCES
      qca-ossl.cpp)

  add_library(qca-ossl ${PLUGIN_TYPE} ${QCA_OSSL_SOURCES})

  if(APPLE AND ${PLUGIN_TYPE} STREQUAL "MODULE")
    set_property(TARGET qca-ossl PROPERTY SUFFIX ".dylib")
  endif()


  target_link_libraries(qca-ossl Qt${QT_MAJOR_VERSION}::Core)
  target_link_libraries(qca-ossl ${QCA_LIB_NAME})
  target_link_libraries(qca-ossl OpenSSL::SSL OpenSSL::Crypto)

  if(NOT DEVELOPER_MODE)
    install(TARGETS qca-ossl
            LIBRARY DESTINATION "${QCA_CRYPTO_INSTALL_DIR}"
            ARCHIVE DESTINATION "${QCA_CRYPTO_INSTALL_DIR}"
            RUNTIME DESTINATION "${QCA_CRYPTO_INSTALL_DIR}")

    install_pdb(qca-ossl ${QCA_CRYPTO_INSTALL_DIR})
  endif()

else()
  disable_plugin("ossl")
endif()
