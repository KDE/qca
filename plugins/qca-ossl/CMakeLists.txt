# QCA OSSL

if(WITH_ossl_PLUGIN STREQUAL "yes")
  find_package(OpenSSL 1.1.1 REQUIRED)
else()
  find_package(OpenSSL 1.1.1)
endif()

if(OPENSSL_FOUND)
  enable_plugin("ossl")

  include(CheckFunctionExists)
  set(CMAKE_REQUIRED_LIBRARIES ${OPENSSL_LIBRARIES})

  macro(hash_detect)
    check_function_exists(EVP_${ARGV0} HAVE_OPENSSL_${ARGV1})
    if(${HAVE_OPENSSL_${ARGV1}})
      add_definitions(-DHAVE_OPENSSL_${ARGV1})
    endif()
  endmacro()

  hash_detect(sha SHA0)
  hash_detect(md2 MD2)
  hash_detect(aes_128_ccm AES_CCM)
  hash_detect(aes_128_ctr AES_CTR)
  hash_detect(aes_128_gcm AES_GCM)
  hash_detect(sha3_224 SHA3_224)
  hash_detect(sha3_256 SHA3_256)
  hash_detect(sha3_384 SHA3_384)
  hash_detect(sha3_512 SHA3_512)
  hash_detect(blake2b512 BLAKE2B_512)

  set(QCA_OSSL_SOURCES
      qca-ossl.cpp
      basetlscontext.cpp
      basetlscontext.h
      dtlscontext.cpp
      dtlscontext.h
      tlscontext.cpp
      tlscontext.h
      certcontext.cpp
      certcontext.h
      pkeycontext.cpp
      pkeycontext.h
      utils.cpp
      utils.h
      rsakey.cpp
      rsakey.h
      dsakey.cpp
      dsakey.h
      dhkey.cpp
      dhkey.h
      evpkey.cpp
      evpkey.h
      )

  add_library(qca-ossl ${PLUGIN_TYPE} ${QCA_OSSL_SOURCES})

  if(APPLE AND ${PLUGIN_TYPE} STREQUAL "MODULE")
    set_property(TARGET qca-ossl PROPERTY SUFFIX ".dylib")
  endif()

  target_link_libraries(qca-ossl Qt5::Core)
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
