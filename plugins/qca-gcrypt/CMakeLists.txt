if(WITH_gcrypt_PLUGIN STREQUAL "yes")
  find_package(LibGcrypt REQUIRED)
else(WITH_gcrypt_PLUGIN STREQUAL "yes")
  find_package(LibGcrypt)
endif(WITH_gcrypt_PLUGIN STREQUAL "yes")

if(LIBGCRYPT_FOUND)
  include(CheckTypeSize)

  set(remember_includes ${CMAKE_EXTRA_INCLUDE_FILES})
  set(remember_defines ${CMAKE_REQUIRED_FLAGS})
  set(CMAKE_EXTRA_INCLUDE_FILES gcrypt.h)
  set(CMAKE_REQUIRED_FLAGS ${LIBGCRYPT_CFLAGS})
  check_type_size(gcry_error_t GCRY_ERROR_T)
  set(CMAKE_REQUIRED_FLAGS ${remember_defines})
  set(CMAKE_EXTRA_INCLUDE_FILES ${remember_includes})
  if(HAVE_GCRY_ERROR_T)
    enable_plugin("gcrypt")

    set(QCA_GCRYPT_SOURCES qca-gcrypt.cpp)
    add_definitions(${LIBGCRYPT_CFLAGS})
    my_automoc(QCA_GCRYPT_SOURCES)
    add_library(qca-gcrypt ${PLUGIN_TYPE} ${QCA_GCRYPT_SOURCES})

    if(APPLE AND ${PLUGIN_TYPE} STREQUAL "MODULE")
      set_property(TARGET qca-gcrypt PROPERTY SUFFIX ".dylib")
    endif()

    target_link_libraries(qca-gcrypt ${QT_QTCORE_LIBRARY} ${QCA_LIB_NAME} ${LIBGCRYPT_LIBRARIES})

    if(NOT DEVELOPER_MODE)
      install(TARGETS qca-gcrypt
              LIBRARY DESTINATION "${QCA_CRYPTO_INSTALL_DIR}"
              ARCHIVE DESTINATION "${QCA_CRYPTO_INSTALL_DIR}"
              RUNTIME DESTINATION "${QCA_CRYPTO_INSTALL_DIR}")

      install_pdb(qca-gcrypt ${QCA_CRYPTO_INSTALL_DIR})
    endif()
  else(HAVE_GCRY_ERROR_T)
    message(STATUS "libgcrypt seems to be too old")
    disable_plugin("gcrypt")
  endif(HAVE_GCRY_ERROR_T)
else(LIBGCRYPT_FOUND)
  disable_plugin("gcrypt")
endif(LIBGCRYPT_FOUND)
