# - Try to find the pkcs11-helper library
# Once done this will define
#
#  PKCS11H_FOUND - system has pkcs11-helper 
#  PKCS11H_INCLUDE_DIRS - the pkcs11-helper include directories
#  PKCS11H_LDFLAGS - Link to these to use pkcs11-helper
#  PKCS11H_CFLAGS_OTHER - Compiler switches required for using pkcs11-helper
#
# Copyright (c) 2006, Laurent Montel, <montel@kde.org>
#
# Redistribution and use is allowed according to the terms of the BSD license.
# For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#
# pkcs11-helper can be found at http://www.opensc-project.org/pkcs11-helper
#

if(PKCS11H_INCLUDE_DIRS AND PKCS11H_LDFLAGS)

  # in cache already
  SET(PKCS11H_FOUND TRUE)

else()
  if(NOT WIN32)
    find_package(PkgConfig)
    pkg_search_module(PKCS11H libpkcs11-helper-1)
  endif()

  if (PKCS11H_FOUND)
    if (NOT Pkcs11Helper_FIND_QUIETLY)
      message(STATUS "Found pkcs11-helper: ${PKCS11H_LDFLAGS}")
    endif()
  else()
    if (Pkcs11Helper_FIND_REQUIRED)
      message(FATAL_ERROR "Could NOT find pkcs11-helper")
    endif()
  endif()
  
  mark_as_advanced(PKCS11H_INCLUDE_DIRS PKCS11H_LDFLAGS PKCS11H_CFLAGS_OTHER)
  
endif()
