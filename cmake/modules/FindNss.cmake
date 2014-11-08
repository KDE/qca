# - Try to find the NSS library
# Once done this will define
#
#  NSS_FOUND - system has mozilla-nss lib
#  NSS_INCLUDE_DIRS - the mozilla-nss include directories
#  NSS_LDFLAGS - Link these to use mozilla-nss
#  NSS_CFLAGS_OTHER - Compiler switches required for using NSS
#
# Copyright (c) 2006, Laurent Montel, <montel@kde.org>
#
# Redistribution and use is allowed according to the terms of the BSD license.
# For details see the accompanying COPYING-CMAKE-SCRIPTS file.

if(NSS_INCLUDE_DIRS AND NSS_LDFLAGS)

  # in cache already
  SET(NSS_FOUND TRUE)

else()
  if(NOT WIN32)
    find_package(PkgConfig)
    pkg_search_module(NSS nss)
  endif(NOT WIN32)

  if (NSS_FOUND)
    if (NOT Nss_FIND_QUIETLY)
      message(STATUS "Found NSS: ${NSS_LDFLAGS}")
    endif (NOT Nss_FIND_QUIETLY)
  else (NSS_FOUND)
    if (Nss_FIND_REQUIRED)
      message(FATAL_ERROR "Could NOT find NSS")
    endif (Nss_FIND_REQUIRED)
  endif (NSS_FOUND)
  
  mark_as_advanced(NSS_INCLUDE_DIRS NSS_LDFLAGS NSS_CFLAGS_OTHER)
  
endif()
