# - Try to find the NSS library
# Once done this will define
#
#  NSS_FOUND - system has mozilla-nss lib
#  NSS_INCLUDE_DIRS - the mozilla-nss include directories
#  NSS_LIBRARIES - Link these to use mozilla-nss
#  NSS_DEFINITIONS - Compiler switches required for using NSS
#
# Copyright (c) 2006, Laurent Montel, <montel@kde.org>
#
# Redistribution and use is allowed according to the terms of the BSD license.
# For details see the accompanying COPYING-CMAKE-SCRIPTS file.

if (NSS_INCLUDE_DIRS AND NSS_LIBRARIES)

  # in cache already
  SET(NSS_FOUND TRUE)

else (NSS_INCLUDE_DIRS AND NSS_LIBRARIES)
  if(NOT WIN32)
    INCLUDE(UsePkgConfig)

    PKGCONFIG(nss _NSSIncDir _NSSLinkDir _NSSLinkFlags _NSSCflags)

    set(NSS_DEFINITIONS ${_NSSCflags})
    set(NSS_INCLUDE_DIRS ${_NSSIncDir})
    set(NSS_LIBRARIES ${_NSSLinkFlags})
  endif(NOT WIN32)

  if (NSS_INCLUDE_DIRS AND NSS_LIBRARIES)
     set(NSS_FOUND TRUE)
  endif (NSS_INCLUDE_DIRS AND NSS_LIBRARIES)
  
  if (NSS_FOUND)
    if (NOT Nss_FIND_QUIETLY)
      message(STATUS "Found NSS: ${NSS_LIBRARIES}")
    endif (NOT Nss_FIND_QUIETLY)
  else (NSS_FOUND)
    if (Nss_FIND_REQUIRED)
      message(FATAL_ERROR "Could NOT find NSS")
    endif (Nss_FIND_REQUIRED)
  endif (NSS_FOUND)
  
  MARK_AS_ADVANCED(NSS_INCLUDE_DIRS NSS_LIBRARIES)
  
endif (NSS_INCLUDE_DIRS AND NSS_LIBRARIES)
