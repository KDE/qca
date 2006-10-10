# - Try to find the NSS library
# Once done this will define
#
#  NSS_FOUND - system has mozilla-nss lib
#  NSS_INCLUDE_DIR - the mozilla-nss include directory
#  NSS_LIBRARIES - Link these to use mozilla-nss
#  NSS_DEFINITIONS - Compiler switches required for using NSS
#
# Copyright (c) 2006, Laurent Montel, <montel@kde.org>
#
# Redistribution and use is allowed according to the terms of the BSD license.
# For details see the accompanying COPYING-CMAKE-SCRIPTS file.

if (NSS_INCLUDE_DIR AND NSS_LIBRARIES)

  # in cache already
  SET(NSS_FOUND TRUE)

else (NSS_INCLUDE_DIR AND NSS_LIBRARIES)

  # use pkg-config to get the directories and then use these values
  # in the FIND_PATH() and FIND_LIBRARY() calls
  INCLUDE(UsePkgConfig)
  
  PKGCONFIG(mozilla-nss _NSSIncDir _NSSLinkDir _NSSLinkFlags _NSSCflags)
  
  set(NSS_DEFINITIONS ${_NSSCflags})

  FIND_PATH(NSS_INCLUDE_DIR nss/pk11func.h
    ${_NSSIncDir}
    /usr/include
    /usr/local/include
  )
  
  FIND_LIBRARY(NSS_LIBRARIES NAMES nss3
    PATHS
    ${_NSSLinkDir}
    /usr/lib
    /usr/local/lib
  )
  
  if (NSS_INCLUDE_DIR AND NSS_LIBRARIES)
     set(NSS_FOUND TRUE)
  endif (NSS_INCLUDE_DIR AND NSS_LIBRARIES)
  
  if (NSS_FOUND)
    if (NOT NSS_FIND_QUIETLY)
      message(STATUS "Found NSS: ${NSS_LIBRARIES}")
    endif (NOT NSS_FIND_QUIETLY)
  else (NSS_FOUND)
    if (NSS_FIND_REQUIRED)
      message(FATAL_ERROR "Could NOT find NSS")
    endif (NSS_FIND_REQUIRED)
  endif (NSS_FOUND)
  
  MARK_AS_ADVANCED(NSS_INCLUDE_DIR NSS_LIBRARIES)
  
endif (NSS_INCLUDE_DIR AND NSS_LIBRARIES)
