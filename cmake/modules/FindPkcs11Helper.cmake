# - Try to find the pkcs11-helper library
# Once done this will define
#
#  PKCS11H_FOUND - system has pkcs11-helper 
#  PKCS11H_INCLUDE_DIRS - the pkcs11-helper include directories
#  PKCS11H_LIBRARIES - Link to these to use pkcs11-helper
#  PKCS11H_DEFINITIONS - Compiler switches required for using pkcs11-helper
#
# Copyright (c) 2006, Laurent Montel, <montel@kde.org>
#
# Redistribution and use is allowed according to the terms of the BSD license.
# For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#
# pkcs11-helper can be found at http://www.opensc-project.org/pkcs11-helper
#

if (PKCS11H_INCLUDE_DIRS AND PKCS11H_LIBRARIES)

  # in cache already
  SET(PKCS11H_FOUND TRUE)

else (PKCS11H_INCLUDE_DIRS AND PKCS11H_LIBRARIES)
  if(NOT WIN32)
    INCLUDE(UsePkgConfig)

    PKGCONFIG(libpkcs11-helper-1 _PKCS11HIncDir _PKCS11HLinkDir _PKCS11HLinkFlags _PKCS11HCflags)

    set(PKCS11H_DEFINITIONS ${_PKCS11HCflags})
    set(PKCS11H_INCLUDE_DIRS ${_PKCS11HIncDir})
    set(PKCS11H_LIBRARIES ${_PKCS11HLinkFlags})
  endif(NOT WIN32)

  if (PKCS11H_INCLUDE_DIRS AND PKCS11H_LIBRARIES)
     set(PKCS11H_FOUND TRUE)
  endif (PKCS11H_INCLUDE_DIRS AND PKCS11H_LIBRARIES)
  
  if (PKCS11H_FOUND)
    if (NOT Pkcs11Helper_FIND_QUIETLY)
      message(STATUS "Found pkcs11-helper: ${PKCS11H_LIBRARIES}")
    endif (NOT Pkcs11Helper_FIND_QUIETLY)
  else (PKCS11H_FOUND)
    if (Pkcs11Helper_FIND_REQUIRED)
      message(FATAL_ERROR "Could NOT find pkcs11-helper")
    endif (Pkcs11Helper_FIND_REQUIRED)
  endif (PKCS11H_FOUND)
  
  MARK_AS_ADVANCED(PKCS11H_INCLUDE_DIRS PKCS11H_LIBRARIES)
  
endif (PKCS11H_INCLUDE_DIRS AND PKCS11H_LIBRARIES)
