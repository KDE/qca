
# - Try to find the Gcrypt library
# Once run this will define
#
#  BOTAN_FOUND - set if the system has the gcrypt library
#  BOTAN_CFLAGS - the required gcrypt compilation flags
#  BOTAN_LIBRARIES - the linker libraries needed to use the gcrypt library
#
# Copyright (c) 2006 Brad Hards <bradh@kde.org>
#
# Redistribution and use is allowed according to the terms of the BSD license.
# For details see the accompanying COPYING-CMAKE-SCRIPTS file.

#reset variables
set(BOTAN_LIBRARIES)
set(BOTAN_CFLAGS)

find_package(PkgConfig)
pkg_search_module(BOTAN botan>=1.10 botan-1.10 botan-2)

if (BOTAN_FOUND)
   if (NOT Botan_FIND_QUIETLY)
     message(STATUS "Found Botan: ${BOTAN_LIBRARIES}")
   endif (NOT Botan_FIND_QUIETLY)
else (BOTAN_FOUND)
   if (Botan_FIND_REQUIRED)
      message(FATAL_ERROR "Could not find Botan libraries")
   endif (Botan_FIND_REQUIRED)
endif (BOTAN_FOUND)


