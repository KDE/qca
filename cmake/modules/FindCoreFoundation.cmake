# Copyright (c) 2014, Samuel Gaist, <samuel.gaist@edeltech.ch>
#
# Redistribution and use is allowed according to the terms of the BSD license.
# For details see the accompanying COPYING-CMAKE-SCRIPTS file.

INCLUDE(CMakeFindFrameworks)

CMAKE_FIND_FRAMEWORKS(CoreFoundation)

if (CoreFoundation_FRAMEWORKS)
   set(COREFOUNDATION_LIBRARY "-framework CoreFoundation" CACHE FILEPATH "CoreFoundation framework" FORCE)
   set(COREFOUNDATION_FOUND 1)
endif (CoreFoundation_FRAMEWORKS)
