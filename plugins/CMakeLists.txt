# Use the same path for shared and static plugins
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib/${QCA_LIB_NAME}/crypto")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib/${QCA_LIB_NAME}/crypto")

set(PLUGINS "botan;cyrus-sasl;gcrypt;gnupg;logger;nss;ossl;pkcs11;softstore" CACHE INTERNAL "")

# Initialize WITH_${PLUGIN}_PLUGIN cache variables
foreach(PLUGIN IN LISTS PLUGINS)
  set(WITH_${PLUGIN}_PLUGIN "" CACHE STRING "Build ${PLUGIN} plugin")
  string(TOLOWER "${WITH_${PLUGIN}_PLUGIN}" WITH_${PLUGIN}_PLUGIN)
endforeach(PLUGIN IN LISTS PLUGINS)

string(REGEX MATCH "^none|all|auto$" NOT_PLUGIN_LIST "${BUILD_PLUGINS}")

if(NOT_PLUGIN_LIST)
  # BUILD_PLUGINS has "none", "all" or "auto" value
  foreach(PLUGIN IN LISTS PLUGINS)
    # If not defined by user use BUILD_PLUGINS value
    # to decide build or not build the plugin
    if("${WITH_${PLUGIN}_PLUGIN}" STREQUAL "")
      if("${BUILD_PLUGINS}" STREQUAL "all")
        set(WITH_${PLUGIN}_PLUGIN "yes")
      elseif("${BUILD_PLUGINS}" STREQUAL "auto")
        set(WITH_${PLUGIN}_PLUGIN "auto")
      else()
        set(WITH_${PLUGIN}_PLUGIN "no")
      endif()
    elseif(NOT WITH_${PLUGIN}_PLUGIN)
      set(WITH_${PLUGIN}_PLUGIN "no")
    elseif("${WITH_${PLUGIN}_PLUGIN}" STREQUAL "auto")
      set(WITH_${PLUGIN}_PLUGIN "auto")
    else()
      set(WITH_${PLUGIN}_PLUGIN "yes")
    endif()

    # Build plugin if yes or auto
    if(WITH_${PLUGIN}_PLUGIN)
      add_subdirectory("qca-${PLUGIN}")
    else()
      disable_plugin(${PLUGIN})
    endif()
  endforeach(PLUGIN IN LISTS PLUGINS)
else()
  # BUILD_PLUGINS has list plugins to builds
  foreach(PLUGIN IN LISTS PLUGINS)
    list(FIND BUILD_PLUGINS "${PLUGIN}" PLUGIN_INDEX)
    if(PLUGIN_INDEX GREATER -1)
      set(WITH_${PLUGIN}_PLUGIN "yes")
      add_subdirectory("qca-${PLUGIN}")
    else()
      disable_plugin(${PLUGIN})
    endif()
  endforeach(PLUGIN IN LISTS PLUGINS)
endif()

message("")
message("Plugins:")
foreach(PLUGIN IN LISTS PLUGINS)
  message("  qca-${PLUGIN} ${WITH_${PLUGIN}_PLUGIN_INTERNAL}")
endforeach(PLUGIN IN LISTS PLUGINS)

# Currently disabled
#
# IF (WIN32)
#         MESSAGE(STATUS "WinCrypto plugin enabled")
#         ADD_SUBDIRECTORY(qca-wincrypto)
# ENDIF (WIN32)

