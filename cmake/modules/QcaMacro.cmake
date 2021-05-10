
MACRO(SETUP_QT_DIRS)
  if(QT6)
    GET_TARGET_PROPERTY(QMAKE_EXECUTABLE Qt6::qmake LOCATION)
  else()
    GET_TARGET_PROPERTY(QMAKE_EXECUTABLE ${Qt5Core_QMAKE_EXECUTABLE} LOCATION)
  endif()
  EXEC_PROGRAM( ${QMAKE_EXECUTABLE} ARGS "-query QT_INSTALL_LIBS" OUTPUT_VARIABLE QT_LIBRARY_DIR )
  EXEC_PROGRAM( ${QMAKE_EXECUTABLE} ARGS "-query QT_INSTALL_PREFIX" OUTPUT_VARIABLE QT_PREFIX_DIR )
  EXEC_PROGRAM( ${QMAKE_EXECUTABLE} ARGS "-query QT_INSTALL_PLUGINS" OUTPUT_VARIABLE QT_PLUGINS_DIR )
  EXEC_PROGRAM( ${QMAKE_EXECUTABLE} ARGS "-query QT_INSTALL_BINS" OUTPUT_VARIABLE QT_BINARY_DIR )
  EXEC_PROGRAM( ${QMAKE_EXECUTABLE} ARGS "-query QT_INSTALL_HEADERS" OUTPUT_VARIABLE QT_HEADERS_DIR )
  EXEC_PROGRAM( ${QMAKE_EXECUTABLE} ARGS "-query QT_INSTALL_DOCS" OUTPUT_VARIABLE QT_DOC_DIR )
  EXEC_PROGRAM( ${QMAKE_EXECUTABLE} ARGS "-query QT_INSTALL_DATA" OUTPUT_VARIABLE QT_DATA_DIR )
  EXEC_PROGRAM( ${QMAKE_EXECUTABLE} ARGS "-query QT_HOST_DATA" OUTPUT_VARIABLE QT_ARCHDATA_DIR )
  SET( QT_MKSPECS_DIR "${QT_ARCHDATA_DIR}/mkspecs" )
ENDMACRO(SETUP_QT_DIRS)

macro(set_enabled_plugin PLUGIN ENABLED)
  # To nice looks
  if(ENABLED)
    set(ENABLED "on")
  else()
    set(ENABLED "off")
  endif()
  set(WITH_${PLUGIN}_PLUGIN_INTERNAL ${ENABLED} CACHE INTERNAL "")
endmacro(set_enabled_plugin)

macro(enable_plugin PLUGIN)
  set_enabled_plugin(${PLUGIN} "on")
endmacro(enable_plugin)

macro(disable_plugin PLUGIN)
  set_enabled_plugin(${PLUGIN} "off")
endmacro(disable_plugin)

# it used to build examples and tools
macro(target_link_qca_libraries TARGET)
  # Link with QCA library
  target_link_libraries(${TARGET} ${QCA_LIB_NAME})

  # Statically link with all enabled QCA plugins
  if(STATIC_PLUGINS)
    target_link_libraries(${TARGET} ${QT_QTCORE_LIB_DEPENDENCIES})
    foreach(PLUGIN IN LISTS PLUGINS)
      # Check plugin for enabled
      if(WITH_${PLUGIN}_PLUGIN_INTERNAL)
        target_link_libraries(${TARGET} qca-${PLUGIN})
      endif()
    endforeach(PLUGIN)
  endif()
endmacro(target_link_qca_libraries)

# it used to build unittests
macro(target_link_qca_test_libraries TARGET)
  target_link_qca_libraries(${TARGET})
  if(QT6)
    target_link_libraries(${TARGET} Qt6::Test)
  else()
    target_link_libraries(${TARGET} Qt5::Test)
  endif()
endmacro(target_link_qca_test_libraries)

# it used to build unittests
macro(add_qca_test TARGET DESCRIPTION)
  add_test(NAME "${DESCRIPTION}"
           WORKING_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}"
           COMMAND "${TARGET}")
endmacro(add_qca_test)

macro(install_pdb TARGET INSTALL_PATH)
  if(MSVC)
    get_target_property(LOCATION ${TARGET} LOCATION_DEBUG)
    string(REGEX REPLACE "\\.[^.]*$" ".pdb" LOCATION "${LOCATION}")
    install(FILES ${LOCATION} DESTINATION ${INSTALL_PATH} CONFIGURATIONS Debug)

    get_target_property(LOCATION ${TARGET} LOCATION_RELWITHDEBINFO)
    string(REGEX REPLACE "\\.[^.]*$" ".pdb" LOCATION "${LOCATION}")
    install(FILES ${LOCATION} DESTINATION ${INSTALL_PATH} CONFIGURATIONS RelWithDebInfo)
  endif()
endmacro(install_pdb)

macro(normalize_path PATH)
  get_filename_component(${PATH} "${${PATH}}" ABSOLUTE)
  # Strip trailing slashes
  string(REGEX REPLACE "/+$" "" PATH ${PATH})
endmacro()
