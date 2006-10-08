
MACRO(MY_AUTOMOC _srcsList)
  QT4_GET_MOC_INC_DIRS(_moc_INCS)
  FOREACH (_current_FILE ${${_srcsList}})
    GET_FILENAME_COMPONENT(_abs_FILE ${_current_FILE} ABSOLUTE)
    GET_FILENAME_COMPONENT(_basename ${_current_FILE} NAME_WE)
    SET(_moc ${CMAKE_CURRENT_BINARY_DIR}/${_basename}.moc)
    ADD_CUSTOM_COMMAND(OUTPUT ${_moc}
                       COMMAND ${QT_MOC_EXECUTABLE}
                       ARGS ${_moc_INCS} -o ${_moc} ${_abs_FILE}
                       DEPENDS ${_current_FILE}
    )
    LIST(APPEND ${_srcsList} ${_moc})
  ENDFOREACH (_current_FILE)
ENDMACRO(MY_AUTOMOC)

#TODO ?
MACRO (QCA_FIND_CERTSTORE)

ENDMACRO (QCA_FIND_CERTSTORE)

MACRO (USE_BUNDLED_CERTSTORE)
  SET( qca_CERTSTORE "${CMAKE_CURRENT_SOURCE_DIR}/certs/rootcerts.pem")
  SET( QCA_USING_BUNDLED_CERTSTORE TRUE )
  # note that INSTALL_FILES targets are relative to the current installation prefix...
  INSTALL_FILES( "/certs" FILES "${CMAKE_CURRENT_SOURCE_DIR}/certs/rootcerts.pem" )
ENDMACRO (USE_BUNDLED_CERTSTORE)

