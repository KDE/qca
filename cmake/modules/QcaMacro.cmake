
MACRO(MY_AUTOMOC _srcsList)
  QT4_GET_MOC_INC_DIRS(_moc_INCS)
  FOREACH (_current_FILE ${${_srcsList}})
    GET_FILENAME_COMPONENT(_abs_FILE ${_current_FILE} ABSOLUTE)
    GET_FILENAME_COMPONENT(_basename ${_current_FILE} NAME_WE)
    SET(_moc ${CMAKE_CURRENT_BINARY_DIR}/${_basename}.moc)
    SET(extra_moc_argument)
    if(WIN32)
       SET(extra_moc_argument -DWIN32)
    endif(WIN32)
    ADD_CUSTOM_COMMAND(OUTPUT ${_moc}
                       COMMAND ${QT_MOC_EXECUTABLE}
                       ARGS ${extra_moc_argument} ${_moc_INCS} -o ${_moc} ${_abs_FILE}
                       DEPENDS ${_current_FILE}
    )
    LIST(APPEND ${_srcsList} ${_moc})
  ENDFOREACH (_current_FILE)
ENDMACRO(MY_AUTOMOC)


