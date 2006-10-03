# QCA GnuPG

SET(QCA_GNUPG_SOURCES qca-gnupg.cpp gpgop.cpp gpgproc/gpgproc.cpp gpgproc/sprocess.cpp)

MY_AUTOMOC( QCA_GNUPG_SOURCES )

ADD_LIBRARY(qca-gnupg SHARED ${QCA_GNUPG_SOURCES})
INCLUDE_DIRECTORIES(gpgproc)
TARGET_LINK_LIBRARIES(qca-gnupg ${QT_QTCORE_LIBRARY} qca)

#TODO perhaps search adavapi on win32
IF (WIN32)
  TARGET_LINK_LIBRARIES(qca-openssl advapi32)
ENDIF (WIN32)

INSTALL(TARGETS qca-gnupg LIBRARY DESTINATION ${qca_PLUGINSDIR})
