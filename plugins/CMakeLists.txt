
FIND_PACKAGE(OpenSSL)
find_package(Sasl2)
FIND_PACKAGE(Nss)
FIND_PACKAGE(LibGcrypt)
FIND_PACKAGE(Botan)

IF (OPENSSL_FOUND)
  ADD_SUBDIRECTORY(qca-openssl)
  ADD_SUBDIRECTORY(qca-pkcs11)
  MESSAGE(STATUS "OpenSSL plugin enabled")
ENDIF(OPENSSL_FOUND)

FIND_PROGRAM(QCA_GPG_EXECUTABLE NAMES gpg)

IF ( QCA_GPG_EXECUTABLE )
  MESSAGE(STATUS "GnuPG plugin enabled")
  ADD_SUBDIRECTORY(qca-gnupg)
ENDIF ( QCA_GPG_EXECUTABLE )

if(SASL2_FOUND)
  MESSAGE(STATUS "Sasl2 plugin enabled")
  MESSAGE(STATUS "Need to port qca-sasl to qt4")
  #add_subdirectory(qca-sasl)
  #add_subdirectory(qca-cyrus-sasl)
endif(SASL2_FOUND)

if(BOTAN_FOUND)
  MESSAGE(STATUS "Botan plugin enabled")
  ADD_SUBDIRECTORY(qca-botan)
endif(BOTAN_FOUND)	

if(LIBGCRYPT_FOUND)
	MESSAGE(STATUS "libgcrypt plugin enabled")
	ADD_SUBDIRECTORY(qca-gcrypt)
endif(LIBGCRYPT_FOUND)

if(NSS_FOUND)
	MESSAGE(STATUS "NSS plugin enabled")
	ADD_SUBDIRECTORY(qca-nss)
endif(NSS_FOUND)	


