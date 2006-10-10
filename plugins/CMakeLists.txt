
FIND_PACKAGE(OpenSSL)
find_package(Sasl2)
find_package(Nss)

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

#if(BOTAN_FOUND)
#	ADD_SUBDIRECTORY(qca-botan)
#endif(BOTAN_FOUND)	

#ADD_SUBDIRECTORY(qca-gcrypt)
if(NSS_FOUND)
	ADD_SUBDIRECTORY(qca-nss)
endif(NSS_FOUND)	
#ADD_SUBDIRECTORY(qca-tls)

