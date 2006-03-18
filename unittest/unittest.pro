TEMPLATE = subdirs

SUBDIRS += \
	base64unittest \
	bigintunittest \
	certunittest \
	cipherunittest \
	hashunittest \
	hexunittest \
	kdfunittest \
	keygenunittest \
	macunittest \
	pkits \
	securearrayunittest \
	staticunittest \
	symmetrickeyunittest \
	tls

QMAKE_EXTRA_TARGETS += check
check.commands = sh ./checkall

