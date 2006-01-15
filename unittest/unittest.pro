TEMPLATE = subdirs

SUBDIRS += \
	base64unittest \
	bigintunittest \
	cipherunittest \
	hashunittest \
	hexunittest \
	kdfunittest \
	keygenunittest \
	macunittest \
	securearrayunittest \
	staticunittest \
	symmetrickeyunittest


QMAKE_EXTRA_TARGETS += check
check.commands = sh ./checkall

