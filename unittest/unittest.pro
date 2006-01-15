TEMPLATE = subdirs

SUBDIRS += \
	base64unittest \
	bigintunittest \
	cipherunittest \
	hashunittest \
	hexunittest \
	kdfunittest \
	keygenunittest \
	securearrayunittest \
	staticunittest


QMAKE_EXTRA_TARGETS += check
check.commands = sh ./checkall

