TEMPLATE = subdirs

SUBDIRS += \
	base64unittest \
	bigintunittest \
        hashunittest \
	hexunittest \
	kdfunittest \
	keygenunittest \
	securearrayunittest \
	staticunittest


QMAKE_EXTRA_TARGETS += check
check.commands = sh ./checkall

