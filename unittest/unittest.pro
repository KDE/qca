TEMPLATE = subdirs

SUBDIRS += \
	bigintunittest \
        hashunittest \
	kdfunittest \
	staticunittest


QMAKE_EXTRA_TARGETS += check
check.commands = sh ./checkall

