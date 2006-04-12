TEMPLATE = subdirs

SUBDIRS += \
	base64unittest \
	bigintunittest \
	certunittest \
	cipherunittest \
	cms \
	dsaunittest \
	filewatchunittest \
	hashunittest \
	hexunittest \
	kdfunittest \
	keygenunittest \
	keylengthunittest \
	macunittest \
	pkits \
	randomunittest \
	rsaunittest \
	securearrayunittest \
	staticunittest \
	symmetrickeyunittest \
	tls

QMAKE_EXTRA_TARGETS += check
check.commands = sh ./checkall

