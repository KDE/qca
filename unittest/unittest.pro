TEMPLATE = subdirs

SUBDIRS += \
	base64unittest \
	bigintunittest \
	certunittest \
	cipherunittest \
	clientplugin \
	cms \
	dsaunittest \
	filewatchunittest \
	hashunittest \
	hexunittest \
	kdfunittest \
	keygenunittest \
	keylengthunittest \
	keystore \
	logger \
	macunittest \
#	pgpunittest \
	pkits \
	randomunittest \
	rsaunittest \
	securearrayunittest \
	staticunittest \
	symmetrickeyunittest \
	tls \
	velox

QMAKE_EXTRA_TARGETS += check
check.commands = sh ./checkall

