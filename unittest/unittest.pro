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
	keybundle \
	keygenunittest \
	keylengthunittest \
	keystore \
	logger \
	macunittest \
	metatype \
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

